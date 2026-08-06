"""Ask at the terminal.

Can't use stdin/stdout — in a running proxy those are the MCP wire. So
we open the controlling terminal directly. That only exists when
tripwire was started from a shell; under Claude Desktop there is no
terminal at all, which is what --gate web is for. We find that out at
startup and refuse to start, not at approval time when it's too late
to matter.
"""

from __future__ import annotations

import io
import json
import os
import select
import termios
import time

import anyio

from tripwire.gate.base import ApprovalRequest, GateUnavailable

ARGS_PREVIEW = 500  # a 10k email body shouldn't flood the terminal

# Args reach this prompt from tool calls the attacker may have authored.
# Anything that can move the cursor, clear the screen, or recolour text
# can redraw the question the human thinks they're answering, so nothing
# outside plain printable text survives to the terminal.
SAFE = set(range(0x20, 0x7F))


def _flatten(text: str) -> str:
    return "".join(c if ord(c) in SAFE else f"\\x{ord(c):02x}" for c in text)


class CliGate:
    def __init__(self, tty_path: str = "/dev/tty", timeout: float = 120.0):
        self.timeout = timeout
        try:
            # Binary + unbuffered under a TextIOWrapper, because text mode
            # "r+" builds a BufferedRandom, which demands a seekable
            # stream — and no terminal is seekable.
            raw = open(tty_path, "r+b", buffering=0)  # noqa: SIM115
            self._tty = io.TextIOWrapper(raw, line_buffering=True, errors="replace")
        except OSError as e:
            raise GateUnavailable(
                f"--gate cli needs a terminal ({e}); if tripwire is being "
                f"launched by an app rather than a shell, use --gate web"
            ) from e

    async def request(self, req: ApprovalRequest) -> bool:
        return await anyio.to_thread.run_sync(self._prompt, req, abandon_on_cancel=True)

    def _prompt(self, req: ApprovalRequest) -> bool:
        args = _flatten(json.dumps(dict(req.args), sort_keys=True, default=str))
        if len(args) > ARGS_PREVIEW:
            args = f"{args[:ARGS_PREVIEW]}... ({len(args) - ARGS_PREVIEW} more chars)"

        taint = "clean session"
        if req.tainted:
            trail = ", ".join(req.tainted_by) if req.tainted_by else "unknown source"
            taint = f"TAINTED session (untrusted content from: {_flatten(trail)})"

        fd = self._tty.fileno()
        # Discard anything already typed. Without this, a keystroke made
        # before the question appeared would answer it — including an
        # answer meant for a previous prompt that has since timed out.
        # The human must answer the question they can actually see.
        try:
            termios.tcflush(fd, termios.TCIFLUSH)
        except termios.error:
            pass  # not a real terminal (a pipe in tests); nothing buffered to drop

        self._tty.write(
            f"\ntripwire: approval needed (turn {req.turn})\n"
            f"  tool:   {_flatten(req.tool)}\n"
            f"  args:   {args}\n"
            f"  rule:   {_flatten(req.rule_id)}\n"
            f"  reason: {_flatten(req.reason)}\n"
            f"  taint:  {taint}\n"
            f"approve? [y/N] "
        )

        line = self._read_line(fd)
        if line is None:
            self._tty.write("\ntripwire: no answer in time; refused.\n")
            return False
        return line.strip().lower() in ("y", "yes")

    def _read_line(self, fd: int) -> str | None:
        """Read until newline or the deadline, never blocking past it.

        Doing our own timeout is what keeps this thread from being
        abandoned mid-read: an abandoned reader sits on the terminal and
        eats the answer to somebody else's question.

        Reads go through os.read rather than the text handle on purpose.
        A buffered reader will happily pull "y\\n" off the fd, hand back
        the "y", and keep the newline in its own buffer — after which
        select() sees an idle fd and we wait for input that already
        arrived. select and buffered reads don't mix.
        """
        deadline = time.monotonic() + self.timeout
        buf = b""
        while b"\n" not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([fd], [], [], remaining)[0]:
                return None
            chunk = os.read(fd, 1024)
            if not chunk:  # EOF: terminal went away, treat as no answer
                return None
            buf += chunk
        return buf.split(b"\n", 1)[0].decode(errors="replace")

    def close(self) -> None:
        self._tty.close()
