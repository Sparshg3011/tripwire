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
import os
import select
import time
from collections.abc import Collection, Mapping
from typing import Any

import anyio

try:
    import termios
except ImportError:  # windows: there is no controlling terminal to ask
    termios = None  # type: ignore[assignment]

from tripwire.gate.base import (
    ApprovalRequest,
    GateUnavailable,
    anchor_notes,
    clip,
    more_args,
    preview_args,
    printable,
)

ARG_PREVIEW = 500  # per value: a 10k email body shouldn't flood the terminal
# ...and nor should a few hundred arguments. The tool and the recipient
# print first, and scrollback loses whatever scrolls out of it.
ARG_BUDGET = 1000  # characters of preview, all lines together
ARG_WIDTH = 70  # short args share a line this long, which fits 80 columns after the indent
# The tool, rule, reason, taint trail and each anchoring note. An unknown
# tool's name is the caller's to pick, and the rest can repeat it.
FIELD_PREVIEW = 200


# Args reach this prompt from tool calls the attacker may have authored,
# so nothing outside plain printable text survives to the terminal.
def _field(text: str) -> str:
    return clip(printable(text), FIELD_PREVIEW)


def _arg_lines(
    args: Mapping[str, Any],
    checked: Collection[str] = frozenset(),
    notes: Mapping[str, str] | None = None,
) -> tuple[list[str], str]:
    """The argument lines that fit, and what was left out ("" if nothing)."""
    # no printable(): encode_args already escapes everything outside SAFE,
    # and the notes come as _field() made them
    lines, _, hidden = preview_args(args, checked, ARG_PREVIEW, ARG_WIDTH, ARG_BUDGET, notes)
    return lines, more_args(hidden) if hidden else ""


def _question(req: ApprovalRequest) -> str:
    # where each authority argument's values came from, beside them
    notes = {name: _field(note) for name, note in anchor_notes(req.authority, req.anchors).items()}
    lines, left_out = _arg_lines(req.args, req.checked, notes)
    args = "\n          ".join(lines) or "{}"
    if left_out:
        # The terminal has no way to show the rest, so the human is
        # told outright that a yes covers arguments they haven't read.
        args += f"\n  hidden: {left_out}, not shown here but forwarded if you approve"

    taint = "clean session"
    if req.tainted:
        trail = ", ".join(req.tainted_by) if req.tainted_by else "unknown source"
        taint = f"TAINTED session (untrusted content from: {_field(trail)})"

    return (
        f"\ntripwire: approval needed (turn {req.turn})\n"
        f"  tool:   {_field(req.tool)}\n"
        f"  args:   {args}\n"
        f"  rule:   {_field(req.rule_id)}\n"
        f"  reason: {_field(req.reason)}\n"
        f"  taint:  {taint}\n"
        f"approve? [y/N] "
    )


class CliGate:
    def __init__(self, tty_path: str = "/dev/tty", timeout: float = 120.0):
        self.timeout = timeout
        if termios is None:
            raise GateUnavailable(
                "--gate cli needs a POSIX terminal, which this platform "
                "doesn't have; use --gate web"
            )
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
        fd = self._tty.fileno()
        # Discard anything already typed. Without this, a keystroke made
        # before the question appeared would answer it — including an
        # answer meant for a previous prompt that has since timed out.
        # The human must answer the question they can actually see.
        try:
            termios.tcflush(fd, termios.TCIFLUSH)
        except termios.error:
            pass  # not a real terminal (a pipe in tests); nothing buffered to drop

        self._tty.write(_question(req))

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
