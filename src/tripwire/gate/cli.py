"""Ask at the terminal.

Can't use stdin/stdout — in a running proxy those are the MCP wire. So
we open the controlling terminal directly. That only exists when
tripwire was started from a shell; under Claude Desktop there is no
terminal at all, which is what --gate web is for. We find that out at
startup and refuse to start, not at approval time when it's too late
to matter.
"""

from __future__ import annotations

import json

import anyio

from tripwire.gate.base import ApprovalRequest, GateUnavailable

ARGS_PREVIEW = 500  # a 10k email body shouldn't flood the terminal


class CliGate:
    def __init__(self, tty_path: str = "/dev/tty"):
        try:
            # line-buffered r+: we write the question and read the answer
            # on the same handle
            self._tty = open(tty_path, "r+", buffering=1)  # noqa: SIM115
        except OSError as e:
            raise GateUnavailable(
                f"--gate cli needs a terminal ({e}); if tripwire is being "
                f"launched by an app rather than a shell, use --gate web"
            ) from e

    async def request(self, req: ApprovalRequest) -> bool:
        # If the timeout fires first, this thread is abandoned mid-read.
        # The next line typed at the terminal will be swallowed by the
        # abandoned reader — mildly confusing, but the swallowed answer
        # arrives at a question that already timed out to "no", so the
        # failure direction is the safe one.
        return await anyio.to_thread.run_sync(self._prompt, req, abandon_on_cancel=True)

    def _prompt(self, req: ApprovalRequest) -> bool:
        args = json.dumps(dict(req.args), sort_keys=True, default=str)
        if len(args) > ARGS_PREVIEW:
            args = f"{args[:ARGS_PREVIEW]}... ({len(args) - ARGS_PREVIEW} more chars)"

        taint = "clean session"
        if req.tainted:
            trail = ", ".join(req.tainted_by) if req.tainted_by else "unknown source"
            taint = f"TAINTED session (untrusted content from: {trail})"

        self._tty.write(
            f"\ntripwire: approval needed (turn {req.turn})\n"
            f"  tool:   {req.tool}\n"
            f"  args:   {args}\n"
            f"  rule:   {req.rule_id}\n"
            f"  reason: {req.reason}\n"
            f"  taint:  {taint}\n"
            f"approve? [y/N] "
        )
        line = self._tty.readline()
        # EOF, empty, anything but an explicit yes: no
        return line.strip().lower() in ("y", "yes")

    def close(self) -> None:
        self._tty.close()
