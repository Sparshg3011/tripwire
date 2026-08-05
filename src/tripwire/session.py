"""Everything the evaluator is allowed to know about the conversation.

One SessionState per agent connection. It records *executed* calls only.
A blocked call leaves nothing behind: no count, no history entry, no
turn. That asymmetry is on purpose — if refused calls moved the state,
an attacker could spend your per-session budget with calls that never
ran, or fire three junk calls to push a fetch_url out of a sequence
window. Refusing a call should never help the caller.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot
from tripwire.taint import TaintTracker


class SessionBroken(Exception):
    """Raised by snapshot() once we've lost track of the session.

    Nothing recovers from this. A session whose bookkeeping failed can't
    be evaluated honestly, so from that point every call fails closed.
    """


def _summed_fields(policy: Policy) -> dict[str, str]:
    """tool -> the one arg the policy sums for it. Nothing else is tracked."""
    fields = {}
    for name, rule in policy.tools.items():
        if rule.limits is not None and rule.limits.sum_per_session is not None:
            fields[name] = rule.limits.sum_per_session.field
    return fields


class SessionState:
    def __init__(self, policy: Policy, taint: TaintTracker | None = None):
        self.policy = policy
        self.taint = taint if taint is not None else TaintTracker(policy)
        self.turn = 0
        self.broken: str | None = None
        self._counts: dict[str, int] = {}
        self._sums: dict[str, dict[str, float]] = {}
        self._history: list[tuple[int, str]] = []
        self._summed = _summed_fields(policy)

    def snapshot(self) -> SessionSnapshot:
        """A frozen copy for the evaluator. Copies, not views — the
        evaluator is pure and must not be able to see state move under
        it, or mutate ours by accident."""
        if self.broken is not None:
            raise SessionBroken(self.broken)
        return SessionSnapshot(
            turn=self.turn,
            tainted=self.taint.tainted,
            tool_counts=dict(self._counts),
            tool_sums={tool: dict(fields) for tool, fields in self._sums.items()},
            history=tuple(self._history),
        )

    def record(self, tool: str, args: Mapping[str, Any]) -> None:
        """Called after a call has actually been forwarded.

        Errored calls count too: upstream saying "500" doesn't tell us
        the email wasn't sent, and a limit that forgets failed attempts
        is a limit you can retry your way past.
        """
        self._counts[tool] = self._counts.get(tool, 0) + 1
        self._history.append((self.turn, tool))

        field = self._summed.get(tool)
        if field is not None:
            value = args.get(field)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals = self._sums.setdefault(tool, {})
                totals[field] = totals.get(field, 0.0) + float(value)

        self.turn += 1

    def observe_result(self, tool: str, is_error: bool = False) -> None:
        self.taint.observe_result(tool, is_error=is_error)
