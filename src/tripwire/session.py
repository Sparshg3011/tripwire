"""Everything the evaluator is allowed to know about the conversation.

One SessionState per agent connection. It records *executed* calls only.
A blocked call leaves nothing behind: no count, no history entry, no
turn. That asymmetry is on purpose — if refused calls moved the state,
an attacker could spend your per-session budget with calls that never
ran, or fire three junk calls to push a fetch_url out of a sequence
window. Refusing a call should never help the caller. (Allowed calls do
move the turn, so a numeric window can still be padded with harmless
ones. `turns: session` is the sequence rule that can't be.)

Two more things live here for anchoring: the user's task text, in
segments that add up and never expire, and the provenance registry of
what every executed call showed the session (tripwire.provenance), which
only a policy with a flow that says `unless: anchored` keeps.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping, Sequence
from typing import Any

from mcp import types

from tripwire.intent import MAX_TASK_BYTES, TaskRejected
from tripwire.policy.canonical import _clean
from tripwire.policy.evaluator import is_number
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, TaskSegment, TaskView
from tripwire.policy.values import TaskIndex
from tripwire.provenance import Caps, Observed, ProvenanceRegistry
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
    def __init__(
        self,
        policy: Policy,
        taint: TaintTracker | None = None,
        *,
        protected_paths: Sequence[str] = (),
        caps: Caps | None = None,
    ):
        """protected_paths: absolute paths no argument may anchor to, the
        policy file, the audit log, the tx db and the task file. caps:
        what provenance keeps before it degrades."""
        self.policy = policy
        # A capability is bound to this live session, not an audit label that
        # an embedding application could accidentally reuse after a restart.
        self.approval_scope = secrets.token_urlsafe(24)
        self.taint = taint if taint is not None else TaintTracker(policy)
        self.turn = 0
        self.broken: str | None = None
        self.protected_paths = tuple(protected_paths)
        self.provenance = ProvenanceRegistry(caps)
        # nothing reads provenance without such a flow, so nothing records it
        self.anchoring = any(flow.unless == "anchored" for flow in policy.flows)
        self._segments: list[TaskSegment] = []
        self._counts: dict[str, int] = {}
        self._sums: dict[str, dict[str, float]] = {}
        self._history: list[tuple[int, str]] = []
        self._summed = _summed_fields(policy)

    def snapshot(self) -> SessionSnapshot:
        """A frozen copy for the evaluator. Copies, not views — the
        evaluator is pure and must not be able to see state move under
        it, or mutate ours by accident. The one exception is provenance,
        whose view is O(1) because the registry only grows and the view
        reads nothing recorded after it was taken."""
        if self.broken is not None:
            raise SessionBroken(self.broken)
        return SessionSnapshot(
            turn=self.turn,
            tainted=self.taint.tainted,
            tool_counts=dict(self._counts),
            tool_sums={tool: dict(fields) for tool, fields in self._sums.items()},
            history=tuple(self._history),
            task=TaskView(tuple(self._segments)) if self._segments else None,
            provenance=self.provenance.view(),
            protected_paths=self.protected_paths,
        )

    def add_task(self, text: str, source: str) -> int:
        """Add a segment of the user's task text and return its number,
        from 1. Raises TaskRejected for text that isn't a str encodable as
        UTF-8, or that is over MAX_TASK_BYTES of it."""
        if not isinstance(text, str) or not isinstance(source, str):
            raise TaskRejected("not_text")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise TaskRejected("not_utf8") from None
        if size > MAX_TASK_BYTES:
            raise TaskRejected("too_long")
        seq = len(self._segments) + 1
        self._segments.append(TaskSegment(seq, source, TaskIndex.build(text), _clean(text)))
        return seq

    def observe_listing(self, text: str) -> Observed | None:
        """The upstream's tool listing, serialized. None when the policy
        reads no provenance."""
        if not self.anchoring:
            return None
        return self.provenance.observe_listing(text)

    def observe_call(
        self,
        tool: str,
        args: Mapping[str, Any],
        outcome: types.CallToolResult | str | None,
        *,
        tainted: bool,
        may_mint: bool,
    ) -> Observed | None:
        """What an executed call showed the session, to be called before
        record() counts it: its arguments when it ran after untrusted
        content, then its result, or the text of the failure the agent
        was handed instead (None when there was neither). may_mint: the
        policy let the call run, not only shadow mode. None when the
        policy reads no provenance."""
        if not self.anchoring:
            return None
        seen: list[Observed] = []
        if tainted:
            seen.append(self.provenance.observe_arguments(tool, self.turn, args))
        if isinstance(outcome, types.CallToolResult):
            trusted = self.policy.source_class(tool) == "trusted"
            seen.append(
                self.provenance.observe_result(
                    tool, self.turn, args, outcome, trusted=trusted, may_mint=may_mint
                )
            )
        elif isinstance(outcome, str):
            seen.append(self.provenance.observe_error(tool, self.turn, outcome))
        counts: dict[str, int] = {}
        for observed in seen:
            for cls, n in observed.counts.items():
                counts[cls] = counts.get(cls, 0) + n
        degraded_by = next((o.degraded_by for o in seen if o.degraded_by is not None), None)
        return Observed(counts, degraded_by)

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
            # shadow mode records calls the budget check refused, and one
            # NaN would leave the total NaN, under every cap, for good
            if is_number(value):
                totals = self._sums.setdefault(tool, {})
                totals[field] = totals.get(field, 0.0) + float(value)

        self.turn += 1

    def observe_result(self, tool: str, is_error: bool = False) -> None:
        self.taint.observe_result(tool, is_error=is_error)

    def observe_failure(self, tool: str) -> None:
        """The call failed upstream and the agent was handed the error."""
        self.taint.observe_failure(tool)
