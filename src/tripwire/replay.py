"""What would a different policy have done?

Changing a policy is the scariest thing an operator does: tighten too
little and the hole stays open, tighten too much and the agent stops
working on Monday morning. Replay answers it with evidence instead of
nerve — take real recorded traffic, re-decide every call under the
candidate policy, and show exactly which verdicts move.

It re-runs the real evaluator over a rebuilt session, not a recorded
one. That matters: `sources:` may have changed too, so taint has to be
recomputed from the candidate policy rather than replayed from the log.
The counts, sums and history are rebuilt the same way the live proxy
builds them — executed calls only.

What replay can't do: tell you what the agent would have done *next*.
A call blocked under the new policy might have led the model somewhere
different, and no amount of replaying old logs will show you that. It
answers "which of these calls would the new policy have judged
differently", which is the question worth answering before a rollout.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from tripwire.policy.canonical import canonicalize as real_canonicalize
from tripwire.policy.evaluator import evaluate as real_evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import ToolCall
from tripwire.session import SessionState
from tripwire.taint import TaintTracker


@dataclass
class Change:
    turn: int
    tool: str
    was: str  # decision recorded at the time
    now: str  # decision the candidate policy gives
    rule: str  # rule that decided it now
    reason: str

    @property
    def moved(self) -> bool:
        return self.was != self.now

    @property
    def tighter(self) -> bool:
        order = {"allow": 0, "gate": 1, "block": 2}
        return order.get(self.now, 0) > order.get(self.was, 0)


@dataclass
class ReplayResult:
    session_id: str
    changes: list[Change]

    @property
    def moved(self) -> list[Change]:
        return [c for c in self.changes if c.moved]

    @property
    def newly_stopped(self) -> list[Change]:
        return [c for c in self.changes if c.tighter]

    @property
    def newly_allowed(self) -> list[Change]:
        return [c for c in self.changes if c.moved and not c.tighter]


def replay(
    records: list[dict[str, Any]],
    session_id: str,
    policy: Policy,
    canonicalize=real_canonicalize,
    evaluate=real_evaluate,
    taint_factory=TaintTracker,
) -> ReplayResult:
    # Taint is rebuilt, not replayed: `sources:` may be exactly what the
    # candidate policy changed, and reusing the old log's taint would
    # answer a question nobody asked.
    session = SessionState(policy, taint=taint_factory(policy))
    changes: list[Change] = []
    pending: dict[str, Any] | None = None
    executed = False

    for r in records:
        if r.get("session", "") != session_id:
            continue
        kind = r.get("kind", "")
        data = r.get("data", {}) or {}

        if kind == "decision":
            if pending is not None:
                _settle(session, pending, executed)
            pending, executed = data, False
            changes.append(_judge(session, data, policy, canonicalize, evaluate))
        elif kind in ("tool_call", "tool_result", "tool_error", "tool_cancelled"):
            # anything that reached the upstream counts as executed, the
            # same way the live proxy counts it
            executed = True

    if pending is not None:
        _settle(session, pending, executed)
    return ReplayResult(session_id=session_id, changes=changes)


def _judge(session, data, policy, canonicalize, evaluate) -> Change:
    tool = data.get("tool", "?")
    args = data.get("args", {}) or {}
    snapshot = session.snapshot()

    try:
        canonical = canonicalize(tool, args, policy)
    except Exception as e:
        return Change(
            snapshot.turn, tool, data.get("decision", "?"), "block", "canonicalizer_error", str(e)
        )
    try:
        verdict = evaluate(ToolCall(tool, canonical), snapshot, policy)
    except Exception as e:
        return Change(
            snapshot.turn, tool, data.get("decision", "?"), "block", "evaluator_error", str(e)
        )

    return Change(
        turn=snapshot.turn,
        tool=tool,
        was=data.get("decision", "?"),
        now=verdict.decision,
        rule=verdict.rule_id,
        reason=verdict.reason,
    )


def _settle(session: SessionState, data: dict[str, Any], executed: bool) -> None:
    """Advance the rebuilt session exactly as the live one would have."""
    if not executed:
        return
    tool = data.get("tool", "?")
    session.record(tool, data.get("args", {}) or {})
    session.observe_result(tool, is_error=False)


def format_replay(result: ReplayResult, policy_path: str) -> str:
    total = len(result.changes)
    moved = result.moved
    out = [f"session {result.session_id}: {total} call(s) re-judged under {policy_path}", ""]

    if not moved:
        out.append("  nothing changes — the candidate policy agrees on every call")
        return "\n".join(out)

    for c in moved:
        arrow = "TIGHTER" if c.tighter else "LOOSER "
        out.append(f"  {arrow} turn {c.turn:<3} {c.tool}: {c.was} -> {c.now}")
        out.append(f"          {c.rule}: {c.reason}")
    out.append("")
    out.append(
        f"  {len(result.newly_stopped)} call(s) the new policy would stop, "
        f"{len(result.newly_allowed)} it would let through."
    )
    if result.newly_allowed:
        out.append("  Check the looser ones before shipping this.")
    return "\n".join(out)
