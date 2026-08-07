"""Reading the audit log back: what happened, and why it was allowed.

The log is written for machines — one flat record per event, in order.
This module turns it back into the two questions people actually ask
after an incident:

  trace   what happened in this session, in order, with causes
  report  across everything, what is my policy actually doing

Both are read-only and work on a log written by any version of the
proxy. Neither needs the policy file, the upstream, or a live session —
you can hand someone a jsonl file and they can answer for themselves.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class LogError(Exception):
    pass


def read_records(path: str | Path) -> list[dict[str, Any]]:
    """Every record in file order. Malformed lines are fatal: a log you
    can only half-read is not evidence."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise LogError(f"cannot read {path}: {e}") from e

    records = []
    for n, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise LogError(f"{path}: line {n} is not valid json ({e})") from e
    return records


def sessions(records: list[dict[str, Any]]) -> list[str]:
    """Session ids in first-seen order."""
    seen = []
    for r in records:
        sid = r.get("session", "")
        if sid not in seen:
            seen.append(sid)
    return seen


# --- trace ------------------------------------------------------------


@dataclass
class Step:
    """One tool call and everything that happened because of it."""

    turn: int
    tool: str
    decision: str
    rule: str
    reason: str
    shadow: bool
    tainted: bool
    args: dict[str, Any] = field(default_factory=dict)
    outcome: str = ""  # ok | error | cancelled | not forwarded
    notes: list[str] = field(default_factory=list)


def trace(records: list[dict[str, Any]], session_id: str) -> list[Step]:
    """Rebuild one session as an ordered causal chain.

    Everything hangs off decision records, because a decision is the one
    event that happens for *every* call. Whatever follows a decision —
    the forward, the gate conversation, the result, the taint — belongs
    to it until the next decision starts.
    """
    steps: list[Step] = []
    current: Step | None = None

    for r in records:
        if r.get("session", "") != session_id:
            continue
        kind = r.get("kind", "")
        data = r.get("data", {}) or {}

        if kind == "decision":
            current = Step(
                turn=data.get("turn", 0),
                tool=data.get("tool", "?"),
                decision=data.get("decision", "?"),
                rule=data.get("rule", "?"),
                reason=data.get("reason", ""),
                shadow=bool(data.get("shadow")),
                tainted=bool(data.get("tainted")),
                outcome="not forwarded",
            )
            steps.append(current)
            continue

        if current is None:
            continue  # proxy_start and friends: not part of any call

        if kind == "tool_call":
            current.args = data.get("args", {}) or {}
            current.outcome = "ok"
        elif kind == "tool_result":
            current.outcome = "error" if data.get("is_error") else "ok"
        elif kind == "tool_error":
            current.outcome = "error"
            current.notes.append(f"upstream failed: {data.get('error', '')}")
        elif kind == "tool_cancelled":
            current.outcome = "cancelled"
            current.notes.append("agent hung up mid-call; the tool may still have run")
        elif kind == "session_tainted":
            current.notes.append("this result tainted the session")
        elif kind == "state_error":
            current.notes.append(f"session bookkeeping failed: {data.get('error', '')}")
        elif kind.startswith("gate_"):
            current.notes.append(_gate_note(kind, data))

    return steps


def _gate_note(kind: str, data: dict[str, Any]) -> str:
    if kind == "gate_requested":
        return f"asked a human (timeout {data.get('timeout')}s)"
    if kind == "gate_approved":
        return "a human approved it"
    if kind == "gate_denied":
        return "a human denied it"
    if kind == "gate_timeout":
        return f"nobody answered within {data.get('seconds')}s"
    if kind == "gate_error":
        return f"the gate failed: {data.get('error', '')}"
    if kind == "gate_unavailable":
        return "no gate was configured, so it was refused"
    return kind


def format_trace(steps: list[Step], session_id: str) -> str:
    if not steps:
        return f"session {session_id}: no tool calls recorded"

    mark = {"allow": "ok    ", "block": "BLOCK ", "gate": "GATE  "}
    out = [f"session {session_id} — {len(steps)} call(s)", ""]

    for step in steps:
        flag = mark.get(step.decision, step.decision)
        if step.shadow:
            flag = "shadow" if step.decision != "allow" else flag
        out.append(f"  turn {step.turn:<3} {flag} {step.tool}")
        if step.args:
            out.append(f"      args   {_short(step.args)}")
        out.append(f"      rule   {step.rule}")
        if step.reason:
            out.append(f"      reason {step.reason}")
        if step.shadow and step.decision != "allow":
            out.append("      NOTE   shadow mode: this ran anyway")
        for note in step.notes:
            out.append(f"      →      {note}")
        if step.outcome != "ok":
            out.append(f"      result {step.outcome}")
        out.append("")

    tainted_at = next((s for s in steps if "this result tainted the session" in s.notes), None)
    if tainted_at is not None:
        out.append(
            f"  untrusted content entered at turn {tainted_at.turn} via {tainted_at.tool}; "
            f"every later verdict was decided with that in mind."
        )
    return "\n".join(out)


def _short(args: dict[str, Any], limit: int = 120) -> str:
    text = json.dumps(args, sort_keys=True, default=str)
    return text if len(text) <= limit else f"{text[:limit]}... ({len(text) - limit} more)"


# --- report -----------------------------------------------------------


@dataclass
class Report:
    sessions: int = 0
    calls: int = 0
    allowed: int = 0
    blocked: int = 0
    gated: int = 0
    shadow_would_block: int = 0
    by_rule: Counter[str] = field(default_factory=Counter)
    by_tool: Counter[str] = field(default_factory=Counter)
    tainted_sessions: int = 0


def report(records: list[dict[str, Any]]) -> Report:
    rep = Report(sessions=len(sessions(records)))
    tainted = set()

    for r in records:
        kind = r.get("kind", "")
        data = r.get("data", {}) or {}
        if kind == "session_tainted":
            tainted.add(r.get("session", ""))
            continue
        if kind != "decision":
            continue

        rep.calls += 1
        decision = data.get("decision", "?")
        rep.by_tool[data.get("tool", "?")] += 1
        if decision == "allow":
            rep.allowed += 1
            continue

        rep.by_rule[data.get("rule", "?")] += 1
        if data.get("shadow"):
            # shadow mode: the call went through, but this is the number
            # that tells you what turning enforcement on would cost
            rep.shadow_would_block += 1
        elif decision == "block":
            rep.blocked += 1
        elif decision == "gate":
            rep.gated += 1

    rep.tainted_sessions = len(tainted)
    return rep


def format_report(rep: Report) -> str:
    out = [
        f"{rep.calls} call(s) across {rep.sessions} session(s)",
        f"  allowed          {rep.allowed}",
        f"  blocked          {rep.blocked}",
        f"  sent to a human  {rep.gated}",
    ]
    if rep.shadow_would_block:
        out.append(f"  WOULD have been stopped (shadow mode)  {rep.shadow_would_block}")
    out.append(f"  sessions that saw untrusted content  {rep.tainted_sessions}")

    if rep.by_rule:
        out.append("")
        out.append("rules that fired:")
        for rule, n in rep.by_rule.most_common():
            out.append(f"  {n:>4}  {rule}")
    if rep.by_tool:
        out.append("")
        out.append("busiest tools:")
        for tool, n in rep.by_tool.most_common(10):
            out.append(f"  {n:>4}  {tool}")
    return "\n".join(out)
