"""Input and output types for the evaluator, and the signatures of the
evaluator and the canonicalizer in front of it.

The inputs and outputs are frozen dataclasses on purpose: the evaluator
is a pure function and its inputs should read like values, not like
objects with behavior.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from tripwire.policy.schema import Policy, Role
from tripwire.policy.values import Key, TaskIndex, is_under
from tripwire.provenance import ProvenanceView, describe

Decision = Literal["allow", "block", "gate"]
# where an anchored value came from
Via = Literal["task", "known", "trusted", "self"]
LeafStatus = Literal["anchored", "unanchored", "invalid", "unanchorable", "not_verbatim"]


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool: str
    # Args as the evaluator sees them: the ones the policy checks already
    # canonicalized (NFKC, zero-width strip, etc), the rest as they
    # arrived. Canonicalization happens before evaluation.
    args: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, repr=False)
class TaskSegment:
    """One piece of the user's task text, as anchoring reads it."""

    seq: int
    source: str
    index: TaskIndex
    # the text after C2 and C1, for the verbatim rule
    text: str

    def __repr__(self) -> str:
        # task text belongs in no log line or error message
        return f"TaskSegment(seq={self.seq}, source={self.source!r}, chars={len(self.text)})"


@dataclass(frozen=True, slots=True)
class TaskView:
    """Every task segment so far. A key anchors when any segment anchors
    it: segments add up, and none takes back another's."""

    segments: tuple[TaskSegment, ...] = ()

    def anchors(self, key: Key, labels: Iterable[str] = ()) -> bool:
        return any(s.index.anchors(key, labels=labels) for s in self.segments)

    def mentions(self, key: Key) -> bool:
        return any(s.index.mentions(key) for s in self.segments)

    def covers(self, key: Key) -> bool:
        """Whether a task path of 2+ components is strictly above key."""
        return key.vtype == "path" and any(
            is_under(key.key, prefix) for s in self.segments for prefix in s.index.under_prefixes
        )

    def verbatim(self, text: str) -> bool:
        return any(text in s.text for s in self.segments)


@dataclass(frozen=True, slots=True)
class SessionSnapshot:
    """Read-only view of session state at evaluation time.

    Counts, sums, and history reflect completed calls only — the call
    being evaluated is not in here yet.
    """

    turn: int = 0
    tainted: bool = False
    # tool name -> how many times it has been called this session
    tool_counts: Mapping[str, int] = field(default_factory=dict)
    # tool name -> arg field -> running sum (for sum_per_session limits)
    tool_sums: Mapping[str, Mapping[str, float]] = field(default_factory=dict)
    # (turn, tool) pairs, oldest first (for sequence rules)
    history: tuple[tuple[int, str], ...] = ()
    # the user's task text, None until there is some
    task: TaskView | None = None
    # where each value the session has seen was seen first
    provenance: ProvenanceView = field(default_factory=ProvenanceView)
    # paths no argument may reach: the policy file, the audit log, the tx db
    protected_paths: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FirstSeen:
    cls: str
    tool: str
    turn: int


def key_sha256(key: Key) -> str:
    return hashlib.sha256(f"{key.vtype}\0{key.key}".encode(errors="replace")).hexdigest()


@dataclass(frozen=True, slots=True)
class LeafReport:
    """One value anchoring checked: an authority leaf, a content leaf
    checked as a target, or a link in content.

    value is the agent's own spelling of it, for the agent's denial and
    nowhere else; the audit log gets the key's hash, and not even that
    for a credential.
    """

    arg: str  # "to", "to[1]", "message.to"
    role: Role
    vtype: str | None  # the type it was read as; None if it couldn't be read
    status: LeafStatus
    # the sources that would have anchored it
    accepted: tuple[str, ...]
    key_sha256: str | None = None
    via: Via | None = None
    first_seen: FirstSeen | None = None
    # why it couldn't be read, or can never anchor
    reason: str | None = None
    value: str = field(default="", repr=False)

    def record(self) -> dict[str, Any]:
        seen = self.first_seen
        return {
            "arg": self.arg,
            "role": self.role,
            "type": self.vtype,
            "key_sha256": self.key_sha256,
            "status": self.status,
            "via": self.via,
            "first_seen": (
                None if seen is None else {"class": seen.cls, "tool": seen.tool, "turn": seen.turn}
            ),
            "reason": self.reason,
            "accepted": list(self.accepted),
        }


def explain_leaf(record: Mapping[str, Any]) -> str:
    """One leaf as LeafReport.record() writes it, in words: "to: first
    seen in free text from read_email, turn 3; accepted: task, known,
    trusted". Takes records read back from a log, so any field may be
    missing or malformed."""
    arg = str(record.get("arg", "?"))
    status = record.get("status")
    if status == "anchored":
        return f"{arg}: anchored via {record.get('via')}"
    reason = record.get("reason")
    seen = record.get("first_seen")
    if status == "invalid":
        what = f"can't be read ({reason})"
    elif status == "unanchorable":
        what = f"can never anchor ({reason})"
    elif status == "not_verbatim":
        what = "a URL whose path or query no tool and no task wrote"
    elif isinstance(seen, Mapping):
        where = describe(str(seen.get("class")), str(seen.get("tool")), _turn(seen.get("turn")))
        what = f"first seen in {where}"
    else:
        what = "nothing vouches for it"
    accepted = record.get("accepted")
    if isinstance(accepted, list) and accepted:
        what += f"; accepted: {', '.join(map(str, accepted))}"
    return f"{arg}: {what}"


def _turn(value: object) -> int:
    return value if isinstance(value, int) else -1


@dataclass(frozen=True, slots=True)
class AnchorReport:
    """What anchoring found for one call: code None when every value
    anchored and the flow was discharged. rule and reason say what failed
    in the terms the policy and the agent use; leaves run up to and
    including the first that failed."""

    code: str | None
    rule: str | None = None
    reason: str = ""
    leaves: tuple[LeafReport, ...] = ()
    # the contract's content arguments, which may carry anything
    unrestricted: tuple[str, ...] = ()

    @property
    def failed(self) -> LeafReport | None:
        return next((leaf for leaf in self.leaves if leaf.status != "anchored"), None)

    def record(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "rule": self.rule,
            "leaves": [leaf.record() for leaf in self.leaves],
        }


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    rule_id: str  # dotted path of the deciding rule, e.g. "tools.send_email.constraints.to"
    reason: str
    shadow: bool = False  # true when policy.enforce is false: log, don't block
    # why an argument contract or anchoring decided it; None for v1 rules
    code: str | None = None
    # what anchoring found, whenever a flow with `unless: anchored` applied
    anchors: AnchorReport | None = None


Canonicalizer = Callable[[str, Mapping[str, Any], Policy], Mapping[str, Any]]
Evaluator = Callable[[ToolCall, SessionSnapshot, Policy], Verdict]
