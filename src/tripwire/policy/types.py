"""Input and output types for the evaluator.

These are frozen dataclasses on purpose: the evaluator is a pure
function and its inputs should read like values, not like objects with
behavior.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

Decision = Literal["allow", "block", "gate"]


@dataclass(frozen=True, slots=True)
class ToolCall:
    tool: str
    # Args as the evaluator sees them: already canonicalized (NFKC,
    # zero-width strip, etc). Canonicalization happens before evaluation.
    args: Mapping[str, Any] = field(default_factory=dict)


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


@dataclass(frozen=True, slots=True)
class Verdict:
    decision: Decision
    rule_id: str  # dotted path of the deciding rule, e.g. "tools.send_email.constraints.to"
    reason: str
    shadow: bool = False  # true when policy.enforce is false: log, don't block
