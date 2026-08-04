"""The core of tripwire: (call, state, policy) -> Verdict.

Rules of this module — these are the invariants everything else leans on:

  * PURE. No I/O, no clock, no randomness, no mutation of inputs.
  * TOTAL. Every input produces a Verdict. Nothing raises. If something
    unexpected happens in here, the answer is a block, not an exception.
  * DETERMINISTIC. Same inputs, same Verdict, forever.

Evaluation order (stage number goes in front of nothing — rule_id is the
dotted path of the deciding rule):

  1. Tool lookup. If the tool has no entry in policy.tools, the verdict
     comes from defaults.unknown_tools (rule_id "defaults.unknown_tools").
     If it does: action=block short-circuits right here (rule_id
     "tools.<name>.action", reason from the rule's `reason` if set).
     action=allow / require_approval set the provisional decision
     (allow / gate) and evaluation continues.

  2. Constraints, checked against the canonicalized args:
       - constraint on an argument the call didn't provide -> block
         (fail closed; rule_id "tools.<name>.constraints.<arg>")
       - regex: full match required; casefold both sides if
         case_insensitive is set
       - max_length: len(str(value)) must be <=
       - type number: value must be int/float (bool doesn't count);
         anything else -> block
       - min/max: numeric bounds, inclusive
     First failed constraint blocks and short-circuits.

  3. Limits, *including the current call*:
       - per_session: N means calls 1..N are fine and call N+1 blocks
         (rule_id "tools.<name>.limits.per_session")
       - sum_per_session: running sum + this call's value; > max blocks,
         == max is fine (rule_id "tools.<name>.limits.sum_per_session").
         If the field is missing or not numeric on this call -> block
         (fail closed).

  4. Sequences: for each rule, if history contains (t, within_turns_after)
     with 0 <= snapshot.turn - t <= turns and call.tool == deny -> block
     (rule_id "sequences[i]").

  5. Flows: if when=context_tainted and snapshot.tainted and call.tool in
     rule.tools -> escalate the provisional decision to the rule's action
     (rule_id "flows[i]", but only when the flow actually changes the
     decision — an already-gated call stays gated under its original
     rule_id). Escalation only: allow -> gate -> block. Never downward.

  Severity is allow < gate < block. Stages 2-4 only ever produce block;
  stage 5 can produce gate or block. A later stage may raise severity,
  never lower it (invariant 6: monotonic tightening).

Shadow mode: when policy.enforce is false, evaluate exactly the same but
set shadow=True on the verdict. The interceptor lets shadowed blocks
through and logs what *would* have happened. The decision field always
holds the real answer.

The contract lives in tests/test_evaluator_golden.py (worked examples
against examples/policy.yaml) and tests/test_evaluator_props.py
(property tests: totality + determinism under garbage inputs). Delete
the skip line at the top of each and make them green.
"""

from __future__ import annotations

from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall, Verdict


def evaluate(call: ToolCall, state: SessionSnapshot, policy: Policy) -> Verdict:
    raise NotImplementedError("evaluator not written yet — see module docstring for the spec")
