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

import re
from typing import Any, TypeGuard

from tripwire.policy.schema import Constraint, Policy
from tripwire.policy.types import Decision, SessionSnapshot, ToolCall, Verdict

SEVERITY: dict[Decision, int] = {"allow": 0, "gate": 1, "block": 2}

# what an `action:` means as a verdict
AS_DECISION: dict[str, Decision] = {
    "allow": "allow",
    "block": "block",
    "require_approval": "gate",
}


def _is_number(value: Any) -> TypeGuard[float]:
    # bool is an int in python; a policy that says "number" does not mean
    # True, and letting it through makes `amount: true` a valid amount
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _constraint_holds(value: Any, c: Constraint) -> bool:
    if c.regex is not None:
        if not isinstance(value, str):
            return False
        text, pattern = value, c.regex
        if c.case_insensitive:
            # casefold both sides rather than passing re.I: casefold
            # handles cases re.I doesn't
            text, pattern = text.casefold(), pattern.casefold()
        if re.fullmatch(pattern, text) is None:
            return False

    if c.max_length is not None and len(str(value)) > c.max_length:
        return False

    if c.type == "number" and not _is_number(value):
        return False
    if c.type == "string" and not isinstance(value, str):
        return False

    if c.min is not None or c.max is not None:
        if not _is_number(value):
            return False
        if c.min is not None and value < c.min:
            return False
        if c.max is not None and value > c.max:
            return False

    return True


def evaluate(call: ToolCall, state: SessionSnapshot, policy: Policy) -> Verdict:
    shadow = not policy.enforce

    def verdict(decision: Decision, rule_id: str, reason: str) -> Verdict:
        return Verdict(decision=decision, rule_id=rule_id, reason=reason, shadow=shadow)

    # --- 1. tool lookup ---
    rule = policy.tools.get(call.tool)
    if rule is None:
        return verdict(
            AS_DECISION[policy.defaults.unknown_tools],
            "defaults.unknown_tools",
            f"No policy rule for {call.tool!r}; unknown tools are {policy.defaults.unknown_tools}.",
        )

    if rule.action == "block":
        return verdict(
            "block", f"tools.{call.tool}.action", rule.reason or f"{call.tool} is blocked."
        )

    provisional = AS_DECISION[rule.action]
    decided_by = f"tools.{call.tool}.action"
    reason = (
        f"{call.tool} requires approval."
        if provisional == "gate"
        else f"{call.tool} is allowed and no rule objected."
    )

    # --- 2. constraints, on the canonicalized args ---
    for arg, constraint in rule.constraints.items():
        rule_id = f"tools.{call.tool}.constraints.{arg}"
        if arg not in call.args:
            # absence is not a free pass: a constraint that can't be
            # checked hasn't been satisfied
            return verdict("block", rule_id, f"{call.tool} requires {arg}, which wasn't provided.")
        if not _constraint_holds(call.args[arg], constraint):
            return verdict("block", rule_id, f"{arg} fails the constraint on {call.tool}.")

    # --- 3. limits, counting this call ---
    if rule.limits is not None:
        if rule.limits.per_session is not None:
            already = state.tool_counts.get(call.tool, 0)
            if already + 1 > rule.limits.per_session:
                return verdict(
                    "block",
                    f"tools.{call.tool}.limits.per_session",
                    f"{call.tool} is limited to {rule.limits.per_session} calls per session.",
                )

        summed = rule.limits.sum_per_session
        if summed is not None:
            rule_id = f"tools.{call.tool}.limits.sum_per_session"
            raw = call.args.get(summed.field)
            if not _is_number(raw):
                return verdict(
                    "block",
                    rule_id,
                    f"{call.tool} needs a numeric {summed.field} to check its budget.",
                )
            value = float(raw)
            running = state.tool_sums.get(call.tool, {}).get(summed.field, 0.0)
            if running + value > summed.max:
                return verdict(
                    "block",
                    rule_id,
                    f"{call.tool} would take {summed.field} to {running + value}, "
                    f"over the session limit of {summed.max}.",
                )

    # --- 4. sequences ---
    for i, seq in enumerate(policy.sequences):
        if call.tool != seq.deny:
            continue
        for turn, tool in state.history:
            if tool == seq.within_turns_after and 0 <= state.turn - turn <= seq.turns:
                return verdict(
                    "block",
                    f"sequences[{i}]",
                    f"{seq.deny} is denied within {seq.turns} turns of {seq.within_turns_after}.",
                )

    # --- 5. flows: may tighten, never relax ---
    for i, flow in enumerate(policy.flows):
        if flow.when != "context_tainted" or not state.tainted:
            continue
        if call.tool not in flow.tools:
            continue
        escalated = AS_DECISION[flow.action]
        if SEVERITY[escalated] > SEVERITY[provisional]:
            provisional = escalated
            decided_by = f"flows[{i}]"
            reason = flow.reason or "Untrusted content is in this conversation."

    return verdict(provisional, decided_by, reason)
