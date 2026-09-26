"""Worked examples pinning down evaluator behavior, all against
examples/policy.yaml. This file is the contract: when these are green,
the evaluator is done.
"""

import pytest

from tripwire.policy.evaluator import evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall

FRESH = SessionSnapshot()

NON_FINITE = [float("nan"), float("inf"), float("-inf")]


def refunds(**rule):
    return Policy.model_validate({"version": 1, "tools": {"refund": {"action": "allow", **rule}}})


# --- stage 1: tool lookup ---------------------------------------------------


def test_unknown_tool_blocks_by_default(reference_policy):
    v = evaluate(ToolCall("format_disk"), FRESH, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "defaults.unknown_tools"


def test_blocked_tool_short_circuits(reference_policy):
    v = evaluate(ToolCall("delete_file", {"path": "/tmp/x"}), FRESH, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.delete_file.action"
    assert v.reason == "Destructive; disabled."


def test_require_approval_becomes_gate(reference_policy):
    call = ToolCall("send_email", {"to": "alice@mycompany.com", "body": "hi"})
    v = evaluate(call, FRESH, reference_policy)
    assert v.decision == "gate"
    assert v.rule_id == "tools.send_email.action"


def test_plain_allow(reference_policy):
    v = evaluate(ToolCall("issue_refund", {"amount": 50}), FRESH, reference_policy)
    assert v.decision == "allow"
    assert v.rule_id == "tools.issue_refund.action"


# --- stage 2: constraints ---------------------------------------------------


def test_regex_mismatch_blocks(reference_policy):
    call = ToolCall("send_email", {"to": "eve@evil.com", "body": "hi"})
    v = evaluate(call, FRESH, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.send_email.constraints.to"


def test_missing_constrained_arg_fails_closed(reference_policy):
    # No "to" at all. That's not a free pass — it's a block.
    v = evaluate(ToolCall("send_email", {"body": "hi"}), FRESH, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.send_email.constraints.to"


def test_max_length_blocks(reference_policy):
    call = ToolCall("send_email", {"to": "a@mycompany.com", "body": "x" * 10_001})
    v = evaluate(call, FRESH, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.send_email.constraints.body"


def test_numeric_bounds(reference_policy):
    block = evaluate(ToolCall("issue_refund", {"amount": -5}), FRESH, reference_policy)
    assert block.decision == "block"
    assert block.rule_id == "tools.issue_refund.constraints.amount"

    edge = evaluate(ToolCall("issue_refund", {"amount": 100}), FRESH, reference_policy)
    assert edge.decision == "allow"  # bounds are inclusive


def test_non_numeric_value_for_number_constraint_blocks(reference_policy):
    v = evaluate(ToolCall("issue_refund", {"amount": "lots"}), FRESH, reference_policy)
    assert v.decision == "block"


def test_bool_is_not_a_number(reference_policy):
    # True == 1 in python; a policy that says "number" should not accept it.
    v = evaluate(ToolCall("issue_refund", {"amount": True}), FRESH, reference_policy)
    assert v.decision == "block"


@pytest.mark.parametrize("amount", NON_FINITE)
@pytest.mark.parametrize("constraint", [{"type": "number"}, {"min": 0}, {"max": 100}])
def test_non_finite_value_fails_number_constraints(constraint, amount):
    # every comparison with NaN is False, so a bare bounds check waves it through
    policy = refunds(constraints={"amount": constraint})
    v = evaluate(ToolCall("refund", {"amount": amount}), FRESH, policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.refund.constraints.amount"


# --- stage 3: limits (count the current call!) ------------------------------


def test_per_session_limit(reference_policy):
    ok_call = ToolCall("send_email", {"to": "a@mycompany.com", "body": "hi"})

    third = SessionSnapshot(tool_counts={"send_email": 2})
    assert evaluate(ok_call, third, reference_policy).decision == "gate"

    fourth = SessionSnapshot(tool_counts={"send_email": 3})
    v = evaluate(ok_call, fourth, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.send_email.limits.per_session"


def test_sum_limit_exactly_at_cap_is_fine(reference_policy):
    state = SessionSnapshot(tool_sums={"issue_refund": {"amount": 480.0}})
    v = evaluate(ToolCall("issue_refund", {"amount": 20}), state, reference_policy)
    assert v.decision == "allow"


def test_sum_limit_one_over_blocks(reference_policy):
    state = SessionSnapshot(tool_sums={"issue_refund": {"amount": 480.0}})
    v = evaluate(ToolCall("issue_refund", {"amount": 21}), state, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "tools.issue_refund.limits.sum_per_session"


BUDGET_ONLY = {"limits": {"sum_per_session": {"field": "amount", "max": 500}}}


@pytest.mark.parametrize("amount", [*NON_FINITE, 10**400], ids=["nan", "inf", "-inf", "10**400"])
def test_budget_refuses_values_it_cannot_add(amount):
    v = evaluate(ToolCall("refund", {"amount": amount}), FRESH, refunds(**BUDGET_ONLY))
    assert v.decision == "block"
    assert v.rule_id == "tools.refund.limits.sum_per_session"


def test_a_nan_running_total_fails_the_budget():
    state = SessionSnapshot(tool_sums={"refund": {"amount": float("nan")}})
    v = evaluate(ToolCall("refund", {"amount": 1}), state, refunds(**BUDGET_ONLY))
    assert v.decision == "block"
    assert v.rule_id == "tools.refund.limits.sum_per_session"


# --- stage 4: sequences -----------------------------------------------------


def test_execute_after_fetch_blocked(reference_policy):
    state = SessionSnapshot(turn=4, history=((2, "fetch_url"),))
    v = evaluate(ToolCall("execute_code"), state, reference_policy)
    assert v.decision == "block"
    assert v.rule_id == "sequences[0]"


def test_sequence_window_boundary(reference_policy):
    # fetch at turn 2, window is 3 turns: turn 5 still blocked, turn 6 clear
    at_edge = SessionSnapshot(turn=5, history=((2, "fetch_url"),))
    assert evaluate(ToolCall("execute_code"), at_edge, reference_policy).decision == "block"

    past = SessionSnapshot(turn=6, history=((2, "fetch_url"),))
    assert evaluate(ToolCall("execute_code"), past, reference_policy).decision == "allow"


# --- stage 5: flows ---------------------------------------------------------


def test_taint_escalates_allow_to_gate(reference_policy):
    tainted = SessionSnapshot(tainted=True)
    v = evaluate(ToolCall("execute_code"), tainted, reference_policy)
    assert v.decision == "gate"
    assert v.rule_id == "flows[0]"


def test_taint_leaves_existing_gate_alone(reference_policy):
    # send_email already gates via its action; the flow doesn't change
    # the outcome, so the original rule keeps the credit.
    call = ToolCall("send_email", {"to": "a@mycompany.com", "body": "hi"})
    v = evaluate(call, SessionSnapshot(tainted=True), reference_policy)
    assert v.decision == "gate"
    assert v.rule_id == "tools.send_email.action"


def test_taint_ignores_tools_outside_the_flow(reference_policy):
    v = evaluate(
        ToolCall("issue_refund", {"amount": 5}), SessionSnapshot(tainted=True), reference_policy
    )
    assert v.decision == "allow"


# --- shadow mode ------------------------------------------------------------


def test_shadow_mode_same_decision_shadow_flag_set(reference_policy):
    shadow_policy = reference_policy.model_copy(update={"enforce": False})
    v = evaluate(ToolCall("delete_file"), FRESH, shadow_policy)
    assert v.decision == "block"  # the real answer, still computed
    assert v.shadow is True

    enforced = evaluate(ToolCall("delete_file"), FRESH, reference_policy)
    assert enforced.shadow is False


# --- case-insensitive constraints -------------------------------------------


def test_case_insensitive_regex():
    from tripwire.policy.schema import Policy

    policy = Policy.model_validate(
        {
            "version": 1,
            "tools": {
                "send_email": {
                    "action": "allow",
                    "constraints": {
                        "to": {"regex": "^admin@corp\\.com$", "case_insensitive": True}
                    },
                }
            },
        }
    )
    assert (
        evaluate(ToolCall("send_email", {"to": "Admin@CORP.com"}), FRESH, policy).decision
        == "allow"
    )
    assert (
        evaluate(ToolCall("send_email", {"to": "other@corp.com"}), FRESH, policy).decision
        == "block"
    )
