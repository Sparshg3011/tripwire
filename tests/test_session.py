"""SessionState's bookkeeping, and the budgets that read it.

The evaluator only ever sees a snapshot, so whatever record() lets into a
running total is something every later budget check has to live with.
"""

from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from tripwire.policy import load_policy
from tripwire.policy.canonical import canonicalize
from tripwire.policy.evaluator import evaluate
from tripwire.policy.types import ToolCall
from tripwire.session import SessionState

# hypothesis doesn't re-run a function-scoped fixture per example
REFERENCE = load_policy(Path(__file__).parent.parent / "examples" / "policy.yaml")


def attempt(session, tool, args):
    """One call the way the proxy makes it: canonicalize, judge, and
    record it only if it would have run."""
    call = ToolCall(tool, canonicalize(tool, args, session.policy))
    verdict = evaluate(call, session.snapshot(), session.policy)
    if verdict.decision != "block":
        session.record(call.tool, call.args)
    return verdict.decision


def test_one_nan_refund_does_not_unlock_the_budget(reference_policy):
    session = SessionState(reference_policy)
    assert attempt(session, "issue_refund", {"amount": float("nan")}) == "block"
    decisions = [attempt(session, "issue_refund", {"amount": 100}) for _ in range(10)]
    assert decisions == ["allow"] * 5 + ["block"] * 5


def test_a_shadowed_nan_is_not_added_to_the_total(reference_policy):
    # shadow mode records calls the evaluator refused, so record() can't
    # lean on the evaluator having filtered them out
    session = SessionState(reference_policy)
    session.record("issue_refund", {"amount": 40})
    session.record("issue_refund", {"amount": float("nan")})
    assert session.snapshot().tool_sums == {"issue_refund": {"amount": 40.0}}


unaddable = st.one_of(
    st.sampled_from([float("nan"), float("inf"), float("-inf"), 10**400, True, None, [1]]),
    st.text(max_size=5),
)


@given(before=st.lists(st.floats(0, 100), max_size=5), junk=unaddable)
def test_anything_but_a_finite_number_leaves_the_total_alone(before, junk):
    session = SessionState(REFERENCE)
    for amount in before:
        session.record("issue_refund", {"amount": amount})
    totals = session.snapshot().tool_sums
    session.record("issue_refund", {"amount": junk})
    assert session.snapshot().tool_sums == totals
