"""Property tests: the evaluator must be total and deterministic no
matter what garbage reaches it. If hypothesis can make it raise, an
attacker can too — and an evaluator that crashes is an evaluator that
didn't say "block".
"""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tripwire.policy.evaluator import evaluate
from tripwire.policy.types import SessionSnapshot, ToolCall, Verdict

pytestmark = pytest.mark.skip(reason="waiting on evaluator implementation")

KNOWN_TOOLS = ["send_email", "issue_refund", "delete_file", "execute_code", "fetch_url"]

tool_names = st.one_of(st.sampled_from(KNOWN_TOOLS), st.text(min_size=0, max_size=30))

junk = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(max_size=50),
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(st.text(max_size=10), children, max_size=3),
    ),
    max_leaves=10,
)

calls = st.builds(
    ToolCall,
    tool=tool_names,
    args=st.dictionaries(st.text(max_size=20), junk, max_size=5),
)

snapshots = st.builds(
    SessionSnapshot,
    turn=st.integers(min_value=0, max_value=100),
    tainted=st.booleans(),
    tool_counts=st.dictionaries(tool_names, st.integers(min_value=0, max_value=50), max_size=5),
    tool_sums=st.dictionaries(
        tool_names,
        st.dictionaries(st.text(max_size=10), st.floats(0, 1e6), max_size=3),
        max_size=5,
    ),
    history=st.lists(
        st.tuples(st.integers(min_value=0, max_value=100), tool_names), max_size=10
    ).map(tuple),
)


@given(call=calls, state=snapshots)
@settings(max_examples=300)
def test_total_and_well_formed(reference_policy, call, state):
    v = evaluate(call, state, reference_policy)
    assert isinstance(v, Verdict)
    assert v.decision in ("allow", "gate", "block")
    assert isinstance(v.rule_id, str) and v.rule_id
    assert isinstance(v.reason, str)


@given(call=calls, state=snapshots)
@settings(max_examples=100)
def test_deterministic(reference_policy, call, state):
    assert evaluate(call, state, reference_policy) == evaluate(call, state, reference_policy)


@given(call=calls, state=snapshots)
@settings(max_examples=100)
def test_taint_never_relaxes(reference_policy, call, state):
    # Same call, same session — flipping taint on may only move the
    # decision toward block. This is invariant 6 as a property.
    severity = {"allow": 0, "gate": 1, "block": 2}
    clean = evaluate(
        call,
        SessionSnapshot(
            turn=state.turn,
            tainted=False,
            tool_counts=state.tool_counts,
            tool_sums=state.tool_sums,
            history=state.history,
        ),
        reference_policy,
    )
    tainted = evaluate(
        call,
        SessionSnapshot(
            turn=state.turn,
            tainted=True,
            tool_counts=state.tool_counts,
            tool_sums=state.tool_sums,
            history=state.history,
        ),
        reference_policy,
    )
    assert severity[tainted.decision] >= severity[clean.decision]


@given(call=calls, state=snapshots)
@settings(max_examples=100)
def test_shadow_flips_flag_not_decision(reference_policy, call, state):
    shadow_policy = reference_policy.model_copy(update={"enforce": False})
    enforced = evaluate(call, state, reference_policy)
    shadowed = evaluate(call, state, shadow_policy)
    assert shadowed.decision == enforced.decision
    assert shadowed.shadow is True and enforced.shadow is False
