"""The taint tracker's contract, executable.

All of it comes down to one property: taint only ever goes on. If
anything here can flip it back off, a session that swallowed an
attacker's text can go back to looking clean, and every flow rule
downstream is decoration.
"""

from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tripwire.policy import load_policy
from tripwire.policy.schema import Policy
from tripwire.taint import TaintTracker

pytestmark = pytest.mark.skip(reason="waiting on TaintTracker implementation")

# The property test can't use the fixture — hypothesis doesn't re-run a
# function-scoped one per example.
REFERENCE = load_policy(Path(__file__).parent.parent / "examples" / "policy.yaml")


# --- source classes ---------------------------------------------------------


def test_fresh_tracker_is_clean(reference_policy):
    t = TaintTracker(reference_policy)
    assert t.tainted is False
    assert t.tainted_by == ()


def test_untrusted_result_taints(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("fetch_url")
    assert t.tainted is True
    assert t.tainted_by == ("fetch_url",)


def test_read_email_taints_too(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("read_email")
    assert t.tainted is True


def test_trusted_result_does_not_taint(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("read_calendar")
    assert t.tainted is False
    assert t.tainted_by == ()


def test_unlisted_tool_falls_back_to_the_wildcard(reference_policy):
    # nothing in sources for this one; "*" is untrusted, so it taints
    t = TaintTracker(reference_policy)
    t.observe_result("execute_code")
    assert t.tainted is True
    assert t.tainted_by == ("execute_code",)


def test_trusted_wildcard_leaves_unlisted_tools_clean():
    policy = Policy.model_validate({"version": 1, "sources": {"*": "trusted"}})
    t = TaintTracker(policy)
    t.observe_result("fetch_url")
    t.observe_result("some_tool_nobody_declared")
    assert t.tainted is False
    assert t.tainted_by == ()


def test_no_sources_block_means_everything_taints():
    # last step of the fallback chain: no entry, no "*", so untrusted
    t = TaintTracker(Policy.model_validate({"version": 1}))
    t.observe_result("read_calendar")
    assert t.tainted is True


# --- errors -----------------------------------------------------------------


def test_errored_result_taints(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("fetch_url", is_error=True)
    assert t.tainted is True
    assert t.tainted_by == ("fetch_url",)


def test_error_flag_changes_nothing(reference_policy):
    ok = TaintTracker(reference_policy)
    failed = TaintTracker(reference_policy)
    for tool in ("read_calendar", "fetch_url", "read_email", "fetch_url"):
        ok.observe_result(tool, is_error=False)
        failed.observe_result(tool, is_error=True)
    assert ok.tainted == failed.tainted
    assert ok.tainted_by == failed.tainted_by


# --- stickiness and provenance ----------------------------------------------


def test_taint_is_sticky(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("fetch_url")
    for _ in range(50):
        t.observe_result("read_calendar")
    assert t.tainted is True
    assert t.tainted_by == ("fetch_url",)


def test_tainted_by_is_ordered_and_deduplicated(reference_policy):
    t = TaintTracker(reference_policy)
    for tool in ("read_calendar", "fetch_url", "read_email", "fetch_url", "read_email"):
        t.observe_result(tool)
    assert t.tainted_by == ("fetch_url", "read_email")


def test_first_entry_is_the_one_that_did_it(reference_policy):
    # `tripwire trace` prints this to answer "what made the session dirty"
    t = TaintTracker(reference_policy)
    t.observe_result("read_calendar")
    t.observe_result("read_email")
    t.observe_result("fetch_url")
    assert t.tainted_by[0] == "read_email"


def test_trusted_tool_never_appears_in_tainted_by(reference_policy):
    t = TaintTracker(reference_policy)
    t.observe_result("read_calendar")
    t.observe_result("fetch_url")
    t.observe_result("read_calendar", is_error=True)
    assert "read_calendar" not in t.tainted_by


# --- totality ---------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["", "   ", "\x00", "\u200b", "🙈💥", "tool\nname", "../../etc/passwd", "x" * 10_000, "*"],
)
def test_junk_tool_names_do_not_raise(reference_policy, name):
    # whatever arrives off the wire is a tool name as far as we're
    # concerned, and under the reference policy all of it is untrusted
    t = TaintTracker(reference_policy)
    t.observe_result(name)
    assert t.tainted is True
    assert t.tainted_by == (name,)


def test_tracker_does_not_mutate_the_policy(reference_policy):
    before = reference_policy.model_dump()
    t = TaintTracker(reference_policy)
    t.observe_result("fetch_url")
    t.observe_result("read_calendar")
    t.observe_result("never_heard_of_it")
    assert reference_policy.model_dump() == before


# --- the property everything else rests on ----------------------------------

tool_names = st.one_of(
    st.sampled_from(["fetch_url", "read_email", "read_calendar", "execute_code"]),
    st.text(max_size=30),
)

observations = st.lists(st.tuples(tool_names, st.booleans()), max_size=25)


@given(obs=observations)
@settings(max_examples=300)
def test_taint_never_goes_back_off(obs):
    t = TaintTracker(REFERENCE)
    was_tainted = False
    for tool, is_error in obs:
        t.observe_result(tool, is_error=is_error)
        if was_tainted:
            assert t.tainted is True
        was_tainted = t.tainted
