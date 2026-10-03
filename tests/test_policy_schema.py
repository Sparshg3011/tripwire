import re
from re import _parser
from re._constants import SUBPATTERN

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from tripwire.policy.schema import (
    Constraint,
    FlowRule,
    Policy,
    SequenceRule,
    SumLimit,
    ToolRule,
)


def test_reference_policy_validates(reference_policy):
    assert reference_policy.version == 1
    assert reference_policy.enforce is True
    assert "send_email" in reference_policy.tools
    assert reference_policy.tools["send_email"].limits.per_session == 3


def test_minimal_policy():
    p = Policy.model_validate({"version": 1})
    assert p.defaults.unknown_tools == "block"
    assert p.defaults.gate_timeout_seconds == 120


def test_version_is_required():
    with pytest.raises(ValidationError):
        Policy.model_validate({})


def test_unknown_version_rejected():
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 2})


def test_typo_in_key_rejected():
    # "actoin" instead of "action" must be an error, not silently ignored
    with pytest.raises(ValidationError):
        Policy.model_validate({"version": 1, "tools": {"send_email": {"actoin": "block"}}})


def test_bad_regex_rejected_at_load_time():
    with pytest.raises(ValidationError, match="regex"):
        Constraint.model_validate({"regex": "([unclosed"})


@pytest.mark.parametrize(
    "regex",
    [
        "(?u)admin",
        "(?iu)admin",
        "(?u:admin)",
        "a(?iu:dmin)",
        "a(?u-i:dmin)",
        r"\\(?u:x)",
        # a # is only a comment under x, and a [ in one opens no class
        "a#(?iu:dmin)",
        "(?x)(?-x:#(?iu:admin))",
        "(?x)# [\n(?iu:admin)#]",
    ],
)
def test_regex_cannot_switch_to_unicode_rules(regex):
    # under Unicode rules, ignoring case lets "admın" pass for "admin"
    with pytest.raises(ValidationError, match="u flag"):
        Constraint.model_validate({"regex": regex})


def test_an_escaped_paren_before_a_u_is_not_a_flag():
    assert Constraint.model_validate({"regex": r"\(?user\)?"}).regex == r"\(?user\)?"


@pytest.mark.parametrize(
    "regex", [r"[(?u)]+", r"[](?u:x)]", r"[\](?u:x)]", "(?#(?u:)admin", "(?x) a  # (?u) comment"]
)
def test_a_u_in_a_class_or_a_comment_is_not_a_flag(regex):
    assert Constraint.model_validate({"regex": regex}).regex == regex


def u_flag_in(node):
    # walks what re's own parser made of a pattern, which is private but
    # the ground truth: a group that turns u on carries it in its flags
    if isinstance(node, _parser.SubPattern):
        return any((op is SUBPATTERN and av[1] & re.UNICODE) or u_flag_in(av) for op, av in node)
    return isinstance(node, (list, tuple)) and any(u_flag_in(item) for item in node)


# flag groups, and text that only looks like one in a class, a comment or
# an escape; # is a comment only under x, and a [ in one opens no class
REGEX_PIECES = [
    "a",
    " ",
    "\n",
    "#",
    "#\n",
    "# (?u:x)\n",
    "# [\n",
    "]",
    "[(?u)]",
    "[](?u:x)]",
    "[^]#]",
    r"[\](?u:x)]",
    r"\(?u",
    "\\\\",
    r"\#",
    "(?#(?u:)",
    "(?u:x)",
    "(?iu:x)",
    "(?-i:x)",
]
regexes = st.tuples(
    st.sampled_from(["", "(?x)", "(?u)", "(?i)"]),
    st.recursive(
        st.sampled_from(REGEX_PIECES),
        lambda inner: st.one_of(
            st.lists(inner, min_size=2, max_size=3).map("".join),
            st.tuples(st.sampled_from(["(", "(?:", "(?x:", "(?-x:", "(?="]), inner).map(
                lambda group: f"{group[0]}{group[1]})"
            ),
        ),
        max_leaves=6,
    ),
).map("".join)


@given(regex=regexes)
@settings(max_examples=500)
def test_the_u_flag_is_refused_exactly_where_re_reads_one(regex):
    try:
        re.compile(regex)
    except re.error:
        assume(False)
    try:
        read_by_re = u_flag_in(_parser.parse(regex, re.ASCII))
    except ValueError:
        read_by_re = True  # a u for the whole pattern can't join ASCII mode
    try:
        Constraint.model_validate({"regex": regex})
    except ValidationError:
        refused = True
    else:
        refused = False
    assert refused == read_by_re


def test_empty_constraint_rejected():
    with pytest.raises(ValidationError, match="no conditions"):
        Constraint.model_validate({})


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_bounds_rejected(value):
    # a NaN bound compares False against everything, so it would bound nothing
    with pytest.raises(ValidationError, match="finite"):
        Constraint.model_validate({"max": value})
    with pytest.raises(ValidationError, match="finite"):
        SumLimit.model_validate({"field": "amount", "max": value})


def test_allowed_args_must_not_repeat():
    with pytest.raises(ValidationError, match="'subject' more than once"):
        ToolRule.model_validate({"action": "allow", "allowed_args": ["subject", "body", "subject"]})


def test_sequence_window_is_a_positive_count_or_session():
    rule = {"deny": "execute_code", "within_turns_after": "fetch_url"}
    assert SequenceRule.model_validate({**rule, "turns": 3}).turns == 3
    assert SequenceRule.model_validate({**rule, "turns": "session"}).turns == "session"
    for bad in (0, -1, "forever", None):
        with pytest.raises(ValidationError):
            SequenceRule.model_validate({**rule, "turns": bad})


def test_flow_rules_cannot_allow():
    # Flows may only tighten. An "allow" flow would let tainted context
    # relax a rule, which defeats the whole point.
    with pytest.raises(ValidationError):
        FlowRule.model_validate({"when": "context_tainted", "tools": ["x"], "action": "allow"})


def test_source_class_defaults_to_untrusted():
    p = Policy.model_validate({"version": 1})
    assert p.source_class("anything") == "untrusted"


def test_source_class_wildcard_and_override():
    p = Policy.model_validate(
        {
            "version": 1,
            "sources": {"read_calendar": "trusted", "*": "untrusted"},
        }
    )
    assert p.source_class("read_calendar") == "trusted"
    assert p.source_class("fetch_url") == "untrusted"


def test_trusted_wildcard_is_allowed_but_explicit():
    # You *can* declare everything trusted, but you have to type it out.
    p = Policy.model_validate({"version": 1, "sources": {"*": "trusted"}})
    assert p.source_class("fetch_url") == "trusted"
