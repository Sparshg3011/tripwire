"""Property tests: the evaluator must be total and deterministic no
matter what garbage reaches it. If hypothesis can make it raise, an
attacker can too — and an evaluator that crashes is an evaluator that
didn't say "block".
"""

import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tripwire.policy.evaluator import evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall, Verdict

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
@settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_total_and_well_formed(reference_policy, call, state):
    v = evaluate(call, state, reference_policy)
    assert isinstance(v, Verdict)
    assert v.decision in ("allow", "gate", "block")
    assert isinstance(v.rule_id, str) and v.rule_id
    assert isinstance(v.reason, str)


# SessionSnapshot and ToolCall are typed, not checked: whatever builds
# one can put anything at all in any field
hostile_calls = st.builds(ToolCall, tool=st.one_of(tool_names, junk), args=junk)
hostile_snapshots = st.builds(
    SessionSnapshot,
    turn=junk,
    tainted=junk,
    tool_counts=st.dictionaries(tool_names, junk, max_size=3),
    tool_sums=st.dictionaries(tool_names, junk, max_size=3),
    history=st.lists(junk, max_size=5).map(tuple),
)


@given(call=hostile_calls, state=hostile_snapshots)
@settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_total_even_over_malformed_inputs(reference_policy, call, state):
    v = evaluate(call, state, reference_policy)
    assert isinstance(v, Verdict)
    assert v.decision in ("allow", "gate", "block")
    if v.rule_id == "evaluator_error":
        assert v.decision == "block"


@given(call=hostile_calls, state=hostile_snapshots, policy=junk)
@settings(max_examples=100)
def test_total_even_over_a_malformed_policy(call, state, policy):
    # nothing to evaluate against, and nothing to say it's in shadow mode
    v = evaluate(call, state, policy)
    assert (v.decision, v.rule_id, v.shadow) == ("block", "evaluator_error", False)


PICKY = Policy.model_validate(
    {
        "version": 1,
        "tools": {
            "refund": {
                "action": "allow",
                "allowed_args": ["memo"],
                "constraints": {"to": {"max_length": 100}},
                "limits": {"sum_per_session": {"field": "amount", "max": 500}},
            }
        },
    }
)


@given(names=st.sets(st.sampled_from(["memo", "to", "amount", "bcc", "note"])), value=junk)
def test_allowed_args_refuses_only_arguments_the_rule_never_reads(names, value):
    # memo is listed, to is constrained, and amount is what the budget sums
    v = evaluate(ToolCall("refund", dict.fromkeys(names, value)), SessionSnapshot(), PICKY)
    unread = names - {"memo", "to", "amount"}
    assert (v.rule_id == "tools.refund.allowed_args") == bool(unread)


@given(call=calls, state=snapshots)
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_deterministic(reference_policy, call, state):
    assert evaluate(call, state, reference_policy) == evaluate(call, state, reference_policy)


@given(call=calls, state=snapshots)
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
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
@settings(max_examples=100, suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_shadow_flips_flag_not_decision(reference_policy, call, state):
    shadow_policy = reference_policy.model_copy(update={"enforce": False})
    enforced = evaluate(call, state, reference_policy)
    shadowed = evaluate(call, state, shadow_policy)
    assert shadowed.decision == enforced.decision
    assert shadowed.shadow is True and enforced.shadow is False


# Nothing in these depends on case, so ignoring it must change nothing,
# but casefolding their source changes what every one of them means.
PATTERNS = [r"\D+", r"\S+", r"\W*", r"\w+\Z", r"\A\w+", r"[\D\s]+"]


def lookup(regex, case_insensitive):
    constraint = {"regex": regex, "case_insensitive": case_insensitive}
    return Policy.model_validate(
        {"version": 1, "tools": {"lookup": {"action": "allow", "constraints": {"q": constraint}}}}
    )


LOOKUPS = {(regex, ci): lookup(regex, ci) for regex in PATTERNS for ci in (False, True)}


@given(
    regex=st.sampled_from(PATTERNS),
    value=st.text(
        alphabet=st.sampled_from(list("aAzZ1 _-\u00df\u0131\u0130\u017f\u212a")), max_size=8
    ),
)
@settings(max_examples=300)
def test_case_insensitive_changes_nothing_on_a_caseless_pattern(regex, value):
    call = ToolCall("lookup", {"q": value})
    sensitive = evaluate(call, SessionSnapshot(), LOOKUPS[regex, False])
    insensitive = evaluate(call, SessionSnapshot(), LOOKUPS[regex, True])
    assert insensitive.decision == sensitive.decision


# Unicode case rules count these as cases of i, s and k
CASE_ALIASES = {"i": "\u0131\u0130", "s": "\u017f", "k": "\u212a"}
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)

# (pattern, case_insensitive, the same pattern not ignoring case), each
# admitting what it matches; a pattern that refuses what it matches is below
FOLDING = [
    ("kiss", True, "kiss"),
    ("(?i)kiss", False, "kiss"),
    ("(?i:kiss)", False, "kiss"),
    ("[a-z]+", True, "[a-z]+"),
]


def respellings(word):
    # each letter as written, upper-cased, or swapped for a Unicode case alias
    letters = [st.sampled_from([c, c.upper(), *CASE_ALIASES.get(c, "")]) for c in word]
    return st.tuples(*letters).map("".join)


tails = st.text(alphabet=st.sampled_from(list("kiS\u0131\u0130\u017f\u212a\u00e9")), max_size=3)


@given(folding=st.sampled_from(FOLDING), word=respellings("kiss"), tail=tails)
@settings(max_examples=300)
def test_ignoring_case_folds_ascii_letters_and_nothing_else(folding, word, tail):
    # whether the flag or an inline (?i) asks for it, ignoring case may do
    # what lower-casing the ASCII letters by hand does, and no more
    regex, case_insensitive, plain = folding
    value = word + tail
    folded = evaluate(
        ToolCall("lookup", {"q": value}), SessionSnapshot(), lookup(regex, case_insensitive)
    )
    by_hand = evaluate(
        ToolCall("lookup", {"q": value.translate(ASCII_LOWER)}),
        SessionSnapshot(),
        lookup(plain, False),
    )
    assert folded.decision == by_hand.decision


REFUSING = [lookup("(?!kiss).*", True), lookup("(?i)(?!kiss).*", False)]


@given(policy=st.sampled_from(REFUSING), word=respellings("kiss"), tail=tails)
def test_ignoring_case_a_lookahead_refuses_every_respelling(policy, word, tail):
    # refusing, the reading that folds more is the strict one, and Unicode
    # case rules make every one of these spellings a case of kiss
    v = evaluate(ToolCall("lookup", {"q": word + tail}), SessionSnapshot(), policy)
    assert v.decision == "block"


# what each class escape covers under Unicode rules, and in ASCII mode
UNICODE_CLASSES = {"d": str.isdecimal, "s": str.isspace, "w": lambda c: c.isalnum() or c == "_"}
ASCII_CLASSES = {
    "d": string.digits,
    "s": " \t\n\r\f\v",
    "w": string.ascii_letters + string.digits + "_",
}


@given(
    escape=st.sampled_from("dsw"),
    negated=st.booleans(),
    bracketed=st.booleans(),
    value=st.text(
        alphabet=st.sampled_from(list("aZ_1 \t\n\x1c\x85\xa0\u2028\u3000\u0661\u00e9\u0131@-")),
        min_size=1,
        max_size=6,
    ),
)
@settings(max_examples=300)
def test_a_class_admits_only_what_both_readings_put_in_it(escape, negated, bracketed, value):
    # \d, \s and \w admit their ASCII members and no others, while \D, \S,
    # \W and [^\s] refuse all that Unicode rules count as digit, space or word
    if bracketed:
        regex = f"[{'^' if negated else ''}\\{escape}]+"
    else:
        regex = f"\\{escape.upper() if negated else escape}+"
    v = evaluate(ToolCall("lookup", {"q": value}), SessionSnapshot(), lookup(regex, False))
    if negated:
        admitted = not any(UNICODE_CLASSES[escape](c) for c in value)
    else:
        admitted = all(c in ASCII_CLASSES[escape] for c in value)
    assert (v.decision == "allow") == admitted
