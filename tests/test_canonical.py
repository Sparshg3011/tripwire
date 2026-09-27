"""Worked examples pinning down canonicalize(), one group per rule in the
canonical.py docstring. C3 is the evaluator's job and isn't tested here.
"""

import copy
import json

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tripwire.policy.canonical import canonicalize, checked_fields
from tripwire.policy.schema import Policy

ZERO_WIDTHS = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]

HOST_FIELDS = ["url", "host", "hostname", "domain", "to", "recipient", "email", "address"]

# Canonicalization only touches the fields a policy checks, so this one
# checks every field the C1/C2/C4 tests poke at, by length only, to keep
# C5 from joining in.
PLAIN = "lookup"
LENGTH_ONLY = Policy.model_validate(
    {
        "version": 1,
        "tools": {
            PLAIN: {
                "action": "allow",
                "constraints": {
                    field: {"max_length": 100_000}
                    for field in [*HOST_FIELDS, "body", "message", "note", "payload", "items"]
                },
            }
        },
    }
)


# --- C1: unicode nfkc -------------------------------------------------------


def test_fullwidth_folds_to_ascii():
    out = canonicalize(PLAIN, {"body": "ａdmin"}, LENGTH_ONLY)
    assert out["body"] == "admin"


def test_ligature_folds():
    out = canonicalize(PLAIN, {"body": "ﬁle"}, LENGTH_ONLY)
    assert out["body"] == "file"


def test_plain_ascii_untouched():
    args = {"body": "admin@corp.com", "note": "nothing here needs folding"}
    assert canonicalize(PLAIN, args, LENGTH_ONLY) == args


# --- C2: invisible formatting characters ------------------------------------


@pytest.mark.parametrize("ch", ZERO_WIDTHS)
def test_zero_width_stripped_from_domain(ch):
    out = canonicalize(PLAIN, {"body": f"cor{ch}p.com"}, LENGTH_ONLY)
    assert out["body"] == "corp.com"


@pytest.mark.parametrize("ch", ZERO_WIDTHS)
def test_zero_width_stripped_at_edges(ch):
    out = canonicalize(PLAIN, {"body": f"{ch}admin{ch}"}, LENGTH_ONLY)
    assert out["body"] == "admin"


def test_nfkc_and_invisibles_combine():
    out = canonicalize(PLAIN, {"body": "ａd\u200bm\ufeffin"}, LENGTH_ONLY)
    assert out["body"] == "admin"


# --- recursion --------------------------------------------------------------


def test_nested_dict_values_canonicalized():
    args = {"payload": {"deeper": {"body": "ﬁle"}}}
    out = canonicalize(PLAIN, args, LENGTH_ONLY)
    assert out["payload"]["deeper"]["body"] == "file"


def test_list_items_canonicalized():
    args = {"items": ["ａdmin", "cor\u200bp.com", {"body": "ﬁle"}, [" ﬁx"]]}
    out = canonicalize(PLAIN, args, LENGTH_ONLY)
    assert out["items"] == ["admin", "corp.com", {"body": "file"}, [" fix"]]


def test_non_string_leaves_survive_recursion():
    args = {"payload": {"n": 3, "ok": True, "missing": None, "f": 1.5}}
    out = canonicalize(PLAIN, args, LENGTH_ONLY)
    assert out["payload"] == {"n": 3, "ok": True, "missing": None, "f": 1.5}


# --- C4: trailing dot on host-like fields -----------------------------------


@pytest.mark.parametrize("field", HOST_FIELDS)
def test_trailing_dot_stripped_on_host_field(field):
    out = canonicalize(PLAIN, {field: "corp.com."}, LENGTH_ONLY)
    assert out[field] == "corp.com"


@pytest.mark.parametrize("field", ["body", "message"])
def test_trailing_dot_kept_on_non_host_field(field):
    out = canonicalize(PLAIN, {field: "corp.com."}, LENGTH_ONLY)
    assert out[field] == "corp.com."


def test_host_field_without_trailing_dot_unchanged():
    out = canonicalize(PLAIN, {"host": "corp.com"}, LENGTH_ONLY)
    assert out["host"] == "corp.com"


def test_trailing_dot_kept_below_top_level():
    # C4 is scoped to top-level fields; a nested "host" key is just a string
    out = canonicalize(PLAIN, {"payload": {"host": "corp.com."}}, LENGTH_ONLY)
    assert out["payload"]["host"] == "corp.com."


def test_zero_width_then_trailing_dot():
    out = canonicalize(PLAIN, {"host": "cor\u200bp.com."}, LENGTH_ONLY)
    assert out["host"] == "corp.com"


# --- scope: only the fields the policy checks -------------------------------


def test_checked_fields_are_the_constraints_and_the_summed_field():
    policy = Policy.model_validate(
        {
            "version": 1,
            "tools": {
                "refund": {
                    "action": "allow",
                    "constraints": {"amount": {"type": "number"}, "memo": {"max_length": 80}},
                    "limits": {"sum_per_session": {"field": "total", "max": 500}},
                }
            },
        }
    )
    assert checked_fields("refund", policy) == {"amount", "memo", "total"}
    assert checked_fields("no_such_tool", policy) == set()


def test_unchecked_fields_are_forwarded_verbatim(reference_policy):
    # send_email checks to and body; nothing reads subject or cc, so
    # nothing has any business rewriting them
    args = {"to": "ａlice@mycompany.com.", "subject": "ﬁle ａ.", "cc": "bob@corp.com."}
    out = canonicalize("send_email", args, reference_policy)
    assert out == {"to": "alice@mycompany.com", "subject": "ﬁle ａ.", "cc": "bob@corp.com."}


def test_unknown_tools_are_forwarded_verbatim(reference_policy):
    args = {"to": "ａdmin@corp.com.", "body": "ﬁle", "payload": {"host": "corp.com."}}
    assert canonicalize("no_such_tool", args, reference_policy) == args


def test_summed_field_is_checked_even_without_a_constraint():
    policy = Policy.model_validate(
        {
            "version": 1,
            "tools": {
                "refund": {
                    "action": "allow",
                    "limits": {"sum_per_session": {"field": "amount", "max": 500}},
                }
            },
        }
    )
    assert canonicalize("refund", {"amount": "４２"}, policy) == {"amount": "42"}


# --- C5: numeric strings on number-constrained fields -----------------------


@pytest.mark.parametrize(("raw", "expected"), [("1e2", 100.0), (" 42 ", 42.0), ("0.5", 0.5)])
def test_numeric_string_parsed(raw, expected, reference_policy):
    out = canonicalize("issue_refund", {"amount": raw}, reference_policy)
    assert out["amount"] == expected
    assert isinstance(out["amount"], float)


def test_unparseable_string_left_alone(reference_policy):
    out = canonicalize("issue_refund", {"amount": "lots"}, reference_policy)
    assert out["amount"] == "lots"


@pytest.mark.parametrize("raw", ["nan", "NaN", "inf", "-inf", "Infinity"])
def test_nan_and_inf_left_alone(raw, reference_policy):
    # left as text so the evaluator's number check blocks the call
    out = canonicalize("issue_refund", {"amount": raw}, reference_policy)
    assert out["amount"] == raw


@pytest.mark.parametrize("value", [True, False])
def test_bools_never_converted(value, reference_policy):
    out = canonicalize("issue_refund", {"amount": value}, reference_policy)
    assert out["amount"] is value


def test_fullwidth_digits_fold_then_parse(reference_policy):
    out = canonicalize("issue_refund", {"amount": "４２"}, reference_policy)
    assert out["amount"] == 42.0


def test_no_number_constraint_means_no_parse(reference_policy):
    # send_email constrains body by length, not type, so "1e2" stays text
    out = canonicalize("send_email", {"body": "1e2"}, reference_policy)
    assert out["body"] == "1e2"


def test_unconstrained_field_stays_text(reference_policy):
    out = canonicalize("issue_refund", {"note": "42"}, reference_policy)
    assert out["note"] == "42"


def test_number_parse_does_not_reach_nested_fields(reference_policy):
    out = canonicalize("issue_refund", {"payload": {"amount": "42"}}, reference_policy)
    assert out["payload"]["amount"] == "42"


def test_parse_follows_the_policy_not_the_field_name():
    policy = Policy.model_validate(
        {
            "version": 1,
            "tools": {
                "set_limit": {
                    "action": "allow",
                    "constraints": {"threshold": {"type": "number", "min": 0}},
                }
            },
        }
    )
    out = canonicalize("set_limit", {"threshold": " 7 ", "amount": " 7 "}, policy)
    assert out["threshold"] == 7.0
    assert out["amount"] == " 7 "


def test_string_typed_constraint_is_not_a_parse_hook():
    policy = Policy.model_validate(
        {
            "version": 1,
            "tools": {"tag": {"action": "allow", "constraints": {"value": {"type": "string"}}}},
        }
    )
    out = canonicalize("tag", {"value": "42"}, policy)
    assert out["value"] == "42"


# --- contract: pure, total, json-serializable -------------------------------


def test_input_is_not_mutated(reference_policy):
    args = {
        "to": "corp.com.",
        "amount": " 42 ",
        "payload": {"body": "ａdmin"},
        "items": ["ﬁle"],
    }
    before = copy.deepcopy(args)
    canonicalize("issue_refund", args, reference_policy)
    assert args == before


def test_result_is_json_serializable(reference_policy):
    args = {
        "to": "corp.com.",
        "amount": "1e2",
        "payload": {"body": "ﬁle", "flags": [True, None, 3, 1.5]},
    }
    json.dumps(canonicalize("issue_refund", args, reference_policy))


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"amount": None},
        {"payload": {}, "items": []},
        {"items": [[], {}, [{}]]},
        {"body": "x" * 100_000},
        {1: "one", None: "none"},
        {"to": None, "host": 3, "url": []},
    ],
)
def test_weird_args_do_not_raise(args, reference_policy):
    assert isinstance(canonicalize("issue_refund", args, reference_policy), dict)


# --- properties -------------------------------------------------------------

TRICKY = ["corp.com.", "corp.com", "ａdmin", "cor\u200bp.com", " 42 ", "1e2", "nan", "ﬁle"]

# no "." in the random alphabet: C4 strips exactly one trailing dot, so a
# generated "x.." would legitimately change again on a second pass
CHARS = list("ab@-019 ") + ZERO_WIDTHS + ["ａ", "ﬁ"]

strings = st.one_of(st.sampled_from(TRICKY), st.text(alphabet=st.sampled_from(CHARS), max_size=12))
keys = st.one_of(st.sampled_from(HOST_FIELDS + ["amount", "body", "payload"]), st.text(max_size=8))

values = st.recursive(
    st.one_of(
        st.none(),
        st.booleans(),
        st.integers(),
        st.floats(allow_nan=False, allow_infinity=False),
        strings,
    ),
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(keys, children, max_size=3),
    ),
    max_leaves=8,
)

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

tools = st.sampled_from(["issue_refund", "send_email", "execute_code", "no_such_tool"])

# the policy fixture is read-only here, so not resetting it per example is fine
REUSES_FIXTURE = [HealthCheck.function_scoped_fixture]


@given(tool=tools, args=st.dictionaries(keys, values, max_size=5))
@settings(max_examples=300, suppress_health_check=REUSES_FIXTURE)
def test_idempotent(reference_policy, tool, args):
    once = canonicalize(tool, args, reference_policy)
    assert canonicalize(tool, once, reference_policy) == once


@given(args=st.dictionaries(keys, values, max_size=5))
@settings(max_examples=300)
def test_idempotent_when_every_host_field_is_checked(args):
    once = canonicalize(PLAIN, args, LENGTH_ONLY)
    assert canonicalize(PLAIN, once, LENGTH_ONLY) == once


@given(tool=tools, args=st.dictionaries(keys, values, max_size=5))
@settings(max_examples=300, suppress_health_check=REUSES_FIXTURE)
def test_unchecked_fields_pass_through_untouched(reference_policy, tool, args):
    checked = checked_fields(tool, reference_policy)
    out = canonicalize(tool, args, reference_policy)
    for key, value in args.items():
        if key not in checked:
            assert out[key] is value


@given(tool=tools, args=st.dictionaries(st.text(max_size=20), junk, max_size=5))
@settings(max_examples=300, suppress_health_check=REUSES_FIXTURE)
def test_total(reference_policy, tool, args):
    assert isinstance(canonicalize(tool, args, reference_policy), dict)
