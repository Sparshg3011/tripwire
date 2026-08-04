import pytest
from pydantic import ValidationError

from tripwire.policy.schema import Constraint, FlowRule, Policy


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


def test_empty_constraint_rejected():
    with pytest.raises(ValidationError, match="no conditions"):
        Constraint.model_validate({})


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
