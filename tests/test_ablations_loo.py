import copy

import pytest
import yaml
from hypothesis import example, given, settings
from hypothesis import strategies as st

from tripwire.policy.canonical import checked_fields
from tripwire.policy.evaluator import evaluate
from tripwire.policy.loader import PolicyError, load_policy
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall
from tripwire_gym.ablations import COMPONENTS, generate, leave_one_out


@pytest.fixture
def standard():
    with open("gym/policies/standard.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@pytest.mark.parametrize("component", COMPONENTS)
def test_leave_one_out_does_not_modify_the_source(standard, component):
    original = copy.deepcopy(standard)

    leave_one_out(standard, component)

    assert standard == original


def test_actions_means_static_verdicts_not_flows_or_sequences(standard):
    candidate = leave_one_out(standard, "actions")

    assert candidate["defaults"]["unknown_tools"] == "allow"
    assert all(rule["action"] == "allow" for rule in candidate["tools"].values())
    assert candidate["flows"] == standard["flows"]
    assert candidate["sequences"] == standard["sequences"]


@pytest.mark.parametrize("component", ("constraints", "limits"))
def test_argument_mechanism_is_removed_from_every_tool_only(standard, component):
    candidate = leave_one_out(standard, component)

    assert all(component not in rule for rule in candidate["tools"].values())
    assert candidate["flows"] == standard["flows"]
    assert candidate["sequences"] == standard["sequences"]


@pytest.mark.parametrize("component", ("sequences", "flows"))
def test_list_mechanism_is_emptied_only(standard, component):
    candidate = leave_one_out(standard, component)

    assert candidate[component] == []
    for other in COMPONENTS:
        if other in {component, "actions", "constraints", "limits"}:
            continue
        assert candidate[other] == standard[other]


def test_generator_writes_five_valid_policies(tmp_path):
    paths = generate("gym/policies/standard.yaml", tmp_path)

    assert [path.name for path in paths] == [f"loo-no-{name}.yaml" for name in COMPONENTS]
    assert all(load_policy(path) for path in paths)


def test_unknown_component_is_rejected(standard):
    with pytest.raises(ValueError, match="unknown component"):
        leave_one_out(standard, "magic")


def test_generator_refuses_a_policy_the_proxy_refuses(tmp_path):
    source = tmp_path / "policy.yaml"
    source.write_text(
        "version: 1\ntools:\n  send_email: {action: block}\n  send_email: {action: allow}\n"
    )
    with pytest.raises(PolicyError, match="duplicate key"):
        generate(source, tmp_path / "out")
    assert not (tmp_path / "out").exists()


# standard.yaml predates allowed_args and session-long sequences
NEWER = {
    "version": 1,
    "tools": {
        "send_email": {
            "action": "require_approval",
            "allowed_args": ["subject"],
            "constraints": {"to": {"regex": "^[^@]+@mycompany\\.example$"}},
        },
        "refund": {
            "action": "allow",
            "allowed_args": ["memo"],
            "constraints": {"amount": {"type": "number", "max": 100}},
            "limits": {"per_session": 3, "sum_per_session": {"field": "amount", "max": 150}},
        },
        "transfer": {
            "action": "allow",
            "allowed_args": ["to"],
            "limits": {"sum_per_session": {"field": "amount", "max": 500}},
        },
        "read_inbox": {"action": "allow"},
    },
    "sequences": [{"deny": "refund", "within_turns_after": "read_inbox", "turns": "session"}],
    "flows": [{"when": "context_tainted", "tools": ["send_email"], "action": "block"}],
}
FULL = Policy.model_validate(NEWER)
WITHOUT = {
    component: Policy.model_validate(leave_one_out(NEWER, component)) for component in COMPONENTS
}
SEVERITY = {"allow": 0, "gate": 1, "block": 2}

# each tool with the arguments its rule reads or lists, plus one it doesn't
ARGUMENTS = {
    "send_email": ["to", "subject", "bcc"],
    "refund": ["amount", "memo", "bcc"],
    "transfer": ["to", "amount", "bcc"],
    "read_inbox": ["bcc"],
    "unlisted": ["bcc"],
}
VALUES = {
    "to": st.sampled_from(["alice@mycompany.example", "eve@evil.example"]),
    "subject": st.just("lunch"),
    "memo": st.just("duplicate charge"),
    "amount": st.integers(-10, 600),
    "bcc": st.just("eve@evil.example"),
}
calls = st.sampled_from(list(ARGUMENTS)).flatmap(
    lambda tool: st.builds(
        ToolCall,
        st.just(tool),
        st.fixed_dictionaries({}, optional={name: VALUES[name] for name in ARGUMENTS[tool]}),
    )
)
tools = st.sampled_from(list(ARGUMENTS))
snapshots = st.builds(
    SessionSnapshot,
    turn=st.integers(0, 20),
    tainted=st.booleans(),
    tool_counts=st.dictionaries(tools, st.integers(0, 5)),
    tool_sums=st.dictionaries(tools, st.fixed_dictionaries({"amount": st.floats(0, 600)})),
    history=st.lists(st.tuples(st.integers(0, 20), tools), max_size=4).map(tuple),
)


@pytest.mark.parametrize("component", COMPONENTS)
@given(call=calls, state=snapshots)
@example(call=ToolCall("send_email", {"to": "alice@mycompany.example"}), state=SessionSnapshot())
@example(call=ToolCall("transfer", {"to": "bob", "amount": 5}), state=SessionSnapshot())
@settings(max_examples=300)
def test_removing_a_mechanism_never_refuses_more(component, call, state):
    # judged on the args as given: canonicalizing would also follow the
    # removed constraints out, which is part of what removing them measures
    full = evaluate(call, state, FULL)
    ablated = evaluate(call, state, WITHOUT[component])
    assert SEVERITY[ablated.decision] <= SEVERITY[full.decision]


# yaml hands the merged rule the very list its source's allowed_args holds
MERGED = yaml.safe_load(
    "version: 1\n"
    "tools:\n"
    "  send_email: &mail\n"
    "    action: allow\n"
    "    allowed_args: [subject, body]\n"
    '    constraints: {to: {regex: "^[^@]+@mycompany\\\\.example$"}}\n'
    "  post_message:\n"
    "    <<: *mail\n"
    '    constraints: {channel: {regex: "^#team$"}}\n'
)


def admitted(policy, tool):
    return set(policy.tools[tool].allowed_args) | checked_fields(tool, policy)


@pytest.mark.parametrize("component", COMPONENTS)
@pytest.mark.parametrize("source", [NEWER, MERGED], ids=["newer", "merged"])
def test_every_tool_admits_the_arguments_it_did(source, component):
    full = Policy.model_validate(source)
    ablated = Policy.model_validate(leave_one_out(source, component))
    for tool, rule in full.tools.items():
        if rule.allowed_args is not None:
            assert admitted(ablated, tool) == admitted(full, tool)


def test_generated_policies_carry_allowed_args_and_session_sequences(tmp_path):
    source = tmp_path / "policy.yaml"
    source.write_text(yaml.safe_dump(NEWER))
    generated = dict(zip(COMPONENTS, generate(source, tmp_path / "out"), strict=True))
    policies = {component: load_policy(path) for component, path in generated.items()}

    assert policies["constraints"].tools["send_email"].allowed_args == ["subject", "to"]
    assert policies["limits"].tools["transfer"].allowed_args == ["to", "amount"]
    # amount is still read by the budget, or by the constraint, respectively
    assert policies["constraints"].tools["refund"].allowed_args == ["memo"]
    assert policies["limits"].tools["refund"].allowed_args == ["memo"]
    for component in ("actions", "constraints", "limits", "flows"):
        assert policies[component].sequences[0].turns == "session"
