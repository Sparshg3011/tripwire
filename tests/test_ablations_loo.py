import copy

import pytest
import yaml

from tripwire.policy.loader import load_policy
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
