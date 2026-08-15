"""The ablation chain, pinned as data.

An ablation only measures a mechanism if that mechanism is the *only*
thing that changed. These files are derived from gym/policies/standard.yaml
by deleting one layer at a time, and the assertions below are what stop
that derivation from quietly drifting into a second edit — a stray
constraint in the limits step would put its contribution in the wrong
row, and nothing about the resulting number would look wrong.
"""

from pathlib import Path

import pytest

from tripwire.policy import load_policy

GYM = Path(__file__).parent.parent / "gym"
ABLATIONS = GYM / "ablations"

# in order, each adding one mechanism to the one before it. standard is
# the top of the chain and lives with the tiers, not with the ablations.
CHAIN = (
    "ablate-none",
    "ablate-actions",
    "ablate-constraints",
    "ablate-limits",
    "ablate-sequences",
)
LAYERS = ("actions", "constraints", "limits", "sequences", "flows")


@pytest.fixture(scope="module")
def steps():
    policies = {name: load_policy(ABLATIONS / f"{name}.yaml") for name in CHAIN}
    policies["standard"] = load_policy(GYM / "policies" / "standard.yaml")
    return policies


def present(policy) -> set[str]:
    """Which of the five mechanisms this file actually carries."""
    layers = set()
    if policy.defaults.unknown_tools != "allow" or any(
        r.action != "allow" for r in policy.tools.values()
    ):
        layers.add("actions")
    if any(r.constraints for r in policy.tools.values()):
        layers.add("constraints")
    if any(r.limits is not None for r in policy.tools.values()):
        layers.add("limits")
    if policy.sequences:
        layers.add("sequences")
    if policy.flows:
        layers.add("flows")
    return layers


@pytest.mark.parametrize("name", CHAIN)
def test_every_ablation_loads(name):
    assert load_policy(ABLATIONS / f"{name}.yaml").version == 1


def test_no_ablation_file_is_left_unmeasured():
    # a file in the directory that no condition runs is a policy nobody
    # is reading and nobody is testing
    on_disk = sorted(p.stem for p in ABLATIONS.glob("*.yaml"))
    assert on_disk == sorted(CHAIN)


def test_ablate_none_removes_every_mechanism(steps):
    floor = steps["ablate-none"]
    assert present(floor) == set()
    assert floor.defaults.unknown_tools == "allow"
    assert [r.action for r in floor.tools.values()] == ["allow"] * len(floor.tools)
    assert not floor.sequences
    assert not floor.flows


def test_each_step_adds_exactly_one_mechanism(steps):
    order = [*CHAIN, "standard"]
    seen = [present(steps[name]) for name in order]
    for (name, before), (later, after) in zip(zip(order, seen), zip(order[1:], seen[1:])):
        assert after - before == {LAYERS[len(before)]}, f"{later} adds more than one layer"
        assert not before - after, f"{later} removed something {name} had"


def test_the_chain_never_removes_a_mechanism(steps):
    counts = [len(present(steps[name])) for name in (*CHAIN, "standard")]
    assert counts == [0, 1, 2, 3, 4, 5]


def test_standard_is_the_top_of_the_chain(steps):
    assert present(steps["standard"]) == set(LAYERS)


def test_each_step_is_standard_with_the_later_layers_deleted(steps):
    # the strong form of the claim: not merely "one more mechanism", but
    # byte-for-byte standard with the rest stripped. Anything else and
    # the ablation is measuring a policy of its own invention.
    standard = steps["standard"].model_dump()
    for index, name in enumerate(CHAIN):
        want = _stripped(standard, drop=set(LAYERS[index:]))
        assert steps[name].model_dump() == want, f"{name} is not standard minus {LAYERS[index:]}"


def _stripped(standard: dict, drop: set[str]) -> dict:
    policy = {**standard, "tools": {n: dict(r) for n, r in standard["tools"].items()}}
    for rule in policy["tools"].values():
        if "constraints" in drop:
            rule["constraints"] = {}
        if "limits" in drop:
            rule["limits"] = None
        if "actions" in drop:
            # the block reasons go with the blocks they explain
            rule["action"], rule["reason"] = "allow", None
    if "actions" in drop:
        policy["defaults"] = {**policy["defaults"], "unknown_tools": "allow"}
    if "sequences" in drop:
        policy["sequences"] = []
    if "flows" in drop:
        policy["flows"] = []
    return policy


def test_taint_labels_are_identical_all_the_way_up(steps):
    # sources are the input to the flow layer, not a layer of their own.
    # Varying them across steps would move taint into whichever row it
    # happened to change on, so they are held still and only `flows` moves.
    assert {name: steps[name].sources for name in (*CHAIN, "standard")} == dict.fromkeys(
        (*CHAIN, "standard"), steps["standard"].sources
    )


def test_every_ablation_enforces(steps):
    # shadow is the tier with enforcement off; an ablation that shadowed
    # would score 0% for a reason that has nothing to do with its layer
    assert all(steps[name].enforce for name in (*CHAIN, "standard"))


def test_no_gate_appears_before_the_flow_layer(steps):
    # standard gates only through flows, so every step below it must be
    # gateless — which is what makes their approve and deny numbers equal
    for name in CHAIN:
        policy = steps[name]
        assert not policy.flows
        assert all(r.action != "require_approval" for r in policy.tools.values()), name


def test_every_tool_the_corpus_calls_is_declared_at_every_step(steps):
    # a tool nobody declared falls through to defaults.unknown_tools, and
    # then the actions row would be scoring a default rather than a rule
    declared = set(steps["standard"].tools)
    for name in CHAIN:
        assert set(steps[name].tools) == declared, name
