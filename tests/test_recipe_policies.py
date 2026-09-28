"""The recipe's committed policies for the AgentDojo and AgentDyn suites:
regenerating them from the committed listings gives them back byte for
byte, and the listings are the suites' tool schemas and nothing more.
"""

import shutil

import pytest

from tripwire.policy import load_policy
from tripwire_benchmarks.recipe_policies import (
    AGENTDOJO,
    AGENTDYN,
    ROOT,
    listing,
    listing_bytes,
    main,
    policies,
    schema_only,
)

SUITES = sorted(AGENTDOJO + AGENTDYN)


def test_every_suite_has_a_listing_and_a_policy_in_each_arm():
    assert sorted(p.stem for p in (ROOT / "tools").glob("*.json")) == SUITES
    for directory in (ROOT, ROOT / "strict", ROOT / "taint"):
        assert sorted(p.stem for p in directory.glob("*.yaml")) == SUITES


def test_regenerating_the_policies_gives_them_back_byte_for_byte():
    generated = policies(ROOT)
    assert len(generated) == 3 * len(SUITES)
    for path, text in generated.items():
        assert path.read_bytes() == text, f"{path} is stale; run generate"


@pytest.mark.parametrize("suite", SUITES)
def test_each_policy_loads_and_its_one_flow_guards_every_write(suite):
    primary = load_policy(ROOT / f"{suite}.yaml")
    strict = load_policy(ROOT / "strict" / f"{suite}.yaml")
    taint = load_policy(ROOT / "taint" / f"{suite}.yaml")
    (flow,) = primary.flows
    assert flow.unless == "anchored" and taint.flows[0].unless is None
    assert flow.tools == strict.flows[0].tools == taint.flows[0].tools
    assert not any(rule.self_scoped for rule in strict.tools.values())
    for name, rule in primary.tools.items():
        assert (name in flow.tools) == (rule.limits is not None or rule.args is not None)


def test_generate_check_fails_on_a_stale_policy_and_generate_repairs_it(tmp_path, capsys):
    root = tmp_path / "recipe_policies"
    shutil.copytree(ROOT, root)
    main(["--root", str(root), "generate", "--check"])

    stale = root / "strict" / "slack.yaml"
    stale.write_text(stale.read_text().replace("per_session: 5", "per_session: 50"))
    with pytest.raises(SystemExit) as exit:
        main(["--root", str(root), "generate", "--check"])
    assert exit.value.code == 1
    assert f"out of date: {stale}" in capsys.readouterr().err

    main(["--root", str(root), "generate"])
    assert stale.read_bytes() == (ROOT / "strict" / "slack.yaml").read_bytes()


def test_a_dumped_schema_keeps_structure_and_argument_names_and_drops_prose():
    schema = {
        "title": "Send",
        "description": "Sends it.",
        "type": "object",
        "properties": {
            "title": {"title": "Title", "type": "string"},
            "description": {"description": "Body.", "anyOf": [{"type": "string"}]},
        },
        "$defs": {"Level": {"title": "Level", "enum": ["a"]}},
        "required": ["title"],
    }
    assert schema_only(schema) == {
        "type": "object",
        "properties": {"title": {"type": "string"}, "description": {"anyOf": [{"type": "string"}]}},
        "$defs": {"Level": {"enum": ["a"]}},
        "required": ["title"],
    }


@pytest.mark.parametrize("suite", SUITES)
def test_the_committed_listing_is_what_the_suite_dumps(suite):
    pytest.importorskip("agentdojo")
    try:
        tools = listing(suite)
    except KeyError:
        pytest.skip(f"this AgentDojo has no {suite} suite; AgentDyn's does")
    assert listing_bytes(tools) == (ROOT / "tools" / f"{suite}.json").read_bytes()


def test_dump_writes_a_suites_listing_where_generate_reads_it(tmp_path):
    pytest.importorskip("agentdojo")
    main(["--root", str(tmp_path), "dump", "banking"])
    dumped = tmp_path / "tools" / "banking.json"
    assert dumped.read_bytes() == (ROOT / "tools" / "banking.json").read_bytes()
    main(["--root", str(tmp_path), "generate"])
    assert (tmp_path / "taint" / "banking.yaml").read_bytes() == (
        ROOT / "taint" / "banking.yaml"
    ).read_bytes()
