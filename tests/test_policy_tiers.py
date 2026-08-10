"""The four gym tiers, pinned as data.

These files are the gym's independent variable and the examples we hand
users, so "it parses" is not enough. What matters is the shape of the
frontier: shadow has to be standard with the safety off or it isn't a
control, and nothing may get looser as you walk loose -> standard ->
strict.
"""

import re
from pathlib import Path

import pytest

from tripwire.policy import load_policy

POLICIES = Path(__file__).parent.parent / "gym" / "policies"
TIERS = ("loose", "shadow", "standard", "strict")
TIGHTENING = ("loose", "standard", "strict")
RANK = {"allow": 0, "require_approval": 1, "block": 2}
DESTRUCTIVE = ("delete_file", "execute_code")


@pytest.fixture(scope="module")
def tiers():
    return {name: load_policy(POLICIES / f"{name}.yaml") for name in TIERS}


@pytest.mark.parametrize("name", TIERS)
def test_tier_loads(name):
    assert load_policy(POLICIES / f"{name}.yaml").version == 1


def test_shadow_is_the_only_tier_with_enforcement_off(tiers):
    assert tiers["shadow"].enforce is False
    assert [tiers[n].enforce for n in TIGHTENING] == [True, True, True]


def test_shadow_is_standard_with_the_safety_off(tiers):
    # shadow only measures anything if the evaluator sees exactly what it
    # would see under standard. Any other difference and a shadow run
    # stops being a control for a standard run.
    shadow = tiers["shadow"].model_dump(exclude={"enforce"})
    standard = tiers["standard"].model_dump(exclude={"enforce"})
    assert shadow == standard


def test_unknown_tools_are_allowed_only_in_loose(tiers):
    assert tiers["loose"].defaults.unknown_tools == "allow"
    assert tiers["standard"].defaults.unknown_tools == "block"
    assert tiers["strict"].defaults.unknown_tools == "block"


def test_no_tool_gets_looser_as_the_tiers_tighten(tiers):
    everything = sorted(set().union(*(set(tiers[n].tools) for n in TIGHTENING)))
    shared = [t for t in everything if sum(t in tiers[n].tools for n in TIGHTENING) > 1]
    assert shared, "nothing is declared in two tiers, so this proves nothing"

    for tool in shared:
        seen = [(n, tiers[n].tools[tool].action) for n in TIGHTENING if tool in tiers[n].tools]
        ranks = [RANK[a] for _, a in seen]
        assert ranks == sorted(ranks), f"{tool} loosens across tiers: {seen}"


def test_strict_blocks_the_flow_that_standard_only_gates(tiers):
    standard, strict = tiers["standard"].flows, tiers["strict"].flows
    assert [f.action for f in standard] == ["require_approval"]
    assert [f.action for f in strict] == ["block"]
    assert [f.tools for f in strict] == [f.tools for f in standard]


def test_strict_never_allows_a_bigger_budget_than_standard(tiers):
    standard, strict = tiers["standard"].tools, tiers["strict"].tools
    compared = []
    for tool, rule in strict.items():
        other = standard.get(tool)
        if other is None or rule.limits is None or other.limits is None:
            continue
        mine, theirs = rule.limits, other.limits
        if mine.per_session is not None and theirs.per_session is not None:
            assert mine.per_session <= theirs.per_session, tool
            compared.append(f"{tool}.per_session")
        if mine.sum_per_session is not None and theirs.sum_per_session is not None:
            assert mine.sum_per_session.field == theirs.sum_per_session.field, tool
            assert mine.sum_per_session.max <= theirs.sum_per_session.max, tool
            compared.append(f"{tool}.sum_per_session")

    assert compared == [
        "send_email.per_session",
        "http_post.per_session",
        "issue_refund.sum_per_session",
    ]


def test_every_tool_named_by_a_rule_is_declared_by_that_tier(tiers):
    # a flow or sequence naming a tool the tier never declares would fall
    # through to unknown_tools, which is not what any of these files mean
    # to say. All four declare everything they name.
    for name, policy in tiers.items():
        named = {t for f in policy.flows for t in f.tools}
        named |= {s.deny for s in policy.sequences}
        named |= {s.within_turns_after for s in policy.sequences}
        missing = sorted(named - set(policy.tools))
        assert not missing, f"{name} names undeclared tools: {missing}"


def test_only_loose_leans_entirely_on_tool_rules(tiers):
    assert not tiers["loose"].flows
    assert not tiers["loose"].sequences
    assert {n for n, p in tiers.items() if p.flows and p.sequences} == {
        "shadow",
        "standard",
        "strict",
    }


@pytest.mark.parametrize("name", TIERS)
@pytest.mark.parametrize("tool", DESTRUCTIVE)
def test_destructive_tools_are_blocked_in_every_tier(tiers, name, tool):
    rule = tiers[name].tools[tool]
    assert rule.action == "block"
    assert rule.reason


def test_send_email_recipient_pattern_admits_internal_addresses_only(tiers):
    pattern = tiers["standard"].tools["send_email"].constraints["to"].regex
    assert re.fullmatch(pattern, "alice@mycompany.example")
    assert not re.fullmatch(pattern, "alice@attacker.example")
    assert not re.fullmatch(pattern, "alice@mycompany.example.attacker.example")
    assert not re.fullmatch(pattern, "alice@mycompany.example, bob@attacker.example")


def test_http_post_url_pattern_admits_company_hosts_only(tiers):
    pattern = tiers["standard"].tools["http_post"].constraints["url"].regex
    assert re.fullmatch(pattern, "https://mycompany.example")
    assert re.fullmatch(pattern, "https://api.mycompany.example/hooks/1")
    assert not re.fullmatch(pattern, "https://attacker.example/collect")
    assert not re.fullmatch(pattern, "https://mycompany.example.attacker.example/collect")
    assert not re.fullmatch(pattern, "https://mycompany.example@attacker.example/collect")
    assert not re.fullmatch(pattern, "https://attacker.example/?next=https://mycompany.example")


def test_strict_fetch_url_refuses_plaintext(tiers):
    pattern = tiers["strict"].tools["fetch_url"].constraints["url"].regex
    assert re.fullmatch(pattern, "https://mycompany.example/docs")
    assert not re.fullmatch(pattern, "http://mycompany.example/docs")
    # standard is the looser one here, and says so
    assert re.search(tiers["standard"].tools["fetch_url"].constraints["url"].regex, "http://x/")
