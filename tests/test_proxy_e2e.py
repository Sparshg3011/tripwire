"""End to end through the real thing: MCP client -> tripwire subprocess
-> toy server. No fakes anywhere, and a complete policy engine.

Everything here is what a user gets: real verdicts from real rules,
real refusals reaching the agent, and a real audit log to read
afterwards.
"""

import json
import shlex
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tripwire.tx import verify_log

TOY = Path(__file__).parent / "toy_server.py"

# paths with spaces in them must survive the trip through --upstream
UPSTREAM_CMD = f"{shlex.quote(sys.executable)} {shlex.quote(str(TOY))}"

ALLOW_ALL = """
version: 1
tools:
  add: { action: allow }
  whoami: { action: allow }
  boom: { action: allow }
"""

# add is fine, whoami is off, and boom is capped so its second call fails
GUARDED = """
version: 1
defaults: { unknown_tools: block }
tools:
  add:
    action: allow
    constraints:
      a: { type: number, max: 10 }
  whoami:
    action: block
    reason: "Identity lookups are disabled."
"""

SHADOWED = "version: 1\nenforce: false\n" + GUARDED.split("version: 1\n", 1)[1]


def proxy(tmp_path, policy_text, name="policy.yaml"):
    policy = tmp_path / name
    policy.write_text(policy_text)
    audit = tmp_path / f"{name}.audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "tripwire",
            "serve",
            "--policy",
            str(policy),
            "--upstream",
            UPSTREAM_CMD,
            "--audit",
            str(audit),
        ],
    )
    return params, audit


@pytest.fixture
def allow_all(tmp_path):
    return proxy(tmp_path, ALLOW_ALL, "allow.yaml")


@pytest.fixture
def guarded(tmp_path):
    return proxy(tmp_path, GUARDED, "guarded.yaml")


@pytest.fixture
def shadowed(tmp_path):
    return proxy(tmp_path, SHADOWED, "shadow.yaml")


def records(audit_path):
    return [json.loads(line) for line in audit_path.read_text().splitlines()]


async def talk(params, calls):
    """Run a list of (tool, args) through the proxy, collect the results."""
    out = []
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for tool, args in calls:
                    out.append(await session.call_tool(tool, args))
    return out


async def test_tools_reappear_through_proxy(allow_all):
    params, _ = allow_all
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {t.name for t in tools.tools} == {"add", "whoami", "boom"}


async def test_an_allowed_call_goes_through_untouched(allow_all):
    params, audit = allow_all
    (result,) = await talk(params, [("add", {"a": 2, "b": 3})])

    assert not result.isError
    assert result.content[0].text == "5"

    kinds = [r["kind"] for r in records(audit)]
    assert kinds.count("decision") == 1
    assert kinds.count("tool_call") == 1
    assert kinds.count("tool_result") == 1


async def test_a_blocked_tool_is_refused_with_its_reason(guarded):
    params, audit = guarded
    (result,) = await talk(params, [("whoami", {})])

    assert result.isError
    text = result.content[0].text
    assert "tripwire_blocked" in text
    assert "Identity lookups are disabled." in text
    assert "tools.whoami.action" in text

    decision = next(r for r in records(audit) if r["kind"] == "decision")
    assert decision["data"]["decision"] == "block"


async def test_a_constraint_violation_is_refused(guarded):
    params, _ = guarded
    (ok, bad) = await talk(params, [("add", {"a": 1, "b": 1}), ("add", {"a": 99, "b": 1})])

    assert not ok.isError and ok.content[0].text == "2"
    assert bad.isError
    assert "tools.add.constraints.a" in bad.content[0].text


async def test_an_unknown_tool_is_refused_by_default(guarded):
    params, _ = guarded
    (result,) = await talk(params, [("boom", {})])

    assert result.isError
    assert "defaults.unknown_tools" in result.content[0].text


async def test_refused_calls_never_reach_upstream(guarded):
    params, audit = guarded
    await talk(params, [("whoami", {}), ("boom", {})])

    kinds = [r["kind"] for r in records(audit)]
    assert kinds.count("decision") == 2
    assert "tool_call" not in kinds  # nothing was forwarded
    assert "tool_result" not in kinds


async def test_upstream_errors_pass_through(allow_all):
    params, _ = allow_all
    (result,) = await talk(params, [("boom", {})])

    assert result.isError
    assert "toy exploded" in result.content[0].text


async def test_shadow_mode_lets_a_block_through_and_says_so(shadowed):
    # same policy that refuses whoami, with enforce off
    params, audit = shadowed
    (result,) = await talk(params, [("whoami", {})])

    assert not result.isError
    assert result.content[0].text == "toy-server"

    decision = next(r for r in records(audit) if r["kind"] == "decision")
    assert decision["data"]["decision"] == "block"  # what it would have done
    assert decision["data"]["shadow"] is True


async def test_the_log_is_a_verifiable_chain(allow_all):
    params, audit = allow_all
    await talk(params, [("add", {"a": 1, "b": 1}), ("whoami", {})])

    assert verify_log(audit).ok
    kinds = [r["kind"] for r in records(audit)]
    assert kinds[0] == "proxy_start"
    assert kinds.count("tool_result") == 2


async def test_a_session_id_is_stamped_on_every_record(allow_all):
    params, audit = allow_all
    await talk(params, [("add", {"a": 1, "b": 1})])

    sessions = {r["session"] for r in records(audit)}
    assert len(sessions) == 1
    assert sessions != {""}
