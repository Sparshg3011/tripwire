"""End to end through the real thing: MCP client -> tripwire subprocess
-> toy server. No fakes anywhere.

The policy engine isn't finished yet (evaluator, canonicalizer and taint
tracker are still stubs), which makes this the honest test of invariant
one: a firewall whose brain is missing refuses everything. When those
modules land, the refusals here turn into real verdicts and this file
grows an allow case.
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

# every rule id the interceptor can refuse under when a piece of the
# policy engine is missing or broken
FAIL_CLOSED_RULES = {"session_error", "canonicalizer_error", "evaluator_error"}


def proxy(tmp_path, policy_text):
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_text)
    audit = tmp_path / "audit.jsonl"
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
def enforcing(tmp_path):
    return proxy(tmp_path, "version: 1\ndefaults: {unknown_tools: allow}\n")


@pytest.fixture
def shadow(tmp_path):
    return proxy(tmp_path, "version: 1\nenforce: false\ndefaults: {unknown_tools: allow}\n")


def records(audit_path):
    return [json.loads(line) for line in audit_path.read_text().splitlines()]


async def test_tools_reappear_through_proxy(enforcing):
    params, _ = enforcing
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {t.name for t in tools.tools} == {"add", "whoami", "boom"}


async def test_calls_are_refused_while_the_policy_engine_is_incomplete(enforcing):
    params, audit = enforcing
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("add", {"a": 2, "b": 3})

    assert result.isError
    assert "tripwire_blocked" in result.content[0].text

    decision = next(r for r in records(audit) if r["kind"] == "decision")
    assert decision["data"]["decision"] == "block"
    assert decision["data"]["rule"] in FAIL_CLOSED_RULES


async def test_refused_calls_never_reach_upstream(enforcing):
    params, audit = enforcing
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("add", {"a": 2, "b": 3})
                await session.call_tool("whoami", {})

    kinds = [r["kind"] for r in records(audit)]
    assert kinds.count("decision") == 2
    assert "tool_call" not in kinds  # nothing was forwarded
    assert "tool_result" not in kinds


async def test_shadow_mode_lets_everything_through(shadow):
    # Same broken policy engine, enforce: false. Shadow mode promises it
    # changes nothing, and that promise has to hold even when the thing
    # it would have said is "block".
    params, audit = shadow
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("add", {"a": 2, "b": 3})

    assert not result.isError
    assert result.content[0].text == "5"

    decision = next(r for r in records(audit) if r["kind"] == "decision")
    assert decision["data"]["decision"] == "block"  # what it would have done
    assert decision["data"]["shadow"] is True


async def test_upstream_errors_pass_through(shadow):
    params, _ = shadow
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("boom", {})

    assert result.isError
    assert "toy exploded" in result.content[0].text


async def test_forwarded_calls_are_audited(shadow):
    params, audit = shadow
    with anyio.fail_after(30):
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("add", {"a": 1, "b": 1})
                await session.call_tool("whoami", {})

    assert verify_log(audit).ok

    kinds = [r["kind"] for r in records(audit)]
    assert kinds[0] == "proxy_start"
    assert kinds.count("decision") == 2
    assert kinds.count("tool_call") == 2
    assert kinds.count("tool_result") == 2
