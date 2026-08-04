"""End-to-end: real MCP client -> tripwire proxy (subprocess) -> toy server.

The proxy spawns the toy server itself, exactly like production.
"""

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


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


@pytest.fixture
def proxy_params(tmp_path, audit_path):
    policy = tmp_path / "allow.yaml"
    policy.write_text("version: 1\ndefaults: {unknown_tools: allow}\n")
    return StdioServerParameters(
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
            str(audit_path),
        ],
    )


async def test_tools_reappear_through_proxy(proxy_params):
    with anyio.fail_after(30):
        async with stdio_client(proxy_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {t.name for t in tools.tools} == {"add", "whoami", "boom"}


async def test_calls_pass_through(proxy_params):
    with anyio.fail_after(30):
        async with stdio_client(proxy_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("add", {"a": 2, "b": 3})
                assert not result.isError
                assert result.content[0].text == "5"


async def test_upstream_errors_pass_through(proxy_params):
    with anyio.fail_after(30):
        async with stdio_client(proxy_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool("boom", {})
                assert result.isError
                assert "toy exploded" in result.content[0].text


async def test_every_call_is_audited(proxy_params, audit_path):
    with anyio.fail_after(30):
        async with stdio_client(proxy_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.call_tool("add", {"a": 1, "b": 1})
                await session.call_tool("whoami", {})

    result = verify_log(audit_path)
    assert result.ok, result.why

    import json

    kinds = [json.loads(line)["kind"] for line in audit_path.read_text().splitlines()]
    assert kinds[0] == "proxy_start"
    assert kinds.count("tool_call") == 2
    assert kinds.count("tool_result") == 2
