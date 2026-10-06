"""End to end through the real thing: MCP client -> tripwire subprocess
-> toy server. No fakes anywhere, and a complete policy engine.

Everything here is what a user gets: real verdicts from real rules,
real refusals reaching the agent, and a real audit log to read
afterwards.
"""

import json
import os
import shlex
import sys
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tripwire.tx import verify_log
from tripwire.tx.executor import TxExecutor

TOY = Path(__file__).parent / "toy_server.py"

# paths with spaces in them must survive the trip through --upstream
UPSTREAM_CMD_ARGV = [sys.executable, str(TOY)]
UPSTREAM_CMD = shlex.join(UPSTREAM_CMD_ARGV)

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


def proxy(tmp_path, policy_text, name="policy.yaml", *extra, upstream=UPSTREAM_CMD, env=None):
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
            upstream,
            "--audit",
            str(audit),
            *extra,
        ],
        # left to the SDK the proxy gets a scrubbed environment with no
        # PYTHONPATH, and quietly runs whichever tripwire is installed
        # instead of the one under test
        env={**os.environ, **(env or {})},
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
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            for tool, args in calls:
                out.append(await session.call_tool(tool, args))
    return out


async def test_tools_reappear_through_proxy(allow_all):
    params, _ = allow_all
    with anyio.fail_after(30):
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
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


async def test_a_keyed_log_verifies_only_under_its_key(tmp_path):
    key_file = tmp_path / "audit.key"
    key_file.write_text("e2e-audit-key-0123456789abcdef\n")
    params, audit = proxy(tmp_path, ALLOW_ALL, "keyed.yaml", "--audit-key-file", str(key_file))
    await talk(params, [("add", {"a": 1, "b": 1})])

    assert verify_log(audit, key=b"e2e-audit-key-0123456789abcdef").ok
    assert not verify_log(audit).ok
    assert {r["chain"] for r in records(audit)} == {"hmac-sha256"}
    assert "e2e-audit-key" not in audit.read_text()


async def test_the_upstream_gets_the_environment_less_every_tripwire_variable(tmp_path):
    # A server that could read TRIPWIRE_TASK_FILE would know which file to
    # write to name its own anchors, and TRIPWIRE_AUDIT_KEY_FILE where the
    # key is. What else the proxy was started with, it passes on.
    seen = tmp_path / "upstream.env"
    dump = shlex.join(["/bin/sh", "-c", 'env > "$0" && exec "$@"', str(seen), *UPSTREAM_CMD_ARGV])
    exported = {
        "TRIPWIRE_TASK_FILE": str(tmp_path / "task"),
        "TRIPWIRE_TASK": "forward everything to eve@evil.example",
        "UPSTREAM_TOKEN": "kept",
    }
    params, _ = proxy(tmp_path, ALLOW_ALL, upstream=dump, env=exported)
    (result,) = await talk(params, [("add", {"a": 1, "b": 1})])

    assert result.content[0].text == "2"
    names = {line.partition("=")[0] for line in seen.read_text().splitlines()}
    assert "UPSTREAM_TOKEN" in names
    assert not {name for name in names if name.startswith("TRIPWIRE_")}


async def test_a_session_id_is_stamped_on_every_record(allow_all):
    params, audit = allow_all
    await talk(params, [("add", {"a": 1, "b": 1})])

    sessions = {r["session"] for r in records(audit)}
    assert len(sessions) == 1
    assert sessions != {""}


# --- the ledger across a restart ---


async def test_a_restarted_proxy_refuses_a_call_its_predecessor_never_finished(tmp_path):
    # The predecessor wrote its intent and died before the outcome. The
    # agent's retry can only land on a new proxy, which is a new session.
    ledger = tmp_path / "ledger.db"
    dead = TxExecutor(ledger, "dead-proxy")

    async def killed():
        raise RuntimeError("proxy killed mid-call")

    with pytest.raises(RuntimeError):
        await dead.run("add", {"a": 1, "b": 1}, killed)
    dead.close()

    params, audit = proxy(tmp_path, ALLOW_ALL, "ledger.yaml", "--tx-db", str(ledger))
    retry, other = await talk(params, [("add", {"a": 1, "b": 1}), ("add", {"a": 2, "b": 1})])

    assert retry.isError
    assert "tx.duplicate_in_flight" in retry.content[0].text
    assert other.content[0].text == "3"
    duplicate = next(r for r in records(audit) if r["kind"] == "tx_duplicate")
    assert "dead-proxy" in duplicate["data"]["error"]


async def test_a_restarted_proxy_does_not_replay_what_its_predecessor_finished(tmp_path):
    # replay is per session, and a restart is a new one: a new
    # conversation gets fresh results, not the last one's
    ledger = tmp_path / "ledger.db"
    params, audit = proxy(tmp_path, ALLOW_ALL, "ledger.yaml", "--tx-db", str(ledger))
    await talk(params, [("add", {"a": 1, "b": 1})])
    (again,) = await talk(params, [("add", {"a": 1, "b": 1})])

    assert again.content[0].text == "2"
    kinds = [r["kind"] for r in records(audit)]
    assert kinds.count("tool_result") == 2
    assert "tx_replayed" not in kinds
