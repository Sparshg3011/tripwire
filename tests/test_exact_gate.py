"""Contract tests, not estimates of autonomous-agent benchmark utility."""

import copy
import json
import shlex
import sys
from pathlib import Path

import anyio
import pytest
from mcp import types

from tripwire.gate import ApprovalRequest, ExactApprovalGate
from tripwire.policy.schema import Policy
from tripwire.policy.types import ToolCall
from tripwire.proxy.interceptor import Interceptor
from tripwire.session import SessionState
from tripwire.tx import AuditLog, format_trace, trace, verify_log

ARGS = {"to": "colleague@example.com", "amount": 25, "body": "Approved payment"}


def policy():
    return Policy.model_validate(
        {
            "version": 1,
            "sources": {"read_email": "untrusted"},
            "tools": {
                "read_email": {"action": "allow"},
                "send_money": {
                    "action": "require_approval",
                    "constraints": {
                        "to": {"regex": "[a-z]+@example\\.com"},
                        "amount": {"type": "number", "min": 0, "max": 100},
                    },
                    "limits": {"per_session": 2},
                },
            },
            "flows": [
                {
                    "when": "context_tainted",
                    "tools": ["send_money"],
                    "action": "require_approval",
                }
            ],
        }
    )


def request(session, args=None, tool="send_money"):
    return ApprovalRequest(
        tool=tool,
        args=copy.deepcopy(ARGS if args is None else args),
        approval_scope=session.approval_scope,
    )


def gate_for(session, args=None, **kwargs):
    return ExactApprovalGate(
        session, [ToolCall("send_money", copy.deepcopy(ARGS if args is None else args))], **kwargs
    )


class Upstream:
    def __init__(self):
        self.tools = []
        self.calls = []
        self.error = None

    async def call(self, name, args):
        self.calls.append((name, args))
        if self.error:
            raise self.error
        return types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


@pytest.fixture
def live(tmp_path):
    session = SessionState(policy())
    audit = AuditLog(tmp_path / "audit.jsonl", session_id="exact-test")
    upstream = Upstream()
    interceptor = Interceptor(session.policy, audit, upstream, session, gate=gate_for(session))
    yield interceptor
    audit.close()


async def test_exact_action_works_after_untrusted_read_but_taint_remains(live):
    await live.handle("read_email", {})
    result = await live.handle("send_money", ARGS)
    assert not result.isError
    assert live.session.snapshot().tainted
    assert live.upstream.calls == [("read_email", {}), ("send_money", ARGS)]
    assert verify_log(live.audit.path).ok
    records = [json.loads(line) for line in live.audit.path.read_text().splitlines()]
    prompt = next(row["data"] for row in records if row["kind"] == "gate_requested")
    assert prompt["gate_type"] == "ExactApprovalGate"
    assert any(row["kind"] == "gate_approved" for row in records)
    rendered = format_trace(trace(records, "exact-test"), "exact-test")
    assert "ExactApprovalGate" in rendered
    assert "human" not in rendered


@pytest.mark.parametrize(
    "changed",
    [
        {**ARGS, "to": "attacker@example.com"},
        {**ARGS, "amount": 26},
        {**ARGS, "amount": True},
        {**ARGS, "body": "different content"},
        {**ARGS, "cc": "attacker@example.com"},
        {**ARGS, "body": {"text": "Approved payment"}},
        {"to": ARGS["to"], "amount": 25},
        {},
    ],
)
async def test_mismatch_does_not_execute_or_consume_the_legitimate_grant(live, changed):
    await live.handle("read_email", {})
    assert (await live.handle("send_money", changed)).isError
    assert not (await live.handle("send_money", ARGS)).isError
    assert live.upstream.calls == [("read_email", {}), ("send_money", ARGS)]


async def test_approved_action_before_taint_cannot_replay_after_taint(live):
    assert not (await live.handle("send_money", ARGS)).isError
    await live.handle("read_email", {})
    assert (await live.handle("send_money", ARGS)).isError
    assert len([name for name, _ in live.upstream.calls if name == "send_money"]) == 1


async def test_upstream_failure_consumes_grant(live):
    live.upstream.error = RuntimeError("outcome unknown")
    assert (await live.handle("send_money", ARGS)).isError
    live.upstream.error = None
    assert (await live.handle("send_money", ARGS)).isError
    assert len(live.upstream.calls) == 1


async def test_cancelled_forward_consumes_grant(live):
    async def wait_forever(name, args):
        live.upstream.calls.append((name, args))
        await anyio.sleep_forever()

    live.upstream.call = wait_forever
    with anyio.move_on_after(0.01):
        await live.handle("send_money", ARGS)
    assert (await live.handle("send_money", ARGS)).isError
    assert len(live.upstream.calls) == 1


async def test_another_session_even_with_same_policy_cannot_spend_grant():
    first = SessionState(policy())
    second = SessionState(first.policy)
    gate = gate_for(first)
    assert not await gate.request(request(second))
    assert not await gate.request(ApprovalRequest(tool="send_money", args=ARGS))
    assert await gate.request(request(first))


async def test_concurrent_requests_get_exactly_one_approval():
    session = SessionState(policy())
    gate = gate_for(session)
    answers = []

    async def ask():
        answers.append(await gate.request(request(session)))

    async with anyio.create_task_group() as group:
        for _ in range(50):
            group.start_soon(ask)
    assert sum(answers) == 1


async def test_expiry_at_boundary_fails_closed(monkeypatch):
    monkeypatch.setattr("tripwire.gate.exact.time.monotonic", lambda: 100.0)
    session = SessionState(policy())
    gate = gate_for(session, ttl_seconds=10)
    monkeypatch.setattr("tripwire.gate.exact.time.monotonic", lambda: 110.0)
    assert not await gate.request(request(session))


async def test_wall_clock_deadline_expires_even_if_monotonic_clock_paused(monkeypatch):
    monkeypatch.setattr("tripwire.gate.exact.time.monotonic", lambda: 100.0)
    monkeypatch.setattr("tripwire.gate.exact.time.time", lambda: 1000.0)
    session = SessionState(policy())
    gate = gate_for(session, ttl_seconds=10)
    monkeypatch.setattr("tripwire.gate.exact.time.time", lambda: 1010.0)
    assert not await gate.request(request(session))
    monkeypatch.setattr("tripwire.gate.exact.time.time", lambda: 1000.0)
    assert not await gate.request(request(session))  # expiry cannot be undone


async def test_expiry_during_argument_matching_fails_closed(monkeypatch):
    from tripwire.gate import exact

    clock = [100.0]
    monkeypatch.setattr(exact.time, "monotonic", lambda: clock[0])
    session = SessionState(policy())
    gate = gate_for(session, ttl_seconds=10)
    original_key = exact._key

    def slow_key(tool, args):
        clock[0] = 111.0
        return original_key(tool, args)

    monkeypatch.setattr(exact, "_key", slow_key)
    assert not await gate.request(request(session))


async def test_revocation_is_permanent_and_idempotent():
    session = SessionState(policy())
    gate = gate_for(session)
    gate.close()
    gate.close()
    assert not await gate.request(request(session))


async def test_policy_change_invalidates_grants():
    session = SessionState(policy())
    gate = gate_for(session)
    session.policy.tools["send_money"].constraints = {}
    assert not await gate.request(request(session))


async def test_unobserved_execution_invalidates_grant_even_if_policy_restored(live):
    live.session.policy.tools["send_money"].action = "allow"
    assert not (await live.handle("send_money", ARGS)).isError
    live.session.policy.tools["send_money"].action = "require_approval"
    assert (await live.handle("send_money", ARGS)).isError
    assert len(live.upstream.calls) == 1


async def test_broken_session_invalidates_grants():
    session = SessionState(policy())
    gate = gate_for(session)
    session.broken = "bookkeeping failure"
    assert not await gate.request(request(session))


async def test_grant_copies_nested_values_and_matches_json_types():
    session = SessionState(policy())
    original = {**ARGS, "metadata": {"reviewed": [True, 1, "1"]}}
    gate = gate_for(session, original)
    saved = copy.deepcopy(original)
    original["metadata"]["reviewed"][0] = 1
    assert not await gate.request(request(session, original))
    assert await gate.request(request(session, saved))


async def test_canonicalized_registration_matches_what_is_forwarded(live):
    variant = {**ARGS, "to": "colleague@ｅxample.com\u200b."}
    live.gate = gate_for(live.session, variant)
    assert not (await live.handle("send_money", variant)).isError
    assert live.upstream.calls == [("send_money", ARGS)]


async def test_unchecked_arguments_must_match_byte_for_byte():
    # body is forwarded as sent, so a grant for one spelling can't cover another
    session = SessionState(policy())
    gate = gate_for(session)
    assert not await gate.request(request(session, {**ARGS, "body": "Approved\u200bpayment"}))


async def test_gate_never_normalizes_only_for_comparison():
    session = SessionState(policy())
    gate = gate_for(session)
    assert not await gate.request(request(session, {**ARGS, "to": "colleague@ｅxample.com"}))


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "x"}, {1, 2}, (1, 2)])
async def test_non_json_and_nonfinite_values_are_rejected(value):
    session = SessionState(policy())
    with pytest.raises(ValueError, match="JSON"):
        gate_for(session, {**ARGS, "extra": value})
    gate = gate_for(session)
    assert not await gate.request(request(session, {**ARGS, "extra": value}))


@pytest.mark.parametrize("ttl", [0, -1, True, float("nan"), float("inf"), "10"])
def test_invalid_ttl_rejected(ttl):
    with pytest.raises(ValueError, match="ttl_seconds"):
        gate_for(SessionState(policy()), ttl_seconds=ttl)


@pytest.mark.parametrize("action", ["allow", "block", "missing"])
def test_grants_cannot_be_registered_for_tools_that_do_not_always_gate(action):
    p = policy()
    if action == "missing":
        p.tools.pop("send_money")
    else:
        p.tools["send_money"].action = action
    with pytest.raises(ValueError, match="always"):
        gate_for(SessionState(p))


def test_duplicate_and_canonical_alias_grants_rejected():
    session = SessionState(policy())
    with pytest.raises(ValueError, match="duplicate"):
        ExactApprovalGate(
            session,
            [
                ToolCall("send_money", ARGS),
                ToolCall("send_money", {**ARGS, "to": "colleague@ｅxample.com"}),
            ],
        )


@pytest.mark.parametrize("state", ["tainted", "started", "shadow"])
def test_registration_requires_fresh_enforcing_session(state):
    session = SessionState(policy())
    if state == "tainted":
        session.observe_result("read_email")
    elif state == "started":
        session.record("read_email", {})
    else:
        session.policy.enforce = False
    with pytest.raises(ValueError):
        gate_for(session)


@pytest.mark.parametrize("blocker", ["constraint", "budget", "sequence", "flow"])
async def test_grant_cannot_override_hard_blocks(live, blocker):
    args = ARGS
    if blocker == "constraint":
        args = {**ARGS, "amount": 101}
    elif blocker == "budget":
        live.session.policy.tools["send_money"].limits.per_session = 1
    elif blocker == "sequence":
        from tripwire.policy.schema import SequenceRule

        live.session.policy.sequences = [
            SequenceRule(deny="send_money", within_turns_after="read_email", turns=3)
        ]
    else:
        live.session.policy.flows[0].action = "block"
    live.gate = gate_for(live.session, args)
    if blocker == "budget":
        live.session.record("send_money", ARGS)
    await live.handle("read_email", {})
    assert (await live.handle("send_money", args)).isError
    assert live.upstream.calls == [("read_email", {})]


async def test_default_no_gate_still_denies(live):
    live.gate = None
    assert (await live.handle("send_money", ARGS)).isError
    assert live.upstream.calls == []


async def test_real_mcp_upstream_exact_action_after_taint(tmp_path):
    from tripwire.proxy.upstream import Upstream as MCPUpstream

    p = Policy.model_validate(
        {
            "version": 1,
            "sources": {"whoami": "untrusted"},
            "tools": {"whoami": {"action": "allow"}, "add": {"action": "require_approval"}},
        }
    )
    session = SessionState(p)
    gate = ExactApprovalGate(session, [ToolCall("add", {"a": 2, "b": 3})])
    toy = Path(__file__).with_name("toy_server.py")
    upstream = MCPUpstream(f"{shlex.quote(sys.executable)} {shlex.quote(str(toy))}")
    audit = AuditLog(tmp_path / "mcp-audit.jsonl")
    with anyio.fail_after(30):
        try:
            await upstream.start()
            proxy = Interceptor(p, audit, upstream, session, gate=gate)
            assert not (await proxy.handle("whoami", {})).isError
            assert session.snapshot().tainted
            assert (await proxy.handle("add", {"a": 200, "b": 3})).isError
            result = await proxy.handle("add", {"a": 2, "b": 3})
            assert not result.isError and result.content[0].text == "5"
            assert (await proxy.handle("add", {"a": 2, "b": 3})).isError
        finally:
            await upstream.aclose()
            gate.close()
            audit.close()
    assert verify_log(audit.path).ok
