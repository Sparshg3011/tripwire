"""The interceptor in isolation: fake canonicalizer, fake evaluator, fake upstream.

The real evaluator and canonicalizer aren't written yet, and the point of
injecting them is that this file doesn't care. What it pins down is the
plumbing: who gets called, in what order, and what the agent is handed back.
"""

import json

import anyio
import pytest
from mcp import types

from tripwire.policy.schema import Policy
from tripwire.policy.types import Verdict
from tripwire.proxy.interceptor import Interceptor
from tripwire.session import SessionState
from tripwire.tx import AuditLog

OK = types.CallToolResult(content=[types.TextContent(type="text", text="ok")])


# --- fakes ---


class FakeTaint:
    """Stands in for TaintTracker, which is still a stub."""

    def __init__(self, unreadable=False, breaks_on_result=False):
        self._unreadable = unreadable
        self._breaks_on_result = breaks_on_result
        self.tainted_by = ()
        self.observed = []

    @property
    def tainted(self):
        if self._unreadable:
            raise RuntimeError("taint store unreadable")
        return False

    def observe_result(self, tool, is_error=False):
        if self._breaks_on_result:
            raise RuntimeError("taint store went away")
        self.observed.append((tool, is_error))


class FakeUpstream:
    def __init__(self, boom=None):
        self.calls = []
        self.tools = []
        self.result = OK
        self._boom = boom

    async def call(self, name, args):
        self.calls.append((name, args))
        if self._boom is not None:
            raise self._boom
        return self.result


class SlowUpstream(FakeUpstream):
    """Yields control mid-call so overlapping calls can actually overlap."""

    def __init__(self, delay=0.01):
        super().__init__()
        self.delay = delay

    async def call(self, name, args):
        self.calls.append((name, args))
        await anyio.sleep(self.delay)
        return self.result


def passthrough(tool, args, policy):
    return dict(args)


# both injected hooks take three positionals, so one shape covers each
def returns(value):
    def hook(*_):
        return value

    return hook


def explodes(exc):
    def hook(*_):
        raise exc

    return hook


# --- fixtures ---


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


@pytest.fixture
def make(audit_path):
    def build(evaluate, canonicalize=passthrough, enforce=True, upstream=None, taint=None):
        policy = Policy(version=1, enforce=enforce)
        session = SessionState(policy, taint=taint if taint is not None else FakeTaint())
        return Interceptor(
            policy,
            AuditLog(audit_path),
            upstream if upstream is not None else FakeUpstream(),
            session,
            canonicalize=canonicalize,
            evaluate=evaluate,
        )

    return build


@pytest.fixture
def records(audit_path):
    def read():
        return [json.loads(line) for line in audit_path.read_text().splitlines()]

    return read


# --- allow ---


async def test_allow_forwards_and_returns_upstream_result_unchanged(make, records):
    itc = make(returns(Verdict("allow", "tools.add", "no rule objected")))
    result = await itc.handle("add", {"a": 1, "b": 2})

    assert itc.upstream.calls == [("add", {"a": 1, "b": 2})]
    assert result is itc.upstream.result
    assert [r["kind"] for r in records()] == ["decision", "tool_call", "tool_result"]


async def test_allowed_calls_advance_session_state(make):
    itc = make(returns(Verdict("allow", "tools.*", "fine")))
    await itc.handle("add", {"a": 1})
    await itc.handle("whoami", {})

    snap = itc.session.snapshot()
    assert snap.turn == 2
    assert snap.tool_counts == {"add": 1, "whoami": 1}


async def test_upstream_sees_canonicalized_args_not_the_originals(make, records):
    def strip_zero_width(tool, args, policy):
        return {k: v.replace("\u200b", "") for k, v in args.items()}

    itc = make(
        returns(Verdict("allow", "tools.send_email", "recipient is internal")),
        canonicalize=strip_zero_width,
    )
    await itc.handle("send_email", {"to": "boss@myc\u200bompany.com"})

    assert itc.upstream.calls == [("send_email", {"to": "boss@mycompany.com"})]
    assert records()[1]["data"]["args"] == {"to": "boss@mycompany.com"}


# --- block ---


async def test_block_never_reaches_upstream(make):
    itc = make(returns(Verdict("block", "tools.delete_file", "Destructive; disabled.")))
    result = await itc.handle("delete_file", {"path": "/etc/passwd"})

    assert itc.upstream.calls == []
    assert result.isError
    text = result.content[0].text
    assert "tripwire_blocked" in text
    assert "tools.delete_file" in text
    assert "Destructive; disabled." in text


async def test_block_does_not_burn_the_session_budget(make):
    # a refused call must leave nothing behind, or an attacker can spend
    # a per-session limit with calls that never ran
    itc = make(returns(Verdict("block", "tools.send_email.limits", "over budget")))
    for _ in range(3):
        await itc.handle("send_email", {"to": "a@b.com"})

    snap = itc.session.snapshot()
    assert snap.turn == 0
    assert snap.tool_counts == {}
    assert snap.history == ()


# --- gate ---


async def test_gate_refuses_while_no_gate_is_wired(make, records):
    itc = make(returns(Verdict("gate", "flows.0", "Untrusted content in context.")))
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == []
    assert result.isError
    text = result.content[0].text.lower()
    assert "no approval gate is configured" in text
    assert [r["kind"] for r in records()] == ["decision", "gate_unavailable"]


# --- fail closed ---


async def test_evaluator_raising_blocks_the_call(make):
    itc = make(explodes(RuntimeError("regex blew up")))
    result = await itc.handle("add", {"a": 1})

    assert itc.upstream.calls == []
    assert result.isError
    assert "evaluator_error" in result.content[0].text


async def test_evaluator_returning_a_non_verdict_blocks_the_call(make):
    itc = make(returns("yes"))
    result = await itc.handle("add", {"a": 1})

    assert itc.upstream.calls == []
    assert result.isError
    assert "evaluator_error" in result.content[0].text


async def test_canonicalizer_raising_blocks_the_call(make):
    itc = make(
        returns(Verdict("allow", "tools.add", "would have been fine")),
        canonicalize=explodes(ValueError("undecodable surrogate")),
    )
    result = await itc.handle("add", {"a": 1})

    assert itc.upstream.calls == []
    assert result.isError
    assert "canonicalizer_error" in result.content[0].text


async def test_unreadable_session_state_blocks_the_call(make, records):
    itc = make(
        returns(Verdict("allow", "tools.add", "would have been fine")),
        taint=FakeTaint(unreadable=True),
    )
    result = await itc.handle("add", {"a": 1})

    assert itc.upstream.calls == []
    assert result.isError
    assert "session_error" in result.content[0].text
    # blind on state means we have to assume the context is dirty
    assert records()[0]["data"]["tainted"] is True


# --- shadow mode ---


async def test_shadow_mode_logs_the_block_and_lets_the_call_through(make, records):
    itc = make(
        returns(Verdict("block", "tools.delete_file", "Destructive; disabled.", shadow=True)),
        enforce=False,
    )
    result = await itc.handle("delete_file", {"path": "/etc/passwd"})

    assert itc.upstream.calls == [("delete_file", {"path": "/etc/passwd"})]
    assert result is itc.upstream.result
    decision = records()[0]["data"]
    assert decision["decision"] == "block"
    assert decision["shadow"] is True


async def test_shadow_mode_lets_a_fail_closed_verdict_through_too(make, records):
    itc = make(explodes(RuntimeError("regex blew up")), enforce=False)
    result = await itc.handle("add", {"a": 1})

    assert itc.upstream.calls == [("add", {"a": 1})]
    assert result is itc.upstream.result
    decision = records()[0]["data"]
    assert decision["rule"] == "evaluator_error"
    assert decision["shadow"] is True


# --- upstream trouble ---


async def test_upstream_failure_is_reported_and_still_counts(make, records):
    itc = make(
        returns(Verdict("allow", "tools.add", "fine")),
        upstream=FakeUpstream(boom=RuntimeError("broken pipe")),
    )
    result = await itc.handle("add", {"a": 1})

    assert result.isError
    assert "broken pipe" in result.content[0].text
    assert [r["kind"] for r in records()] == ["decision", "tool_call", "tool_error"]

    # we don't know how far upstream got, so the call counts and the
    # result it never gave us is treated as untrusted
    snap = itc.session.snapshot()
    assert snap.turn == 1
    assert snap.tool_counts == {"add": 1}
    assert itc.session.taint.observed == [("add", True)]


# --- lost bookkeeping ---


async def test_bookkeeping_failure_is_not_reported_to_the_agent(make, records):
    # the side effect already happened; handing back an error would just
    # invite a retry and a second one
    itc = make(
        returns(Verdict("allow", "tools.add", "fine")), taint=FakeTaint(breaks_on_result=True)
    )
    result = await itc.handle("add", {"a": 1})

    assert result is itc.upstream.result
    assert not result.isError
    assert [r["kind"] for r in records()] == ["decision", "tool_call", "tool_result", "state_error"]


async def test_a_broken_session_fails_every_later_call_closed(make):
    itc = make(
        returns(Verdict("allow", "tools.add", "fine")), taint=FakeTaint(breaks_on_result=True)
    )
    await itc.handle("add", {"a": 1})
    result = await itc.handle("add", {"a": 2})

    assert itc.upstream.calls == [("add", {"a": 1})]
    assert result.isError
    assert "session_error" in result.content[0].text


# --- concurrency and cancellation ---


async def test_parallel_calls_do_not_share_a_stale_snapshot(make):
    # Two calls in flight at once must not both decide from turn 0. If
    # they do, any per-session limit can be walked straight through by
    # firing the calls together instead of one after another.
    seen = []

    def watch(call, snapshot, policy):
        seen.append(snapshot.turn)
        return Verdict("allow", "tools.*", "fine")

    itc = make(watch, upstream=SlowUpstream())
    async with anyio.create_task_group() as tg:
        for _ in range(4):
            tg.start_soon(itc.handle, "add", {})

    assert sorted(seen) == [0, 1, 2, 3]


async def test_cancelled_call_is_still_recorded(make, records):
    # Hanging up on tripwire doesn't hang up on the tool. Whatever the
    # tool did still happened, so it still counts and still gets logged.
    itc = make(returns(Verdict("allow", "tools.*", "fine")), upstream=SlowUpstream(delay=5))

    with anyio.move_on_after(0.05):
        await itc.handle("send_email", {"to": "a@b.com"})

    kinds = [r["kind"] for r in records()]
    assert kinds == ["decision", "tool_call", "tool_cancelled"]
    assert itc.session.snapshot().tool_counts == {"send_email": 1}


async def test_fail_closed_reasons_name_the_exception_type(make, records):
    itc = make(explodes(KeyError()))  # empty message on purpose
    result = await itc.handle("add", {})

    assert "KeyError" in result.content[0].text
    assert "KeyError" in records()[0]["data"]["reason"]


# --- gate flow ---


GATED = Verdict("gate", "flows.0", "Untrusted content in context.")


class FakeGate:
    """Answers every request the same way and keeps what it was asked."""

    def __init__(self, answer):
        self._answer = answer
        self.requests = []

    async def request(self, req):
        self.requests.append(req)
        if isinstance(self._answer, Exception):
            raise self._answer
        return self._answer


class StuckGate:
    """The human never came back to the terminal."""

    async def request(self, req):
        await anyio.sleep(3600)


class DirtyTaint(FakeTaint):
    """A session that already touched something untrusted."""

    tainted = True

    def __init__(self):
        super().__init__()
        self.tainted_by = ("fetch_url",)


# the make fixture can't take a gate, so gated interceptors are built by
# hand the same way it builds them
def gated(
    audit_path, gate, evaluate, canonicalize=passthrough, enforce=True, taint=None, timeout=120
):
    policy = Policy(version=1, enforce=enforce, defaults={"gate_timeout_seconds": timeout})
    session = SessionState(policy, taint=taint if taint is not None else FakeTaint())
    return Interceptor(
        policy,
        AuditLog(audit_path),
        FakeUpstream(),
        session,
        gate=gate,
        canonicalize=canonicalize,
        evaluate=evaluate,
    )


async def test_approval_forwards_and_audits_the_whole_exchange(audit_path, records):
    itc = gated(audit_path, FakeGate(True), returns(GATED))
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == [("send_email", {"to": "a@b.com"})]
    assert result is itc.upstream.result
    assert [r["kind"] for r in records()] == [
        "decision",
        "gate_requested",
        "gate_approved",
        "tool_call",
        "tool_result",
    ]


async def test_denial_refuses_without_touching_upstream(audit_path, records):
    itc = gated(audit_path, FakeGate(False), returns(GATED))
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == []
    assert result.isError
    assert "denied" in result.content[0].text
    assert [r["kind"] for r in records()] == ["decision", "gate_requested", "gate_denied"]


async def test_gate_timeout_refuses_and_says_nobody_answered(audit_path, records):
    itc = gated(audit_path, StuckGate(), returns(GATED), timeout=1)
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == []
    assert result.isError
    assert "No human answered within 1s" in result.content[0].text
    assert [r["kind"] for r in records()] == ["decision", "gate_requested", "gate_timeout"]


async def test_gate_crash_is_audited_and_fails_closed(audit_path, records):
    itc = gated(audit_path, FakeGate(RuntimeError("terminal went away")), returns(GATED))
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == []
    assert result.isError
    assert "approval gate failed" in result.content[0].text
    assert [r["kind"] for r in records()] == ["decision", "gate_requested", "gate_error"]


async def test_a_truthy_answer_that_is_not_true_is_refused(audit_path, records):
    # only True is a yes. A gate returning "yes" is a broken gate, not a
    # human saying no, and the log shouldn't claim someone reviewed this
    itc = gated(audit_path, FakeGate("yes"), returns(GATED))
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == []
    assert result.isError
    assert [r["kind"] for r in records()] == ["decision", "gate_requested", "gate_error"]


async def test_shadow_mode_never_consults_the_gate(audit_path, records):
    class NeverGate:
        async def request(self, req):
            raise AssertionError("gate consulted in shadow mode")

    itc = gated(
        audit_path,
        NeverGate(),
        returns(Verdict("gate", "flows.0", "would have gated", shadow=True)),
        enforce=False,
    )
    result = await itc.handle("send_email", {"to": "a@b.com"})

    assert itc.upstream.calls == [("send_email", {"to": "a@b.com"})]
    assert result is itc.upstream.result
    assert [r["kind"] for r in records()] == ["decision", "tool_call", "tool_result"]


async def test_approved_gated_call_advances_session_state(audit_path):
    itc = gated(audit_path, FakeGate(True), returns(GATED))
    await itc.handle("send_email", {"to": "a@b.com"})

    snap = itc.session.snapshot()
    assert snap.turn == 1
    assert snap.tool_counts == {"send_email": 1}


async def test_denied_gated_call_leaves_no_trace_in_the_session(audit_path):
    itc = gated(audit_path, FakeGate(False), returns(GATED))
    await itc.handle("send_email", {"to": "a@b.com"})

    snap = itc.session.snapshot()
    assert snap.turn == 0
    assert snap.tool_counts == {}
    assert snap.history == ()


async def test_the_gate_is_asked_with_canonicalized_args_and_session_context(audit_path):
    def strip_zero_width(tool, args, policy):
        return {k: v.replace("\u200b", "") for k, v in args.items()}

    gate = FakeGate(True)
    itc = gated(audit_path, gate, returns(GATED), canonicalize=strip_zero_width, taint=DirtyTaint())
    await itc.handle("send_email", {"to": "a@b\u200b.com"})
    await itc.handle("send_email", {"to": "c@d.com"})

    first, second = gate.requests
    assert first.tool == "send_email"
    assert first.args == {"to": "a@b.com"}  # the human judges what would actually run
    assert first.rule_id == "flows.0"
    assert first.reason == "Untrusted content in context."
    assert first.tainted is True
    assert first.tainted_by == ("fetch_url",)
    assert first.turn == 0
    assert second.turn == 1
