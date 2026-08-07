"""One tool call in, one verdict, one outcome — and a record of both.

This is the only path from the agent to a tool. Everything it can do is
in handle(): get a verdict, write it down, then either refuse or forward.
There is no branch that reaches upstream without passing through the
evaluator first, and no branch that returns without an audit record.

The two jobs it does not do itself — canonicalizing args and deciding —
are injected so they can be faked in tests, but the defaults are the
real ones and the proxy never passes anything else.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any

import anyio
from mcp import types

from tripwire.gate import ApprovalGate, ApprovalRequest
from tripwire.policy.canonical import canonicalize as real_canonicalize
from tripwire.policy.evaluator import evaluate as real_evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall, Verdict
from tripwire.proxy.upstream import Upstream
from tripwire.session import SessionState
from tripwire.tx import AuditLog, AuditWriteError

BLOCKED_CODE = "tripwire_blocked"

DECISIONS = ("allow", "block", "gate")

_NO_ANSWER = object()  # distinct from any value a gate could return


def _describe(e: BaseException) -> str:
    """Exceptions with empty messages are common (KeyError(''), plenty of
    the builtins), and "policy evaluation failed: " tells a reader
    nothing. The type name is the part that always says something."""
    text = str(e)
    return f"{type(e).__name__}: {text}" if text else type(e).__name__


def _refused(reason: str, rule_id: str) -> types.CallToolResult:
    """What the agent gets instead of the tool.

    It's a normal tool error, not a protocol error, so the model reads it
    and can say "I wasn't allowed to do that" rather than falling over.
    The reason is written for that reader.
    """
    return types.CallToolResult(
        isError=True,
        content=[
            types.TextContent(type="text", text=f"{BLOCKED_CODE}: {reason} (rule: {rule_id})")
        ],
    )


class Interceptor:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        upstream: Upstream,
        session: SessionState,
        gate: ApprovalGate | None = None,
        canonicalize=real_canonicalize,
        evaluate=real_evaluate,
    ):
        self.policy = policy
        self.audit = audit
        self.upstream = upstream
        self.session = session
        self.gate = gate
        self.canonicalize = canonicalize
        self.evaluate = evaluate
        self._lock = anyio.Lock()

    async def handle(self, name: str, arguments: dict) -> types.CallToolResult:
        try:
            # One call at a time. Everything stateful — per-session
            # limits, sequence windows, taint — is decided from a
            # snapshot taken before the upstream round trip, so letting
            # two calls overlap would let both read the same state and
            # both pass a limit that only had room for one. Serialising
            # costs throughput inside a single session; a limit that two
            # parallel calls can walk through costs the whole feature.
            async with self._lock:
                return await self._handle(name, arguments)
        except AuditWriteError as e:
            # We can't write down what we're about to do, so we stop
            # doing things. This lives here rather than in the server
            # wrapper because every way of using tripwire — proxy or
            # library — comes through this method.
            print(f"tripwire: FATAL: {e}", file=sys.stderr, flush=True)
            os._exit(70)

    async def _handle(self, name: str, arguments: dict) -> types.CallToolResult:
        verdict, args, snapshot = self._decide(name, arguments)

        self.audit.append(
            "decision",
            {
                "tool": name,
                # the args go here, not just on the forward: a refused
                # call is exactly the one whose arguments you want to
                # read afterwards, and it never gets a tool_call record
                "args": args,
                "decision": verdict.decision,
                "rule": verdict.rule_id,
                "reason": verdict.reason,
                "shadow": verdict.shadow,
                "tainted": snapshot.tainted,
                "turn": snapshot.turn,
            },
        )

        # shadow mode evaluates everything and stops nothing — and that
        # includes not dragging a human out of their day for a gate that
        # wouldn't have gated
        if not verdict.shadow:
            if verdict.decision == "block":
                return _refused(verdict.reason, verdict.rule_id)
            if verdict.decision == "gate":
                approved, why = await self._ask_human(name, args, verdict, snapshot)
                if not approved:
                    return _refused(f"{verdict.reason} {why}", verdict.rule_id)

        self.audit.append("tool_call", {"tool": name, "args": args})
        try:
            result = await self.upstream.call(name, args)
        except Exception as e:
            # Upstream died holding our request. We don't know how far it
            # got, so the call counts and whatever came back is untrusted.
            self.audit.append("tool_error", {"tool": name, "error": _describe(e)})
            self._remember(name, args, is_error=True)
            return types.CallToolResult(
                isError=True,
                content=[
                    types.TextContent(type="text", text=f"upstream call failed: {_describe(e)}")
                ],
            )
        except BaseException:
            # Cancellation lands here — the agent hung up, or a timeout
            # fired, while the tool was already running. Cancelling us
            # doesn't cancel the side effect, so it still gets written
            # down and still counts. Then we let the cancellation finish
            # its job.
            self.audit.append("tool_cancelled", {"tool": name})
            self._remember(name, args, is_error=True)
            raise

        self.audit.append("tool_result", {"tool": name, "is_error": bool(result.isError)})
        self._remember(name, args, is_error=bool(result.isError))
        return result

    async def _ask_human(
        self, name: str, args: Mapping[str, Any], verdict: Verdict, snapshot: SessionSnapshot
    ) -> tuple[bool, str]:
        """One question, one answer, and only "yes" is a yes. A timeout,
        a crashed gate, or no gate at all air on the side the firewall
        always airs on.

        Note what holding the session lock through this means: while a
        human thinks, the session queues. That's not an accident — later
        calls must be judged against a world where this call either
        happened or didn't, and that isn't known until the human says.
        """
        if self.gate is None:
            self.audit.append("gate_unavailable", {"tool": name, "rule": verdict.rule_id})
            return False, (
                "A human needs to approve this call, but no approval gate is "
                "configured (start tripwire with --gate cli or --gate web)."
            )

        request = ApprovalRequest(
            tool=name,
            args=args,
            rule_id=verdict.rule_id,
            reason=verdict.reason,
            tainted=snapshot.tainted,
            tainted_by=self._taint_trail(),
            turn=snapshot.turn,
        )
        timeout = self.policy.defaults.gate_timeout_seconds
        self.audit.append(
            "gate_requested", {"tool": name, "rule": verdict.rule_id, "timeout": timeout}
        )

        # A gate that returns None is not the same event as a gate that
        # never returned, even though both refuse. Own sentinel, so the
        # log says which actually happened.
        answer: object = _NO_ANSWER
        try:
            with anyio.move_on_after(timeout):
                answer = await self.gate.request(request)
        except AuditWriteError:
            raise
        except Exception as e:
            self.audit.append("gate_error", {"tool": name, "error": _describe(e)})
            return False, f"The approval gate failed ({_describe(e)}), so the call is refused."

        if answer is True:
            self.audit.append("gate_approved", {"tool": name, "rule": verdict.rule_id})
            return True, ""
        if answer is _NO_ANSWER:
            self.audit.append("gate_timeout", {"tool": name, "seconds": timeout})
            return False, f"No human answered within {timeout}s."
        if answer is not False:
            # the gate answered, but not with a yes or a no
            self.audit.append("gate_error", {"tool": name, "error": f"gate returned {answer!r}"})
            return False, "The approval gate gave an unusable answer, so the call is refused."
        self.audit.append("gate_denied", {"tool": name, "rule": verdict.rule_id})
        return False, "A human reviewed this call and denied it."

    def _taint_trail(self) -> tuple[str, ...]:
        # display context for the human, not enforcement — if the tracker
        # can't say, the human just sees less history
        try:
            return tuple(self.session.taint.tainted_by)
        except Exception:
            return ()

    def _remember(self, name: str, args: Mapping[str, Any], is_error: bool) -> None:
        """Book-keeping for a call that has already happened.

        If this fails we do NOT turn it into an error for the agent. The
        side effect is already out there; reporting failure would invite
        a retry and a second one. Instead the session is marked broken,
        which makes every later call fail closed — contained, not hidden.
        """
        was_tainted = self._tainted_now()
        try:
            self.session.record(name, args)
            self.session.observe_result(name, is_error=is_error)
        except Exception as e:
            self.session.broken = f"lost track of the session after {name}: {_describe(e)}"
            self.audit.append("state_error", {"tool": name, "error": _describe(e)})
            return

        # The moment untrusted content entered is the first line of any
        # incident report, and it's only visible here — one turn later
        # every verdict just says "tainted: true" with no cause.
        if not was_tainted and self._tainted_now():
            self.audit.append("session_tainted", {"tool": name})

    def _tainted_now(self) -> bool:
        try:
            return bool(self.session.taint.tainted)
        except Exception:
            return False

    def _decide(
        self, name: str, arguments: dict
    ) -> tuple[Verdict, Mapping[str, Any], SessionSnapshot]:
        """Never raises. A policy engine that throws has still answered:
        the answer is no."""
        original = dict(arguments or {})

        try:
            snapshot = self.session.snapshot()
        except Exception as e:
            # We don't know how many times this has been called or
            # whether anything untrusted is in play. Assume the worst.
            blind = SessionSnapshot(tainted=True)
            return (
                self._fail_closed("session_error", f"session state unreadable: {_describe(e)}"),
                original,
                blind,
            )

        try:
            args = self.canonicalize(name, original, self.policy)
        except Exception as e:
            return (
                self._fail_closed(
                    "canonicalizer_error", f"could not read arguments: {_describe(e)}"
                ),
                original,
                snapshot,
            )

        try:
            verdict = self.evaluate(ToolCall(name, args), snapshot, self.policy)
        except Exception as e:
            return (
                self._fail_closed("evaluator_error", f"policy evaluation failed: {_describe(e)}"),
                args,
                snapshot,
            )

        if not isinstance(verdict, Verdict) or verdict.decision not in DECISIONS:
            return (
                self._fail_closed(
                    "evaluator_error", "policy evaluation returned something that isn't a verdict"
                ),
                args,
                snapshot,
            )

        return verdict, args, snapshot

    def _fail_closed(self, rule_id: str, reason: str) -> Verdict:
        # Shadow mode is a promise that nothing gets stopped, and a
        # promise with an exception in it isn't much of a promise.
        return Verdict(
            decision="block", rule_id=rule_id, reason=reason, shadow=not self.policy.enforce
        )
