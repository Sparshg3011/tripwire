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
from dataclasses import replace
from typing import Any

from mcp import types

from tripwire.policy.canonical import canonicalize as real_canonicalize
from tripwire.policy.evaluator import evaluate as real_evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import SessionSnapshot, ToolCall, Verdict
from tripwire.proxy.upstream import Upstream
from tripwire.session import SessionState
from tripwire.tx import AuditLog, AuditWriteError

BLOCKED_CODE = "tripwire_blocked"

DECISIONS = ("allow", "block", "gate")


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
        canonicalize=real_canonicalize,
        evaluate=real_evaluate,
    ):
        self.policy = policy
        self.audit = audit
        self.upstream = upstream
        self.session = session
        self.canonicalize = canonicalize
        self.evaluate = evaluate

    async def handle(self, name: str, arguments: dict) -> types.CallToolResult:
        try:
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
                "decision": verdict.decision,
                "rule": verdict.rule_id,
                "reason": verdict.reason,
                "shadow": verdict.shadow,
                "tainted": snapshot.tainted,
                "turn": snapshot.turn,
            },
        )

        # shadow mode evaluates everything and stops nothing; that is the
        # entire point of it, including when the verdict is a block.
        if not verdict.shadow and verdict.decision != "allow":
            if verdict.decision == "gate":
                verdict = replace(
                    verdict,
                    reason=f"{verdict.reason} Approval gates aren't wired up yet, "
                    f"so this call is refused rather than guessed at.",
                )
                self.audit.append("gate_unavailable", {"tool": name, "rule": verdict.rule_id})
            return _refused(verdict.reason, verdict.rule_id)

        self.audit.append("tool_call", {"tool": name, "args": args})
        try:
            result = await self.upstream.call(name, args)
        except Exception as e:
            # Upstream died holding our request. We don't know how far it
            # got, so the call counts and whatever came back is untrusted.
            self.audit.append("tool_error", {"tool": name, "error": str(e)})
            self._remember(name, args, is_error=True)
            return types.CallToolResult(
                isError=True,
                content=[types.TextContent(type="text", text=f"upstream call failed: {e}")],
            )

        self.audit.append("tool_result", {"tool": name, "is_error": bool(result.isError)})
        self._remember(name, args, is_error=bool(result.isError))
        return result

    def _remember(self, name: str, args: Mapping[str, Any], is_error: bool) -> None:
        """Book-keeping for a call that has already happened.

        If this fails we do NOT turn it into an error for the agent. The
        side effect is already out there; reporting failure would invite
        a retry and a second one. Instead the session is marked broken,
        which makes every later call fail closed — contained, not hidden.
        """
        try:
            self.session.record(name, args)
            self.session.observe_result(name, is_error=is_error)
        except Exception as e:
            self.session.broken = f"lost track of the session after {name}: {e}"
            self.audit.append("state_error", {"tool": name, "error": str(e)})

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
                self._fail_closed("session_error", f"session state unreadable: {e}"),
                original,
                blind,
            )

        try:
            args = self.canonicalize(name, original, self.policy)
        except Exception as e:
            return (
                self._fail_closed("canonicalizer_error", f"could not read arguments: {e}"),
                original,
                snapshot,
            )

        try:
            verdict = self.evaluate(ToolCall(name, args), snapshot, self.policy)
        except Exception as e:
            return (
                self._fail_closed("evaluator_error", f"policy evaluation failed: {e}"),
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
