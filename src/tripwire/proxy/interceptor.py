"""One tool call in, one verdict, one outcome — and a record of both.

This is the only path from the agent to a tool. Everything it can do is
in handle(): get a verdict, write it down, then either refuse or forward.
There is no branch that reaches upstream without passing through the
evaluator first, and no branch that returns without an audit record.

The two jobs it does not do itself — canonicalizing args and deciding —
are injected so they can be faked in tests, but the defaults are the
real ones and the proxy never passes anything else.

Everything the session learns comes through here too: the user's task
text (add_task()), the upstream's tool listing (observe_listing()), and
what each executed call showed the agent, its result or the text of its
failure, which _remember() hands the session before it counts the call.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any, NoReturn

import anyio
from mcp import types

from tripwire.gate import ApprovalGate, ApprovalRequest
from tripwire.policy.canonical import canonicalize as real_canonicalize
from tripwire.policy.canonical import checked_fields
from tripwire.policy.evaluator import evaluate as real_evaluate
from tripwire.policy.schema import Policy
from tripwire.policy.types import Canonicalizer, Evaluator, SessionSnapshot, ToolCall, Verdict
from tripwire.provenance import Observed
from tripwire.proxy.denial import denied
from tripwire.proxy.denial import refused as _refused
from tripwire.proxy.upstream import Upstream
from tripwire.session import SessionState, TaskRejected
from tripwire.tx import AuditLog, AuditWriteError
from tripwire.tx.executor import DuplicateInFlight, TxError, TxExecutor

DECISIONS = ("allow", "block", "gate")

_NO_ANSWER = object()  # distinct from any value a gate could return


def _describe(e: BaseException) -> str:
    """Exceptions with empty messages are common (KeyError(''), plenty of
    the builtins), and "policy evaluation failed: " tells a reader
    nothing. The type name is the part that always says something."""
    text = str(e)
    return f"{type(e).__name__}: {text}" if text else type(e).__name__


def _halt(error: AuditWriteError) -> NoReturn:
    # We can't write down what we're about to do, so we stop doing
    # things. This lives here rather than in the server wrapper because
    # every way of using tripwire — proxy or library — comes through
    # the interceptor.
    print(f"tripwire: FATAL: {error}", file=sys.stderr, flush=True)
    os._exit(70)


def _listing(tools: Sequence[types.Tool]) -> str:
    """The tool listing as the agent receives it, one JSON text: names,
    descriptions, schemas, annotations, everything an upstream wrote."""
    return json.dumps(
        [tool.model_dump(mode="json", by_alias=True, exclude_none=True) for tool in tools],
        sort_keys=True,
        ensure_ascii=False,
    )


class Interceptor:
    def __init__(
        self,
        policy: Policy,
        audit: AuditLog,
        upstream: Upstream,
        session: SessionState,
        gate: ApprovalGate | None = None,
        tx: TxExecutor | None = None,
        canonicalize: Canonicalizer = real_canonicalize,
        evaluate: Evaluator = real_evaluate,
    ):
        self.policy = policy
        self.audit = audit
        self.upstream = upstream
        self.session = session
        self.gate = gate
        self.tx = tx
        self.canonicalize = canonicalize
        self.evaluate = evaluate
        self._lock = anyio.Lock()

    async def handle(self, name: str, arguments: Mapping[str, Any]) -> types.CallToolResult:
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
            _halt(e)

    async def add_task(self, text: str, source: str) -> int:
        """Add a segment of the user's task text and return its number.
        What it names anchors in every later call of the session. The
        log gets its hash and size, never the text. Raises TaskRejected,
        after an intent_rejected record, for text that isn't UTF-8 or is
        over 64 KiB of it."""
        try:
            async with self._lock:
                try:
                    segment = self.session.add_task(text, source)
                except TaskRejected as e:
                    shown = source if isinstance(source, str) else None
                    self.audit.append("intent_rejected", {"source": shown, "reason": str(e)})
                    raise
                self.audit.append(
                    "task",
                    {
                        "segment": segment,
                        "source": source,
                        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                        "chars": len(text),
                    },
                )
                return segment
        except AuditWriteError as e:
            _halt(e)

    async def observe_listing(self, tools: Sequence[types.Tool]) -> None:
        """The upstream's tool listing, as the agent is shown it: every
        word of it is the upstream's, so it poisons what it names. It
        doesn't taint."""
        try:
            async with self._lock:
                self._observed(None, self.session.observe_listing(_listing(tools)))
        except AuditWriteError as e:
            _halt(e)

    async def _handle(self, name: str, arguments: Mapping[str, Any]) -> types.CallToolResult:
        verdict, args, snapshot = self._decide(name, arguments)

        decision: dict[str, Any] = {
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
        }
        if verdict.code is not None:
            decision["code"] = verdict.code
        if verdict.anchors is not None:
            decision["anchors"] = verdict.anchors.record()
        self.audit.append("decision", decision)

        # shadow mode evaluates everything and stops nothing — and that
        # includes not dragging a human out of their day for a gate that
        # wouldn't have gated
        if not verdict.shadow:
            if verdict.decision == "block":
                return denied(name, verdict, verdict.reason)
            if verdict.decision == "gate":
                approved, why = await self._ask_human(name, args, verdict, snapshot)
                if not approved:
                    return denied(name, verdict, f"{verdict.reason} {why}")
        # a self id comes only from a call the policy let run
        mint = not verdict.shadow or verdict.decision == "allow"

        # Observation mode must be a genuine transport control. Evaluate
        # canonical arguments so the audit still says what enforcement
        # would have decided, but forward the caller's exact values. Before
        # this split, shadow mode silently rewrote Unicode and host fields,
        # so it was a weak defence rather than a pass-through control.
        forward_args: Mapping[str, Any] = dict(arguments or {}) if verdict.shadow else args
        self.audit.append("tool_call", {"tool": name, "args": forward_args})
        try:
            result = await self._forward(name, forward_args, shadow=verdict.shadow)
        except DuplicateInFlight as e:
            # An identical call is on the ledger with no recorded outcome:
            # a previous attempt died between intent and completion, so
            # nobody knows whether the side effect happened. Guessing
            # "probably not" is how you send the same payment twice.
            self.audit.append("tx_duplicate", {"tool": name, "error": str(e)})
            return _refused(
                "An identical call is already recorded with no known outcome, so "
                "repeating it could repeat its effect. An operator needs to check "
                "the ledger.",
                "tx.duplicate_in_flight",
            )
        except TxError as e:
            # Same principle as the audit log, one layer down: if we can't
            # record the intent, we don't perform the act.
            self.audit.append("tx_error", {"tool": name, "error": _describe(e)})
            return _refused(f"The transaction ledger is unusable ({e}).", "tx.error")
        except Exception as e:
            # Upstream died holding our request. We don't know how far it
            # got, so the call counts, and the text we hand back came from
            # upstream: it taints, whatever the tool's class.
            self.audit.append("tool_error", {"tool": name, "error": _describe(e)})
            text = f"upstream call failed: {_describe(e)}"
            self._remember(name, args, text, mint=mint)
            return types.CallToolResult(
                isError=True, content=[types.TextContent(type="text", text=text)]
            )
        except BaseException:
            # Cancellation lands here — the agent hung up, or a timeout
            # fired, while the tool was already running. Cancelling us
            # doesn't cancel the side effect, so it still gets written
            # down and still counts. Then we let the cancellation finish
            # its job.
            self.audit.append("tool_cancelled", {"tool": name})
            self._remember(name, args, None, mint=mint)
            raise

        self.audit.append("tool_result", {"tool": name, "is_error": bool(result.isError)})
        # Keep the counterfactual state in canonical form in shadow mode,
        # while the upstream still received forward_args unchanged.
        self._remember(name, args, result, mint=mint)
        return result

    async def _forward(
        self, name: str, args: Mapping[str, Any], shadow: bool
    ) -> types.CallToolResult:
        """Through the ledger when there is one, straight through when not.

        Without a ledger an agent that retries a timed-out send_email
        sends it twice; with one, the second attempt gets the first
        attempt's answer and the tool is never touched again.

        Shadow mode goes straight through even with a ledger. A replayed
        answer, or a refusal over a call some earlier session left
        unresolved, isn't what the agent would get without tripwire, and
        that is all shadow mode may hand it. It writes nothing there
        either, so it never strands a call for an enforcing session.
        """
        if self.tx is None or shadow:
            return await self.upstream.call(name, dict(args))

        async def forward() -> types.CallToolResult:
            return await self.upstream.call(name, dict(args))

        result, replayed = await self.tx.run(name, dict(args), forward)
        if replayed:
            # the side effect didn't happen this time, and the log has to
            # say so or the trace shows two sends where there was one
            self.audit.append("tx_replayed", {"tool": name})
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
            checked=checked_fields(name, self.policy),
            approval_scope=self.session.approval_scope,
            anchors=verdict.anchors,
        )
        timeout = self.policy.defaults.gate_timeout_seconds
        self.audit.append(
            "gate_requested",
            {
                "tool": name,
                "rule": verdict.rule_id,
                "timeout": timeout,
                "gate_type": type(self.gate).__name__,
            },
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
        return False, "The approval gate denied this call."

    def _taint_trail(self) -> tuple[str, ...]:
        # display context for the human, not enforcement — if the tracker
        # can't say, the human just sees less history
        try:
            return tuple(self.session.taint.tainted_by)
        except Exception:
            return ()

    def _remember(
        self,
        name: str,
        args: Mapping[str, Any],
        outcome: types.CallToolResult | str | None,
        *,
        mint: bool,
    ) -> None:
        """Book-keeping for a call that has already happened: what it
        showed the agent (its result, the text of its failure, or nothing
        when it was cancelled), then the call itself.

        If this fails we do NOT turn it into an error for the agent. The
        side effect is already out there; reporting failure would invite
        a retry and a second one. Instead the session is marked broken,
        which makes every later call fail closed — contained, not hidden.
        """
        was_tainted = self._tainted_now()
        try:
            observed = self.session.observe_call(
                name, args, outcome, tainted=was_tainted, may_mint=mint
            )
            self.session.record(name, args)
            if isinstance(outcome, str):
                self.session.observe_failure(name)
            else:
                self.session.observe_result(name, is_error=outcome is None or bool(outcome.isError))
        except Exception as e:
            self.session.broken = f"lost track of the session after {name}: {_describe(e)}"
            self.audit.append("state_error", {"tool": name, "error": _describe(e)})
            return

        self._observed(name, observed)
        # The moment untrusted content entered is the first line of any
        # incident report, and it's only visible here — one turn later
        # every verdict just says "tainted: true" with no cause.
        if not was_tainted and self._tainted_now():
            self.audit.append("session_tainted", {"tool": name})

    def _observed(self, tool: str | None, observed: Observed | None) -> None:
        """One provenance_observed record per observation, for a policy
        that keeps provenance: typed keys by class, and whether the
        session is degraded. Never the keys."""
        if observed is None:
            return
        data: dict[str, Any] = {
            "tool": tool,
            "counts": dict(observed.counts),
            "degraded": self.session.provenance.degraded is not None,
        }
        if observed.degraded_by is not None:
            data["degraded_by"] = observed.degraded_by
        self.audit.append("provenance_observed", data)

    def _tainted_now(self) -> bool:
        try:
            return bool(self.session.taint.tainted)
        except Exception:
            return False

    def _decide(
        self, name: str, arguments: Mapping[str, Any]
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
