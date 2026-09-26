"""Opt-in, experimental model review for trusted Python embedding hosts.

Not human approval, not a deterministic authorization guarantee. The host must
classify tools and supply the task independently of agent-controlled content.
There is intentionally no MCP tool or CLI option that can enable this gate.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import asdict
from functools import partial
from typing import Any

import anyio
from mcp import types

from tripwire.gate.base import ApprovalRequest
from tripwire.gate.reviewer import (
    MAX_REVIEW_INPUT_CHARS,
    MAX_REVIEWS_PER_TASK,
    PROMPT_SHA256,
    ActionReviewer,
    ReviewResult,
)
from tripwire.policy.schema import Policy
from tripwire.session import SessionState
from tripwire.tx import AuditLog


class ReviewGate:
    """One bounded reviewer per fresh session, attached by Interceptor.

    ``complete`` is a synchronous, tool-free text completion callback. Configure
    provider timeouts and disable retries there; cancellation cannot stop an
    already running provider thread. A cancelled review permanently closes this
    gate, and a late answer can never authorize a tool call.

    ``read_only_tools`` is an explicit HOST assertion, not MCP annotations.
    Every allowed tool must be on it; every other non-blocked tool must always
    require approval. Reads that mark messages read or otherwise mutate state
    are NOT read-only. Unknown tools must be blocked. Review is still fallible.
    """

    def __init__(
        self,
        session: SessionState,
        *,
        task: str,
        reviewer_id: str,
        complete: Callable[[list[dict[str, str]]], str],
        read_only_tools: Sequence[str],
        max_reviews: int = MAX_REVIEWS_PER_TASK,
        max_input_chars: int = MAX_REVIEW_INPUT_CHARS,
    ) -> None:
        if not isinstance(task, str) or not task.strip():
            raise ValueError("review requires a nonempty task from the trusted host")
        if not isinstance(reviewer_id, str) or not reviewer_id.strip():
            raise ValueError("review requires a host-supplied model/configuration identifier")
        if session.snapshot().turn != 0 or session.snapshot().tainted:
            raise ValueError("review requires a fresh session")
        policy = session.policy
        if not policy.enforce or policy.defaults.unknown_tools != "block":
            raise ValueError("review requires enforcement and unknown_tools: block")
        if isinstance(read_only_tools, (str, bytes)):
            raise TypeError("read_only_tools must be a sequence of tool names")
        reads = set(read_only_tools)
        if not reads <= policy.tools.keys():
            raise ValueError("read-only declarations must have explicit policy rules")
        for name, rule in policy.tools.items():
            if rule.action == "allow" and name not in reads:
                raise ValueError(f"{name} must always require approval or be declared read-only")
            if policy.source_class(name) != "untrusted":
                raise ValueError("experimental review requires all tool sources untrusted")
        self._session = session
        self._policy_json = policy.model_dump_json()
        self._task = task
        self._reviewer_id = reviewer_id
        self._reviewer = ActionReviewer(
            complete, max_reviews=max_reviews, max_input_chars=max_input_chars
        )
        self._observations: list[dict[str, Any]] = []
        self._evidence_chars = 0
        self._observed_turn = 0
        self._closed: str | None = None
        self._audit: AuditLog | None = None
        self._lock = anyio.Lock()

    def bind(self, session: SessionState, policy: Policy, audit: AuditLog) -> None:
        """Host-only hook; one interceptor owns this gate and its evidence."""
        if self._audit is not None:
            raise ValueError("a reviewer gate cannot be shared between interceptors")
        self.check_context(session, policy)
        self._audit = audit
        audit.append(
            "review_config",
            {
                "experimental": True,
                "reviewer_id": self._reviewer_id,
                "prompt_sha256": PROMPT_SHA256,
                "max_reviews": self._reviewer.max_reviews,
                "max_input_chars": self._reviewer.max_input_chars,
            },
        )

    def check_context(self, session: SessionState, policy: Policy) -> None:
        if (
            self._closed == "context_changed"
            or session is not self._session
            or policy is not session.policy
            or policy.model_dump_json() != self._policy_json
            or session.snapshot().turn != self._observed_turn
        ):
            self.close("context_changed")
            raise ValueError("review session, policy, or observation history changed")

    def close(self, reason: str = "closed") -> None:
        self._closed = self._closed or reason

    def observe(self, tool: str, args: dict, result: types.CallToolResult) -> None:
        """Capture actual complete MCP results, including structured content/errors.

        Oversized evidence closes the gate rather than silently dropping history.
        """
        self._observed_turn = self._session.turn
        if self._closed:
            return
        try:
            observation = {"tool": tool, "args": args, "result": result.model_dump(mode="json")}
            encoded = json.dumps(observation, ensure_ascii=True, allow_nan=False)
            self._evidence_chars += len(encoded)
            if self._evidence_chars > self._reviewer.max_input_chars:
                self.close("input_limit")
                self._observations.clear()
                return
            self._observations.append(json.loads(encoded))
        except (TypeError, ValueError, RecursionError):
            self.close("invalid_observation")

    async def request(self, req: ApprovalRequest) -> bool:
        if self._audit is None:
            return False
        async with self._lock:
            try:
                self.check_context(self._session, self._session.policy)
            except ValueError:
                pass  # check_context permanently closes the gate
            if req.approval_scope != self._session.approval_scope:
                result = ReviewResult(False, "wrong_session", "Request belongs to another session.")
            elif self._closed:
                result = ReviewResult(False, self._closed, "Review gate is closed.")
            else:
                try:
                    result = await anyio.to_thread.run_sync(
                        partial(
                            self._reviewer.review,
                            task=self._task,
                            tool=req.tool,
                            args=req.args,
                            observations=self._observations,
                        ),
                        abandon_on_cancel=True,
                    )
                except BaseException:
                    self.close("cancelled")
                    self._audit.append(
                        "action_review",
                        {"tool": req.tool, "approved": False, "status": "cancelled"},
                    )
                    raise
                # A late answer must not authorize after host closure or mutation.
                try:
                    self.check_context(self._session, self._session.policy)
                except ValueError:
                    pass
                if self._closed:
                    result = ReviewResult(False, self._closed, "Review context is no longer valid.")
            self._audit.append("action_review", {"tool": req.tool, **asdict(result)})
            return result.approved is True
