"""Exact, one-use approvals issued by a trusted embedding application.

This does not infer user intent and is not an injection detector. The host
must obtain approval for the FULL canonical call before the session starts.
No method is exposed over MCP to mint, extend, or replenish these grants.

Tools covered by grants must ALWAYS require approval, not only after taint.
Otherwise a call executed before taint would not consume its grant, allowing
an attacker to execute the same approved action a second time afterwards.
"""

from __future__ import annotations

import json
import math
import threading
import time
from collections.abc import Mapping, Sequence
from typing import Any

from tripwire.gate.base import ApprovalRequest
from tripwire.policy.canonical import canonicalize
from tripwire.policy.types import ToolCall
from tripwire.session import SessionBroken, SessionState


def _json_value(value: Any) -> None:
    """Reject coercions that could conflate distinct authorizations."""
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list:
        for item in value:
            _json_value(item)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for item in value.values():
            _json_value(item)
        return
    raise ValueError("exact approvals require finite JSON values and string object keys")


def _key(tool: str, args: Mapping[str, Any]) -> str:
    if type(tool) is not str or not tool:
        raise ValueError("an exact approval requires a nonempty tool name")
    value = dict(args)
    _json_value(value)
    return json.dumps([tool, value], sort_keys=True, separators=(",", ":"), allow_nan=False)


class ExactApprovalGate:
    """Approve each exact call once, in one live session, before expiry.

    Library-only and opt-in. ``calls`` must come from a trusted control
    surface, not an agent plan, retrieved document, or benchmark solution.
    Arguments are canonicalized with the session policy when registered;
    approval therefore authorizes the canonical values the upstream receives.

    A failed or cancelled forwarding attempt still consumes its grant. Grants
    are not durable across process restarts; constructing a new gate is a NEW
    authorization and must not be done automatically as a retry mechanism.
    """

    def __init__(
        self,
        session: SessionState,
        calls: Sequence[ToolCall],
        *,
        ttl_seconds: float = 300,
    ) -> None:
        if (
            type(ttl_seconds) not in (int, float)
            or not math.isfinite(ttl_seconds)
            or ttl_seconds <= 0
        ):
            raise ValueError("ttl_seconds must be finite and positive")
        snapshot = session.snapshot()
        if snapshot.turn != 0 or snapshot.tainted:
            raise ValueError("exact approvals must be registered before the session starts")
        if not session.policy.enforce:
            raise ValueError("exact approvals require an enforcing policy")
        self._session = session
        self._scope = session.approval_scope
        self._policy_json = session.policy.model_dump_json()
        self._remaining: set[str] = set()
        self._approved_counts: dict[str, int] = {}
        for call in calls:
            rule = session.policy.tools.get(call.tool)
            if rule is None or rule.action != "require_approval":
                raise ValueError(f"{call.tool} must always have action: require_approval")
            # Validate before canonicalization, which intentionally tolerates
            # non-JSON inputs in other uses of the policy engine.
            _key(call.tool, call.args)
            key = _key(call.tool, canonicalize(call.tool, call.args, session.policy))
            if key in self._remaining:
                raise ValueError("duplicate exact approval (including canonical aliases)")
            self._remaining.add(key)
        self._expires = time.monotonic() + ttl_seconds
        # Some platform monotonic clocks pause during system suspend. Either
        # deadline can expire the grant; a wall-clock rollback cannot extend
        # the monotonic lifetime, and sleeping cannot preserve a stale grant.
        self._expires_wall = time.time() + ttl_seconds
        self._lock = threading.Lock()
        self._closed = False

    async def request(self, req: ApprovalRequest) -> bool:
        with self._lock:
            if (
                self._closed
                or time.monotonic() >= self._expires
                or time.time() >= self._expires_wall
            ):
                self._closed = True
                return False
            if req.approval_scope != self._scope:
                return False
            try:
                snapshot = self._session.snapshot()
                if self._session.policy.model_dump_json() != self._policy_json:
                    self._closed = True
                    return False
                # Detect an execution that bypassed this gate, including a
                # host that temporarily changed a rule to allow then restored
                # it. Unobserved executions must not leave spare approvals.
                if snapshot.tool_counts.get(req.tool, 0) > self._approved_counts.get(req.tool, 0):
                    self._closed = True
                    return False
                # Requests from Interceptor already carry the exact canonical
                # values it will forward. Never normalize only for comparison.
                key = _key(req.tool, req.args)
            except (TypeError, ValueError, RecursionError, SessionBroken):
                return False
            if key not in self._remaining:
                return False
            # Matching a large argument tree can take time. Expiry applies
            # when we issue approval, not just when validation began.
            if time.monotonic() >= self._expires or time.time() >= self._expires_wall:
                self._closed = True
                return False
            self._remaining.remove(key)
            self._approved_counts[req.tool] = self._approved_counts.get(req.tool, 0) + 1
            return True

    def close(self) -> None:
        """Revoke every unused approval. Closing is permanent and idempotent."""
        with self._lock:
            self._closed = True
            self._remaining.clear()
