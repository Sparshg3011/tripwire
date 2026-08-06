"""What an approval gate is: one yes/no question, asked with context.

A gate never decides anything. Policy already decided this call needs a
human; the gate's whole job is to put the question in front of one and
report back what they said. Everything else — timeouts, gate crashes,
no gate configured — is handled by the interceptor, and every one of
those paths ends in a refusal. Silence is a no.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol


class GateUnavailable(Exception):
    """The configured gate can't run here (e.g. --gate cli with no
    terminal). Raised at startup, so serve refuses to start rather than
    running with a gate that can never answer."""


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    """Everything a human needs to make the call without digging.

    The taint fields matter most: "send_email, to=boss@corp.com" reads
    as harmless until you see the session touched fetch_url two turns
    ago. Context is the difference between an approval gate and a
    click-yes-to-continue box.
    """

    tool: str
    args: Mapping[str, Any] = field(default_factory=dict)
    rule_id: str = ""
    reason: str = ""
    tainted: bool = False
    tainted_by: tuple[str, ...] = ()
    turn: int = 0


class ApprovalGate(Protocol):
    async def request(self, req: ApprovalRequest) -> bool:
        """True means a human approved. Anything else means no."""
        ...
