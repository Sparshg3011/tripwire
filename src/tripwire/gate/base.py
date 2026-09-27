"""What an approval gate is: one yes/no question, asked with context.

A gate cannot override a policy block. Policy already decided this call
needs approval; a gate obtains that approval interactively or matches a
host-issued, exact pre-authorization. Everything else — timeouts, gate crashes,
no gate configured — is handled by the interceptor, and every one of
those paths ends in a refusal. Silence is a no.
"""

from __future__ import annotations

import json
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
    # Set by the host interceptor, never taken from tool arguments.
    approval_scope: str = ""


class ApprovalGate(Protocol):
    async def request(self, req: ApprovalRequest) -> bool:
        """True means approved by this gate. Anything else means no."""
        ...


def encode_args(args: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every argument as a JSON-encoded (name, value) pair, shortest first.

    Clipping the arguments as one sorted blob puts `body` ahead of `to`
    and then cuts, so a long enough body pushes the recipient out of the
    prompt and the human approves a send whose address they never saw.
    Shortest first keeps the scalars a decision turns on — recipients,
    amounts, paths — together at the top, and gates clip each value on
    its own, never at another's expense.

    JSON because quotes show where a name or value ends, and ensure_ascii
    turns every control character, bidi override and lookalike letter
    into a visible escape instead of letting it act on the screen.
    """
    encoded = [
        (json.dumps(name), json.dumps(value, sort_keys=True, default=str))
        for name, value in args.items()
    ]
    return sorted(encoded, key=lambda pair: (len(pair[0]) + len(pair[1]), pair))


def clip(value: str, limit: int) -> str:
    """At most `limit` characters of an encoded value, then how many
    more there were. No encoded value contains a literal ellipsis, so
    the marker can't be forged by the value it follows."""
    if len(value) <= limit:
        return value
    return f"{value[:limit]}…[+{len(value) - limit} chars]"
