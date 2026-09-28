"""What an approval gate is: one yes/no question, asked with context.

A gate cannot override a policy block. Policy already decided this call
needs approval; a gate obtains that approval interactively or matches a
host-issued, exact pre-authorization. Everything else — timeouts, gate crashes,
no gate configured — is handled by the interceptor, and every one of
those paths ends in a refusal. Silence is a no.
"""

from __future__ import annotations

import json
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from tripwire.policy.types import AnchorReport, explain_leaf

NAME_PREVIEW = 60  # a real argument name is a word or two; past this it's padding
# a call's anchoring lines; one failed, and a list of recipients can be long
ANCHOR_LINES = 4


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
    checked: frozenset[str] = frozenset()  # the args the policy reads (checked_fields())
    approval_scope: str = ""
    # what anchoring found, when a flow with `unless: anchored` applied
    anchors: AnchorReport | None = None


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
    encoded = [(json.dumps(name), _encode(value)) for name, value in args.items()]
    return sorted(encoded, key=lambda pair: (len(pair[0]) + len(pair[1]), pair))


def _encode(value: Any) -> str:
    """JSON with every object's members shortest first, like the arguments
    themselves: a message={to, body} gets clipped as one value, and sorted
    keys would put its body ahead of its recipient. Lists keep their order,
    because order is part of what a list says."""
    if isinstance(value, Mapping):
        members = [f"{json.dumps(str(key))}: {_encode(item)}" for key, item in value.items()]
        return "{" + ", ".join(sorted(members, key=lambda m: (len(m), m))) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_encode(item) for item in value) + "]"
    return json.dumps(value, default=str)


def clip(value: str, limit: int) -> str:
    """At most `limit` characters of an encoded value, then how many
    more there were. No encoded value contains a literal ellipsis, so
    the marker can't be forged by the value it follows."""
    if len(value) <= limit:
        return value
    return f"{value[:limit]}…[+{len(value) - limit} chars]"


def preview_arg(name: str, value: str, limit: int) -> str:
    """One encoded argument as a prompt shows it, name clipped as well as
    value: the caller writes the names too."""
    return f"{clip(name, NAME_PREVIEW)}: {clip(value, limit)}"


def preview_args(
    args: Mapping[str, Any], checked: Collection[str], limit: int, width: int, budget: int
) -> tuple[list[str], list[tuple[str, str]], list[tuple[str, str]]]:
    """The lines a prompt shows, the encoded arguments on them, and the
    encoded arguments it leaves out.

    The caller picks how many arguments a call has and what they're
    called, and plenty of upstreams ignore the ones they don't know. So a
    few hundred junk arguments, each under the value clip, would bury the
    ones that matter. The arguments the policy checks are shown first,
    one to a line, and always: the tool's rule reads them, and their
    names come from the policy. The rest follow shortest first while the
    preview, read as one list, stays within `budget` characters, and
    share lines up to `width`. Capping the lines instead would let a
    dozen one-letter arguments push out every argument of a tool with no
    constraints, like the code of an execute_code a flow rule stopped.
    The first that doesn't fit is left out along with everything after
    it, so a flood costs the prompt one line saying how much it left out.
    """
    shown = encode_args({k: v for k, v in args.items() if k in checked})
    lines = [preview_arg(name, value, limit) for name, value in shown]
    used = len(", ".join(lines))
    rest: list[str] = []
    hidden: list[tuple[str, str]] = []
    for name, value in encode_args({k: v for k, v in args.items() if k not in checked}):
        arg = preview_arg(name, value, limit)
        size = used + len(", ") + len(arg) if shown else len(arg)
        if hidden or size > budget:
            hidden.append((name, value))
            continue
        shown.append((name, value))
        used = size
        if rest and len(f"{rest[-1]}, {arg}") <= width:
            rest[-1] += f", {arg}"
        else:
            rest.append(arg)
    return lines + rest, shown, hidden


def anchor_lines(report: AnchorReport | None) -> list[str]:
    """Where each value anchoring checked came from, the one that failed
    first: at most ANCHOR_LINES of them, then how many more there were.
    Unescaped, since a value's path holds dict keys the caller wrote."""
    if report is None:
        return []
    leaves = sorted(report.leaves, key=lambda leaf: leaf.status == "anchored")
    lines = [explain_leaf(leaf.record()) for leaf in leaves[:ANCHOR_LINES]]
    if len(leaves) > ANCHOR_LINES:
        lines.append(f"{len(leaves) - ANCHOR_LINES} more values checked")
    return lines


def more_args(hidden: list[tuple[str, str]]) -> str:
    """Exactly what a preview left out, in encoded characters."""
    chars = sum(len(name) + len(value) for name, value in hidden)
    noun = "argument" if len(hidden) == 1 else "arguments"
    return f"{len(hidden)} more {noun} ({chars} chars)"
