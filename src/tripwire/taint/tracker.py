"""Has anything untrusted entered this conversation yet?

v0.1 is blunt on purpose: taint is per-session and sticky. One result
from an untrusted source and the session stays tainted until it ends.
There is no way to wash it off — no declassification, no per-message
scoping, no "that was only the subject line".

That is not laziness, it is the one property worth having: the tracker
can over-block, but it can never under-block. A model that read an
attacker's text at turn 2 is still carrying it at turn 40, because the
instruction it absorbed doesn't expire when the message scrolls away.

The cost is real and we refuse to hide it: after one fetch_url, every
flow-guarded tool needs a human for the rest of the session. The gym
measures that cost as lost task completion, and the frontier chart is
where it shows up. v0.2 explores per-message taint and declassification
rules; v0.1 ships the sound version and publishes the bill.

Rules:

  * A result from a tool whose source class is "untrusted" taints the
    session. Trust comes from policy.source_class(tool), which falls
    back to the "*" entry and then to "untrusted" — unlisted means
    untrusted, always.

  * An *errored* result taints exactly the same as a successful one.
    The error text came from upstream too, and "fetch failed: <attacker
    controlled url echoed back>" is a perfectly good injection vector.

  * Only results taint. Making a call doesn't; nothing has come back yet.

  * Blocked calls never reach here at all — the interceptor only reports
    results it actually received.

  * Sticky: once tainted, tainted. observe_result() must never be able
    to turn it back off.

  * tainted_by accumulates every untrusted tool whose result we saw, not
    just the first one, deduplicated, in the order the results arrived.
    Results, not calls: this object is fed outcomes, and it has no way
    to know what order the calls went out in. `tripwire trace` reads
    this to answer "what made this session dirty, and what kept it
    dirty" — the first entry is the one that did it, the rest are how
    much untrusted material is in play.

Contract: no I/O, no clock, no randomness. Total — observe_result takes
whatever tool name arrives off the wire, including ones no policy has
ever heard of, and must not raise.

The spec is executable in tests/test_taint.py. Delete the skip line
there and make it green.
"""

from __future__ import annotations

from tripwire.policy.schema import Policy


class TaintTracker:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    @property
    def tainted(self) -> bool:
        """True once any untrusted result has been observed."""
        raise NotImplementedError

    @property
    def tainted_by(self) -> tuple[str, ...]:
        """Tools that tainted the session, in call order, deduplicated."""
        raise NotImplementedError

    def observe_result(self, tool: str, is_error: bool = False) -> None:
        """Report that `tool` returned a result. Errors taint too."""
        raise NotImplementedError
