"""A stand-in for the person at the approval gate.

Gates are the one part of tripwire whose effectiveness depends on
somebody outside the software. That makes them awkward to benchmark:
you cannot put a real human in a hundred-run matrix, and a simulated
one is a model of a person, not a person.

So the gym refuses to pretend. Instead of one invented human it runs
the two extremes and reports both, which brackets the truth:

    approve   a maximally cooperative human who says yes to everything.
              Upper bound on utility, worst case for security — every
              gate is a formality.
    deny      a maximally cautious human who says no to everything.
              Lower bound on utility, best case for security.

A real operator lives somewhere between. Quoting one number as "the"
gated result would be picking a point on that line and hoping; quoting
the interval is honest, and the width of the interval is itself the
finding — it is exactly how much of tripwire's protection is being
delegated to a human's attention.

This drives the real web gate over real HTTP, so the code under test is
the same code a user gets, token check and all.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request

import anyio

POLL_SECONDS = 0.1

# the proxy announces the gate on stderr at startup
GATE_URL = re.compile(r"approvals at (http://127\.0\.0\.1:\d+/\?k=[\w\-]+)")

# each pending card carries its own request id in a hidden input
PENDING_RID = re.compile(r'name="rid" value="([\w\-]+)"')


def find_gate_url(stderr_text: str) -> str | None:
    match = GATE_URL.search(stderr_text)
    return match.group(1) if match else None


class Human:
    """Answers every approval the gate offers, one way, until stopped."""

    def __init__(self, url: str, answer: str = "approve"):
        if answer not in ("approve", "deny"):
            raise ValueError(f"answer must be approve or deny, not {answer!r}")
        self.url = url
        self.answer = answer
        self.answered = 0
        self.poll_failures = 0
        self.last_failure = ""
        parts = urllib.parse.urlsplit(url)
        self.token = urllib.parse.parse_qs(parts.query)["k"][0]
        self.origin = f"{parts.scheme}://{parts.netloc}"

    async def watch(self) -> None:
        """Poll until cancelled. The runner cancels this when the agent
        is done, so it never outlives the run it belongs to."""
        while True:
            try:
                await anyio.to_thread.run_sync(self._answer_pending)
            except Exception as e:  # noqa: BLE001
                # the proxy shutting down mid-poll is the normal way this
                # ends, so it's counted rather than raised — but counted,
                # because a run whose human silently stopped answering
                # would look like a run nobody asked
                self.poll_failures += 1
                self.last_failure = f"{type(e).__name__}: {e}"
            await anyio.sleep(POLL_SECONDS)

    def _answer_pending(self) -> None:
        page = urllib.request.urlopen(f"{self.origin}/?k={self.token}", timeout=5).read().decode()
        for rid in dict.fromkeys(PENDING_RID.findall(page)):
            body = urllib.parse.urlencode(
                {"k": self.token, "rid": rid, "action": self.answer}
            ).encode()
            urllib.request.urlopen(f"{self.origin}/decide", data=body, timeout=5).read()
            self.answered += 1
