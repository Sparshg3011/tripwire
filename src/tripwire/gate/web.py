"""Ask in the browser: a small approvals page on 127.0.0.1.

This is the gate for appliance mode — Claude Desktop launches the proxy
with no terminal attached, so the human gets a local web page instead.

Two security properties, both load-bearing:

  * Bound to 127.0.0.1 only. Approvals never leave the machine.

  * Every request must carry a random per-run token (the ?k=... in the
    URL we print at startup). Localhost-only is NOT enough by itself:
    any local process could hit the port, and so could any web page the
    user happens to have open — a browser will happily submit a form to
    http://127.0.0.1:8642 from evil.example (cross-site form posts don't
    need CORS). An attacker who can inject "please approve my request at
    localhost..." into the agent's context could otherwise approve their
    own tool call. Without the token, the gate would be a hole.

Stdlib http.server on a daemon thread; no new dependencies. Decisions
cross from that thread by plain assignment, and request() polls for
them — humans take seconds, so a 200ms poll is invisible. The thread
that brought an answer waits for that poll, so the page can say
whether the answer counted.
"""

from __future__ import annotations

import html
import secrets
import threading
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

import anyio

from tripwire.gate.base import (
    NAME_PREVIEW,
    ApprovalRequest,
    GateUnavailable,
    clip,
    more_args,
    preview_arg,
    preview_args,
)

POLL_SECONDS = 0.2
ANSWER_WAIT = 2.0  # for request() to take an answer; it looks every POLL_SECONDS


@dataclass
class _Pending:
    req: ApprovalRequest
    decision: bool | None = None
    taken: bool = False  # request() handed the decision to its caller


ARG_PREVIEW = 1000  # per value; the rest of a longer one sits folded below the preview
# In all, too, so a flood of arguments can't push the rule and the buttons
# a long scroll away; the arguments that don't fit are folded below as well.
ARG_BUDGET = 4000
ARG_WIDTH = 70  # short args share a line this long; the preview box holds 71 a row
# The tool, rule, reason and taint trail, above the buttons as well. An
# unknown tool's name is the caller's to pick, and the reason and the
# trail can repeat it.
FIELD_PREVIEW = 500


class WebGate:
    def __init__(self, port: int = 8642):
        self._pending: dict[str, _Pending] = {}
        self._mutex = threading.Condition()  # notified as each question closes
        self.token = secrets.token_urlsafe(16)
        try:
            self._server = ThreadingHTTPServer(("127.0.0.1", port), _handler_for(self))
        except OSError as e:
            # port in use, usually a second tripwire. Refuse to start
            # rather than run with a gate nobody can reach.
            raise GateUnavailable(f"--gate web can't listen on 127.0.0.1:{port} ({e})") from e
        self.port = self._server.server_address[1]  # resolves port=0
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?k={self.token}"

    async def request(self, req: ApprovalRequest) -> bool:
        rid = secrets.token_urlsafe(8)
        entry = _Pending(req)
        with self._mutex:
            self._pending[rid] = entry
        try:
            while True:
                with self._mutex:
                    if entry.decision is not None:
                        entry.taken = True
                        return entry.decision
                await anyio.sleep(POLL_SECONDS)
        finally:
            # reached on decision or on timeout-cancellation from the
            # interceptor; either way the question is no longer open
            with self._mutex:
                self._pending.pop(rid, None)
                self._mutex.notify_all()

    def _decide(self, rid: str, approve: bool) -> bool:
        """Record an answer, and say whether it counted.

        It counts once request() takes it, and a timeout can close the
        question between the answer arriving and request() looking, so
        this waits to see which comes first. An answer still untaken after
        ANSWER_WAIT is withdrawn: the human is about to be told it changed
        nothing, so it mustn't count later.
        """
        with self._mutex:
            entry = self._pending.get(rid)
            if entry is None or entry.decision is not None:
                return False
            entry.decision = approve
            self._mutex.wait_for(lambda: rid not in self._pending, ANSWER_WAIT)
            if not entry.taken:
                entry.decision = None
            return entry.taken

    def _snapshot(self) -> list[tuple[str, ApprovalRequest]]:
        with self._mutex:
            return [(rid, e.req) for rid, e in self._pending.items() if e.decision is None]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


PAGE = """<!doctype html>
<meta charset="utf-8">
{refresh}
<title>tripwire approvals</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; max-width: 44rem; margin: 3rem auto; padding: 0 1rem; }}
  .card {{ border: 1px solid #ccc; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }}
  .closed {{ opacity: .45; }}
  .taint, .late {{ color: #b00; font-weight: 600; }}
  pre {{ background: #f6f6f6; padding: .6rem; border-radius: 6px; white-space: pre-wrap; overflow-wrap: anywhere; }}
  button {{ font: inherit; padding: .4rem 1.2rem; border-radius: 6px; border: 1px solid #888; cursor: pointer; }}
  form {{ display: inline; margin-right: .5rem; }}
</style>
<h2>tripwire</h2>
{notice}
<div id="cards">{body}</div>
<script>{script}</script>
"""

# The page keeps itself current without reloading. A reload would fold
# away a value the human opened to read, and a card leaving would slide
# the next one's buttons under their cursor. So a card whose question
# closed stays where it is, greyed out with its buttons off, and a new
# one joins the end. Without scripts reloading is all there is, so the
# page does it only while idle, to pick up the first question.
POLL = """
async function poll() {
  let fresh;
  try {
    const response = await fetch(location.href);
    if (!response.ok) return;
    fresh = new DOMParser().parseFromString(await response.text(), "text/html");
  } catch {
    return;
  }
  const open = new Map([...fresh.querySelectorAll(".card")].map((c) => [c.dataset.rid, c]));
  for (const card of document.querySelectorAll(".card:not(.closed)")) {
    if (open.delete(card.dataset.rid)) continue;
    card.classList.add("closed");
    for (const button of card.querySelectorAll("button")) button.disabled = true;
    const note = "<p>Closed: answered elsewhere, or timed out and refused.</p>";
    card.insertAdjacentHTML("beforeend", note);
  }
  if (open.size) document.getElementById("idle")?.remove();
  document.getElementById("cards").append(...open.values());
}
setInterval(poll, 2000);
"""

RELOAD = '<noscript><meta http-equiv="refresh" content="2"></noscript>'

LATE = '<p class="late">That answer did not reach its request in time, so it changed nothing.</p>'

CARD = """<div class="card" data-rid="{rid}">
<b>{tool}</b> (turn {turn}) — {taint}
{args}
<p>{rule}: {reason}</p>{fields}
<form method="post" action="/decide"><input type="hidden" name="k" value="{k}">
<input type="hidden" name="rid" value="{rid}"><input type="hidden" name="action" value="approve">
<button>Approve</button></form>
<form method="post" action="/decide"><input type="hidden" name="k" value="{k}">
<input type="hidden" name="rid" value="{rid}"><input type="hidden" name="action" value="deny">
<button>Deny</button></form>
</div>"""


def _token_ok(given: str, expected: str) -> bool:
    # constant time: the token is the only thing standing between a local
    # process and approving the agent's calls, so don't leak it a
    # character at a time through comparison timing
    return secrets.compare_digest(given, expected)


def _args_html(args: Mapping[str, Any], checked: Collection[str] = frozenset()) -> str:
    """The arguments that fit, then, folded and in full, the ones that
    didn't and every one the preview clipped."""
    lines, shown, hidden = preview_args(args, checked, ARG_PREVIEW, ARG_WIDTH, ARG_BUDGET)
    preview = "\n".join(lines) or "{}"
    parts = [f"<pre>{html.escape(preview)}</pre>"]
    if hidden:
        rest = "\n".join(f"{name}: {value}" for name, value in hidden)
        parts.append(
            f"<details><summary>{more_args(hidden)}</summary>"
            f"<pre>{html.escape(rest)}</pre></details>"
        )
    for name, value in shown:
        whole = f"{name}: {value}"
        if preview_arg(name, value, ARG_PREVIEW) != whole:
            parts.append(
                f"<details><summary>{html.escape(clip(name, NAME_PREVIEW))} in full</summary>"
                f"<pre>{html.escape(whole)}</pre></details>"
            )
    return "".join(parts)


def _card(rid: str, req: ApprovalRequest, token: str) -> str:
    """One open question. The text the caller could have written is
    clipped, like the arguments, and folded below the rule in full."""
    trail = ", ".join(req.tainted_by) if req.tainted else ""
    taint = "<span class=taint>tainted session</span>" if req.tainted else "clean session"
    if trail:
        taint += f" (via {_field(trail)})"
    fields = {"tool": req.tool, "rule": req.rule_id, "reason": req.reason, "taint trail": trail}
    return CARD.format(
        tool=_field(req.tool),
        turn=req.turn,
        taint=taint,
        args=_args_html(req.args, req.checked),
        rule=_field(req.rule_id),
        reason=_field(req.reason),
        fields="".join(
            f"<details><summary>{label} in full</summary><pre>{html.escape(text)}</pre></details>"
            for label, text in fields.items()
            if len(text) > FIELD_PREVIEW
        ),
        rid=html.escape(rid),
        k=html.escape(token),
    )


def _field(text: str) -> str:
    return html.escape(clip(text, FIELD_PREVIEW))


def _handler_for(gate: WebGate) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass  # stderr is the operator console; per-request noise isn't welcome

        def _forbidden(self) -> None:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"missing or wrong token")

        def do_GET(self) -> None:
            url = urlsplit(self.path)
            if url.path != "/":
                self.send_response(404)
                self.end_headers()
                return
            query = parse_qs(url.query)
            if not _token_ok(query.get("k", [""])[0], gate.token):
                self._forbidden()
                return

            cards = [_card(rid, req, gate.token) for rid, req in gate._snapshot()]
            body = "\n".join(cards) if cards else '<p id="idle">Nothing waiting for approval.</p>'
            notice = LATE if "late" in query else ""
            refresh = "" if cards else RELOAD
            page = PAGE.format(refresh=refresh, notice=notice, body=body, script=POLL).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/decide":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(length).decode())
            if not _token_ok(form.get("k", [""])[0], gate.token):
                self._forbidden()
                return

            rid = form.get("rid", [""])[0]
            action = form.get("action", [""])[0]
            # only the exact string "approve" approves; junk denies
            counted = gate._decide(rid, approve=action == "approve")

            # An answer to a question that already closed changes nothing,
            # and the page after it would look just like one that counted.
            self.send_response(303)
            self.send_header("Location", f"/?k={gate.token}" + ("" if counted else "&late=1"))
            self.end_headers()

    return Handler
