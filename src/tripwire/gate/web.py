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
them — humans take seconds, so a 200ms poll is invisible.
"""

from __future__ import annotations

import html
import json
import secrets
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import anyio

from tripwire.gate.base import ApprovalRequest

POLL_SECONDS = 0.2


@dataclass
class _Pending:
    req: ApprovalRequest
    decision: bool | None = None


class WebGate:
    def __init__(self, port: int = 8642):
        self._pending: dict[str, _Pending] = {}
        self._mutex = threading.Lock()
        self.token = secrets.token_urlsafe(16)
        self._server = ThreadingHTTPServer(("127.0.0.1", port), _handler_for(self))
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
            while entry.decision is None:
                await anyio.sleep(POLL_SECONDS)
            return entry.decision
        finally:
            # reached on decision or on timeout-cancellation from the
            # interceptor; either way the question is no longer open
            with self._mutex:
                self._pending.pop(rid, None)

    def _decide(self, rid: str, approve: bool) -> None:
        with self._mutex:
            entry = self._pending.get(rid)
            if entry is not None and entry.decision is None:
                entry.decision = approve

    def _snapshot(self) -> list[tuple[str, ApprovalRequest]]:
        with self._mutex:
            return [(rid, e.req) for rid, e in self._pending.items() if e.decision is None]

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


PAGE = """<!doctype html>
<meta charset="utf-8">
<meta http-equiv="refresh" content="2">
<title>tripwire approvals</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; max-width: 44rem; margin: 3rem auto; padding: 0 1rem; }}
  .card {{ border: 1px solid #ccc; border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; }}
  .taint {{ color: #b00; font-weight: 600; }}
  pre {{ background: #f6f6f6; padding: .6rem; border-radius: 6px; overflow-x: auto; }}
  button {{ font: inherit; padding: .4rem 1.2rem; border-radius: 6px; border: 1px solid #888; cursor: pointer; }}
  form {{ display: inline; margin-right: .5rem; }}
</style>
<h2>tripwire</h2>
{body}
"""

CARD = """<div class="card">
<b>{tool}</b> (turn {turn}) — {taint}
<pre>{args}</pre>
<p>{rule}: {reason}</p>
<form method="post" action="/decide"><input type="hidden" name="k" value="{k}">
<input type="hidden" name="rid" value="{rid}"><input type="hidden" name="action" value="approve">
<button>Approve</button></form>
<form method="post" action="/decide"><input type="hidden" name="k" value="{k}">
<input type="hidden" name="rid" value="{rid}"><input type="hidden" name="action" value="deny">
<button>Deny</button></form>
</div>"""


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
            if parse_qs(url.query).get("k", [""])[0] != gate.token:
                self._forbidden()
                return

            cards = []
            for rid, req in gate._snapshot():
                taint = (
                    "<span class=taint>tainted session</span>" if req.tainted else "clean session"
                )
                if req.tainted and req.tainted_by:
                    taint += f" (via {html.escape(', '.join(req.tainted_by))})"
                cards.append(
                    CARD.format(
                        tool=html.escape(req.tool),
                        turn=req.turn,
                        taint=taint,
                        args=html.escape(
                            json.dumps(dict(req.args), sort_keys=True, indent=2, default=str)
                        ),
                        rule=html.escape(req.rule_id),
                        reason=html.escape(req.reason),
                        rid=html.escape(rid),
                        k=html.escape(gate.token),
                    )
                )
            body = "\n".join(cards) if cards else "<p>Nothing waiting for approval.</p>"
            page = PAGE.format(body=body).encode()
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
            if form.get("k", [""])[0] != gate.token:
                self._forbidden()
                return

            rid = form.get("rid", [""])[0]
            action = form.get("action", [""])[0]
            # only the exact string "approve" approves; junk denies
            gate._decide(rid, approve=action == "approve")

            self.send_response(303)
            self.send_header("Location", f"/?k={gate.token}")
            self.end_headers()

    return Handler
