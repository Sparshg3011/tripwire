"""Server side of the proxy: what the agent connects to.

Tools are re-advertised from upstream unchanged, so the agent sees the
same toolbox it would have seen directly. Every call it makes goes
through the interceptor instead of the tool.
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tripwire.gate import ApprovalGate, CliGate, WebGate
from tripwire.policy import load_policy
from tripwire.proxy.interceptor import Interceptor
from tripwire.proxy.upstream import Upstream
from tripwire.session import SessionState
from tripwire.tx import AuditLog
from tripwire.tx.executor import TxExecutor


def build_server(interceptor: Interceptor) -> Server:
    server = Server("tripwire")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return interceptor.upstream.tools

    # validate_input=False: the upstream validates its own inputs, and a
    # firewall shouldn't quietly change what gets through on its own
    # judgement. Saying no is the policy engine's job.
    # the interceptor halts the process itself if the audit log fails, so
    # there is nothing to catch here
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        return await interceptor.handle(name, arguments)

    return server


async def serve(
    policy_path: str | Path,
    upstream_cmd: str,
    audit_path: str | Path,
    gate_mode: str = "none",
    gate_port: int = 8642,
    tx_db: str | Path | None = None,
) -> None:
    # Everything here raises on problems, and that's the point: bad
    # policy / dead upstream / unwritable log / unreachable gate =
    # refuse to start.
    policy = load_policy(policy_path)
    # 64 bits, not 32: sessions from one log get traced by id, and two
    # runs colliding would splice two unrelated incidents into one
    # convincing-looking causal chain
    session_id = secrets.token_hex(8)
    audit = AuditLog(audit_path, session_id=session_id)

    gate: ApprovalGate | None = None
    if gate_mode == "cli":
        gate = CliGate()
    elif gate_mode == "web":
        gate = WebGate(port=gate_port)
        # stdout is the MCP wire; stderr is the operator's console
        print(f"tripwire: approvals at {gate.url}", file=sys.stderr, flush=True)

    print(f"tripwire: session {session_id}", file=sys.stderr, flush=True)

    upstream = Upstream(upstream_cmd)
    await upstream.start()

    audit.append(
        "proxy_start",
        {
            "upstream": upstream_cmd,
            "tools": [t.name for t in upstream.tools],
            "enforce": policy.enforce,
            "gate": gate_mode,
        },
    )

    session = SessionState(policy)
    tx = TxExecutor(tx_db, session_id) if tx_db else None
    server = build_server(Interceptor(policy, audit, upstream, session, gate=gate, tx=tx))
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        audit.append("proxy_stop", {})
        await upstream.aclose()
        if tx is not None:
            tx.close()
        if isinstance(gate, (CliGate, WebGate)):
            gate.close()
