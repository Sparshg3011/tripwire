"""Server side of the proxy: what the agent connects to.

Tools are re-advertised from upstream unchanged, so the agent sees the
same toolbox it would have seen directly. Every call it makes goes
through the interceptor instead of the tool.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tripwire.policy import load_policy
from tripwire.proxy.interceptor import Interceptor
from tripwire.proxy.upstream import Upstream
from tripwire.session import SessionState
from tripwire.tx import AuditLog, AuditWriteError


def build_server(interceptor: Interceptor) -> Server:
    server = Server("tripwire")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return interceptor.upstream.tools

    # validate_input=False: the upstream validates its own inputs, and a
    # firewall shouldn't quietly change what gets through on its own
    # judgement. Saying no is the policy engine's job.
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        try:
            return await interceptor.handle(name, arguments)
        except AuditWriteError as e:
            # Invariant: if we can't record it, we don't do it — and we
            # don't keep running either.
            print(f"tripwire: FATAL: {e}", file=sys.stderr, flush=True)
            os._exit(70)

    return server


async def serve(policy_path: str | Path, upstream_cmd: str, audit_path: str | Path) -> None:
    # All three of these raise on problems, and that's the point:
    # bad policy / dead upstream / unwritable log = refuse to start.
    policy = load_policy(policy_path)
    audit = AuditLog(audit_path)
    upstream = Upstream(upstream_cmd)
    await upstream.start()

    audit.append(
        "proxy_start",
        {
            "upstream": upstream_cmd,
            "tools": [t.name for t in upstream.tools],
            "enforce": policy.enforce,
        },
    )

    session = SessionState(policy)
    server = build_server(Interceptor(policy, audit, upstream, session))
    try:
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
    finally:
        audit.append("proxy_stop", {})
        await upstream.aclose()
