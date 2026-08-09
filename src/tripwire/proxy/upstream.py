"""Client side of the proxy: the connection to the real tool server."""

from __future__ import annotations

import os
import shlex
from contextlib import AsyncExitStack

from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


class UpstreamError(Exception):
    pass


class Upstream:
    """One upstream MCP server over stdio.

    Spawns the server as a subprocess, introspects its tools once at
    startup, and forwards calls. Tool list is a startup snapshot — if
    an upstream mutates its tools mid-session, we keep advertising what
    we vetted at start.
    """

    def __init__(self, command: str, env: dict[str, str] | None = None):
        argv = shlex.split(command)
        if not argv:
            raise UpstreamError("empty upstream command")
        self.command = command
        # The child gets our environment, because that is what it would
        # have got if the agent had launched it directly — and being
        # invisible is the whole job. Left to the SDK's default the child
        # sees a scrubbed environment with no API tokens in it, so
        # wrapping a server that needs GITHUB_TOKEN would break it, and
        # the breakage would look like tripwire being wrong about the
        # tool rather than about the environment.
        #
        # This is not a widening: without tripwire in the way, that
        # server was already being started with exactly this environment.
        self._params = StdioServerParameters(
            command=argv[0], args=argv[1:], env=dict(env if env is not None else os.environ)
        )
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None
        self.tools: list[types.Tool] = []

    async def start(self) -> None:
        try:
            read, write = await self._stack.enter_async_context(stdio_client(self._params))
            self._session = await self._stack.enter_async_context(ClientSession(read, write))
            await self._session.initialize()
            self.tools = (await self._session.list_tools()).tools
        except Exception as e:
            await self.aclose()
            raise UpstreamError(f"upstream {argv0(self.command)!r} failed to start: {e}") from e

    async def call(self, name: str, arguments: dict) -> types.CallToolResult:
        assert self._session is not None, "call() before start()"
        return await self._session.call_tool(name, arguments)

    async def aclose(self) -> None:
        await self._stack.aclose()


def argv0(command: str) -> str:
    return shlex.split(command)[0]
