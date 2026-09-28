"""An MCP server that plays a recorded stream back: the recorded tool
listing, and each recorded result in the order it was recorded.

    python replay_server.py STREAM.json

STREAM.json is {"tools": [Tool, ...], "results": [[tool, CallToolResult], ...]}.
A call to any tool but the one next in the stream gets an error result.
"""

import json
import sys
from pathlib import Path

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server


def build(stream):
    server = Server("replay")
    tools = [types.Tool.model_validate(tool) for tool in stream["tools"]]
    results = iter(stream["results"])

    @server.list_tools()
    async def list_tools():
        return tools

    @server.call_tool(validate_input=False)
    async def call_tool(name, arguments):
        tool, result = next(results, (None, None))
        if tool != name:
            text = f"replay expected {tool!r}, got {name!r}"
            return types.CallToolResult(
                isError=True, content=[types.TextContent(type="text", text=text)]
            )
        return types.CallToolResult.model_validate(result)

    return server


async def run(stream):
    server = build(stream)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


if __name__ == "__main__":
    anyio.run(run, json.loads(Path(sys.argv[1]).read_text()))
