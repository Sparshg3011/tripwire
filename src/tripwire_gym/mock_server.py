"""A real MCP server that serves one scenario's toolbox.

The gym doesn't fake the tool layer. It runs this over stdio, behind the
real tripwire proxy, so a scenario exercises the same code path a user
would get. The answers are scripted — every call to a tool returns that
tool's `returns` verbatim, no clock, no randomness — because a benchmark
whose environment drifts between runs isn't measuring the firewall.

Every call that arrives here is appended to $TRIPWIRE_GYM_CALLS as one
JSON line. That file is the ground truth for scoring: it lists what
*executed*. A call the proxy refused never gets this far, which is
precisely why "the attack was blocked" is checkable rather than a matter
of reading the model's prose.

    python -m tripwire_gym.mock_server gym/scenarios/exfil-email-01.yaml
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
from mcp import types
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from tripwire_gym.scenario import MockTool, Scenario, ScenarioError, load_scenario

# an empty schema means "no arguments", not "anything goes"
EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}


class CallRecorder:
    """Appends one line per executed call. No path, no recording."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None

    def record(self, tool: str, args: dict[str, Any]) -> None:
        if self.path is None:
            return
        line = json.dumps(
            {"ts": datetime.now(UTC).isoformat(), "tool": tool, "args": args},
            sort_keys=True,
            separators=(",", ":"),
        )
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _advertise(tool: MockTool) -> types.Tool:
    return types.Tool(
        name=tool.name,
        description=tool.description or None,
        inputSchema=tool.schema_ or EMPTY_SCHEMA,
    )


def _answer(tool: MockTool) -> types.CallToolResult:
    text = tool.returns.get("text")
    content: list[types.ContentBlock] = []
    if text is not None:
        content.append(types.TextContent(type="text", text=str(text)))
    # anything besides `text` rides along as structured output, so a
    # scenario can script a json-shaped tool without a second mechanism
    extra = {k: v for k, v in tool.returns.items() if k != "text"}
    return types.CallToolResult(
        content=content,
        structuredContent=extra or None,
        isError=tool.is_error,
    )


def build_server(scenario: Scenario, recorder: CallRecorder) -> Server:
    server = Server(f"gym-{scenario.id}")
    by_name = {t.name: t for t in scenario.tools}

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [_advertise(t) for t in scenario.tools]

    # validate_input=False: the mock toolbox is an observer, not a
    # second gatekeeper. Whatever the agent tried is what gets recorded,
    # even if it's malformed — that's data about the attack.
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
        tool = by_name.get(name)
        if tool is None:
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=f"no tool {name!r} in this scenario")],
                isError=True,
            )
        recorder.record(name, arguments)
        return _answer(tool)

    return server


async def _run(scenario: Scenario, recorder: CallRecorder) -> None:
    server = build_server(scenario, recorder)
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m tripwire_gym.mock_server <scenario.yaml>", file=sys.stderr)
        sys.exit(2)

    try:
        scenario = load_scenario(args[0])
    except ScenarioError as e:
        print(f"mock_server: {e}", file=sys.stderr)
        sys.exit(2)

    recorder = CallRecorder(os.environ.get("TRIPWIRE_GYM_CALLS"))
    print(
        f"mock_server: {scenario.id} ({len(scenario.tools)} tools)",
        file=sys.stderr,
        flush=True,
    )
    try:
        anyio.run(_run, scenario, recorder)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
