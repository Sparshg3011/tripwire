"""Tiny MCP server to point the proxy at during tests."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("toy")


@mcp.tool()
def add(a: int, b: int) -> int:
    return a + b


@mcp.tool()
def whoami() -> str:
    return "toy-server"


@mcp.tool()
def boom() -> str:
    """Always fails, for error-passthrough tests."""
    raise RuntimeError("toy exploded")


if __name__ == "__main__":
    mcp.run()
