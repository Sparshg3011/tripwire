import importlib.metadata


def check_mcp(version: str) -> None:
    """Refuse an mcp tripwire can't read. mcp 2 renamed the fields read off
    every result, so under it a call would run and its result go
    unrecorded: no taint, no provenance, a policy half enforced."""
    if int(version.split(".")[0]) >= 2:
        raise ImportError(f"tripwire needs mcp 1.x (>=1.10,<2), and mcp {version} is installed")


check_mcp(importlib.metadata.version("mcp"))

from tripwire.proxy.server import serve
from tripwire.proxy.upstream import Upstream, UpstreamError

__all__ = ["Upstream", "UpstreamError", "serve"]
