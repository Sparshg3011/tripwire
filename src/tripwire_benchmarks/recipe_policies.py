"""The recipe's policies for the AgentDojo and AgentDyn suites.

Two steps, since the suites live in two environments:

  dump SUITE...  write each suite's tool listing to tools/<suite>.json:
                 tool names and input schemas, with no description or
                 title left in them. Run it under the interpreter that
                 has the suite: AgentDojo's for banking, slack, travel
                 and workspace, AgentDyn's for github, shopping and
                 dailylife.
  generate       write <suite>.yaml, strict/<suite>.yaml and
                 taint/<suite>.yaml for every tools/<suite>.json, with
                 tripwire.recipe; with --check, write nothing and fail
                 if any file would change.

The taint arm is the primary one without `unless: anchored`: the same
contracts, and every tainted write and fetch gated.

Nothing here reads a task, an injection or a ground truth.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tripwire.recipe import Arm, recipe
from tripwire_gym.resources import GYM

ROOT = GYM / "recipe_policies"
VERSION = "v1.2.2"
AGENTDOJO = ("banking", "slack", "travel", "workspace")
AGENTDYN = ("github", "shopping", "dailylife")
# where each arm's policy for a suite goes, under ROOT
ARMS: dict[Arm, str] = {"primary": "", "strict": "strict", "taint": "taint"}
# JSON Schema keywords that hold prose, not structure
PROSE = frozenset({"description", "title"})


def schema_only(node: Any) -> Any:
    """A JSON schema without its prose keywords. The names under
    properties and $defs are arguments and definitions, not keywords."""
    if isinstance(node, list):
        return [schema_only(item) for item in node]
    if not isinstance(node, dict):
        return node
    out: dict[str, Any] = {}
    for key, value in node.items():
        if key in PROSE:
            continue
        if key in ("properties", "$defs", "definitions") and isinstance(value, dict):
            out[key] = {name: schema_only(sub) for name, sub in value.items()}
        else:
            out[key] = schema_only(value)
    return out


def listing(suite_name: str, version: str = VERSION) -> list[dict[str, Any]]:
    """A suite's tools as a tools/list result would give them, less their
    prose."""
    from agentdojo.task_suite.load_suites import get_suite

    suite = get_suite(version, suite_name)
    return [
        {"name": tool.name, "inputSchema": schema_only(tool.parameters.model_json_schema())}
        for tool in suite.tools
    ]


def listing_bytes(tools: list[dict[str, Any]]) -> bytes:
    return (json.dumps(tools, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def policy_path(root: Path, suite: str, arm: Arm) -> Path:
    return root / ARMS[arm] / f"{suite}.yaml"


def policies(root: Path) -> dict[Path, bytes]:
    """Every arm's policy for every dumped suite, by where it goes."""
    out: dict[Path, bytes] = {}
    for source in sorted((root / "tools").glob("*.json")):
        text = source.read_bytes()
        for arm in ARMS:
            out[policy_path(root, source.stem, arm)] = recipe(text, arm=arm).encode()
    return out


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="draft the benchmark suites' recipe policies")
    parser.add_argument("--root", type=Path, default=ROOT)
    sub = parser.add_subparsers(dest="command", required=True)
    p_dump = sub.add_parser("dump", help="write suites' tool listings under ROOT/tools")
    p_dump.add_argument("suites", nargs="+", choices=AGENTDOJO + AGENTDYN)
    p_generate = sub.add_parser("generate", help="write every arm's policy from the listings")
    p_generate.add_argument("--check", action="store_true", help="fail if any file would change")
    args = parser.parse_args(argv)

    if args.command == "dump":
        (args.root / "tools").mkdir(parents=True, exist_ok=True)
        for suite in args.suites:
            path = args.root / "tools" / f"{suite}.json"
            path.write_bytes(listing_bytes(listing(suite)))
            print(f"wrote {path}", file=sys.stderr)
        return

    stale = []
    for path, text in policies(args.root).items():
        if path.exists() and path.read_bytes() == text:
            continue
        stale.append(path)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(text)
            print(f"wrote {path}", file=sys.stderr)
    if args.check and stale:
        for path in stale:
            print(f"out of date: {path}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
