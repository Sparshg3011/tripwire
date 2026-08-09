"""One run: a real agent, a real proxy, a real toolbox, one scenario.

Nothing below the agent is simulated. The mock server is a real MCP
server, tripwire is the real proxy in a real subprocess, and the agent
reaches its tools the same way any MCP client would. The only thing the
gym controls is which policy tripwire was started with — that's the
independent variable, and everything else is held still.

Ground truth for scoring comes from the mock server's own record of
what it was asked to do, not from the audit log and not from the
model's account of itself. A refused call never reaches the mock, so
"the attack was blocked" is a fact about a file on disk rather than an
interpretation.

Conditions:
    undefended   the agent talks straight to the toolbox
    shadow       tripwire evaluating everything, blocking nothing
    loose | standard | strict   the three policy tiers
"""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import anyio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from tripwire_gym.agent import Agent, ToolCallRecord
from tripwire_gym.scenario import Scenario
from tripwire_gym.scoring import Call, Outcome, score

GYM = Path(__file__).resolve().parent.parent.parent / "gym"
POLICY_TIERS = ("loose", "standard", "strict")
CONDITIONS = ("undefended", "shadow", *POLICY_TIERS)


class GymError(Exception):
    pass


def policy_for(condition: str, policy_dir: Path | None = None) -> Path | None:
    """None means 'no proxy at all' — the undefended control."""
    if condition == "undefended":
        return None
    directory = policy_dir or (GYM / "policies")
    if condition == "shadow":
        return directory / "shadow.yaml"
    if condition in POLICY_TIERS:
        return directory / f"{condition}.yaml"
    raise GymError(f"unknown condition {condition!r}; expected one of {', '.join(CONDITIONS)}")


class Session:
    """The agent's view of its tools: an MCP client, wherever it points."""

    def __init__(self, session: ClientSession):
        self._session = session

    async def list_tools(self) -> list[dict[str, Any]]:
        listing = await self._session.list_tools()
        return [
            {"name": t.name, "description": t.description, "inputSchema": t.inputSchema}
            for t in listing.tools
        ]

    async def call(self, name: str, args: dict[str, Any]) -> tuple[str, bool]:
        result = await self._session.call_tool(name, args)
        text = "\n".join(b.text for b in result.content if getattr(b, "type", "") == "text")
        return text, bool(result.isError)


@dataclass
class RunResult:
    scenario_id: str
    condition: str
    seed: int
    outcome: Outcome
    attempted: list[ToolCallRecord] = field(default_factory=list)
    executed: list[Call] = field(default_factory=list)
    error: str = ""


def _executed_calls(calls_path: Path) -> list[Call]:
    """What the toolbox was actually asked to do."""
    if not calls_path.exists():
        return []
    out = []
    for line in calls_path.read_text().splitlines():
        if line.strip():
            row = json.loads(line)
            out.append(Call(tool=row["tool"], args=row.get("args", {}), executed=True))
    return out


def _refused_calls(attempted: list[ToolCallRecord], executed: list[Call]) -> list[Call]:
    """Everything the agent tried that never landed.

    Matched by position per tool rather than by identity, because the
    same call can legitimately be made twice and we want the count right
    rather than the pairing pretty.
    """
    landed: dict[str, int] = {}
    for call in executed:
        landed[call.tool] = landed.get(call.tool, 0) + 1

    refused = []
    for record in attempted:
        if landed.get(record.tool, 0) > 0:
            landed[record.tool] -= 1
        else:
            refused.append(
                Call(
                    tool=record.tool,
                    args=record.args,
                    executed=False,
                    refused_reason=record.result_text[:200],
                )
            )
    return refused


async def run_once(
    scenario: Scenario,
    condition: str,
    agent: Agent,
    seed: int = 0,
    policy_dir: Path | None = None,
    workdir: Path | None = None,
) -> RunResult:
    policy = policy_for(condition, policy_dir)

    with TemporaryDirectory() as tmp:
        room = Path(workdir or tmp)
        scenario_file = room / f"{scenario.id}.yaml"
        scenario_file.write_text(_dump_scenario(scenario))
        calls_path = room / "calls.jsonl"
        audit_path = room / "audit.jsonl"

        mock_cmd = [sys.executable, "-m", "tripwire_gym.mock_server", str(scenario_file)]
        env = {**os.environ, "TRIPWIRE_GYM_CALLS": str(calls_path)}

        if policy is None:
            params = StdioServerParameters(command=mock_cmd[0], args=mock_cmd[1:], env=env)
        else:
            params = StdioServerParameters(
                command=sys.executable,
                args=[
                    "-m",
                    "tripwire",
                    "serve",
                    "--policy",
                    str(policy),
                    "--upstream",
                    shlex.join(mock_cmd),
                    "--audit",
                    str(audit_path),
                ],
                # the proxy spawns the mock itself, and the child needs
                # the calls path — this is why Upstream takes an env
                env=env,
            )

        attempted: list[ToolCallRecord] = []
        error = ""
        try:
            with anyio.fail_after(180):
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as mcp:
                        await mcp.initialize()
                        attempted = await agent.run(scenario.task, Session(mcp))
        except Exception as e:  # noqa: BLE001 — a crashed run is a data point
            error = f"{type(e).__name__}: {e}"

        executed = _executed_calls(calls_path)
        calls = executed + _refused_calls(attempted, executed)
        gate_prompts = _count_gate_prompts(audit_path)

    return RunResult(
        scenario_id=scenario.id,
        condition=condition,
        seed=seed,
        outcome=score(scenario, calls, gate_prompts=gate_prompts),
        attempted=attempted,
        executed=executed,
        error=error,
    )


def _count_gate_prompts(audit_path: Path) -> int:
    if not audit_path.exists():
        return 0
    return sum(
        1
        for line in audit_path.read_text().splitlines()
        if line.strip() and json.loads(line).get("kind") == "gate_requested"
    )


def _dump_scenario(scenario: Scenario) -> str:
    import yaml

    return yaml.safe_dump(scenario.model_dump(by_alias=True, exclude_none=True), sort_keys=False)


async def run_matrix(
    scenarios: Sequence[Scenario],
    conditions: Sequence[str],
    agent_for,
    runs: int = 1,
    policy_dir: Path | None = None,
    on_result=None,
) -> list[RunResult]:
    """Every scenario, under every condition, N times.

    Sequential on purpose. Runs share nothing, but a machine juggling
    five proxies and five model conversations measures its own load as
    much as the firewall, and this number ends up on a chart.
    """
    results = []
    for scenario in scenarios:
        for condition in conditions:
            for seed in range(runs):
                result = await run_once(
                    scenario, condition, agent_for(scenario, condition, seed), seed, policy_dir
                )
                results.append(result)
                if on_result is not None:
                    on_result(result)
    return results
