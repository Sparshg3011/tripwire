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
from tripwire_gym.human import Human, find_gate_url
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
        # a scenario can script a json-shaped tool, and dropping the
        # structured half would quietly hide whatever it put there —
        # including an injection
        if result.structuredContent:
            extra = json.dumps(result.structuredContent, sort_keys=True, default=str)
            text = f"{text}\n{extra}" if text else extra
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
    gate_answers: int = 0  # approvals the simulated human granted or refused


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
    human: str = "none",
) -> RunResult:
    """`human` decides who stands at the approval gate: "approve" or
    "deny" for the two extremes, "none" to run without a gate at all
    (which makes every gated call a refusal)."""
    policy = policy_for(condition, policy_dir)

    # a fresh directory per run: calls.jsonl is the ground truth, and
    # one run inheriting another's would be undetectable in the numbers
    with TemporaryDirectory() as tmp:
        room = Path(tmp)
        scenario_file = room / f"{scenario.id}.yaml"
        scenario_file.write_text(_dump_scenario(scenario))
        calls_path = room / "calls.jsonl"
        audit_path = room / "audit.jsonl"

        mock_cmd = [sys.executable, "-m", "tripwire_gym.mock_server", str(scenario_file)]
        env = {**os.environ, "TRIPWIRE_GYM_CALLS": str(calls_path)}

        gated = policy is not None and human != "none"
        if policy is None:
            params = StdioServerParameters(command=mock_cmd[0], args=mock_cmd[1:], env=env)
        else:
            argv = [
                "-m",
                "tripwire",
                "serve",
                "--policy",
                str(policy),
                "--upstream",
                shlex.join(mock_cmd),
                "--audit",
                str(audit_path),
            ]
            if gated:
                # port 0: every run gets its own gate, so a matrix can't
                # have two proxies fighting over one port
                argv += ["--gate", "web", "--gate-port", "0"]
            params = StdioServerParameters(
                command=sys.executable,
                args=argv,
                # the proxy spawns the mock itself, and the child needs
                # the calls path — this is why Upstream takes an env
                env=env,
            )

        # owned here, not returned by the agent: a run that dies halfway
        # must keep what it already attempted, or a crashed attack run
        # looks exactly like a defended one
        attempted: list[ToolCallRecord] = []
        error = ""
        answered = 0
        stderr_path = room / "proxy-stderr.log"
        try:
            with anyio.fail_after(180):
                # one small local file, opened once at run start
                with open(stderr_path, "w+") as errlog:  # noqa: ASYNC230
                    async with stdio_client(params, errlog=errlog) as (read, write):
                        async with ClientSession(read, write) as mcp:
                            await mcp.initialize()
                            async with anyio.create_task_group() as tg:
                                approver = None
                                if gated:
                                    approver = await _start_human(tg, stderr_path, human)
                                await agent.run(scenario.task, Session(mcp), attempted)
                                # the agent is done, so nobody is left to
                                # ask; without this the group waits forever
                                tg.cancel_scope.cancel()
                            if approver is not None:
                                answered = approver.answered
        except Exception as e:  # noqa: BLE001 — a crashed run is a data point
            error = f"{type(e).__name__}: {e}"

        executed = _executed_calls(calls_path)
        calls = executed + _refused_calls(attempted, executed)
        gate_prompts = _count_gate_prompts(audit_path)

    outcome = score(scenario, calls, gate_prompts=gate_prompts)
    # A run that crashed proves nothing about the firewall. Marking it
    # here keeps summarize() from counting a harness failure as an
    # attack the policy stopped.
    outcome.errored = bool(error)

    return RunResult(
        scenario_id=scenario.id,
        condition=condition,
        seed=seed,
        outcome=outcome,
        attempted=attempted,
        executed=executed,
        error=error,
        gate_answers=answered,
    )


async def _start_human(tg, stderr_path: Path, answer: str) -> Human | None:
    """Wait for the proxy to announce its gate, then stand at it.

    The URL carries a per-run token and a port we didn't choose, so it
    can only be learned by reading what the proxy printed.
    """
    for _ in range(50):
        url = find_gate_url(stderr_path.read_text() if stderr_path.exists() else "")
        if url is not None:
            approver = Human(url, answer=answer)
            tg.start_soon(approver.watch)
            return approver
        await anyio.sleep(0.1)
    return None  # no gate appeared; gated calls will simply be refused


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
    human: str = "none",
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
                    scenario,
                    condition,
                    agent_for(scenario, condition, seed),
                    seed,
                    policy_dir,
                    human=human,
                )
                results.append(result)
                if on_result is not None:
                    on_result(result)
    return results
