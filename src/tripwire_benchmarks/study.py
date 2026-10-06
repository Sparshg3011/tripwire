"""Run the v0.2 study matrix (gym/preregistration-v0.2.md).

One process per benchmark, suite and condition, all at once, drawing on
one shared request budget per model (--pace-file), so the provider's
rate limit is the only thing that decides how fast the matrix goes.
Every cell resumes from the traces it already has, so the whole command
can be stopped and started again at will.

AgentDojo runs the 85 held-out users of the v0.1 study and nothing else;
AgentDyn runs every user and pair.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from tripwire_benchmarks.protectai_heldout import PROTECTAI_MODEL_REVISION

ROOT = Path(__file__).resolve().parent.parent.parent
HELDOUT_PLAN = ROOT / "docs" / "results" / "agentdojo-heldout" / "plan.json"

SUITES = {
    "agentdyn": ("github", "shopping", "dailylife"),
    "agentdojo": ("banking", "slack", "travel", "workspace"),
}
CONDITIONS = (
    "direct",
    "tripwire-deny/taint",
    "tripwire-deny/primary",
    "tripwire-deny/strict",
    "transformers_pi_detector",
)


def heldout_users(plan: dict[str, Any], suite: str) -> list[str]:
    return [user for shard in plan["suites"][suite]["shards"] for user in shard]


def cell_command(
    python: str,
    benchmark: str,
    suite: str,
    condition: str,
    model: str,
    out: Path,
    pace_file: Path,
    per_minute: float,
    users: list[str],
) -> list[str]:
    base, _, recipe = condition.partition("/")
    command = [
        python,
        "-m",
        "tripwire_benchmarks.agentdojo",
        "--suite",
        suite,
        "--model",
        model,
        "--condition",
        base,
        "--attack",
        "important_instructions",
        "--temperature",
        "0",
        "--disable-thinking",
        "--pace-file",
        str(pace_file),
        "--per-minute",
        str(per_minute),
        "--out",
        str(out),
    ]
    if recipe:
        command += ["--recipe", recipe]
    if base == "transformers_pi_detector":
        command += ["--protectai-model-revision", PROTECTAI_MODEL_REVISION]
    for user in users:
        command += ["--user-task", user]
    return command


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9.-]+", "_", text)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--benchmark", choices=list(SUITES), action="append", required=True)
    parser.add_argument("--condition", choices=CONDITIONS, action="append", required=True)
    parser.add_argument("--pace-file", required=True, type=Path)
    parser.add_argument("--per-minute", required=True, type=float)
    parser.add_argument("--python-agentdojo", default=sys.executable)
    parser.add_argument("--python-agentdyn", default=".venv-agentdyn/bin/python")
    args = parser.parse_args(argv)

    plan = json.loads(HELDOUT_PLAN.read_text(encoding="utf-8"))
    cells = []
    for benchmark in args.benchmark:
        python = args.python_agentdyn if benchmark == "agentdyn" else args.python_agentdojo
        for suite in SUITES[benchmark]:
            users = heldout_users(plan, suite) if benchmark == "agentdojo" else []
            for condition in args.condition:
                out = args.root / benchmark / slug(args.model) / suite / slug(condition)
                out.mkdir(parents=True, exist_ok=True)
                command = cell_command(
                    python,
                    benchmark,
                    suite,
                    condition,
                    args.model,
                    out,
                    args.pace_file,
                    args.per_minute,
                    users,
                )
                log = (out / "runner.log").open("a", encoding="utf-8")
                cells.append((out, subprocess.Popen(command, stdout=log, stderr=log), log))
                print(f"started {out}", flush=True)

    failed = 0
    for out, process, log in cells:
        code = process.wait()
        log.close()
        failed += code != 0
        print(f"{'done' if code == 0 else f'exit {code}'} {out}", flush=True)
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
