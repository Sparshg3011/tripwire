"""Frozen, bounded development experiment; never a publication efficacy result."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL = "nvidia/nemotron-3-super-120b-a12b"
CONDITIONS = ("direct", "tripwire-deny", "tripwire-review")


def commands(out: Path) -> list[list[str]]:
    return [
        [
            sys.executable,
            "-m",
            "tripwire_benchmarks.agentdojo",
            "--suite",
            "banking",
            "--benchmark-version",
            "v1.2.2",
            "--model",
            MODEL,
            "--base-url",
            "https://integrate.api.nvidia.com/v1",
            "--api-key-var",
            "NVIDIA_API_KEY",
            "--condition",
            condition,
            "--user-task",
            "user_task_3",
            "--injection-task",
            "injection_task_5",
            "--attack",
            "important_instructions",
            "--repetitions",
            "1",
            "--temperature",
            "0",
            "--disable-thinking",
            "--max-tokens",
            "2048",
            "--timeout",
            "60",
            "--min-call-interval",
            "2",
            "--rate-limit-retries",
            "2",
            "--retry-base-seconds",
            "10",
            "--retry-cap-seconds",
            "20",
            "--out",
            str(out / condition),
        ]
        for condition in CONDITIONS
    ]


def validate(out: Path) -> dict:
    summaries = {}
    for condition in CONDITIONS:
        result = json.loads((out / condition / "results.json").read_text())
        runs = result["runs"]
        if len(runs) != 1:
            raise ValueError("expected exactly one repetition")
        run = runs[0]
        for field in ("benign_results", "attack_results", "attacked_utility_results"):
            rows = run[field]
            if len(rows) != 1 or rows[0]["user_task"] != "user_task_3":
                raise ValueError(f"unexpected population in {condition}: {field}")
            expected = "none" if field == "benign_results" else "injection_task_5"
            if rows[0]["injection_task"] != expected or type(rows[0]["value"]) is not bool:
                raise ValueError(f"invalid outcome in {condition}: {field}")
        setup = run["injection_task_utility_results"]
        if len(setup) != 1 or setup[0]["injection_task"] != "injection_task_5":
            raise ValueError("unexpected setup population")
        if type(setup[0]["value"]) is not bool:
            raise ValueError("incomplete setup outcome")
        if run["trace_errors"] or run.get("review_errors", 0):
            raise ValueError(f"experiment errors in {condition}; not a clean comparison")
        summaries[condition] = result["summary"]
    return {"purpose": "development_smoke_not_efficacy_evidence", "summaries": summaries}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if not os.environ.get("NVIDIA_API_KEY"):
        raise SystemExit("NVIDIA_API_KEY is required; no paid fallback is supported")
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)
    if dirty.strip():
        raise SystemExit("commit implementation before running the development experiment")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    jobs = commands(out)
    contract = {"source_commit": commit, "commands": jobs, "timeout_per_condition": 1800}
    out.mkdir(parents=True, exist_ok=True)
    manifest = out / "experiment.json"
    if manifest.exists():
        if json.loads(manifest.read_text()) != contract:
            raise SystemExit("experiment contract changed; use a new output directory")
    elif any(out.iterdir()):
        raise SystemExit("output contains artifacts without an experiment contract")
    else:
        manifest.write_text(json.dumps(contract, indent=2) + "\n")
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONUNBUFFERED": "1"}
    for condition, command in zip(CONDITIONS, jobs, strict=True):
        print(f"Starting development condition: {condition}", flush=True)
        with (out / f"{condition}.log").open("a", buffering=1) as log:
            subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=1800,
                check=True,
            )
    report = validate(out)
    (out / "SMOKE-COMPLETENESS.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
