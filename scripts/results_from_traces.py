"""Rebuild a cell's results.json from the traces it scored.

For a cell that stopped before writing one, as the v0.2 study's primary
model did when the provider retired it. Only scored traces count: one
cut off mid-task has no utility and is left out. The output has the
shape tripwire_benchmarks.agentdojo writes, so tripwire_benchmarks.report
reads it unchanged.

    python scripts/results_from_traces.py CELL OUT --model M --suite S \\
        --condition tripwire-deny [--recipe primary]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from tripwire_benchmarks.agentdojo import (
    _read_enforcement_receipts,
    _read_trace_errors,
    _read_trace_usage,
)


def _scored(directory: Path) -> list[dict[str, Any]]:
    out = []
    for path in sorted(directory.rglob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if "utility" in data and data.get("error") is None:
            out.append(data)
    return out


def _value(item: dict[str, Any], key: str) -> dict[str, Any]:
    return {
        "injection_task": item.get("injection_task_id") or "",
        "user_task": item["user_task_id"],
        "value": bool(item[key]),
    }


def rebuild(cell: Path, *, model: str, suite: str, condition: str, recipe: str | None) -> dict:
    root = cell / "traces" / "repetition-0"
    benign_dir, attacked_dir = root / "benign", root / "attacked"
    benign = _scored(benign_dir)
    attacked = _scored(attacked_dir)
    pairs = [t for t in attacked if t.get("attack_type") is not None]
    goals = [t for t in attacked if t.get("attack_type") is None]

    attack_results = sorted((_value(t, "security") for t in pairs), key=_order)
    attacked_utility = sorted((_value(t, "utility") for t in pairs), key=_order)
    benign_results = sorted((_value(t, "utility") for t in benign), key=_order)
    run: dict[str, Any] = {
        "repetition": 0,
        "benign_utility": _mean([r["value"] for r in benign_results]),
        "attack_success_rate": _mean([r["value"] for r in attack_results]),
        "utility_under_attack": _mean([r["value"] for r in attacked_utility]),
        "benign_results": benign_results,
        "attack_results": attack_results,
        "attacked_utility_results": attacked_utility,
        # a goal run is the injection task done as a user task, so its
        # trace names the injection task as the user task
        "injection_task_utility_results": sorted(
            ({"injection_task": t["user_task_id"], "value": bool(t["utility"])} for t in goals),
            key=lambda r: r["injection_task"],
        ),
        "trace_errors": _read_trace_errors(benign_dir, attacked_dir),
        **_read_trace_usage(benign_dir, attacked_dir),
    }
    if condition.startswith("tripwire-"):
        run["enforcement"] = {
            "benign": _read_enforcement_receipts(benign_dir, task_kind="user"),
            "attacked": _read_enforcement_receipts(attacked_dir, task_kind="user"),
            "injection_checks": _read_enforcement_receipts(
                attacked_dir, task_kind="injection_check"
            ),
        }
    return {
        "schema_version": 1,
        "benchmark": "agentdojo-family",
        "benchmark_version": "v1.2.2",
        "suite": suite,
        "attack": "important_instructions",
        "condition": condition,
        "model": model,
        "settings": {"recipe": recipe, "rebuilt_from_traces": True},
        "runs": [run],
    }


def _order(row: dict[str, Any]) -> tuple[str, str]:
    return (row["user_task"], row["injection_task"])


def _mean(values: list[bool]) -> float:
    return sum(values) / len(values) if values else 0.0


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cell", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--model", required=True)
    parser.add_argument("--suite", required=True)
    parser.add_argument("--condition", required=True)
    parser.add_argument("--recipe")
    args = parser.parse_args(argv)
    data = rebuild(
        args.cell,
        model=args.model,
        suite=args.suite,
        condition=args.condition,
        recipe=args.recipe,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
