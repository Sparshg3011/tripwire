"""Combine many immutable run directories into one publication table."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from tripwire_gym.analysis import load_results, wilson_interval
from tripwire_gym.runner import RunResult
from tripwire_gym.scoring import summarize


def _rate(hits: int, total: int) -> dict[str, Any]:
    low, high = wilson_interval(hits, total)
    return {
        "hits": hits,
        "total": total,
        "rate": hits / total if total else None,
        "ci_low": low if total else None,
        "ci_high": high if total else None,
    }


def _label(settings: dict[str, Any], condition: str) -> str:
    profile = settings.get("prompt_profile", "unknown-prompt")
    if condition in {"undefended", "shadow"}:
        return f"{profile}/{condition}"
    return f"{profile}/{condition}/gate-{settings.get('human', 'none')}"


def collect(root: str | Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = Path(root)
    grouped: dict[tuple[str, str], list[RunResult]] = defaultdict(list)
    receipts = []
    for manifest_path in sorted(root.rglob("manifest.json")):
        results_path = manifest_path.with_name("results.jsonl")
        if not results_path.exists():
            continue
        manifest = json.loads(manifest_path.read_text())
        settings = manifest.get("settings", {})
        model = settings.get("model") or settings.get("agent") or "unknown"
        rows = load_results(results_path)
        for row in rows:
            grouped[(str(model), _label(settings, row.condition))].append(row)
        receipts.append(
            {
                "run_id": manifest.get("run_id", ""),
                "path": str(manifest_path),
                "git_commit": manifest.get("source", {}).get("git_commit", ""),
                "git_dirty": manifest.get("source", {}).get("git_dirty", False),
                "corpus_sha256": manifest.get("corpus", {}).get("sha256", ""),
            }
        )

    table = []
    for (model, label), rows in sorted(grouped.items()):
        condition = rows[0].condition
        summary = summarize(condition, [row.outcome for row in rows])
        measured = [row for row in rows if not row.error]
        table.append(
            {
                "model": model,
                "condition": label,
                "runs": len(rows),
                "errors": sum(bool(row.error) for row in rows),
                "attack_success": _rate(summary.attacks_succeeded, summary.attack_runs),
                "utility_under_attack": _rate(summary.attacked_completed, summary.attack_runs),
                "benign_utility": _rate(summary.benign_completed, summary.benign_runs),
                "gate_prompts_per_run": (
                    summary.gate_prompts / len(measured) if measured else None
                ),
                "mean_wall_seconds": (
                    sum(row.wall_seconds for row in measured) / len(measured) if measured else None
                ),
                "mean_model_seconds": (
                    sum(row.model_seconds for row in measured) / len(measured) if measured else None
                ),
                "prompt_tokens": sum(row.prompt_tokens for row in measured),
                "completion_tokens": sum(row.completion_tokens for row in measured),
            }
        )
    return table, receipts


def _percent(cell: dict[str, Any]) -> str:
    if cell["rate"] is None:
        return "n/a"
    return (
        f"{100 * cell['rate']:.1f}% ({cell['hits']}/{cell['total']}; "
        f"95% CI {100 * cell['ci_low']:.1f}-{100 * cell['ci_high']:.1f}%)"
    )


def markdown(table: list[dict[str, Any]], receipts: list[dict[str, Any]]) -> str:
    lines = [
        "# Publication benchmark summary",
        "",
        (
            "Attack success is lower-is-better. Utility columns are higher-is-better. "
            "Intervals are descriptive Wilson intervals; scenario-clustered paired effects "
            "should be used for the paper's hypothesis tests."
        ),
        "",
        (
            "| model | condition | attack success | utility under attack | benign utility "
            "| gate prompts/run | errors |"
        ),
        "|---|---|---|---|---|---:|---:|",
    ]
    for row in table:
        gates = row["gate_prompts_per_run"]
        gate_text = f"{gates:.2f}" if gates is not None else "n/a"
        lines.append(
            f"| `{row['model']}` | `{row['condition']}` "
            f"| {_percent(row['attack_success'])} "
            f"| {_percent(row['utility_under_attack'])} "
            f"| {_percent(row['benign_utility'])} "
            f"| {gate_text} | {row['errors']} |"
        )
    lines += ["", "## Run receipts", ""]
    for receipt in receipts:
        dirty = " **DIRTY WORKTREE**" if receipt["git_dirty"] else ""
        lines.append(
            f"- `{receipt['run_id']}` — `{receipt['git_commit']}` — corpus "
            f"`{receipt['corpus_sha256']}`{dirty}"
        )
    return "\n".join(lines) + "\n"


def write_outputs(root: str | Path, out: str | Path) -> None:
    table, receipts = collect(root)
    if not table:
        raise SystemExit(f"no manifest.json + results.jsonl pairs under {root}")
    destination = Path(out)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "summary.json").write_text(
        json.dumps({"results": table, "receipts": receipts}, indent=2, sort_keys=True) + "\n"
    )
    flat = []
    for row in table:
        flat.append(
            {
                "model": row["model"],
                "condition": row["condition"],
                "runs": row["runs"],
                "errors": row["errors"],
                "attack_success_rate": row["attack_success"]["rate"],
                "utility_under_attack": row["utility_under_attack"]["rate"],
                "benign_utility": row["benign_utility"]["rate"],
                "gate_prompts_per_run": row["gate_prompts_per_run"],
                "mean_wall_seconds": row["mean_wall_seconds"],
                "mean_model_seconds": row["mean_model_seconds"],
                "prompt_tokens": row["prompt_tokens"],
                "completion_tokens": row["completion_tokens"],
            }
        )
    with (destination / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)
    (destination / "REPORT.md").write_text(markdown(table, receipts), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="combine publication run receipts")
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    write_outputs(args.root, args.out)


if __name__ == "__main__":
    main()
