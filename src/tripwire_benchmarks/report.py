"""Aggregate AgentDojo-family JSON receipts into publication tables."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from tripwire_gym.analysis import mcnemar, wilson_interval


def _rate(values: list[bool]) -> dict[str, Any]:
    return _rate_counts(sum(values), len(values))


def _rate_counts(hits: int, total: int) -> dict[str, Any]:
    low, high = wilson_interval(hits, total)
    return {
        "hits": hits,
        "total": total,
        "rate": hits / total if total else None,
        "ci_low": low if total else None,
        "ci_high": high if total else None,
    }


def collect(root: str | Path) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(Path(root).rglob("results.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("benchmark") != "agentdojo-family":
            continue
        key = (data["model"], data["suite"], data["attack"], data["condition"])
        grouped[key].extend(data["runs"])

    direct_valid: dict[tuple[str, str, str, int], set[str]] = {}
    for (model, suite, attack, condition), runs in grouped.items():
        if condition != "direct":
            continue
        for run in runs:
            direct_valid[(model, suite, attack, int(run["repetition"]))] = {
                str(item["injection_task"])
                for item in run.get("injection_task_utility_results", [])
                if item.get("value") is True
            }

    rows = []
    for (model, suite, attack, condition), runs in sorted(grouped.items()):
        attack_values = [bool(item["value"]) for run in runs for item in run["attack_results"]]
        valid_attack_values = [
            bool(item["value"])
            for run in runs
            for item in run["attack_results"]
            if str(item["injection_task"])
            in direct_valid.get((model, suite, attack, int(run["repetition"])), set())
        ]
        attacked_utility = [
            bool(item["value"]) for run in runs for item in run["attacked_utility_results"]
        ]
        benign = [bool(item["value"]) for run in runs for item in run["benign_results"]]
        enforcement_observed = any("enforcement" in run for run in runs)
        attacked_gated_cases = sum(
            run.get("enforcement", {}).get("attacked", {}).get("gated_cases", 0)
            for run in runs
        )
        benign_gated_cases = sum(
            run.get("enforcement", {}).get("benign", {}).get("gated_cases", 0)
            for run in runs
        )
        rows.append(
            {
                "model": model,
                "suite": suite,
                "attack": attack,
                "condition": condition,
                "repetitions": len(runs),
                "attack_success": _rate(attack_values),
                "attack_success_valid_injection_subset": _rate(valid_attack_values),
                "utility_under_attack": _rate(attacked_utility),
                "benign_utility": _rate(benign),
                "attack_intervention": _rate_counts(
                    attacked_gated_cases, len(attack_values) if enforcement_observed else 0
                ),
                "benign_intervention": _rate_counts(
                    benign_gated_cases, len(benign) if enforcement_observed else 0
                ),
                "attacked_gate_prompts": sum(
                    run.get("enforcement", {})
                    .get("attacked", {})
                    .get("gate_prompts", 0)
                    for run in runs
                ),
                "benign_gate_prompts": sum(
                    run.get("enforcement", {})
                    .get("benign", {})
                    .get("gate_prompts", 0)
                    for run in runs
                ),
                "model_calls": sum(run.get("model_calls", 0) for run in runs),
                "provider_attempts": sum(run.get("provider_attempts", 0) for run in runs),
                "rate_limit_retries": sum(
                    run.get("rate_limit_retries", 0) for run in runs
                ),
                "prompt_tokens": sum(run.get("prompt_tokens", 0) for run in runs),
                "completion_tokens": sum(run.get("completion_tokens", 0) for run in runs),
                "model_seconds": sum(run.get("model_seconds", 0.0) for run in runs),
                "rate_limit_wait_seconds": sum(
                    run.get("rate_limit_wait_seconds", 0.0) for run in runs
                ),
                "trace_errors": sum(len(run.get("trace_errors", [])) for run in runs),
            }
        )
    return rows


def collect_overall(root: str | Path) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in collect(root):
        grouped[(row["model"], row["attack"], row["condition"])].append(row)

    overall = []
    rate_fields = (
        "attack_success",
        "attack_success_valid_injection_subset",
        "utility_under_attack",
        "benign_utility",
        "attack_intervention",
        "benign_intervention",
    )
    for (model, attack, condition), rows in sorted(grouped.items()):
        row: dict[str, Any] = {
            "model": model,
            "suite": "ALL",
            "attack": attack,
            "condition": condition,
            "repetitions": max(item["repetitions"] for item in rows),
            "suite_cells": len(rows),
        }
        for field in rate_fields:
            row[field] = _rate_counts(
                sum(item[field]["hits"] for item in rows),
                sum(item[field]["total"] for item in rows),
            )
        for field in (
            "attacked_gate_prompts",
            "benign_gate_prompts",
            "model_calls",
            "provider_attempts",
            "rate_limit_retries",
            "prompt_tokens",
            "completion_tokens",
            "model_seconds",
            "rate_limit_wait_seconds",
            "trace_errors",
        ):
            row[field] = sum(item[field] for item in rows)
        overall.append(row)
    return overall


def paired_effects(root: str | Path) -> list[dict[str, Any]]:
    cells: dict[tuple[str, str, str, str], dict[tuple[int, str, str], bool]] = {}
    for path in sorted(Path(root).rglob("results.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("benchmark") != "agentdojo-family":
            continue
        values = {}
        for run in data["runs"]:
            repetition = int(run["repetition"])
            for item in run["attack_results"]:
                values[(repetition, item["user_task"], item["injection_task"])] = bool(
                    item["value"]
                )
        cells.setdefault(
            (data["model"], data["suite"], data["attack"], data["condition"]), {}
        ).update(values)

    effects = []
    bases = {(model, suite, attack) for model, suite, attack, condition in cells if condition == "direct"}
    for model, suite, attack in sorted(bases):
        direct = cells[(model, suite, attack, "direct")]
        for condition in ("tripwire-approve", "tripwire-deny"):
            defended = cells.get((model, suite, attack, condition))
            if defended is None:
                continue
            shared = direct.keys() & defended.keys()
            comparison = mcnemar(direct, defended)
            direct_rate = sum(direct[key] for key in shared) / len(shared) if shared else None
            defended_rate = sum(defended[key] for key in shared) / len(shared) if shared else None
            effects.append(
                {
                    "model": model,
                    "suite": suite,
                    "attack": attack,
                    "condition": condition,
                    "pairs": len(shared),
                    "asr_difference": (
                        defended_rate - direct_rate if direct_rate is not None else None
                    ),
                    "direct_only_successes": comparison.only_a,
                    "defended_only_successes": comparison.only_b,
                    "mcnemar_p": comparison.p_value,
                }
            )
    return effects


def _exact_mcnemar_p(only_a: int, only_b: int) -> float:
    discordant = only_a + only_b
    if discordant == 0:
        return 1.0
    smaller = min(only_a, only_b)
    tail = sum(math.comb(discordant, index) for index in range(smaller + 1))
    return min(1.0, 2 * tail / 2**discordant)


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return math.nan
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _bootstrap_rng(seed: int, *labels: str) -> random.Random:
    digest = hashlib.sha256("\x00".join(labels).encode()).digest()
    return random.Random(seed ^ int.from_bytes(digest[:8], "big"))


def _paired_cluster_intervals(
    root: str | Path,
    *,
    samples: int,
    seed: int,
) -> dict[tuple[str, str, str], dict[str, Any]]:
    attack_cells: dict[
        tuple[str, str, str, str], dict[tuple[int, str, str], bool]
    ] = defaultdict(dict)
    benign_cells: dict[
        tuple[str, str, str, str], dict[tuple[int, str], bool]
    ] = defaultdict(dict)
    for path in sorted(Path(root).rglob("results.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("benchmark") != "agentdojo-family":
            continue
        key = (data["model"], data["suite"], data["attack"], data["condition"])
        for run in data["runs"]:
            repetition = int(run["repetition"])
            for item in run["attack_results"]:
                attack_cells[key][
                    (repetition, item["user_task"], item["injection_task"])
                ] = bool(item["value"])
            for item in run["benign_results"]:
                benign_cells[key][(repetition, item["user_task"])] = bool(
                    item["value"]
                )

    comparisons = {
        (model, attack, condition)
        for model, _suite, attack, condition in attack_cells
        if condition in {"tripwire-approve", "tripwire-deny"}
    }
    intervals: dict[tuple[str, str, str], dict[str, Any]] = {}
    for model, attack, condition in sorted(comparisons):
        attack_grids: list[tuple[list[str], list[str], dict[tuple[str, str], float]]] = []
        benign_grids: list[tuple[list[str], dict[str, float]]] = []
        for suite in sorted({key[1] for key in attack_cells if key[0] == model}):
            direct_attack = attack_cells.get((model, suite, attack, "direct"), {})
            defended_attack = attack_cells.get((model, suite, attack, condition), {})
            shared_attack = direct_attack.keys() & defended_attack.keys()
            repeated_differences: dict[tuple[str, str], list[float]] = defaultdict(list)
            for repetition, user, injection in shared_attack:
                repeated_differences[(user, injection)].append(
                    float(defended_attack[(repetition, user, injection)])
                    - float(direct_attack[(repetition, user, injection)])
                )
            attack_grid = {
                pair: sum(values) / len(values)
                for pair, values in repeated_differences.items()
            }
            users = sorted({user for user, _injection in attack_grid})
            injections = sorted({injection for _user, injection in attack_grid})
            if users and injections and all(
                (user, injection) in attack_grid
                for user in users
                for injection in injections
            ):
                attack_grids.append((users, injections, attack_grid))

            direct_benign = benign_cells.get((model, suite, attack, "direct"), {})
            defended_benign = benign_cells.get((model, suite, attack, condition), {})
            shared_benign = direct_benign.keys() & defended_benign.keys()
            benign_repeated: dict[str, list[float]] = defaultdict(list)
            for repetition, user in shared_benign:
                benign_repeated[user].append(
                    float(defended_benign[(repetition, user)])
                    - float(direct_benign[(repetition, user)])
                )
            benign_grid = {
                user: sum(values) / len(values)
                for user, values in benign_repeated.items()
            }
            if benign_grid:
                benign_grids.append((sorted(benign_grid), benign_grid))

        rng = _bootstrap_rng(seed, model, attack, condition)
        attack_draws: list[float] = []
        benign_draws: list[float] = []
        for _ in range(samples):
            attack_sum = 0.0
            attack_total = 0
            for users, injections, grid in attack_grids:
                drawn_users = rng.choices(users, k=len(users))
                drawn_injections = rng.choices(injections, k=len(injections))
                attack_sum += sum(
                    grid[(user, injection)]
                    for user in drawn_users
                    for injection in drawn_injections
                )
                attack_total += len(drawn_users) * len(drawn_injections)
            if attack_total:
                attack_draws.append(attack_sum / attack_total)

            benign_sum = 0.0
            benign_total = 0
            for users, grid in benign_grids:
                drawn_users = rng.choices(users, k=len(users))
                benign_sum += sum(grid[user] for user in drawn_users)
                benign_total += len(drawn_users)
            if benign_total:
                benign_draws.append(benign_sum / benign_total)

        intervals[(model, attack, condition)] = {
            "bootstrap_seed": seed,
            "bootstrap_samples": samples,
            "asr_crossed_cluster_ci_low": _percentile(attack_draws, 0.025),
            "asr_crossed_cluster_ci_high": _percentile(attack_draws, 0.975),
            "asr_user_clusters": sum(len(users) for users, _, _ in attack_grids),
            "asr_injection_clusters": sum(
                len(injections) for _, injections, _ in attack_grids
            ),
            "benign_user_cluster_ci_low": _percentile(benign_draws, 0.025),
            "benign_user_cluster_ci_high": _percentile(benign_draws, 0.975),
            "benign_user_clusters": sum(len(users) for users, _ in benign_grids),
            "benign_utility_difference": (
                sum(sum(grid.values()) for _, grid in benign_grids)
                / sum(len(grid) for _, grid in benign_grids)
                if benign_grids
                else None
            ),
        }
    return intervals


def paired_effects_overall(
    root: str | Path,
    *,
    bootstrap_samples: int = 10_000,
    bootstrap_seed: int = 17_229,
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for effect in paired_effects(root):
        grouped[(effect["model"], effect["attack"], effect["condition"])].append(
            effect
        )
    interval_rows = _paired_cluster_intervals(
        root, samples=bootstrap_samples, seed=bootstrap_seed
    )
    overall = []
    for (model, attack, condition), effects in sorted(grouped.items()):
        pairs = sum(effect["pairs"] for effect in effects)
        only_a = sum(effect["direct_only_successes"] for effect in effects)
        only_b = sum(effect["defended_only_successes"] for effect in effects)
        row = {
                "model": model,
                "suite": "ALL",
                "attack": attack,
                "condition": condition,
                "pairs": pairs,
                "asr_difference": (only_b - only_a) / pairs if pairs else None,
                "direct_only_successes": only_a,
                "defended_only_successes": only_b,
                "mcnemar_p": _exact_mcnemar_p(only_a, only_b),
            }
        row.update(interval_rows.get((model, attack, condition), {}))
        overall.append(row)
    return overall


def _percent(cell: dict[str, Any]) -> str:
    if cell["rate"] is None:
        return "n/a"
    return (
        f"{100 * cell['rate']:.1f}% ({cell['hits']}/{cell['total']}; "
        f"95% CI {100 * cell['ci_low']:.1f}-{100 * cell['ci_high']:.1f}%)"
    )


def write_outputs(root: str | Path, out: str | Path) -> None:
    rows = collect(root)
    if not rows:
        raise SystemExit(f"no AgentDojo-family results.json files under {root}")
    effects = paired_effects(root)
    overall = collect_overall(root)
    overall_effects = paired_effects_overall(root)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(
            {
                "overall": overall,
                "results": rows,
                "overall_paired_effects": overall_effects,
                "paired_effects": effects,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    flat = [
        {
            "model": row["model"],
            "suite": row["suite"],
            "attack": row["attack"],
            "condition": row["condition"],
            "repetitions": row["repetitions"],
            "attack_success_rate": row["attack_success"]["rate"],
            "attack_success_valid_injection_subset": row[
                "attack_success_valid_injection_subset"
            ]["rate"],
            "utility_under_attack": row["utility_under_attack"]["rate"],
            "benign_utility": row["benign_utility"]["rate"],
            "attack_intervention_rate": row["attack_intervention"]["rate"],
            "benign_intervention_rate": row["benign_intervention"]["rate"],
            "attacked_gate_prompts": row["attacked_gate_prompts"],
            "benign_gate_prompts": row["benign_gate_prompts"],
            "model_calls": row["model_calls"],
            "provider_attempts": row["provider_attempts"],
            "rate_limit_retries": row["rate_limit_retries"],
            "prompt_tokens": row["prompt_tokens"],
            "completion_tokens": row["completion_tokens"],
            "model_seconds": row["model_seconds"],
            "rate_limit_wait_seconds": row["rate_limit_wait_seconds"],
            "trace_errors": row["trace_errors"],
        }
        for row in [*overall, *rows]
    ]
    with (out / "summary.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(flat[0]))
        writer.writeheader()
        writer.writerows(flat)

    table_header = (
        "| model | suite | condition | attack success | utility under attack | "
        "benign utility | valid-goal ASR | attack intervention | benign intervention | errors |"
    )
    table_separator = "|---|---|---|---|---|---|---|---|---|---:|"
    lines = [
        "# External benchmark summary",
        "",
        (
            "Lower attack success is better; higher utility is better. Wilson intervals are "
            "descriptive. Overall effect intervals use a predeclared two-way cluster "
            "bootstrap over user and injection tasks; benign-utility intervals cluster "
            "over user tasks. Exact McNemar tests are descriptive."
        ),
        "",
        "## Overall",
        "",
        table_header,
        table_separator,
    ]
    for row in overall:
        lines.append(
            f"| `{row['model']}` | `{row['suite']}` | `{row['condition']}` "
            f"| {_percent(row['attack_success'])} | {_percent(row['utility_under_attack'])} "
            f"| {_percent(row['benign_utility'])} "
            f"| {_percent(row['attack_success_valid_injection_subset'])} "
            f"| {_percent(row['attack_intervention'])} "
            f"| {_percent(row['benign_intervention'])} | {row['trace_errors']} |"
        )
    lines += ["", "### Overall paired effects against direct", ""]
    for effect in overall_effects:
        asr_ci = (
            f"95% crossed-cluster CI "
            f"{100 * effect['asr_crossed_cluster_ci_low']:+.1f} to "
            f"{100 * effect['asr_crossed_cluster_ci_high']:+.1f} points"
        )
        benign = effect.get("benign_utility_difference")
        benign_text = ""
        if benign is not None:
            benign_text = (
                f" Benign utility {100 * benign:+.1f} points "
                f"(95% user-cluster CI "
                f"{100 * effect['benign_user_cluster_ci_low']:+.1f} to "
                f"{100 * effect['benign_user_cluster_ci_high']:+.1f})."
            )
        lines.append(
            f"- `{effect['condition']}`: ASR {100 * effect['asr_difference']:+.1f} points "
            f"over {effect['pairs']} pairs ({asr_ci}); direct-only breaches "
            f"{effect['direct_only_successes']}, defended-only breaches "
            f"{effect['defended_only_successes']}; descriptive exact McNemar "
            f"p={effect['mcnemar_p']:.4f}.{benign_text}"
        )
    lines += ["", "## Per-suite results", "", table_header, table_separator]
    for row in rows:
        lines.append(
            f"| `{row['model']}` | `{row['suite']}` | `{row['condition']}` "
            f"| {_percent(row['attack_success'])} | {_percent(row['utility_under_attack'])} "
            f"| {_percent(row['benign_utility'])} "
            f"| {_percent(row['attack_success_valid_injection_subset'])} "
            f"| {_percent(row['attack_intervention'])} "
            f"| {_percent(row['benign_intervention'])} | {row['trace_errors']} |"
        )
    lines += ["", "### Per-suite paired effects against direct", ""]
    for effect in effects:
        lines.append(
            f"- `{effect['suite']}` / `{effect['condition']}`: "
            f"ASR {100 * effect['asr_difference']:+.1f} points over {effect['pairs']} pairs; "
            f"direct-only breaches {effect['direct_only_successes']}, "
            f"defended-only breaches {effect['defended_only_successes']}; "
            f"exact McNemar p={effect['mcnemar_p']:.4f}."
        )
    (out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="aggregate external benchmark receipts")
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    write_outputs(args.root, args.out)


if __name__ == "__main__":
    main()
