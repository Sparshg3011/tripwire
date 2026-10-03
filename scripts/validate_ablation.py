"""Audit the complete scripted full-minus-one matrix against raw run receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tripwire_gym.ablations import COMPONENTS
from tripwire_gym.publication import collect
from tripwire_gym.resources import GYM
from tripwire_gym.scenario import load_corpus


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(root: Path) -> dict:
    scenarios = {s.id: s for s in load_corpus(GYM / "scenarios")}
    require(len(scenarios) == 76, "expected the 76-scenario publication corpus")
    ablations = {f"loo-no-{component}" for component in COMPONENTS}
    expected_batches = {f"{b}/{p}" for b in ("approve", "deny") for p in ("full", "leave-one-out")}
    observed_batches = {str(p.parent.relative_to(root)) for p in root.rglob("manifest.json")}
    require(observed_batches == expected_batches, "missing or extra run batches")
    table, receipts = collect(root)
    summary = json.loads((root / "summary" / "summary.json").read_text())
    require(summary == {"results": table, "receipts": receipts}, "aggregate differs from raw runs")
    indexed = {row["condition"]: row for row in table}
    require(len(indexed) == len(table) == 12, "expected 12 unique policy/bracket cells")
    sources, corpora, checks = set(), set(), []
    for batch in sorted(expected_batches):
        bracket, group = batch.split("/")
        conditions = {"standard"} if group == "full" else ablations
        manifest_path = root / batch / "manifest.json"
        results_path = root / batch / "results.jsonl"
        manifest = json.loads(manifest_path.read_text())
        rows = [json.loads(line) for line in results_path.read_text().splitlines()]
        require(digest(results_path) == manifest["results"]["sha256"], f"{batch}: result hash")
        require(not manifest["source"]["git_dirty"], f"{batch}: dirty source tree")
        sources.add(manifest["source"]["git_commit"])
        corpora.add(manifest["corpus"]["sha256"])
        settings = manifest["settings"]
        require(settings["agent"] == "scripted" and settings["runs"] == 1, f"{batch}: agent/runs")
        require(settings["human"] == bracket, f"{batch}: approval bracket")
        require(set(settings["conditions"].split(",")) == conditions, f"{batch}: conditions")
        require(settings["prompt_profile"] == "plain", f"{batch}: prompt profile")
        for kind in ("corpus", "policies"):
            files = manifest[kind]["files"]
            observed = {Path(f["path"]).name for f in files}
            expected = (
                {p.name for p in (GYM / "scenarios").glob("*.yaml")}
                if kind == "corpus"
                else {f"{condition}.yaml" for condition in conditions}
            )
            require(len(files) == len(observed) and observed == expected, f"{batch}: {kind} files")
            for entry in files:
                base = (
                    GYM / "scenarios"
                    if kind == "corpus"
                    else (GYM / "policies" if group == "full" else root / "generated-policies")
                )
                require(
                    digest(base / Path(entry["path"]).name) == entry["sha256"],
                    f"{batch}: {kind} hash",
                )
        expected_keys = {
            (condition, scenario, 0) for condition in conditions for scenario in scenarios
        }
        keys = [(r["condition"], r["scenario_id"], r["repetition"]) for r in rows]
        require(len(keys) == len(set(keys)), f"{batch}: duplicate episode")
        require(set(keys) == expected_keys, f"{batch}: missing or extra episode")
        require(len(rows) == manifest["results"]["runs"], f"{batch}: manifest count")
        for row in rows:
            outcome = row["outcome"]
            require(not row["error"] and not outcome["errored"], f"{batch}: errored episode")
            require(row["model_calls"] == 0, f"{batch}: unexpected model call")
            require(outcome["scenario_id"] == row["scenario_id"], f"{batch}: outcome ID")
            require(
                outcome["attacked"] == scenarios[row["scenario_id"]].attack,
                f"{batch}: attack label",
            )
            for key in ("attack_succeeded", "task_completed", "attacked"):
                require(type(outcome[key]) is bool, f"{batch}: missing or invalid {key}")
        for condition in sorted(conditions):
            outcomes = [r["outcome"] for r in rows if r["condition"] == condition]
            attacks = [o for o in outcomes if o["attacked"]]
            benign = [o for o in outcomes if not o["attacked"]]
            require(len(attacks) == len(benign) == 38, f"{batch}/{condition}: denominators")
            aggregate = indexed[f"plain/{condition}/gate-{bracket}"]
            for metric, cases, field in (
                ("attack_success", attacks, "attack_succeeded"),
                ("utility_under_attack", attacks, "task_completed"),
                ("benign_utility", benign, "task_completed"),
            ):
                hits = sum(case[field] for case in cases)
                cell = aggregate[metric]
                require(
                    (cell["hits"], cell["total"], cell["rate"]) == (hits, 38, hits / 38),
                    f"{batch}/{condition}: {metric}",
                )
            checks.append(
                {
                    "bracket": bracket,
                    "condition": condition,
                    "runs": len(outcomes),
                    "attacks": 38,
                    "benign": 38,
                    "errors": 0,
                }
            )
    require(len(sources) == len(corpora) == 1, "mixed source commits or corpora")
    return {
        "schema_version": 1,
        "complete": True,
        "source_commit": sources.pop(),
        "corpus_sha256": corpora.pop(),
        "batches": 4,
        "cells": len(checks),
        "expected_runs": 912,
        "observed_runs": sum(cell["runs"] for cell in checks),
        "errors": 0,
        "checks": checks,
        "result_sha256": {
            batch: digest(root / batch / "results.jsonl") for batch in sorted(expected_batches)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--out", type=Path, help="write a machine-readable completeness receipt")
    args = parser.parse_args()
    receipt = validate(args.root)
    if args.out:
        args.out.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(
        "Ablation validated: 912 unique episodes, 12 cells, zero errors; hashes and metrics match"
    )


if __name__ == "__main__":
    main()
