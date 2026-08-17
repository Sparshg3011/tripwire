"""Run AutoDojo's adaptive optimizer against Tripwire using NVIDIA NIM."""

from __future__ import annotations

import argparse
import json
import os
import runpy
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from tripwire_benchmarks.agentdojo import NVIDIA_BASE_URL

PROFILES = {
    "smoke": {"n_variants": 2, "iterations": 1, "max_injection_tasks": 1},
    "feasible": {"n_variants": 3, "iterations": 4, "max_injection_tasks": None},
    "paper": {"n_variants": 5, "iterations": 8, "max_injection_tasks": None},
}


def _git_revision(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.stdout.strip() if completed.returncode == 0 else ""


def optimizer_argv(args) -> list[str]:
    profile = PROFILES[args.profile]
    values = [
        "--suite",
        args.suite,
        "--n-variants",
        str(profile["n_variants"]),
        "--iterations",
        str(profile["iterations"]),
        "--model",
        args.optimizer_model,
        "--provider",
        "nvidia",
        "--eval-asr",
        "--target-model",
        f"nim:{args.target_model}",
        "--defense",
        "tripwire",
        "--run-defense",
        "--analyzer-prompt",
        f"analyzer_{args.suite}",
        "--injection-prompt",
        f"injection_task_iterative_{args.suite}",
        "--store-traces",
    ]
    if profile["max_injection_tasks"] is not None:
        values += ["--max-injection-tasks", str(profile["max_injection_tasks"])]
    if args.resume:
        values.append("--resume")
    if args.dry_run:
        values.append("--dry-run")
    return values


def parse_args(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="adapt AutoDojo attacks to Tripwire")
    parser.add_argument("--autodojo-root", type=Path, required=True)
    parser.add_argument(
        "--suite",
        choices=["banking", "slack", "travel", "github", "shopping", "dailylife"],
        required=True,
    )
    parser.add_argument("--gate", choices=["approve", "deny"], required=True)
    parser.add_argument("--target-model", default="nvidia/nemotron-3-super-120b-a12b")
    parser.add_argument("--optimizer-model", default="z-ai/glm-5.2")
    parser.add_argument("--profile", choices=list(PROFILES), default="feasible")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not os.environ.get("NVIDIA_API_KEY"):
        raise SystemExit("NVIDIA_API_KEY is not set")
    root = args.autodojo_root.resolve()
    script = root / "agentdojo" / "variant_generation" / "optimize_variants.py"
    source = root / "agentdojo" / "src"
    variant_source = script.parent
    if not script.exists():
        raise SystemExit(f"not an AutoDojo checkout: {root}")

    args.out.mkdir(parents=True, exist_ok=True)
    os.environ["AGENTDOJO_DEFENSE_PLUGINS"] = "tripwire_benchmarks.autodojo_plugin"
    os.environ["TRIPWIRE_GATE"] = args.gate
    os.environ["AUTODOJO_OUTPUT_DIR"] = str(args.out.resolve())
    os.environ.setdefault("NVIDIA_BASE_URL", NVIDIA_BASE_URL)
    for path in (str(variant_source), str(source)):
        if path not in sys.path:
            sys.path.insert(0, path)

    # AutoDojo already supports arbitrary OpenAI-compatible providers through
    # this registry; add NIM without modifying its pinned checkout.
    import llm_utils

    llm_utils.PROVIDERS["nvidia"] = {
        "base_url": os.environ["NVIDIA_BASE_URL"],
        "api_key_env": "NVIDIA_API_KEY",
        "client_type": "openai",
    }

    forwarded = optimizer_argv(args)
    receipt = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "autodojo_commit": _git_revision(root),
        "suite": args.suite,
        "gate": args.gate,
        "target_model": args.target_model,
        "optimizer_model": args.optimizer_model,
        "profile": args.profile,
        "optimizer_arguments": forwarded,
    }
    (args.out / "tripwire-run.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    old_argv = sys.argv
    try:
        sys.argv = [str(script), *forwarded]
        runpy.run_path(str(script), run_name="__main__")
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    main()
