"""Run the frozen AgentDojo held-out matrix in resumable paired shards."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from tripwire_benchmarks.agentdojo import _source_state
from tripwire_benchmarks.report import collect, paired_effects_overall, write_outputs

BENCHMARK_VERSION = "v1.2.2"
EXPECTED = {
    "workspace": {"users": 40, "injections": 14},
    "banking": {"users": 16, "injections": 9},
    "slack": {"users": 21, "injections": 5},
    "travel": {"users": 20, "injections": 7},
}
DEVELOPMENT_USERS = {
    "workspace": {"user_task_13", "user_task_19", "user_task_27"},
    "banking": {"user_task_10", "user_task_3", "user_task_6"},
    "slack": {"user_task_1", "user_task_13", "user_task_14"},
    "travel": {"user_task_17", "user_task_18", "user_task_9"},
}
EXPECTED_HELDOUT_CASES = 844
MIN_CALL_INTERVAL_SECONDS = 2.0
RATE_LIMIT_RETRIES = 20
RETRY_BASE_SECONDS = 10.0
RETRY_CAP_SECONDS = 60.0
PRIMARY_CONDITION_ORDER = {
    "workspace": ["direct", "tripwire-deny"],
    "banking": ["tripwire-deny", "direct"],
    "slack": ["direct", "tripwire-deny"],
    "travel": ["tripwire-deny", "direct"],
}


class HeldoutError(RuntimeError):
    pass


def _authorize_transport_resume(
    root: Path,
    *,
    planned_source: dict[str, Any],
    current_source: dict[str, Any],
    contract_sha256: str,
    allow: bool,
) -> None:
    """Permit one clean, documented transport-only source transition."""
    if planned_source == current_source:
        return
    receipt_path = root / "TRANSPORT-RESUME.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if (
            receipt.get("planned_source") == planned_source
            and receipt.get("resume_source") == current_source
            and receipt.get("contract_sha256") == contract_sha256
        ):
            return
        raise HeldoutError("transport-resume receipt does not match this checkout")
    if not allow:
        raise HeldoutError(
            "existing held-out source state does not match this checkout; "
            "use --allow-transport-resume only for an audited transport-only fix"
        )
    if planned_source.get("git_dirty") or current_source.get("git_dirty"):
        raise HeldoutError("transport resume requires clean planned and current sources")
    trace_files = list(root.glob("**/traces/**/*.json"))
    failed_logs = []
    for path in sorted(root.glob("**/runner.log")):
        content = path.read_bytes()
        if b"Traceback (most recent call last)" in content:
            failed_logs.append(
                {
                    "path": str(path.relative_to(root)),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
    receipt = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "transport-only provider retry expansion; scientific contract unchanged",
        "contract_sha256": contract_sha256,
        "planned_source": planned_source,
        "resume_source": current_source,
        "checkpoint_trace_files": len(trace_files),
        "failed_runner_logs": failed_logs,
    }
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_frozen_protocol(*, model: str, conditions: list[str], workers: int) -> None:
    protocol_path = Path(__file__).resolve().parents[2] / "gym" / "agentdojo-heldout.yaml"
    protocol = yaml.safe_load(protocol_path.read_text(encoding="utf-8"))
    expected = protocol.get("expected", {})
    mismatches = []
    if protocol.get("status") != "frozen":
        mismatches.append("status is not frozen")
    if protocol.get("benchmark_version") != BENCHMARK_VERSION:
        mismatches.append("benchmark version changed")
    if protocol.get("target_model") != model:
        mismatches.append("target model changed")
    if protocol.get("conditions") != conditions:
        mismatches.append("conditions changed")
    if expected.get("heldout_attack_pairs") != EXPECTED_HELDOUT_CASES:
        mismatches.append("held-out pair count changed")
    if protocol.get("execution", {}).get("primary_condition_order") != (PRIMARY_CONDITION_ORDER):
        mismatches.append("condition order changed")
    transport = protocol.get("execution", {}).get("free_endpoint_transport", {})
    if transport != {
        "workers": workers,
        "min_call_interval_seconds": MIN_CALL_INTERVAL_SECONDS,
        "rate_limit_retries": RATE_LIMIT_RETRIES,
        "retry_base_seconds": RETRY_BASE_SECONDS,
        "retry_cap_seconds": RETRY_CAP_SECONDS,
    }:
        mismatches.append("free-endpoint transport changed")
    if mismatches:
        raise HeldoutError("protocol guard failed: " + ", ".join(mismatches))


def _numeric_task_key(task_id: str) -> tuple[str, int]:
    prefix, _, suffix = task_id.rpartition("_")
    return prefix, int(suffix)


def build_plan(shard_size: int) -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suite

    if shard_size < 1:
        raise ValueError("shard_size must be positive")
    suites = {}
    total_cases = 0
    for suite_name, expected in EXPECTED.items():
        suite = get_suite(BENCHMARK_VERSION, suite_name)
        if len(suite.user_tasks) != expected["users"]:
            raise HeldoutError(
                f"{suite_name} user-task count changed: "
                f"{len(suite.user_tasks)} != {expected['users']}"
            )
        if len(suite.injection_tasks) != expected["injections"]:
            raise HeldoutError(
                f"{suite_name} injection-task count changed: "
                f"{len(suite.injection_tasks)} != {expected['injections']}"
            )
        users = sorted(
            set(suite.user_tasks) - DEVELOPMENT_USERS[suite_name],
            key=_numeric_task_key,
        )
        injections = sorted(suite.injection_tasks, key=_numeric_task_key)
        shards = [users[index : index + shard_size] for index in range(0, len(users), shard_size)]
        cases = len(users) * len(injections)
        total_cases += cases
        suites[suite_name] = {
            "development_users_excluded": sorted(
                DEVELOPMENT_USERS[suite_name], key=_numeric_task_key
            ),
            "heldout_users": users,
            "injection_tasks": injections,
            "attack_pairs": cases,
            "shards": shards,
            "primary_condition_order": PRIMARY_CONDITION_ORDER[suite_name],
        }
    if total_cases != EXPECTED_HELDOUT_CASES:
        raise HeldoutError(
            f"held-out case count changed: {total_cases} != {EXPECTED_HELDOUT_CASES}"
        )
    plan = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "benchmark": "AgentDojo",
        "benchmark_version": BENCHMARK_VERSION,
        "selection": "all user tasks except frozen development-pilot users",
        "heldout_attack_pairs": total_cases,
        "heldout_user_tasks": sum(len(row["heldout_users"]) for row in suites.values()),
        "suites": suites,
    }
    selection = {
        suite: {
            "development_users_excluded": row["development_users_excluded"],
            "heldout_users": row["heldout_users"],
            "injection_tasks": row["injection_tasks"],
        }
        for suite, row in suites.items()
    }
    encoded = json.dumps(selection, sort_keys=True, separators=(",", ":"))
    plan["selection_sha256"] = hashlib.sha256(encoded.encode()).hexdigest()
    return plan


def _command(
    *,
    suite: str,
    condition: str,
    users: list[str],
    model: str,
    destination: Path,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "tripwire_benchmarks.agentdojo",
        "--suite",
        suite,
        "--benchmark-version",
        BENCHMARK_VERSION,
        "--model",
        model,
        "--condition",
        condition,
        "--attack",
        "important_instructions",
        "--repetitions",
        "1",
        "--temperature",
        "0",
        "--disable-thinking",
        "--min-call-interval",
        str(MIN_CALL_INTERVAL_SECONDS),
        "--rate-limit-retries",
        str(RATE_LIMIT_RETRIES),
        "--retry-base-seconds",
        str(RETRY_BASE_SECONDS),
        "--retry-cap-seconds",
        str(RETRY_CAP_SECONDS),
        "--out",
        str(destination),
    ]
    for user in users:
        command.extend(("--user-task", user))
    return command


def _run_shard(
    *,
    root: Path,
    suite: str,
    shard_index: int,
    users: list[str],
    conditions: list[str],
    model: str,
) -> str:
    completed = []
    preferred = PRIMARY_CONDITION_ORDER[suite]
    ordered_conditions = sorted(
        conditions,
        key=lambda condition: (
            preferred.index(condition) if condition in preferred else len(preferred),
            condition,
        ),
    )
    for condition in ordered_conditions:
        destination = root / suite / condition / f"shard-{shard_index:02d}"
        destination.mkdir(parents=True, exist_ok=True)
        command = _command(
            suite=suite,
            condition=condition,
            users=users,
            model=model,
            destination=destination,
        )
        process = subprocess.run(command, text=True, capture_output=True, check=False)
        (destination / "runner.log").write_text(process.stdout + process.stderr, encoding="utf-8")
        if process.returncode != 0:
            raise HeldoutError(
                f"{suite} shard {shard_index} {condition} failed with "
                f"exit {process.returncode}; see {destination / 'runner.log'}"
            )
        completed.append(condition)
    return f"{suite}/shard-{shard_index:02d}: {', '.join(completed)}"


def validate_results(
    root: Path,
    plan: dict[str, Any],
    *,
    conditions: list[str],
    model: str,
) -> dict[str, Any]:
    """Prove every predeclared case is present once and every trace succeeded."""
    rows = collect(root)
    indexed = {(row["model"], row["suite"], row["condition"]): row for row in rows}
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    for suite, suite_plan in plan["suites"].items():
        expected_attacks = int(suite_plan["attack_pairs"])
        expected_benign = len(suite_plan["heldout_users"])
        for condition in conditions:
            row = indexed.get((model, suite, condition))
            observed_attacks = row["attack_success"]["total"] if row else 0
            observed_benign = row["benign_utility"]["total"] if row else 0
            errors = row["trace_errors"] if row else 0
            complete = (
                observed_attacks == expected_attacks
                and observed_benign == expected_benign
                and errors == 0
            )
            check = {
                "suite": suite,
                "condition": condition,
                "expected_attack_pairs": expected_attacks,
                "observed_attack_pairs": observed_attacks,
                "expected_benign_tasks": expected_benign,
                "observed_benign_tasks": observed_benign,
                "trace_errors": errors,
                "complete": complete,
            }
            checks.append(check)
            if not complete:
                failures.append(f"{suite}/{condition}")

    paired = {
        (effect["model"], effect["condition"]): effect for effect in paired_effects_overall(root)
    }
    if {"direct", "tripwire-deny"} <= set(conditions):
        observed_pairs = paired.get((model, "tripwire-deny"), {}).get("pairs", 0)
        if observed_pairs != plan["heldout_attack_pairs"]:
            failures.append(f"paired comparison ({observed_pairs}/{plan['heldout_attack_pairs']})")

    receipt = {
        "schema_version": 1,
        "selection_sha256": plan["selection_sha256"],
        "complete": not failures,
        "failures": failures,
        "checks": checks,
    }
    (root / "COMPLETENESS.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if failures:
        raise HeldoutError("held-out result is incomplete: " + ", ".join(failures))
    return receipt


def run(args: argparse.Namespace) -> None:
    if not os.environ.get("NVIDIA_API_KEY"):
        raise SystemExit("NVIDIA_API_KEY is not set")
    conditions = [item.strip() for item in args.conditions.split(",") if item.strip()]
    allowed = {"direct", "tripwire-approve", "tripwire-deny"}
    if not conditions or not set(conditions) <= allowed:
        raise SystemExit(f"conditions must be comma-separated values from {sorted(allowed)}")
    require_frozen_protocol(model=args.model, conditions=conditions, workers=args.workers)
    plan = build_plan(args.shard_size)
    policies = {
        suite: hashlib.sha256(Path(f"gym/external_policies/{suite}.yaml").read_bytes()).hexdigest()
        for suite in plan["suites"]
    }
    contract = {
        "benchmark_version": BENCHMARK_VERSION,
        "selection_sha256": plan["selection_sha256"],
        "model": args.model,
        "attack": "important_instructions",
        "conditions": conditions,
        "temperature": 0,
        "thinking": "disabled",
        "repetitions": 1,
        "min_call_interval_seconds": MIN_CALL_INTERVAL_SECONDS,
        "rate_limit_retries": RATE_LIMIT_RETRIES,
        "retry_base_seconds": RETRY_BASE_SECONDS,
        "retry_cap_seconds": RETRY_CAP_SECONDS,
        "primary_condition_order": PRIMARY_CONDITION_ORDER,
        "policy_sha256": policies,
    }
    encoded_contract = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    plan["execution"] = contract
    plan["contract_sha256"] = hashlib.sha256(encoded_contract.encode()).hexdigest()
    plan["source"] = _source_state()
    root = Path(args.out)
    root.mkdir(parents=True, exist_ok=True)
    plan_path = root / "heldout-plan.json"
    if plan_path.exists():
        existing = json.loads(plan_path.read_text(encoding="utf-8"))
        if existing.get("contract_sha256") != plan["contract_sha256"]:
            raise HeldoutError("existing held-out contract does not match this invocation")
        _authorize_transport_resume(
            root,
            planned_source=existing.get("source", {}),
            current_source=plan["source"],
            contract_sha256=plan["contract_sha256"],
            allow=args.allow_transport_resume,
        )
    else:
        plan_path.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    jobs = [
        (suite, index, users)
        for suite, suite_plan in plan["suites"].items()
        for index, users in enumerate(suite_plan["shards"])
    ]
    executor = ThreadPoolExecutor(max_workers=args.workers)
    try:
        futures = {
            executor.submit(
                _run_shard,
                root=root,
                suite=suite,
                shard_index=index,
                users=users,
                conditions=conditions,
                model=args.model,
            ): (suite, index)
            for suite, index, users in jobs
        }
        for future in as_completed(futures):
            print(future.result(), flush=True)
    except BaseException:
        for future in futures:
            future.cancel()
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)

    write_outputs(root, root / "summary")
    validate_results(root, plan, conditions=conditions, model=args.model)
    print(f"Held-out report: {root / 'summary' / 'REPORT.md'}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="gym/results/agentdojo-heldout")
    parser.add_argument("--model", default="nvidia/nemotron-3-super-120b-a12b")
    parser.add_argument("--conditions", default="direct,tripwire-deny")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--allow-transport-resume",
        action="store_true",
        help="record and permit a clean transport-only source change on a frozen run",
    )
    parser.add_argument(
        "--shard-size",
        type=int,
        default=100,
        help="Users per suite job; 100 gives one resumable job per AgentDojo suite.",
    )
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be positive")
    if args.shard_size < 1:
        parser.error("--shard-size must be positive")
    return args


def main(argv: list[str] | None = None) -> None:
    try:
        run(parse_args(argv))
    except HeldoutError as exc:
        print(f"tripwire_benchmarks.heldout: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
