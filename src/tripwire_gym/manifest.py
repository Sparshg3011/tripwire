"""A machine-readable receipt for a benchmark run.

Results without the exact corpus, policies, model settings, and source
revision are not reproducible results. This module records those inputs
without ever reading or writing an API key.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tripwire_gym.runner import RunResult
from tripwire_gym.scenario import load_scenario


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fingerprint(paths: Iterable[str | Path], root: str | Path | None = None) -> dict[str, Any]:
    """Hash files individually and as one order-independent collection."""
    files = sorted({Path(p).resolve() for p in paths})
    base = Path(root).resolve() if root is not None else None
    rows = []
    combined = hashlib.sha256()
    for path in files:
        name = (
            str(path.relative_to(base))
            if base is not None and path.is_relative_to(base)
            else str(path)
        )
        digest = sha256_file(path)
        rows.append({"path": name, "sha256": digest})
        combined.update(name.encode("utf-8"))
        combined.update(b"\0")
        combined.update(digest.encode("ascii"))
        combined.update(b"\n")
    return {"sha256": combined.hexdigest(), "files": rows}


def _git(repo: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _versions(names: Iterable[str]) -> dict[str, str]:
    versions = {}
    for name in names:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
    return versions


def build_manifest(
    *,
    repo: str | Path,
    scenarios: str | Path,
    policy_dir: str | Path,
    conditions: list[str],
    settings: dict[str, Any],
    results: list[RunResult],
    results_path: str | Path,
    scenario_ids: set[str] | None = None,
) -> dict[str, Any]:
    repo_path = Path(repo).resolve()
    scenario_dir = Path(scenarios).resolve()
    policies = [Path(policy_dir) / f"{condition}.yaml" for condition in conditions]
    policies = [p for p in policies if p.exists()]
    scenario_files = [
        p for p in scenario_dir.iterdir() if p.is_file() and p.suffix in {".yaml", ".yml"}
    ]
    if scenario_ids is not None:
        scenario_files = [p for p in scenario_files if load_scenario(p).id in scenario_ids]
    result_file = Path(results_path)
    dirty = bool(_git(repo_path, "status", "--porcelain"))

    manifest = {
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "benchmark": "tripwire-gym",
        "source": {
            "git_commit": _git(repo_path, "rev-parse", "HEAD"),
            "git_dirty": dirty,
        },
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "packages": _versions(
                ["tripwire-agent", "mcp", "pydantic", "openai", "anthropic", "agentdojo"]
            ),
        },
        "settings": settings,
        "corpus": fingerprint(scenario_files, root=repo_path),
        "policies": fingerprint(policies, root=repo_path),
        "results": {
            "runs": len(results),
            "errored_runs": sum(bool(r.error) for r in results),
            "sha256": sha256_file(result_file),
            "model_calls": sum(r.model_calls for r in results),
            "prompt_tokens": sum(r.prompt_tokens for r in results),
            "completion_tokens": sum(r.completion_tokens for r in results),
            "wall_seconds_sum": sum(r.wall_seconds for r in results),
            "model_seconds_sum": sum(r.model_seconds for r in results),
        },
    }
    # A short content ID makes it easy to match a chart to its receipt.
    stable = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest["run_id"] = hashlib.sha256(stable).hexdigest()[:16]
    return manifest


def write_manifest(manifest: dict[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    destination.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def public_settings(args: Any) -> dict[str, Any]:
    """The CLI namespace with only experiment settings, never credentials."""
    names = (
        "agent",
        "model",
        "base_url",
        "conditions",
        "runs",
        "concurrency",
        "timeout",
        "human",
        "prompt_profile",
        "temperature",
        "api_seed",
        "shuffle_seed",
        "disable_thinking",
        "max_tokens",
        "scenario",
    )
    return {name: getattr(args, name, None) for name in names}


def run_as_dict(result: RunResult) -> dict[str, Any]:
    """Kept here for external tools that want the canonical JSON shape."""
    return asdict(result)
