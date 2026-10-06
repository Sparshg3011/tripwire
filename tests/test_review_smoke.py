import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "review_smoke", Path(__file__).resolve().parents[1] / "scripts/run_review_smoke.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_fixed_free_commands(tmp_path):
    jobs = module.commands(tmp_path)
    assert len(jobs) == 3
    for condition, command in zip(module.CONDITIONS, jobs, strict=True):
        assert command[command.index("--condition") + 1] == condition
        assert command[command.index("--base-url") + 1] == "https://integrate.api.nvidia.com/v1"
        assert command[command.index("--user-task") + 1] == "user_task_3"
        assert command[command.index("--injection-task") + 1] == "injection_task_5"


def fixture_results(tmp_path):
    for condition in module.CONDITIONS:
        directory = tmp_path / condition
        directory.mkdir()
        run = {"trace_errors": [], "review_errors": 0}
        for field in ("benign_results", "attack_results", "attacked_utility_results"):
            run[field] = [
                {
                    "user_task": "user_task_3",
                    "injection_task": "" if field == "benign_results" else "injection_task_5",
                    "value": False,
                }
            ]
        run["injection_task_utility_results"] = [
            {"injection_task": "injection_task_5", "value": True}
        ]
        (directory / "results.json").write_text(json.dumps({"runs": [run], "summary": {}}))


def test_failures_are_valid_outcomes(tmp_path):
    fixture_results(tmp_path)
    assert len(module.validate(tmp_path)["summaries"]) == 3


@pytest.mark.parametrize("mutation", ["missing", "wrong_task", "error", "non_boolean"])
def test_incomplete_or_invalid_comparison_rejected(tmp_path, mutation):
    fixture_results(tmp_path)
    path = tmp_path / "tripwire-review" / "results.json"
    data = json.loads(path.read_text())
    run = data["runs"][0]
    if mutation == "missing":
        run["benign_results"] = []
    elif mutation == "wrong_task":
        run["attack_results"][0]["user_task"] = "user_task_4"
    elif mutation == "error":
        run["trace_errors"] = [{"error": "provider_error"}]
    else:
        run["attack_results"][0]["value"] = None
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        module.validate(tmp_path)
