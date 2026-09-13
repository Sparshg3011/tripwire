import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "review_audit", Path(__file__).resolve().parents[1] / "scripts/audit_review_development.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def fixture(root):
    selection = {"slack": {"user_tasks": ["user_task_1"], "injection_tasks": ["injection_task_1"]}}
    for condition in audit.CONDITIONS:
        directory = root / "slack" / condition
        (directory / "traces").mkdir(parents=True)
        benign = {"user_task": "user_task_1", "injection_task": "", "value": True}
        attacked = {**benign, "injection_task": "injection_task_1", "value": False}
        run = {
            "trace_errors": [],
            "benign_results": [benign],
            "attack_results": [attacked],
            "attacked_utility_results": [{**attacked, "value": True}],
            "injection_task_utility_results": [
                {"injection_task": "injection_task_1", "value": True}
            ],
        }
        (directory / "results.json").write_text(
            json.dumps({"condition": condition, "suite": "slack", "runs": [run]})
        )
        for n, (user, injection) in enumerate(
            [("user_task_1", None), ("user_task_1", "injection_task_1"), ("injection_task_1", None)]
        ):
            (directory / "traces" / f"{n}.json").write_text(
                json.dumps(
                    {
                        "suite_name": "slack",
                        "user_task_id": user,
                        "injection_task_id": injection,
                        "utility": True,
                        "security": False,
                        "error": None,
                        "tripwire_enforcement": {"task_id": user, "events": []},
                    }
                )
            )
    return selection


def test_equal_totals_do_not_mean_baseline_tasks_retained():
    result = audit.paired_retention({"a": True, "b": False}, {"a": False, "b": True})
    assert result["retention"] == 0 and result["lost"] == result["gained"] == 1


def test_zero_baseline_does_not_produce_a_fake_ratio():
    assert audit.paired_retention({"a": False}, {"a": True})["retention"] is None


def test_complete_trace_backed_audit(tmp_path):
    result = audit.audit(tmp_path, fixture(tmp_path))
    assert len(result["artifact_sha256"]) == 12
    assert result["attack_relative_reduction"] is None


def test_single_condition_does_not_invent_a_control(tmp_path):
    selection = fixture(tmp_path)
    result = audit.audit(
        tmp_path / "slack/tripwire-review", selection, conditions=("tripwire-review",), flat=True
    )
    assert len(result["artifact_sha256"]) == 4
    assert "paired_retention" not in result


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "duplicate",
        "changed",
        "error",
        "review_error",
        "extra_row",
        "missing_receipt",
        "unreviewed_gate",
        "denied_but_executed",
    ],
)
def test_corrupted_evidence_rejected(tmp_path, mutation):
    selection = fixture(tmp_path)
    directory = tmp_path / "slack/tripwire-review"
    path = directory / "traces/0.json"
    data = json.loads(path.read_text())
    if mutation == "missing":
        path.unlink()
    elif mutation == "duplicate":
        (directory / "traces/duplicate.json").write_text(json.dumps(data))
    elif mutation == "extra_row":
        path = directory / "results.json"
        data = json.loads(path.read_text())
        data["runs"][0]["benign_results"] *= 2
        path.write_text(json.dumps(data))
    else:
        if mutation == "changed":
            data["utility"] = False
        elif mutation == "error":
            data["error"] = "timeout"
        elif mutation == "missing_receipt":
            del data["tripwire_enforcement"]
        elif mutation in {"unreviewed_gate", "denied_but_executed"}:
            data["tripwire_enforcement"]["events"] = [
                {
                    "decision": "gate",
                    "executed": True,
                    "review": None
                    if mutation == "unreviewed_gate"
                    else {"status": "reviewed", "approved": False},
                }
            ]
        else:
            data["tripwire_enforcement"]["events"] = [{"review": {"status": "provider_error"}}]
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        audit.audit(tmp_path, selection)
