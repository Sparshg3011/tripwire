import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "utility_diagnosis", Path(__file__).parents[1] / "scripts" / "diagnose_agentdojo_utility.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def save(root, condition, task, completed, *, blocked=False, suffix=""):
    path = root / "banking" / condition / "traces" / "benign" / f"{task}{suffix}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    trace = {
        "suite_name": "banking",
        "user_task_id": task,
        "injection_task_id": None,
        "utility": completed,
        "error": None,
    }
    if condition == "tripwire-deny":
        trace["tripwire_enforcement"] = {
            "task_id": task,
            "task_kind": "user",
            "events": [
                {
                    "tool": "send_money",
                    "rule": "flows[0]",
                    "decision": "gate",
                    "executed": False,
                }
            ]
            if blocked
            else [],
        }
    path.write_text(json.dumps(trace))
    return path


def fixture(root):
    for task, direct, strict, blocked in [
        ("one", True, False, True),
        ("two", True, False, False),
        ("three", False, True, False),
        ("four", True, True, False),
        ("five", False, False, True),
    ]:
        save(root, "direct", task, direct)
        save(root, "tripwire-deny", task, strict, blocked=blocked)


def test_pairs_not_net_difference_define_regressions(tmp_path):
    fixture(tmp_path)
    result = module.diagnose(tmp_path, 5)
    assert result["transitions"] == {
        "regressed": 2,
        "improved": 1,
        "both_complete": 1,
        "both_failed": 1,
    }
    assert result["direct_completed"] == 3
    assert result["strict_completed"] == 2
    assert result["regressions_with_intervention"] == 1
    assert result["regressions_without_intervention"] == 1
    assert result["intervened_cases"] == 2
    assert result["blocked_tools_in_regressions"] == {"send_money": 1}
    assert len(result["trace_sha256"]) == 10


def test_duplicate_condition_rejected(tmp_path):
    fixture(tmp_path)
    save(tmp_path, "direct", "one", True, suffix="-duplicate")
    with pytest.raises(ValueError, match="duplicate"):
        module.diagnose(tmp_path, 5)


def test_missing_pair_rejected(tmp_path):
    save(tmp_path, "direct", "one", True)
    with pytest.raises(ValueError, match="missing paired"):
        module.diagnose(tmp_path, 1)


@pytest.mark.parametrize("field,value", [("utility", None), ("utility", 1), ("error", "timeout")])
def test_partial_or_errored_trace_rejected(tmp_path, field, value):
    fixture(tmp_path)
    path = save(tmp_path, "direct", "one", True)
    data = json.loads(path.read_text())
    data[field] = value
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="incomplete or errored"):
        module.diagnose(tmp_path, 5)


def test_missing_enforcement_cannot_be_counted_as_no_intervention(tmp_path):
    fixture(tmp_path)
    path = save(tmp_path, "tripwire-deny", "one", False)
    data = json.loads(path.read_text())
    data.pop("tripwire_enforcement")
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="missing enforcement"):
        module.diagnose(tmp_path, 5)


def test_wrong_population_size_rejected(tmp_path):
    fixture(tmp_path)
    with pytest.raises(ValueError, match="expected 85 pairs"):
        module.diagnose(tmp_path)
