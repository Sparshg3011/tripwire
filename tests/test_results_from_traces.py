import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from results_from_traces import rebuild

from tripwire_benchmarks.report import collect

PIPE = "local-m-none"


def _trace(root, kind, user, attack, injection, **fields):
    path = (
        root / "traces" / "repetition-0" / kind / PIPE / "s" / user / attack / f"{injection}.json"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "user_task_id": user,
        "injection_task_id": None if injection == "none" else injection,
        "attack_type": None if attack == "none" else attack,
        "error": None,
        **fields,
    }
    path.write_text(json.dumps(data), encoding="utf-8")


def test_scored_traces_become_a_result_the_report_reads(tmp_path):
    cell = tmp_path / "cell"
    _trace(cell, "benign", "u0", "none", "none", utility=True, security=True)
    _trace(cell, "benign", "u1", "none", "none", utility=False, security=True)
    _trace(cell, "attacked", "u0", "ii", "i0", utility=True, security=False)
    _trace(cell, "attacked", "u1", "ii", "i0", utility=False, security=True)
    _trace(cell, "attacked", "i0", "none", "none", utility=True, security=True)

    data = rebuild(cell, model="m", suite="s", condition="direct", recipe=None)
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "results.json").write_text(json.dumps(data), encoding="utf-8")
    [row] = collect(tmp_path / "out")

    assert row["benign_utility"]["hits"] == 1
    assert row["attack_success"]["hits"] == 1
    assert row["attack_success"]["total"] == 2
    assert data["runs"][0]["injection_task_utility_results"] == [
        {"injection_task": "i0", "value": True}
    ]


def test_a_task_cut_off_before_it_was_scored_is_left_out(tmp_path):
    cell = tmp_path / "cell"
    _trace(cell, "attacked", "u0", "ii", "i0", utility=False, security=True)
    _trace(cell, "attacked", "u1", "ii", "i0")
    _trace(cell, "attacked", "u2", "ii", "i0", utility=True, security=False, error="timeout")

    run = rebuild(cell, model="m", suite="s", condition="direct", recipe=None)["runs"][0]

    assert [r["user_task"] for r in run["attack_results"]] == ["u0"]


def test_a_recipe_arm_keeps_its_label(tmp_path):
    cell = tmp_path / "cell"
    _trace(cell, "benign", "u0", "none", "none", utility=True, security=True)
    data = rebuild(cell, model="m", suite="s", condition="tripwire-deny", recipe="primary")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "results.json").write_text(json.dumps(data), encoding="utf-8")

    assert collect(tmp_path / "out")[0]["condition"] == "tripwire-deny/primary"
