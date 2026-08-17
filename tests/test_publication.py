import json
from dataclasses import asdict

from tripwire_gym.publication import collect, markdown, write_outputs
from tripwire_gym.runner import RunResult
from tripwire_gym.scoring import Outcome


def _run(scenario, condition, attacked, attack_succeeded, completed, gates=0):
    return RunResult(
        scenario_id=scenario,
        condition=condition,
        seed=0,
        outcome=Outcome(
            scenario_id=scenario,
            family="exfiltration",
            attacked=attacked,
            attack_succeeded=attack_succeeded,
            task_completed=completed,
            executed_calls=1,
            refused_calls=0,
            gate_prompts=gates,
        ),
        prompt_tokens=11,
        completion_tokens=3,
        wall_seconds=2.0,
        model_seconds=1.0,
    )


def _receipt(path, condition="undefended", human="none"):
    path.mkdir()
    rows = [
        _run("attack-1", condition, True, True, True, gates=2),
        _run("attack-1-benign", condition, False, False, True),
    ]
    (path / "results.jsonl").write_text(
        "".join(json.dumps(asdict(row)) + "\n" for row in rows), encoding="utf-8"
    )
    (path / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": path.name,
                "settings": {
                    "model": "nvidia/test-model",
                    "prompt_profile": "plain",
                    "human": human,
                },
                "source": {"git_commit": "abc123", "git_dirty": False},
                "corpus": {"sha256": "corpus-hash"},
            }
        ),
        encoding="utf-8",
    )


def test_collect_groups_immutable_receipts_and_tracks_cost(tmp_path):
    _receipt(tmp_path / "one")
    _receipt(tmp_path / "two")

    table, receipts = collect(tmp_path)

    assert len(table) == 1
    assert table[0]["runs"] == 4
    assert table[0]["attack_success"]["rate"] == 1.0
    assert table[0]["utility_under_attack"]["rate"] == 1.0
    assert table[0]["benign_utility"]["rate"] == 1.0
    assert table[0]["prompt_tokens"] == 44
    assert len(receipts) == 2


def test_markdown_keeps_the_whole_row_when_gate_count_is_missing():
    row = {
        "model": "m",
        "condition": "plain/direct",
        "errors": 0,
        "attack_success": {"hits": 0, "total": 0, "rate": None},
        "utility_under_attack": {"hits": 0, "total": 0, "rate": None},
        "benign_utility": {"hits": 0, "total": 0, "rate": None},
        "gate_prompts_per_run": None,
    }

    report = markdown([row], [])

    assert "| `m` | `plain/direct` | n/a | n/a | n/a | n/a | 0 |" in report


def test_write_outputs_creates_json_csv_and_report(tmp_path):
    root = tmp_path / "runs"
    root.mkdir()
    _receipt(root / "one", condition="standard", human="approve")

    out = tmp_path / "publication"
    write_outputs(root, out)

    assert (out / "summary.json").exists()
    assert "gate-approve" in (out / "summary.csv").read_text()
    assert "Publication benchmark summary" in (out / "REPORT.md").read_text()
