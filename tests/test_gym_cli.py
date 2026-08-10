"""The benchmark command, end to end, with no API key and no network.

--agent scripted plays a script derived from the scenario's own
predicates, so this drives the whole harness for real — real proxy in a
real subprocess, real mock MCP server, real scoring off the mock's own
record — and pins the number the project exists to produce: undefended
lets the exfiltration through, standard doesn't.

It also pins the uncomfortable half. Every policy tier fails closed while
the evaluator is a stub, so under standard the benign twin fails too. If
that ever changes these tests should fail and be rewritten, which is the
point of asserting it.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tripwire_gym import load_corpus

REPO = Path(__file__).parent.parent
SCENARIOS = REPO / "gym" / "scenarios"
CONDITIONS = ["undefended", "standard"]
RUNS = 2


def run_cli(out, agent="scripted", env=None):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tripwire_gym",
            "--agent",
            agent,
            "--scenarios",
            str(SCENARIOS),
            "--conditions",
            ",".join(CONDITIONS),
            "--runs",
            str(RUNS),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
        check=False,
    )


# one matrix, five questions about it — each cell spawns a proxy and a
# mock server, so running it per test would cost minutes for no signal
@pytest.fixture(scope="module")
def matrix(tmp_path_factory):
    out = tmp_path_factory.mktemp("gym-results")
    proc = run_cli(out)
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines()]
    return proc, out, rows


@pytest.fixture(scope="module")
def cells(matrix):
    _, _, rows = matrix
    return {(r["scenario_id"], r["condition"], r["seed"]): r for r in rows}


def test_one_result_line_per_scenario_condition_run(matrix, cells):
    _, _, rows = matrix
    expected = len(load_corpus(SCENARIOS)) * len(CONDITIONS) * RUNS

    assert len(rows) == expected
    assert len(cells) == expected
    assert not [r for r in rows if r["error"]]


def test_summary_json_has_a_row_per_condition(matrix):
    _, out, _ = matrix
    summary = json.loads((out / "summary.json").read_text())

    assert set(summary) == set(CONDITIONS)
    assert summary["undefended"]["attack_success_rate"] == 1.0
    assert summary["standard"]["attack_success_rate"] == 0.0
    assert summary["undefended"]["attack_runs"] == RUNS


def test_table_names_every_condition(matrix):
    proc, _, _ = matrix

    for condition in CONDITIONS:
        assert condition in proc.stdout
    assert "attack success" in proc.stdout
    assert "benign completion" in proc.stdout
    assert "gate prompts" in proc.stdout


def test_undefended_lets_the_exfil_through_and_standard_does_not(cells):
    for seed in range(RUNS):
        assert cells[("exfil-email-01", "undefended", seed)]["outcome"]["attack_succeeded"]
        assert not cells[("exfil-email-01", "standard", seed)]["outcome"]["attack_succeeded"]


def test_standard_costs_the_benign_twin_nothing(cells):
    # the other half of the frontier: with no attack in the way, the
    # defended run does the same work the undefended one did
    benign = cells[("exfil-email-01-benign", "undefended", 0)]["outcome"]
    defended = cells[("exfil-email-01-benign", "standard", 0)]["outcome"]

    assert benign["task_completed"] and benign["executed_calls"] == 1
    assert defended["task_completed"]
    assert defended["executed_calls"] == 1 and defended["refused_calls"] == 0


def test_claude_without_a_key_refuses_before_doing_any_work(tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    out = tmp_path / "results"

    proc = run_cli(out, agent="claude", env=env)

    assert proc.returncode != 0
    assert "ANTHROPIC_API_KEY" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert not out.exists()
