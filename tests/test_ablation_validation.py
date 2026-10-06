"""A complete aggregate must not conceal missing, duplicated, or failed cases."""

import json
import runpy
from dataclasses import asdict
from pathlib import Path

import pytest

from tripwire_gym.ablations import COMPONENTS, generate
from tripwire_gym.manifest import fingerprint, sha256_file
from tripwire_gym.publication import write_outputs
from tripwire_gym.resources import GYM
from tripwire_gym.runner import RunResult
from tripwire_gym.scenario import load_corpus
from tripwire_gym.scoring import Outcome

validate = runpy.run_path(str(Path(__file__).parents[1] / "scripts" / "validate_ablation.py"))[
    "validate"
]


@pytest.fixture
def matrix(tmp_path):
    generate(GYM / "policies" / "standard.yaml", tmp_path / "generated-policies")
    corpus = fingerprint((GYM / "scenarios").glob("*.yaml"))
    for bracket in ("approve", "deny"):
        for group in ("full", "leave-one-out"):
            conditions = (
                ["standard"]
                if group == "full"
                else [f"loo-no-{component}" for component in COMPONENTS]
            )
            batch = tmp_path / bracket / group
            batch.mkdir(parents=True)
            rows = [
                asdict(
                    RunResult(
                        scenario_id=scenario.id,
                        condition=condition,
                        seed=0,
                        repetition=0,
                        outcome=Outcome(
                            scenario.id, scenario.family, scenario.attack, False, True, 0, 0
                        ),
                    )
                )
                for condition in conditions
                for scenario in load_corpus(GYM / "scenarios")
            ]
            results = batch / "results.jsonl"
            results.write_text("".join(json.dumps(row) + "\n" for row in rows))
            policy_dir = GYM / "policies" if group == "full" else tmp_path / "generated-policies"
            manifest = {
                "run_id": f"{bracket}-{group}",
                "source": {"git_commit": "fixture", "git_dirty": False},
                "corpus": corpus,
                "policies": fingerprint(policy_dir / f"{c}.yaml" for c in conditions),
                "settings": {
                    "agent": "scripted",
                    "runs": 1,
                    "human": bracket,
                    "conditions": ",".join(conditions),
                    "prompt_profile": "plain",
                },
                "results": {"sha256": sha256_file(results), "runs": len(rows)},
            }
            (batch / "manifest.json").write_text(json.dumps(manifest))
    write_outputs(tmp_path, tmp_path / "summary")
    return tmp_path


def test_complete_matrix_has_912_unique_runs(matrix):
    receipt = validate(matrix)
    assert receipt["complete"]
    assert receipt["observed_runs"] == receipt["expected_runs"] == 912
    assert receipt["cells"] == 12


@pytest.mark.parametrize(
    "damage, message",
    [
        ("duplicate", "duplicate episode"),
        ("missing", "missing or extra episode"),
        ("error", "errored episode"),
    ],
)
def test_valid_hashes_and_regenerated_metrics_do_not_hide_bad_cases(matrix, damage, message):
    results = matrix / "approve" / "full" / "results.jsonl"
    rows = [json.loads(line) for line in results.read_text().splitlines()]
    if damage == "duplicate":
        rows[-1] = rows[0]
    elif damage == "missing":
        rows.pop()
    else:
        rows[0]["error"] = "simulated runner failure"
        rows[0]["outcome"]["errored"] = True
    results.write_text("".join(json.dumps(row) + "\n" for row in rows))
    manifest_path = results.with_name("manifest.json")
    manifest = json.loads(manifest_path.read_text())
    manifest["results"].update(sha256=sha256_file(results), runs=len(rows))
    manifest_path.write_text(json.dumps(manifest))
    write_outputs(matrix, matrix / "summary")
    with pytest.raises(ValueError, match=message):
        validate(matrix)
