import json
from pathlib import Path

import yaml

from tripwire_benchmarks.study import HELDOUT_PLAN, cell_command, heldout_users, slug

PILOT = Path(__file__).resolve().parent.parent / "gym" / "agentdojo-pilot.yaml"


def test_heldout_users_are_the_85_and_never_a_development_user():
    plan = json.loads(HELDOUT_PLAN.read_text(encoding="utf-8"))
    pilot = yaml.safe_load(PILOT.read_text(encoding="utf-8"))
    total = 0
    for suite, spec in pilot["suites"].items():
        users = heldout_users(plan, suite)
        assert not set(users) & set(spec["user_tasks"])
        total += len(users)
    assert total == 85


def test_a_recipe_condition_runs_its_arm_on_the_shared_budget(tmp_path):
    command = cell_command(
        "py", "agentdyn", "github", "tripwire-deny/primary", "m", tmp_path, tmp_path / "p", 7, []
    )
    assert command[command.index("--condition") + 1] == "tripwire-deny"
    assert command[command.index("--recipe") + 1] == "primary"
    assert command[command.index("--per-minute") + 1] == "7"
    assert "--user-task" not in command


def test_the_detector_is_pinned_and_users_are_passed_through(tmp_path):
    command = cell_command(
        "py", "agentdojo", "slack", "transformers_pi_detector", "m", tmp_path, tmp_path, 7, ["u0"]
    )
    assert "--recipe" not in command
    assert "--protectai-model-revision" in command
    assert command[-2:] == ["--user-task", "u0"]


def test_slugs_are_path_safe():
    assert slug("nvidia/nemotron-3-super-120b-a12b") == "nvidia_nemotron-3-super-120b-a12b"
    assert slug("tripwire-deny/primary") == "tripwire-deny_primary"
