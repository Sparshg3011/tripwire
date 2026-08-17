from argparse import Namespace

from tripwire_benchmarks.autodojo import PROFILES, optimizer_argv
from tripwire_benchmarks.autodojo_plugin import (
    _enabled_as_plugin,
    _is_tripwire_pipeline,
    _tripwire_policy_path,
)


def _args(**overrides):
    values = {
        "suite": "banking",
        "gate": "approve",
        "target_model": "nvidia/target",
        "optimizer_model": "z-ai/writer",
        "profile": "feasible",
        "resume": False,
        "dry_run": False,
    }
    values.update(overrides)
    return Namespace(**values)


def test_optimizer_uses_nim_for_target_and_nvidia_for_writer():
    args = optimizer_argv(_args())

    assert args[args.index("--provider") + 1] == "nvidia"
    assert args[args.index("--target-model") + 1] == "nim:nvidia/target"
    assert args[args.index("--defense") + 1] == "tripwire"
    assert "--run-defense" in args


def test_profiles_make_the_budget_explicit():
    assert PROFILES["smoke"]["iterations"] < PROFILES["feasible"]["iterations"]
    assert PROFILES["feasible"]["iterations"] < PROFILES["paper"]["iterations"]
    args = optimizer_argv(_args(profile="smoke", resume=True, dry_run=True))
    assert args[args.index("--max-injection-tasks") + 1] == "1"
    assert "--resume" in args and "--dry-run" in args


def test_plugin_only_auto_installs_when_autodojo_requested_it(monkeypatch):
    monkeypatch.setenv("AGENTDOJO_DEFENSE_PLUGINS", "one,two")
    assert _enabled_as_plugin() is False
    monkeypatch.setenv(
        "AGENTDOJO_DEFENSE_PLUGINS", "one,tripwire_benchmarks.autodojo_plugin"
    )
    assert _enabled_as_plugin() is True


def test_plugin_finds_bundled_suite_policy(monkeypatch):
    monkeypatch.delenv("TRIPWIRE_POLICY", raising=False)
    monkeypatch.delenv("TRIPWIRE_POLICY_DIR", raising=False)
    assert _tripwire_policy_path("banking").name == "banking.yaml"
    assert _tripwire_policy_path("banking").exists()


def test_tripwire_pipeline_detection_is_exact():
    assert _is_tripwire_pipeline(Namespace(name="m/tripwire"))
    assert not _is_tripwire_pipeline(Namespace(name="m/no_defense"))
