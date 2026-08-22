import json

import pytest

pytest.importorskip(
    "agentdojo",
    reason="Held-out planning tests require the publication extra",
)

from tripwire_benchmarks.heldout import (
    DEVELOPMENT_USERS,
    EXPECTED_HELDOUT_CASES,
    HeldoutError,
    _authorize_transport_resume,
    build_plan,
    require_frozen_protocol,
    validate_results,
)


def test_heldout_plan_excludes_every_development_user():
    plan = build_plan(shard_size=7)

    assert plan["heldout_attack_pairs"] == EXPECTED_HELDOUT_CASES
    assert plan["heldout_user_tasks"] == 85
    for suite, development_users in DEVELOPMENT_USERS.items():
        heldout = set(plan["suites"][suite]["heldout_users"])
        assert heldout.isdisjoint(development_users)


def test_heldout_selection_hash_does_not_depend_on_shard_size_or_clock():
    small = build_plan(shard_size=3)
    large = build_plan(shard_size=11)

    assert small["selection_sha256"] == large["selection_sha256"]

    # Sharding is an execution detail. The selected cases are identical.
    for suite in small["suites"]:
        assert small["suites"][suite]["heldout_users"] == large["suites"][suite]["heldout_users"]
        assert (
            small["suites"][suite]["injection_tasks"] == large["suites"][suite]["injection_tasks"]
        )


def test_default_scale_yields_one_job_per_suite():
    plan = build_plan(shard_size=100)

    assert all(len(row["shards"]) == 1 for row in plan["suites"].values())


def test_committed_heldout_protocol_matches_runner_contract():
    require_frozen_protocol(
        model="nvidia/nemotron-3-super-120b-a12b",
        conditions=["direct", "tripwire-deny"],
        workers=1,
    )


def test_completeness_receipt_rejects_missing_results(tmp_path):
    plan = build_plan(shard_size=100)

    try:
        validate_results(
            tmp_path,
            plan,
            conditions=["direct", "tripwire-deny"],
            model="nvidia/m",
        )
    except HeldoutError as exc:
        assert "incomplete" in str(exc)
    else:
        raise AssertionError("missing results should not pass completeness validation")

    assert (tmp_path / "COMPLETENESS.json").exists()


def test_transport_only_source_change_requires_and_records_explicit_resume(tmp_path):
    planned = {"git_commit": "a" * 40, "git_dirty": False}
    current = {"git_commit": "b" * 40, "git_dirty": False}

    try:
        _authorize_transport_resume(
            tmp_path,
            planned_source=planned,
            current_source=current,
            contract_sha256="contract",
            allow=False,
        )
    except HeldoutError as exc:
        assert "--allow-transport-resume" in str(exc)
    else:
        raise AssertionError("source transition should require explicit authorization")

    _authorize_transport_resume(
        tmp_path,
        planned_source=planned,
        current_source=current,
        contract_sha256="contract",
        allow=True,
    )
    receipt = json.loads((tmp_path / "TRANSPORT-RESUME.json").read_text())
    assert receipt["planned_source"] == planned
    assert receipt["resume_source"] == current
    assert receipt["contract_sha256"] == "contract"

    # A restart from the same audited checkout no longer needs the flag.
    _authorize_transport_resume(
        tmp_path,
        planned_source=planned,
        current_source=current,
        contract_sha256="contract",
        allow=False,
    )
