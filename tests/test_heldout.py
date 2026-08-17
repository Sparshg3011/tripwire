from tripwire_benchmarks.heldout import (
    DEVELOPMENT_USERS,
    EXPECTED_HELDOUT_CASES,
    HeldoutError,
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
        assert small["suites"][suite]["heldout_users"] == large["suites"][suite][
            "heldout_users"
        ]
        assert small["suites"][suite]["injection_tasks"] == large["suites"][suite][
            "injection_tasks"
        ]


def test_default_scale_yields_one_job_per_suite():
    plan = build_plan(shard_size=100)

    assert all(len(row["shards"]) == 1 for row in plan["suites"].values())


def test_committed_heldout_protocol_matches_runner_contract():
    require_frozen_protocol(
        model="nvidia/nemotron-3-super-120b-a12b",
        conditions=["direct", "tripwire-deny"],
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
