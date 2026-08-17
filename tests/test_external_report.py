import json

from tripwire_benchmarks.report import (
    collect,
    collect_overall,
    paired_effects,
    paired_effects_overall,
    write_outputs,
)


def _write(
    path,
    condition,
    attack_values,
    *,
    suite="banking",
    user_prefix="u",
    attacked_gated=0,
    benign_gated=0,
):
    path.mkdir(parents=True)
    pairs = [
        {
            "user_task": f"{user_prefix}{index}",
            "injection_task": "i",
            "value": value,
        }
        for index, value in enumerate(attack_values)
    ]
    data = {
        "benchmark": "agentdojo-family",
        "model": "nvidia/m",
        "suite": suite,
        "attack": "important_instructions",
        "condition": condition,
        "runs": [
            {
                "repetition": 0,
                "attack_results": pairs,
                "attacked_utility_results": pairs,
                "benign_results": [
                    {"user_task": "u0", "injection_task": "", "value": True}
                ],
                "model_calls": 2,
                "provider_attempts": 3,
                "rate_limit_retries": 1,
                "prompt_tokens": 10,
                "completion_tokens": 3,
                "model_seconds": 1.5,
                "rate_limit_wait_seconds": 10.0,
                "enforcement": {
                    "attacked": {
                        "gated_cases": attacked_gated,
                        "gate_prompts": attacked_gated,
                    },
                    "benign": {
                        "gated_cases": benign_gated,
                        "gate_prompts": benign_gated,
                    },
                },
            }
        ],
    }
    (path / "results.json").write_text(json.dumps(data), encoding="utf-8")


def test_external_report_aggregates_and_pairs_exact_cases(tmp_path):
    _write(tmp_path / "direct", "direct", [True, True, False])
    _write(tmp_path / "defended", "tripwire-approve", [False, True, False])

    rows = collect(tmp_path)
    effects = paired_effects(tmp_path)

    assert len(rows) == 2
    assert effects[0]["pairs"] == 3
    assert effects[0]["asr_difference"] == -1 / 3
    assert effects[0]["direct_only_successes"] == 1
    assert effects[0]["defended_only_successes"] == 0


def test_external_report_writes_all_formats(tmp_path):
    _write(tmp_path / "direct", "direct", [True, False])
    out = tmp_path / "out"

    write_outputs(tmp_path, out)

    assert (out / "summary.json").exists()
    assert "attack_success_rate" in (out / "summary.csv").read_text()
    assert "External benchmark summary" in (out / "REPORT.md").read_text()


def test_external_report_separates_attack_and_benign_interventions(tmp_path):
    _write(
        tmp_path / "strict",
        "tripwire-deny",
        [False, False, False],
        attacked_gated=2,
        benign_gated=1,
    )

    row = collect(tmp_path)[0]

    assert row["attack_intervention"]["hits"] == 2
    assert row["attack_intervention"]["total"] == 3
    assert row["benign_intervention"]["hits"] == 1
    assert row["benign_intervention"]["total"] == 1
    assert row["model_seconds"] == 1.5
    assert row["provider_attempts"] == 3
    assert row["rate_limit_retries"] == 1
    assert row["rate_limit_wait_seconds"] == 10.0


def test_overall_report_preserves_cross_suite_pairing(tmp_path):
    _write(tmp_path / "banking-direct", "direct", [True, True], suite="banking")
    _write(
        tmp_path / "banking-strict",
        "tripwire-deny",
        [False, True],
        suite="banking",
    )
    _write(tmp_path / "slack-direct", "direct", [True, False], suite="slack")
    _write(
        tmp_path / "slack-strict",
        "tripwire-deny",
        [False, False],
        suite="slack",
    )

    overall = collect_overall(tmp_path)
    effect = paired_effects_overall(tmp_path)[0]

    direct = next(row for row in overall if row["condition"] == "direct")
    strict = next(row for row in overall if row["condition"] == "tripwire-deny")
    assert direct["attack_success"]["hits"] == 3
    assert strict["attack_success"]["hits"] == 1
    assert effect["pairs"] == 4
    assert effect["direct_only_successes"] == 2
    assert effect["defended_only_successes"] == 0
    assert effect["asr_difference"] == -0.5
    assert effect["asr_crossed_cluster_ci_low"] <= effect["asr_difference"]
    assert effect["asr_crossed_cluster_ci_high"] >= effect["asr_difference"]
    assert effect["benign_utility_difference"] == 0.0


def test_paired_effects_merge_resumable_shards(tmp_path):
    _write(tmp_path / "direct-a", "direct", [True], user_prefix="a")
    _write(tmp_path / "direct-b", "direct", [True], user_prefix="b")
    _write(
        tmp_path / "strict-a",
        "tripwire-deny",
        [False],
        user_prefix="a",
    )
    _write(
        tmp_path / "strict-b",
        "tripwire-deny",
        [False],
        user_prefix="b",
    )

    effect = paired_effects(tmp_path)[0]

    assert effect["pairs"] == 2
    assert effect["direct_only_successes"] == 2
