"""The chart, checked for the things a picture can get wrong silently.

Mostly this is about the numbers on their way to the axes: which runs
got grouped into which point, and what the error bars are made of. The
drawing itself is only checked as far as "a real png came out", because
anything past that is a matter of taste.

matplotlib is a [gym] extra, so the whole file skips without it.
"""

import pytest

pytest.importorskip("matplotlib")

from tripwire_gym.chart import (
    LABEL_MIN_GAP,
    _label_layout,
    family_breakdown,
    frontier,
    summaries_from_results,
)
from tripwire_gym.runner import RunResult
from tripwire_gym.scoring import Outcome, Summary


def result(
    condition, seed=0, family="exfiltration", attacked=True, succeeded=False, completed=True
):
    return RunResult(
        scenario_id="s-01",
        condition=condition,
        seed=seed,
        outcome=Outcome(
            scenario_id="s-01",
            family=family,
            attacked=attacked,
            attack_succeeded=succeeded,
            task_completed=completed,
            executed_calls=1,
            refused_calls=0,
        ),
    )


def matrix(conditions=("undefended", "standard"), seeds=2):
    runs = []
    for condition in conditions:
        for seed in range(seeds):
            leaked = condition == "undefended" or seed == 0
            runs.append(result(condition, seed=seed, succeeded=leaked))
            runs.append(result(condition, seed=seed, family="destruction", succeeded=leaked))
            runs.append(result(condition, seed=seed, attacked=False, completed=seed == 0))
    return summaries_from_results(runs)


def is_png(path):
    return path.read_bytes().startswith(b"\x89PNG")


# --- grouping ---


def test_one_summary_per_condition():
    summaries = summaries_from_results(
        [
            result("undefended", succeeded=True),
            result("undefended", attacked=False, completed=True),
            result("strict", succeeded=False),
            result("strict", attacked=False, completed=False),
        ]
    )

    assert [s.condition for s in summaries] == ["undefended", "strict"]
    assert (summaries[0].attack_success_rate, summaries[0].benign_completion_rate) == (1.0, 1.0)
    assert (summaries[1].attack_success_rate, summaries[1].benign_completion_rate) == (0.0, 0.0)


def test_conditions_come_back_in_the_order_the_story_is_told():
    runs = [result(c) for c in ("strict", "undefended", "loose", "shadow", "standard")]

    assert [s.condition for s in summaries_from_results(runs)] == [
        "undefended",
        "shadow",
        "loose",
        "standard",
        "strict",
    ]


def test_a_condition_the_runner_never_heard_of_sorts_last():
    runs = [result("homebrew-policy"), result("strict")]

    assert [s.condition for s in summaries_from_results(runs)] == ["strict", "homebrew-policy"]


def test_families_are_tallied_within_the_condition():
    runs = [
        result("loose", succeeded=True),
        result("loose", succeeded=False),
        result("loose", family="destruction", succeeded=True),
    ]

    assert summaries_from_results(runs)[0].by_family == {
        "exfiltration": (1, 2),
        "destruction": (1, 1),
    }


# --- what the error bars are made of ---


def test_per_seed_attack_rates_are_kept_for_the_error_bars():
    # seed 0 leaked both attacks, seed 1 leaked neither: same mean as two
    # coin flips, very different spread, and the bar is the difference
    runs = [
        result("loose", seed=0, succeeded=True),
        result("loose", seed=0, succeeded=True),
        result("loose", seed=1, succeeded=False),
        result("loose", seed=1, succeeded=False),
    ]
    s = summaries_from_results(runs)[0]

    assert s.attack_success_rate == 0.5
    assert sorted(s.attack_rates) == [0.0, 1.0]


def test_per_seed_benign_rates_follow_task_completion():
    runs = [
        result("standard", seed=0, attacked=False, completed=True),
        result("standard", seed=1, attacked=False, completed=False),
    ]
    s = summaries_from_results(runs)[0]

    assert s.benign_completion_rate == 0.5
    assert sorted(s.benign_rates) == [0.0, 1.0]


def test_a_single_seed_carries_no_spread():
    s = summaries_from_results([result("strict"), result("strict", attacked=False)])[0]

    assert s.attack_rates == []
    assert s.benign_rates == []


# --- the files ---


def test_frontier_writes_a_png(tmp_path):
    path = frontier(
        matrix(("undefended", "shadow", "loose", "standard", "strict")), tmp_path / "f.png"
    )

    assert path == tmp_path / "f.png"
    assert is_png(path)


def test_frontier_draws_without_error_bars_too(tmp_path):
    path = frontier(matrix(), tmp_path / "plain.png", error_bars=False)

    assert is_png(path)


def test_frontier_direct_labels_do_not_overlap_at_the_published_coordinates():
    points = [(94.7, 39.5), (97.4, 39.5), (97.4, 26.3), (94.7, 13.2), (15.8, 0.0)]

    labels = _label_layout(points)

    # The four right-edge labels share one column, with coincident rates
    # separated vertically. The strict label remains beside its own point.
    assert len({label[0] for label in labels[:4]}) == 1
    assert abs(labels[0][1] - labels[1][1]) >= LABEL_MIN_GAP
    assert labels[0][2] == labels[1][2] == "right"
    assert labels[4][0] > points[4][0]
    assert labels[4][2] == "left"


def test_family_breakdown_writes_a_png(tmp_path):
    path = family_breakdown(matrix(), tmp_path / "families.png")

    assert is_png(path)


def test_charts_make_the_directory_they_were_pointed_at(tmp_path):
    path = frontier(matrix(), tmp_path / "out" / "nested" / "f.png")

    assert is_png(path)


def test_both_charts_handle_a_single_condition(tmp_path):
    only = matrix(("standard",))

    assert is_png(frontier(only, tmp_path / "f.png"))
    assert is_png(family_breakdown(only, tmp_path / "b.png"))


# --- nothing to divide by ---


def test_a_condition_with_no_attack_runs_does_not_divide_by_zero(tmp_path):
    benign_only = summaries_from_results(
        [result("strict", seed=s, attacked=False) for s in range(2)]
    )

    assert benign_only[0].attack_success_rate == 0.0
    assert is_png(frontier(benign_only, tmp_path / "f.png"))
    assert is_png(family_breakdown(benign_only, tmp_path / "b.png"))


def test_a_family_with_no_attack_runs_is_a_zero_bar_not_a_crash(tmp_path):
    counted_nothing = Summary(condition="strict", by_family={"destruction": (0, 0)})

    assert is_png(family_breakdown([counted_nothing], tmp_path / "b.png"))


def test_charts_survive_having_nothing_to_plot(tmp_path):
    assert is_png(frontier([], tmp_path / "f.png"))
    assert is_png(family_breakdown([], tmp_path / "b.png"))
