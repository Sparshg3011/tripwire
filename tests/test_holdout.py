import pytest

from tripwire_gym.corpus import validate_pairs
from tripwire_gym.holdout import materialize, split_pairs
from tripwire_gym.scenario import load_corpus


def test_holdout_is_deterministic_stratified_and_keeps_twins_together():
    corpus = load_corpus("gym/scenarios")

    first = split_pairs(corpus, evaluation_fraction=0.25, salt="secret")
    second = split_pairs(corpus, evaluation_fraction=0.25, salt="secret")

    assert first == second
    by_id = {scenario.id: scenario for scenario in corpus}
    evaluation = set(first["evaluation"])
    assert {by_id[item].family for item in evaluation} == {
        scenario.family for scenario in corpus if scenario.attack
    }
    for attack in (scenario for scenario in corpus if scenario.attack):
        assert (attack.id in evaluation) == (attack.benign_twin in evaluation)


def test_different_salt_changes_the_selection():
    corpus = load_corpus("gym/scenarios")
    assert split_pairs(corpus, salt="one") != split_pairs(corpus, salt="two")


def test_materialized_halves_are_independently_valid_and_fingerprinted(tmp_path):
    receipt = materialize("gym/scenarios", tmp_path / "split", salt="not-published-yet")

    for name in ("development", "evaluation"):
        corpus = load_corpus(tmp_path / "split" / name)
        assert validate_pairs(corpus)
        assert receipt[name]["corpus"]["corpus"]["sha256"]
    assert receipt["salt_sha256"] != "not-published-yet"


def test_split_refuses_to_overwrite_results(tmp_path):
    destination = tmp_path / "split"
    materialize("gym/scenarios", destination, salt="one")

    with pytest.raises(FileExistsError):
        materialize("gym/scenarios", destination, salt="two")


def test_fraction_must_be_a_probability():
    with pytest.raises(ValueError):
        split_pairs(load_corpus("gym/scenarios"), evaluation_fraction=1.0, salt="x")
