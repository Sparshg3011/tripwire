from pathlib import Path

import pytest

from tripwire_gym.corpus import CorpusValidationError, freeze, validate_pairs
from tripwire_gym.scenario import load_corpus

CORPUS = Path(__file__).parent.parent / "gym" / "scenarios"


def test_pilot_corpus_is_fully_paired_and_fingerprintable():
    receipt = freeze(CORPUS)

    assert receipt["attacks"] == 38
    assert receipt["benign_twins"] == 38
    assert receipt["scenarios"] == 76
    assert len(receipt["families"]) == 7
    assert len(receipt["corpus"]["sha256"]) == 64


def test_an_attack_without_a_twin_cannot_be_frozen():
    scenarios = load_corpus(CORPUS)
    index = next(i for i, scenario in enumerate(scenarios) if scenario.attack)
    scenarios[index] = scenarios[index].model_copy(update={"benign_twin": None})

    with pytest.raises(CorpusValidationError, match="no benign_twin"):
        validate_pairs(scenarios)
