"""Create a deterministic, family-stratified development/evaluation split."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path

from tripwire_gym.corpus import freeze, validate_pairs
from tripwire_gym.scenario import Scenario, load_corpus, load_scenario


def _rank(salt: str, scenario_id: str) -> str:
    return hashlib.sha256(f"{salt}\0{scenario_id}".encode()).hexdigest()


def split_pairs(
    scenarios: list[Scenario], *, evaluation_fraction: float = 0.25, salt: str
) -> dict[str, list[str]]:
    if not 0 < evaluation_fraction < 1:
        raise ValueError("evaluation_fraction must be inside (0, 1)")
    validate_pairs(scenarios)
    attacks = [scenario for scenario in scenarios if scenario.attack]
    by_family: dict[str, list[Scenario]] = defaultdict(list)
    for attack in attacks:
        by_family[attack.family].append(attack)

    evaluation_attacks: set[str] = set()
    for family_attacks in by_family.values():
        ordered = sorted(family_attacks, key=lambda scenario: _rank(salt, scenario.id))
        wanted = max(1, round(len(ordered) * evaluation_fraction))
        if len(ordered) > 1:
            wanted = min(wanted, len(ordered) - 1)
        evaluation_attacks.update(scenario.id for scenario in ordered[:wanted])

    by_id = {scenario.id: scenario for scenario in scenarios}
    evaluation = set(evaluation_attacks)
    for attack_id in evaluation_attacks:
        twin = by_id[attack_id].benign_twin
        assert twin is not None
        evaluation.add(twin)
    development = set(by_id) - evaluation
    return {"development": sorted(development), "evaluation": sorted(evaluation)}


def materialize(
    source: str | Path,
    destination: str | Path,
    *,
    evaluation_fraction: float = 0.25,
    salt: str,
) -> dict:
    source = Path(source).resolve()
    destination = Path(destination)
    scenarios = load_corpus(source)
    split = split_pairs(scenarios, evaluation_fraction=evaluation_fraction, salt=salt)
    by_id = {scenario.id: scenario for scenario in scenarios}
    files_by_id = {}
    for path in source.iterdir():
        if path.suffix in {".yaml", ".yml"}:
            # Filenames need not equal IDs; load once to establish the exact map.
            scenario_id = load_scenario(path).id
            files_by_id[scenario_id] = path

    for name, ids in split.items():
        directory = destination / name
        if directory.exists() and any(directory.iterdir()):
            raise FileExistsError(f"refusing to overwrite non-empty split directory: {directory}")
        directory.mkdir(parents=True, exist_ok=True)
        for scenario_id in ids:
            shutil.copy2(files_by_id[scenario_id], directory / files_by_id[scenario_id].name)
        validate_pairs([by_id[scenario_id] for scenario_id in ids])

    receipt = {
        "schema_version": 1,
        "evaluation_fraction": evaluation_fraction,
        "salt_sha256": hashlib.sha256(salt.encode()).hexdigest(),
        "source": freeze(source),
        "development": {
            "ids": split["development"],
            "corpus": freeze(destination / "development"),
        },
        "evaluation": {
            "ids": split["evaluation"],
            "corpus": freeze(destination / "evaluation"),
        },
    }
    (destination / "split.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="create a paired benchmark holdout")
    parser.add_argument("--scenarios", default="gym/scenarios")
    parser.add_argument("--out", required=True)
    parser.add_argument("--evaluation-fraction", type=float, default=0.25)
    parser.add_argument("--salt", required=True, help="private random split salt")
    args = parser.parse_args(argv)
    receipt = materialize(
        args.scenarios,
        args.out,
        evaluation_fraction=args.evaluation_fraction,
        salt=args.salt,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
