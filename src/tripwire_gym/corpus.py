"""Validate and freeze a paired attack corpus before an expensive run."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from tripwire_gym.manifest import fingerprint
from tripwire_gym.scenario import Scenario, ScenarioError, load_corpus


class CorpusValidationError(Exception):
    pass


def validate_pairs(scenarios: list[Scenario]) -> dict:
    by_id = {scenario.id: scenario for scenario in scenarios}
    attacks = [scenario for scenario in scenarios if scenario.attack]
    benign = [scenario for scenario in scenarios if not scenario.attack]
    problems: list[str] = []
    referenced: list[str] = []

    for attack in attacks:
        if attack.benign_twin is None:
            problems.append(f"{attack.id}: no benign_twin")
            continue
        twin = by_id.get(attack.benign_twin)
        if twin is None:
            problems.append(f"{attack.id}: missing twin {attack.benign_twin}")
            continue
        referenced.append(twin.id)
        if twin.attack:
            problems.append(f"{attack.id}: twin {twin.id} is marked as an attack")
        if twin.benign_twin is not None:
            problems.append(f"{twin.id}: benign twin must not point to another twin")
        if twin.family != attack.family:
            problems.append(f"{attack.id}: twin changed family")
        if twin.task != attack.task:
            problems.append(f"{attack.id}: twin changed the user task")
        if twin.task_success != attack.task_success:
            problems.append(f"{attack.id}: twin changed task-success scoring")
        if [(t.name, t.description, t.schema_) for t in twin.tools] != [
            (t.name, t.description, t.schema_) for t in attack.tools
        ]:
            problems.append(f"{attack.id}: twin changed the advertised toolbox")
        if [t.returns for t in twin.tools] == [t.returns for t in attack.tools]:
            problems.append(f"{attack.id}: twin did not remove or change any tool output")

    duplicate_twins = sorted(twin for twin, n in Counter(referenced).items() if n > 1)
    if duplicate_twins:
        problems.append("benign twins reused by multiple attacks: " + ", ".join(duplicate_twins))
    orphans = sorted({scenario.id for scenario in benign} - set(referenced))
    if orphans:
        problems.append("unpaired benign scenarios: " + ", ".join(orphans))
    if problems:
        raise CorpusValidationError("\n".join(problems))

    families = Counter(scenario.family for scenario in attacks)
    return {
        "scenarios": len(scenarios),
        "attacks": len(attacks),
        "benign_twins": len(benign),
        "families": dict(sorted(families.items())),
    }


def freeze(directory: str | Path) -> dict:
    root = Path(directory).resolve()
    scenarios = load_corpus(root)
    summary = validate_pairs(scenarios)
    files = [p for p in root.iterdir() if p.suffix in {".yaml", ".yml"}]
    return {"schema_version": 1, **summary, "corpus": fingerprint(files, root=root)}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="validate and fingerprint a Tripwire corpus")
    parser.add_argument("--scenarios", default="gym/scenarios")
    parser.add_argument("--out", help="write the frozen receipt to this JSON file")
    args = parser.parse_args(argv)
    try:
        receipt = freeze(args.scenarios)
    except (ScenarioError, CorpusValidationError, OSError) as exc:
        print(f"tripwire_gym.corpus: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.out:
        destination = Path(args.out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()
