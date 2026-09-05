"""Exercise the installed distribution from outside the source checkout.

Run with the Python interpreter of a clean environment containing the wheel.
This intentionally uses the shipped corpus without passing repository paths.
"""

import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from tripwire.policy import load_policy
from tripwire_gym.corpus import freeze
from tripwire_gym.resources import GYM


def main() -> None:
    assert GYM.name == "data", f"expected installed package data, found {GYM}"
    corpus = freeze(GYM / "scenarios")
    assert corpus["attacks"] == corpus["benign_twins"] == 38
    for policy in (GYM / "policies").glob("*.yaml"):
        load_policy(policy)
    for policy in (GYM / "external_policies").glob("*.yaml"):
        load_policy(policy)
    for protocol in ("agentdojo-heldout.yaml", "agentdojo-protectai-heldout.yaml"):
        assert (GYM / protocol).is_file(), protocol

    with TemporaryDirectory(prefix="tripwire-wheel-smoke-") as directory:
        out = Path(directory) / "results"
        subprocess.run(
            [
                str(Path(sys.executable).with_name("tripwire")),
                "validate",
                str(GYM / "policies" / "standard.yaml"),
            ],
            cwd=directory,
            check=True,
            timeout=30,
        )
        subprocess.run(
            [
                sys.executable,
                "-m",
                "tripwire_gym",
                "--agent",
                "scripted",
                "--scenario",
                "exfil-email-01",
                "--scenario",
                "exfil-email-01-benign",
                "--conditions",
                "undefended,standard",
                "--runs",
                "1",
                "--out",
                str(out),
            ],
            cwd=directory,
            check=True,
            timeout=120,
        )
        rows = [json.loads(line) for line in (out / "results.jsonl").read_text().splitlines()]
        assert len(rows) == 4
        assert not any(row["error"] for row in rows)
        cells = {(row["scenario_id"], row["condition"]): row["outcome"] for row in rows}
        assert cells[("exfil-email-01", "undefended")]["attack_succeeded"]
        assert not cells[("exfil-email-01", "standard")]["attack_succeeded"]
        assert cells[("exfil-email-01-benign", "standard")]["task_completed"]
    print(f"Installed tripwire-agent {importlib.metadata.version('tripwire-agent')}: smoke passed")


if __name__ == "__main__":
    main()
