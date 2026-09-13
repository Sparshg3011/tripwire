"""The full-policy invocation must not overwrite the later ablation matrix."""

import json
import os
import subprocess
import sys
from pathlib import Path


def test_both_approval_bounds_run_all_five_ablation_conditions(tmp_path):
    recorder = tmp_path / "python-recorder"
    calls = tmp_path / "calls.jsonl"
    recorder.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "with open(os.environ['ABLATION_CALLS'], 'a') as log:\n"
        "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
    )
    recorder.chmod(0o755)
    root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            "bash",
            str(root / "gym" / "run_ablation_loo.sh"),
            "scripted",
            "1",
            "",
            "1",
            str(tmp_path / "results"),
        ],
        cwd=root,
        env={**os.environ, "PY": str(recorder), "ABLATION_CALLS": str(calls)},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    recorded = [json.loads(line) for line in calls.read_text().splitlines()]
    matrices = [call for call in recorded if call[:2] == ["-m", "tripwire_gym"]]
    assert len(matrices) == 4
    cases = [
        (call[call.index("--human") + 1], call[call.index("--conditions") + 1]) for call in matrices
    ]
    ablations = "loo-no-actions,loo-no-constraints,loo-no-limits,loo-no-sequences,loo-no-flows"
    assert cases == [
        ("approve", "standard"),
        ("approve", ablations),
        ("deny", "standard"),
        ("deny", ablations),
    ]
