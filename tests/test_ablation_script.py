"""The full-policy invocation must not overwrite the later ablation matrix."""

import os
import subprocess
from pathlib import Path


def test_both_approval_bounds_run_all_five_ablation_conditions(tmp_path, fake_python):
    python, calls = fake_python
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
        env={**os.environ, "PY": str(python)},
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    matrices = [call for call in calls() if call[:2] == ["-m", "tripwire_gym"]]
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
