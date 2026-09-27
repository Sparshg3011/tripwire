"""The gym scripts are how a number gets reproduced, so they have to run
from whatever checkout a reader has, under the bash 3.2 macOS still
ships as /bin/bash.

Each runs against a stand-in interpreter that records its argv and does
nothing else: what is under test is the shell, not the benchmark.
"""

import os
import subprocess
from pathlib import Path

import pytest

GYM = Path(__file__).resolve().parents[1] / "gym"


def run(script, *args, cwd, env):
    # /bin/bash, not the first bash on PATH: on macOS that is the 3.2
    # these scripts are most likely to meet
    return subprocess.run(
        ["/bin/bash", str(GYM / script), *args],
        check=False,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize("resume", [False, True])
def test_heldout_passes_the_resume_flag_only_when_asked(tmp_path, fake_python, resume):
    python, calls = fake_python
    env = {**os.environ, "PY": str(python), "NVIDIA_API_KEY": "unused"}
    env.pop("ALLOW_TRANSPORT_RESUME", None)
    if resume:
        env["ALLOW_TRANSPORT_RESUME"] = "1"

    done = run("run_agentdojo_heldout.sh", str(tmp_path / "out"), cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    (call,) = calls()
    assert call[:2] == ["-m", "tripwire_benchmarks.heldout"]
    assert ("--allow-transport-resume" in call) is resume
