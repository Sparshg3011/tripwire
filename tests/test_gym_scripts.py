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
    # /bin/bash rather than the first bash on PATH: on macOS it is 3.2,
    # the oldest bash these scripts will meet
    return subprocess.run(
        ["/bin/bash", str(GYM / script), *args],
        check=False,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "script, args",
    [
        ("run_ablation.sh", []),
        ("run_ablation_loo.sh", ["scripted", "1", "", "1", "out"]),
        ("run_agentdojo_heldout.sh", ["out"]),
        ("run_agentdojo_pilot.sh", ["out"]),
        ("run_agentdojo_protectai_heldout.sh", ["out"]),
        ("run_benchmark.sh", []),
        ("run_models.sh", []),
        ("run_publication.sh", []),
        ("run_static_external.sh", ["workspace", "direct", "out"]),
    ],
)
def test_scripts_run_the_python_they_are_given(tmp_path, fake_python, script, args):
    python, calls = fake_python
    env = {**os.environ, "PY": str(python), "NVIDIA_API_KEY": "unused"}

    # the scripts write under the working directory, so give them this one
    done = run(script, *args, cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    assert calls()


def test_setup_builds_its_environments_with_the_python_it_is_given(tmp_path, fake_python):
    python, calls = fake_python
    deps = tmp_path / "deps"
    for checkout in ("AgentDyn", "AutoDojo"):
        (deps / checkout / ".git").mkdir(parents=True)
    # stands in for git: every checkout is clean and moves to whatever
    # commit it is asked for
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    git = bin_dir / "git"
    git.write_text('#!/bin/sh\n[ "$3" = rev-parse ] && echo elsewhere\nexit 0\n')
    git.chmod(0o755)
    path = f"{bin_dir}{os.pathsep}{os.environ['PATH']}"
    env = {**os.environ, "PYTHON": str(python), "PATH": path}

    run("setup_external_benchmarks.sh", str(deps), cwd=tmp_path, env=env)

    # the fake makes no environment, so the script stops at the next step
    assert calls()[:1] == [["-m", "venv", ".venv-agentdyn"]]


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
