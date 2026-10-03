"""The gym scripts are how a number gets reproduced, so they have to run
from whatever checkout a reader has, under the bash 3.2 macOS still
ships as /bin/bash.

Each runs against a stand-in interpreter that records its argv and does
nothing else: what is under test is the shell, not the benchmark.
"""

import os
import re
import shlex
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


# One row per branch that runs the interpreter: quoting it on one side of
# an if says nothing about the other.
@pytest.mark.parametrize(
    "script, args, variables",
    [
        ("run_ablation.sh", [], {}),
        ("run_ablation.sh", ["scripted", "1", "a-model"], {}),
        ("run_ablation_loo.sh", ["scripted", "1", "", "1", "out"], {}),
        ("run_ablation_loo.sh", ["scripted", "1", "a-model", "1", "out"], {}),
        ("run_agentdojo_heldout.sh", ["out"], {}),
        ("run_agentdojo_pilot.sh", ["out"], {}),
        ("run_agentdojo_protectai_heldout.sh", ["out"], {}),
        ("run_benchmark.sh", [], {}),
        ("run_benchmark.sh", ["scripted", "1", "a-model"], {}),
        ("run_models.sh", [], {}),
        ("run_publication.sh", ["smoke"], {}),
        ("run_publication.sh", ["feasible"], {}),
        ("run_static_external.sh", ["workspace", "direct", "out"], {"PROFILE": "full"}),
        ("run_static_external.sh", ["workspace", "direct", "out"], {"PROFILE": "smoke"}),
    ],
)
def test_scripts_run_the_python_they_are_given(tmp_path, fake_python, script, args, variables):
    python, calls = fake_python
    env = {**os.environ, **variables, "PY": str(python), "NVIDIA_API_KEY": "unused"}

    # the scripts write under the working directory, so give them this one
    done = run(script, *args, cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    assert calls()


@pytest.mark.parametrize("script", ["run_benchmark.sh", "run_models.sh"])
def test_reports_and_charts_stay_under_gym_results(tmp_path, fake_python, script):
    # a rerun measures something new, so it can't write over a published file
    python, calls = fake_python
    env = {**os.environ, "PY": str(python), "NVIDIA_API_KEY": "unused"}

    done = run(script, cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    inline = [call[-1] for call in calls() if call[:1] == ["-"]]
    written = [path for source in inline for path in re.findall(r"[\w./-]+\.(?:md|png)\b", source)]
    assert written
    assert all(path.startswith("gym/results/") for path in written), written


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
    # the fake builds no environments, so both are laid out in advance,
    # each with the fake as its python, and the script runs to the end
    for venv in (".venv-agentdyn", ".venv-autodojo"):
        (tmp_path / venv / "bin").mkdir(parents=True)
        (tmp_path / venv / "bin" / "python").symlink_to(python)

    done = run("setup_external_benchmarks.sh", str(deps), cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    assert [call for call in calls() if call[:2] == ["-m", "venv"]] == [
        ["-m", "venv", ".venv-agentdyn"],
        ["-m", "venv", ".venv-autodojo"],
    ]


def test_leave_one_out_prints_an_aggregation_command_that_pastes(tmp_path, fake_python):
    python, _ = fake_python
    out = tmp_path / "loo results"
    env = {**os.environ, "PY": str(python)}

    done = run("run_ablation_loo.sh", "scripted", "1", "", "1", str(out), cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    assert shlex.split(done.stdout.splitlines()[-1]) == [
        str(python),
        "-m",
        "tripwire_gym.publication",
        "--root",
        str(out),
        "--out",
        f"{out}/summary",
    ]


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


def test_recipe_policies_dump_each_benchmark_with_its_own_python(tmp_path, fake_python):
    python, calls = fake_python
    # the same fake, marked, so the calls say which interpreter ran them
    agentdyn = tmp_path / "agentdyn python"
    agentdyn.write_text(f'#!/bin/sh\nexec {shlex.quote(str(python))} agentdyn "$@"\n')
    agentdyn.chmod(0o755)
    env = {**os.environ, "PY": str(python), "DYN_PY": str(agentdyn)}

    done = run("make_recipe_policies.sh", cwd=tmp_path, env=env)

    assert done.returncode == 0, done.stderr
    module = ["-m", "tripwire_benchmarks.recipe_policies"]
    assert calls() == [
        [*module, "dump", "banking", "slack", "travel", "workspace"],
        ["agentdyn", *module, "dump", "github", "shopping", "dailylife"],
        [*module, "generate"],
    ]
