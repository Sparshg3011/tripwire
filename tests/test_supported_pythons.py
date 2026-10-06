"""Which Pythons tripwire supports is written down in several places, and
a reader believes whichever one they see first. CI's matrix is the only
one anything checks, so the rest have to say what it says."""

import re
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
JOBS = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())["jobs"]
TESTED = JOBS["test"]["strategy"]["matrix"]["python"]


def test_the_installed_wheel_is_exercised_on_every_python_the_suite_runs_on():
    assert JOBS["package"]["strategy"]["matrix"]["python"] == TESTED


def test_the_package_metadata_claims_the_pythons_ci_tests():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    classified = [
        c.rsplit(" :: ", 1)[1]
        for c in project["classifiers"]
        if re.fullmatch(r"Programming Language :: Python :: 3\.\d+", c)
    ]

    assert classified == TESTED
    assert project["requires-python"] == f">={TESTED[0]}"


def test_every_range_the_docs_quote_is_the_range_ci_tests():
    docs = [*ROOT.glob("*.md"), *(ROOT / "docs").rglob("*.md")]
    # the badge escapes its dash as "--", prose uses an en dash
    ranges = [
        (doc.relative_to(ROOT).as_posix(), match.groups())
        for doc in docs
        for match in re.finditer(r"Python[- ](3\.\d+)(?:--|–)(3\.\d+)", doc.read_text())
    ]

    assert ranges
    assert [r for r in ranges if r[1] != (TESTED[0], TESTED[-1])] == []
