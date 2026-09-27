import json
import shlex
import sys
from pathlib import Path

import pytest

from tripwire.policy import load_policy

EXAMPLES = Path(__file__).parent.parent / "examples"
FAKE_PYTHON = Path(__file__).parent / "fake_python.py"


@pytest.fixture
def reference_policy():
    return load_policy(EXAMPLES / "policy.yaml")


@pytest.fixture
def fake_python(tmp_path):
    """An executable to hand a gym script as $PY, and a function that
    reads back the argv of every call it got."""
    home = tmp_path / "fake-python"
    home.mkdir()
    log = home / "calls.jsonl"
    log.touch()
    python = home / "python"
    # A shebang can't name sys.executable: the kernel ends the
    # interpreter path at the first space, and checkouts have spaces.
    command = shlex.join([sys.executable, str(FAKE_PYTHON), str(log)])
    python.write_text(f'#!/bin/sh\nexec {command} "$@"\n')
    python.chmod(0o755)
    return python, lambda: [json.loads(line) for line in log.read_text().splitlines()]
