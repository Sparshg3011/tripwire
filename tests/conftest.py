from pathlib import Path

import pytest

from tripwire.policy import load_policy

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture
def reference_policy():
    return load_policy(EXAMPLES / "policy.yaml")
