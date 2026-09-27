from pathlib import Path

import pytest

from tripwire.policy import load_policy

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(autouse=True)
def no_audit_key_from_the_shell(monkeypatch):
    # docs/production.md suggests exporting it, and every proxy and cli
    # the tests start would pick it up and key or check the log with it
    monkeypatch.delenv("TRIPWIRE_AUDIT_KEY_FILE", raising=False)


@pytest.fixture
def reference_policy():
    return load_policy(EXAMPLES / "policy.yaml")
