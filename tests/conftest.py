from pathlib import Path

import pytest

from tripwire.policy import load_policy

EXAMPLES = Path(__file__).parent.parent / "examples"


@pytest.fixture(autouse=True, scope="session")
def no_audit_key_from_the_shell():
    # docs/production.md suggests exporting it, and every proxy and cli
    # the tests start would pick it up and key or check the log with it.
    # Session-wide, because a module fixture is set up before any
    # function one and the gym matrix starts its proxies in one.
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("TRIPWIRE_AUDIT_KEY_FILE", raising=False)
        yield


@pytest.fixture
def reference_policy():
    return load_policy(EXAMPLES / "policy.yaml")
