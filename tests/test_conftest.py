"""The suite runs the same whatever the developer's shell exports."""

from pathlib import Path

pytest_plugins = ["pytester"]

CONFTEST = Path(__file__).parent / "conftest.py"


def test_a_module_fixture_sees_no_audit_key_from_the_shell(pytester, monkeypatch):
    # module fixtures are set up before function ones, and the gym matrix
    # starts every proxy it runs from one
    pytester.makeconftest(CONFTEST.read_text())
    pytester.makepyfile(
        """
        import os

        import pytest


        @pytest.fixture(scope="module")
        def exported():
            return os.environ.get("TRIPWIRE_AUDIT_KEY_FILE")


        def test_it(exported):
            assert exported is None
        """
    )
    monkeypatch.setenv("TRIPWIRE_AUDIT_KEY_FILE", "")

    pytester.runpytest_subprocess().assert_outcomes(passed=1)
