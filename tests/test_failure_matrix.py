"""Every way this thing can break, and what it does about it.

The rule for all of them is the same: when tripwire can't do its job it
stops, loudly. It never degrades into a plain pipe, because a firewall
that quietly turns into a pipe is worse than no firewall — you'd still
think you had one.
"""

import shlex
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TOY = Path(__file__).parent / "toy_server.py"
GOOD_UPSTREAM = f"{shlex.quote(sys.executable)} {shlex.quote(str(TOY))}"

REFUSED = 2  # exit code for "I will not start"
HALTED = 70  # exit code for "I started, then lost the audit log"


def serve(tmp_path, policy_text="version: 1\n", upstream=GOOD_UPSTREAM, audit=None):
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_text)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "tripwire",
            "serve",
            "--policy",
            str(policy),
            "--upstream",
            upstream,
            "--audit",
            str(audit if audit is not None else tmp_path / "audit.jsonl"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


def test_invalid_policy_refuses_to_start(tmp_path):
    done = serve(tmp_path, "version: 1\ntools:\n  a: {action: nonsense}\n")
    assert done.returncode == REFUSED
    assert "refusing to start" in done.stderr
    assert "tools.a.action" in done.stderr


def test_unparseable_policy_refuses_to_start(tmp_path):
    done = serve(tmp_path, "version: 1\n\tbroken: [\n")
    assert done.returncode == REFUSED
    assert "invalid yaml" in done.stderr


def test_missing_policy_refuses_to_start(tmp_path):
    done = subprocess.run(
        [
            sys.executable,
            "-m",
            "tripwire",
            "serve",
            "--policy",
            str(tmp_path / "nope.yaml"),
            "--upstream",
            GOOD_UPSTREAM,
            "--audit",
            str(tmp_path / "audit.jsonl"),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )
    assert done.returncode == REFUSED
    assert "cannot read" in done.stderr


def test_upstream_that_does_not_exist_refuses_to_start(tmp_path):
    done = serve(tmp_path, upstream="/nonexistent/tool-server")
    assert done.returncode == REFUSED
    assert "refusing to start" in done.stderr


def test_upstream_that_dies_immediately_refuses_to_start(tmp_path):
    # exits 0 straight away, so the MCP handshake never completes
    done = serve(tmp_path, upstream=f"{shlex.quote(sys.executable)} -c pass")
    assert done.returncode == REFUSED
    assert "failed to start" in done.stderr


def test_upstream_that_is_not_an_mcp_server_refuses_to_start(tmp_path):
    # speaks, but not our protocol
    done = serve(tmp_path, upstream="/bin/cat")
    assert done.returncode == REFUSED


def test_unwritable_audit_log_refuses_to_start(tmp_path):
    done = serve(tmp_path, audit=tmp_path / "no" / "such" / "dir" / "audit.jsonl")
    assert done.returncode == REFUSED
    assert "refusing to start" in done.stderr
    assert "Traceback" not in done.stderr


def test_audit_failure_mid_session_halts_the_proxy(tmp_path):
    # The log going away underneath a running proxy is the one failure we
    # can't just report — an unrecorded call is exactly what we promise
    # can't happen, so the process dies instead.
    script = tmp_path / "halt.py"
    script.write_text(
        textwrap.dedent(
            """
            import anyio
            from tripwire.policy.schema import Policy
            from tripwire.policy.types import Verdict
            from tripwire.proxy.interceptor import Interceptor
            from tripwire.session import SessionState
            from tripwire.tx import AuditWriteError

            class DeadLog:
                def append(self, kind, data=None):
                    raise AuditWriteError("disk went away")

            class Taint:
                tainted = False
                tainted_by = ()
                def observe_result(self, tool, is_error=False):
                    pass

            class Upstream:
                tools = []
                async def call(self, name, args):
                    raise AssertionError("must not be reached")

            policy = Policy(version=1)
            interceptor = Interceptor(
                policy, DeadLog(), Upstream(), SessionState(policy, taint=Taint()),
                canonicalize=lambda t, a, p: dict(a),
                evaluate=lambda c, s, p: Verdict("allow", "x", "y"),
            )
            anyio.run(interceptor.handle, "add", {})
            """
        )
    )
    done = subprocess.run(
        [sys.executable, str(script)], check=False, capture_output=True, text=True, timeout=60
    )
    assert done.returncode == HALTED
    assert "FATAL" in done.stderr


@pytest.mark.parametrize("subcommand", ["validate", "verify"])
def test_cli_reports_bad_input_without_a_traceback(tmp_path, subcommand):
    done = subprocess.run(
        [sys.executable, "-m", "tripwire", subcommand, str(tmp_path / "nope")],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert done.returncode == 1
    assert "Traceback" not in done.stderr
