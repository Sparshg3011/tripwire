import json
import sys

import pytest

from tripwire_benchmarks.heldout import HeldoutError, _run_sequential, _run_shard


def test_one_worker_stops_before_starting_the_next_suite():
    calls = []

    def fail(job):
        calls.append(job)
        raise HeldoutError("provider returned 404")

    with pytest.raises(HeldoutError):
        _run_sequential(["banking", "slack", "travel"], fail)
    assert calls == ["banking"]


def test_one_worker_preserves_the_declared_order():
    calls = []

    def run(job):
        calls.append(job)
        return job

    _run_sequential(["workspace", "banking", "slack", "travel"], run)
    assert calls == ["workspace", "banking", "slack", "travel"]


def test_shard_logs_preserve_previous_failure_and_stream_both_channels(tmp_path, monkeypatch):
    destination = tmp_path / "banking" / "direct" / "shard-00"
    destination.mkdir(parents=True)
    log = destination / "runner.log"
    log.write_text("older failed attempt\n")
    monkeypatch.setattr(
        "tripwire_benchmarks.heldout._command",
        lambda **kwargs: [
            sys.executable,
            "-c",
            "import sys; print('stdout'); print('stderr', file=sys.stderr); sys.exit(7)",
        ],
    )
    with pytest.raises(HeldoutError, match="exit 7"):
        _run_shard(
            root=tmp_path,
            suite="banking",
            shard_index=0,
            users=["u"],
            conditions=["direct"],
            model="test",
        )
    lines = log.read_text().splitlines()
    assert lines[0] == "older failed attempt"
    assert "stdout" in lines and "stderr" in lines
    assert json.loads(lines[1])["runner_event"] == "started"
    assert json.loads(lines[-1])["returncode"] == 7


def test_child_can_see_its_output_in_log_before_it_exits(tmp_path, monkeypatch):
    log = tmp_path / "banking" / "direct" / "shard-00" / "runner.log"
    script = "import pathlib,sys; print('LIVE_MARKER', flush=True); assert 'LIVE_MARKER' in pathlib.Path(sys.argv[1]).read_text()"
    monkeypatch.setattr(
        "tripwire_benchmarks.heldout._command",
        lambda **kwargs: [sys.executable, "-c", script, str(log)],
    )
    result = _run_shard(
        root=tmp_path,
        suite="banking",
        shard_index=0,
        users=["u"],
        conditions=["direct"],
        model="test",
    )
    assert result == "banking/shard-00: direct"
    assert json.loads(log.read_text().splitlines()[-1])["returncode"] == 0
