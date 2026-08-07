"""Reading a log back: one session as a story, all sessions as a number.

Every log here is written by the real AuditLog, so the record shapes are
whatever the proxy actually writes rather than what these tests wish it
wrote. The interesting cases are the ones where the log is the only
evidence left: a call that never ran, a gate nobody answered, and shadow
mode, where "blocked" would be a lie.
"""

import subprocess
import sys
from collections import Counter

import pytest

from tripwire.tx import (
    AuditLog,
    LogError,
    format_report,
    format_trace,
    read_records,
    report,
    sessions,
    trace,
)

# --- writing logs ---


def emit(path, session, events):
    """Append events as `session`. Reopening continues the chain, so
    alternating calls interleaves two sessions in one file."""
    log = AuditLog(path, session_id=session)
    for kind, data in events:
        log.append(kind, data)
    log.close()


def verdict(tool, decision="allow", rule="tools.*", reason="fine", turn=0, shadow=False):
    return (
        "decision",
        {
            "tool": tool,
            "decision": decision,
            "rule": rule,
            "reason": reason,
            "shadow": shadow,
            "tainted": False,
            "turn": turn,
        },
    )


def ran(tool, args=None, is_error=False):
    return [
        ("tool_call", {"tool": tool, "args": args or {}}),
        ("tool_result", {"tool": tool, "is_error": is_error}),
    ]


def cli(*argv):
    return subprocess.run(
        [sys.executable, "-m", "tripwire", *argv],
        check=False,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
    )


@pytest.fixture
def log_path(tmp_path):
    return tmp_path / "audit.jsonl"


# --- reading ---


def test_reads_every_record_in_order(log_path):
    emit(log_path, "s1", [("proxy_start", {"upstream": "toy"}), verdict("add"), *ran("add")])

    records = read_records(log_path)
    assert [r["kind"] for r in records] == ["proxy_start", "decision", "tool_call", "tool_result"]
    assert [r["seq"] for r in records] == [0, 1, 2, 3]


def test_blank_lines_are_skipped(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add")])
    log_path.write_text(log_path.read_text().replace("\n", "\n\n"))

    assert len(read_records(log_path)) == 3


def test_a_malformed_line_names_the_line_number(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add")])
    lines = log_path.read_text().splitlines()
    lines[1] = "{torn"
    log_path.write_text("\n".join(lines) + "\n")

    with pytest.raises(LogError, match="line 2"):
        read_records(log_path)


def test_an_unreadable_path_is_a_log_error(tmp_path):
    with pytest.raises(LogError, match="cannot read"):
        read_records(tmp_path / "nope.jsonl")


def test_sessions_are_listed_once_in_first_seen_order(log_path):
    emit(log_path, "s1", [verdict("add")])
    emit(log_path, "s2", [verdict("add")])
    emit(log_path, "s1", [verdict("add")])

    assert sessions(read_records(log_path)) == ["s1", "s2"]


# --- trace ---


def test_a_forwarded_call_becomes_one_step(log_path):
    emit(log_path, "s1", [verdict("add", rule="tools.add"), *ran("add", {"a": 1, "b": 2})])

    (step,) = trace(read_records(log_path), "s1")
    assert step.tool == "add"
    assert step.decision == "allow"
    assert step.rule == "tools.add"
    assert step.args == {"a": 1, "b": 2}
    assert step.outcome == "ok"


def test_a_blocked_call_was_never_forwarded(log_path):
    emit(log_path, "s1", [verdict("delete_file", "block", rule="tools.delete_file")])

    (step,) = trace(read_records(log_path), "s1")
    assert step.outcome == "not forwarded"
    assert step.args == {}


def test_other_sessions_are_left_out_entirely(log_path):
    # interleaved on purpose: another session's tool_call must not end up
    # as this session's arguments
    emit(log_path, "s1", [verdict("add")])
    emit(log_path, "s2", [verdict("delete_file", "block")])
    emit(log_path, "s2", [("tool_call", {"tool": "delete_file", "args": {"path": "/etc/passwd"}})])
    emit(log_path, "s1", ran("add", {"a": 1}))

    (step,) = trace(read_records(log_path), "s1")
    assert step.tool == "add"
    assert step.args == {"a": 1}


def test_the_gate_conversation_lands_on_the_gated_call(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            *ran("add"),
            verdict("send_email", "gate", rule="flows.0", turn=1),
            ("gate_requested", {"tool": "send_email", "rule": "flows.0", "timeout": 120}),
            ("gate_approved", {"tool": "send_email", "rule": "flows.0"}),
            *ran("send_email", {"to": "a@b.com"}),
        ],
    )

    first, gated = trace(read_records(log_path), "s1")
    assert first.notes == []
    assert gated.notes == ["asked a human (timeout 120s)", "a human approved it"]
    assert gated.outcome == "ok"


@pytest.mark.parametrize(
    "event, note",
    [
        (("gate_denied", {"tool": "send_email"}), "a human denied it"),
        (("gate_timeout", {"tool": "send_email", "seconds": 30}), "nobody answered within 30s"),
        (("gate_unavailable", {"tool": "send_email"}), "no gate was configured, so it was refused"),
    ],
)
def test_a_refused_gate_says_which_way_it_was_refused(log_path, event, note):
    emit(log_path, "s1", [verdict("send_email", "gate", rule="flows.0"), event])

    (step,) = trace(read_records(log_path), "s1")
    assert step.notes == [note]
    assert step.outcome == "not forwarded"


def test_taint_lands_on_the_call_whose_result_caused_it(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            *ran("add"),
            verdict("fetch_url", turn=1),
            *ran("fetch_url", {"url": "http://evil"}),
            ("session_tainted", {"tool": "fetch_url"}),
        ],
    )

    add, fetch = trace(read_records(log_path), "s1")
    assert add.notes == []
    assert fetch.notes == ["this result tainted the session"]


def test_an_upstream_failure_sets_the_outcome_and_says_what_broke(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            ("tool_call", {"tool": "add", "args": {"a": 1}}),
            ("tool_error", {"tool": "add", "error": "RuntimeError: broken pipe"}),
        ],
    )

    (step,) = trace(read_records(log_path), "s1")
    assert step.outcome == "error"
    assert "broken pipe" in step.notes[0]


def test_a_cancelled_call_warns_that_the_tool_may_still_have_run(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("send_email"),
            ("tool_call", {"tool": "send_email", "args": {"to": "a@b.com"}}),
            ("tool_cancelled", {"tool": "send_email"}),
        ],
    )

    (step,) = trace(read_records(log_path), "s1")
    assert step.outcome == "cancelled"
    assert "may still have run" in step.notes[0]


def test_lost_bookkeeping_shows_up_as_a_note(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            *ran("add"),
            ("state_error", {"tool": "add", "error": "RuntimeError: taint store went away"}),
        ],
    )

    (step,) = trace(read_records(log_path), "s1")
    assert "taint store went away" in step.notes[0]


def test_records_before_the_first_decision_belong_to_no_step(log_path):
    emit(
        log_path,
        "s1",
        [
            ("proxy_start", {"upstream": "toy"}),
            ("state_error", {"tool": "?", "error": "before anything was decided"}),
            verdict("add"),
            *ran("add"),
        ],
    )

    (step,) = trace(read_records(log_path), "s1")
    assert step.notes == []


def test_an_unknown_session_traces_nothing(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add")])

    assert trace(read_records(log_path), "nope") == []


def test_a_shadow_block_is_marked_and_says_it_ran_anyway(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("delete_file", "block", rule="tools.delete_file", shadow=True),
            *ran("delete_file", {"path": "/etc/passwd"}),
        ],
    )

    steps = trace(read_records(log_path), "s1")
    assert steps[0].shadow is True
    assert steps[0].outcome == "ok"

    out = format_trace(steps, "s1")
    assert "shadow" in out
    assert "this ran anyway" in out


# --- format_trace ---


def test_the_trace_names_the_session_every_tool_and_every_rule(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("fetch_url", rule="tools.fetch_url"),
            *ran("fetch_url", {"url": "http://x"}),
            verdict("delete_file", "block", rule="tools.delete_file", turn=1),
            verdict("send_email", "gate", rule="flows.0", turn=1),
            ("gate_requested", {"tool": "send_email", "rule": "flows.0", "timeout": 120}),
            ("gate_denied", {"tool": "send_email", "rule": "flows.0"}),
        ],
    )

    out = format_trace(trace(read_records(log_path), "s1"), "s1")
    assert "session s1" in out
    for name in ("fetch_url", "delete_file", "send_email"):
        assert name in out
    for rule in ("tools.fetch_url", "tools.delete_file", "flows.0"):
        assert rule in out


def test_the_closing_line_names_where_untrusted_content_got_in(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            *ran("add"),
            verdict("fetch_url", turn=1),
            *ran("fetch_url"),
            ("session_tainted", {"tool": "fetch_url"}),
            verdict("send_email", turn=2),
            *ran("send_email"),
        ],
    )

    closing = format_trace(trace(read_records(log_path), "s1"), "s1").splitlines()[-1]
    assert "turn 1" in closing
    assert "fetch_url" in closing


def test_long_arguments_are_truncated(log_path):
    emit(log_path, "s1", [verdict("write_file"), *ran("write_file", {"body": "x" * 4000})])

    out = format_trace(trace(read_records(log_path), "s1"), "s1")
    args_line = next(line for line in out.splitlines() if "args" in line)
    assert "more chars)" in args_line
    assert len(args_line) < 300


def test_a_session_with_no_calls_says_so():
    assert "no tool calls" in format_trace([], "s1")


# --- report ---


def test_counts_two_sessions_sharing_one_file(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add", rule="tools.add"),
            *ran("add"),
            verdict("delete_file", "block", rule="tools.delete_file", turn=1),
        ],
    )
    emit(
        log_path,
        "s2",
        [
            verdict("add", rule="tools.add"),
            *ran("add"),
            verdict("send_email", "gate", rule="flows.0", turn=1),
            ("gate_requested", {"tool": "send_email", "rule": "flows.0", "timeout": 120}),
            ("gate_denied", {"tool": "send_email", "rule": "flows.0"}),
        ],
    )

    rep = report(read_records(log_path))
    assert rep.sessions == 2
    assert rep.calls == 4
    assert rep.allowed == 2
    assert rep.blocked == 1
    assert rep.gated == 1


def test_shadow_verdicts_are_would_have_blocked_not_blocked(log_path):
    # every one of these calls RAN. Counting them as blocked would tell an
    # operator the policy is already protecting them while nothing at all
    # has been stopped — the one number shadow mode exists to produce.
    emit(
        log_path,
        "s1",
        [
            verdict("delete_file", "block", rule="tools.delete_file", shadow=True),
            *ran("delete_file"),
            verdict("send_email", "gate", rule="flows.0", shadow=True, turn=1),
            *ran("send_email"),
            verdict("add", rule="tools.add", shadow=True, turn=2),
            *ran("add"),
        ],
    )

    rep = report(read_records(log_path))
    assert rep.shadow_would_block == 2
    assert rep.blocked == 0
    assert rep.gated == 0
    assert rep.allowed == 1
    assert rep.calls == 3


def test_enforced_and_shadow_verdicts_are_counted_apart(log_path):
    emit(log_path, "s1", [verdict("delete_file", "block", rule="tools.delete_file")])
    emit(
        log_path,
        "s2",
        [
            verdict("delete_file", "block", rule="tools.delete_file", shadow=True),
            *ran("delete_file"),
        ],
    )

    rep = report(read_records(log_path))
    assert rep.blocked == 1
    assert rep.shadow_would_block == 1
    assert rep.by_rule["tools.delete_file"] == 2  # fired twice, stopped one


def test_by_rule_and_by_tool_tallies(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add", rule="tools.add"),
            *ran("add"),
            verdict("add", rule="tools.add", turn=1),
            *ran("add"),
            verdict("delete_file", "block", rule="tools.delete_file", turn=2),
            verdict("delete_file", "block", rule="tools.delete_file", turn=2),
            verdict("send_email", "gate", rule="flows.0", turn=2),
        ],
    )

    rep = report(read_records(log_path))
    assert rep.by_tool == Counter({"add": 2, "delete_file": 2, "send_email": 1})
    # by_rule is "rules that fired": the verdicts that stopped or
    # questioned something, not the rule that let a call through
    assert rep.by_rule == Counter({"tools.delete_file": 2, "flows.0": 1})


def test_tainted_sessions_counts_sessions_not_events(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("fetch_url"),
            *ran("fetch_url"),
            ("session_tainted", {"tool": "fetch_url"}),
            verdict("fetch_url", turn=1),
            *ran("fetch_url"),
            ("session_tainted", {"tool": "fetch_url"}),
        ],
    )
    emit(log_path, "s2", [verdict("add"), *ran("add")])

    rep = report(read_records(log_path))
    assert rep.sessions == 2
    assert rep.tainted_sessions == 1


def test_format_report_renders_every_nonzero_number(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add", rule="tools.add"),
            *ran("add"),
            verdict("add", rule="tools.add", turn=1),
            *ran("add"),
            verdict("add", rule="tools.add", turn=2),
            *ran("add"),
            verdict("delete_file", "block", rule="tools.delete_file", turn=3),
            verdict("delete_file", "block", rule="tools.delete_file", turn=3),
            verdict("send_email", "gate", rule="flows.0", turn=3),
            ("gate_requested", {"tool": "send_email", "rule": "flows.0", "timeout": 120}),
            ("gate_denied", {"tool": "send_email", "rule": "flows.0"}),
            verdict("write_file", "block", rule="tools.write_file", shadow=True, turn=3),
            *ran("write_file"),
            ("session_tainted", {"tool": "write_file"}),
        ],
    )

    squeezed = " ".join(format_report(report(read_records(log_path))).split())
    assert "7 call(s) across 1 session(s)" in squeezed
    assert "allowed outright 3" in squeezed
    assert "blocked by policy 2" in squeezed
    # a gate verdict says a human was asked; the gate_* record says what
    # they answered, and the report has to show both
    assert "sent to a human 1 (approved 0, refused 1)" in squeezed
    assert "shadow mode) 1" in squeezed
    assert "untrusted content 1" in squeezed
    assert "2 tools.delete_file" in squeezed
    assert "1 flows.0" in squeezed
    assert "3 add" in squeezed
    assert "3 tools.add" not in squeezed


# --- cli ---


def test_trace_without_a_session_id_takes_the_last_one(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add")])
    emit(log_path, "s2", [verdict("send_email"), *ran("send_email")])

    done = cli("trace", str(log_path))
    assert done.returncode == 0
    assert "session s2" in done.stdout
    assert "session s1" not in done.stdout


def test_trace_can_be_pointed_at_one_session(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add", {"a": 1})])
    emit(log_path, "s2", [verdict("send_email"), *ran("send_email")])

    done = cli("trace", str(log_path), "s1")
    assert done.returncode == 0
    assert "session s1" in done.stdout
    assert "add" in done.stdout
    assert "send_email" not in done.stdout


def test_trace_of_an_unknown_session_lists_the_known_ones(log_path):
    emit(log_path, "s1", [verdict("add"), *ran("add")])
    emit(log_path, "s2", [verdict("add"), *ran("add")])

    done = cli("trace", str(log_path), "s3")
    assert done.returncode == 1
    assert "s1, s2" in done.stderr
    assert "Traceback" not in done.stderr


def test_report_prints_the_summary(log_path):
    emit(
        log_path,
        "s1",
        [
            verdict("add"),
            *ran("add"),
            verdict("delete_file", "block", rule="tools.delete_file", turn=1),
        ],
    )

    done = cli("report", str(log_path))
    assert done.returncode == 0
    assert "2 call(s) across 1 session(s)" in done.stdout
    assert "tools.delete_file" in done.stdout


@pytest.mark.parametrize("command", ["trace", "report"])
def test_a_malformed_log_is_reported_without_a_traceback(log_path, command):
    emit(log_path, "s1", [verdict("add"), *ran("add")])
    log_path.write_text(log_path.read_text() + "{torn\n")

    done = cli(command, str(log_path))
    assert done.returncode == 1
    assert "not valid json" in done.stderr
    assert "Traceback" not in done.stderr
