import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from tripwire.tx import AuditKeyError, AuditLog, AuditWriteError, load_key, verify_log

KEY_ENV = "TRIPWIRE_AUDIT_KEY_FILE"
KEY = b"audit-test-key-0123456789abcdef"


def cli(*argv, env=None):
    return subprocess.run(
        [sys.executable, "-m", "tripwire", *argv],
        check=False,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        env={**os.environ, **(env or {})},
    )


def dump(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def write_log(path, n, key=None):
    log = AuditLog(path, session_id="s1", key=key)
    for i in range(n):
        log.append("event", {"n": i})
    log.close()


def forge(index):
    def change(records):
        records[index]["data"] = {"forged": True}

    return change


def rechain(path, start, change, key=None):
    """What anyone who can write the file can do: alter records, then
    recompute every link from `start` on — as plain hashes, or as MACs
    under whatever key they have."""
    records = [json.loads(line) for line in path.read_text().splitlines()]
    change(records)
    lines = [dump(r) for r in records[:start]]
    if start == 0:
        prev = "0" * 64
    elif key is None:
        prev = hashlib.sha256(lines[-1].encode()).hexdigest()
    else:
        prev = records[start - 1]["mac"]
    for record in records[start:]:
        record["prev"] = prev
        record.pop("mac", None)
        if key is None:
            lines.append(dump(record))
            prev = hashlib.sha256(lines[-1].encode()).hexdigest()
        else:
            record["mac"] = hmac.new(key, dump(record).encode(), hashlib.sha256).hexdigest()
            lines.append(dump(record))
            prev = record["mac"]
    path.write_text("\n".join(lines) + "\n")


def test_append_and_verify(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("proxy_start", {"upstream": "toy"})
    log.append("tool_call", {"tool": "add", "args": {"a": 1, "b": 2}})
    log.append("tool_result", {"tool": "add", "ok": True})
    log.close()

    result = verify_log(tmp_path / "audit.jsonl")
    assert result.ok
    assert result.records == 3


def test_chain_continues_across_reopen(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("a", {})
    log.close()

    log = AuditLog(path)
    log.append("b", {})
    log.close()

    result = verify_log(path)
    assert result.ok and result.records == 2


def test_tampered_line_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"n": i})
    log.close()

    lines = path.read_text().splitlines()
    doctored = json.loads(lines[2])
    doctored["data"]["n"] = 999  # attacker edits history
    lines[2] = json.dumps(doctored, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n")

    result = verify_log(path)
    assert not result.ok
    assert result.bad_line == 4  # the line after the edit no longer chains


def test_deleted_line_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(5):
        log.append("event", {"n": i})
    log.close()

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    assert not verify_log(path).ok


def test_rewritten_bytes_detected_even_if_content_matches(tmp_path):
    # Same json content but different formatting = someone rewrote the file.
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("event", {"n": 1})
    log.close()

    record = json.loads(path.read_text())
    path.write_text(json.dumps(record, indent=2) + "\n")

    result = verify_log(path)
    assert not result.ok


@pytest.mark.parametrize("line", ["[1]", "42", "null", '"text"'])
def test_json_that_is_not_a_record_is_a_bad_line(tmp_path, line):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("event", {})
    log.close()
    with open(path, "a") as fh:
        fh.write(line + "\n")

    result = verify_log(path)
    assert not result.ok
    assert result.bad_line == 2
    assert result.why == "not a record object"


def test_verify_says_so_when_it_cannot_read_the_log(tmp_path):
    done = cli("verify", str(tmp_path / "missing.jsonl"))
    assert done.returncode == 1
    assert "cannot verify" in done.stderr
    assert "line None" not in done.stderr


def test_corrupt_tail_refuses_to_continue(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("event", {})
    log.close()

    with open(path, "a") as fh:
        fh.write('{"torn line')  # crash mid-write

    with pytest.raises(AuditWriteError, match="corrupt last line"):
        AuditLog(path)


def test_unwritable_path_fails_closed(tmp_path):
    with pytest.raises(AuditWriteError):
        AuditLog(tmp_path / "no" / "such" / "dir" / "audit.jsonl")


def test_redactor_runs_before_hashing(tmp_path):
    path = tmp_path / "audit.jsonl"

    def redact(data):
        return {k: ("<redacted>" if k == "body" else v) for k, v in data.items()}

    log = AuditLog(path, redact=redact)
    log.append("tool_call", {"tool": "send_email", "body": "secret stuff"})
    log.close()

    text = path.read_text()
    assert "secret stuff" not in text
    assert "<redacted>" in text
    # and the chain still verifies, because the redacted form is what was hashed
    assert verify_log(path).ok


def test_empty_log_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.touch()
    result = verify_log(path)
    assert result.ok and result.records == 0


def test_only_one_writer_at_a_time(tmp_path):
    # two proxies on one log would each cache the chain head at startup
    # and then build on a stale hash, shredding the chain for both
    first = AuditLog(tmp_path / "audit.jsonl", session_id="a")
    with pytest.raises(AuditWriteError, match="already writing"):
        AuditLog(tmp_path / "audit.jsonl", session_id="b")

    first.close()
    second = AuditLog(tmp_path / "audit.jsonl", session_id="b")
    second.append("proxy_start", {})
    second.close()
    assert verify_log(tmp_path / "audit.jsonl").ok


def test_records_carry_their_session(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl", session_id="deadbeef")
    log.append("decision", {"tool": "add"})
    log.close()

    record = json.loads((tmp_path / "audit.jsonl").read_text())
    assert record["session"] == "deadbeef"


# --- what an unkeyed chain can't see, and a keyed one can ---


def test_an_unkeyed_chain_cannot_catch_a_rewrite(tmp_path):
    # the limit verify states out loud: recompute the hashes after an
    # edit and the chain is as good as new
    path = tmp_path / "audit.jsonl"
    write_log(path, 5)
    rechain(path, 2, forge(2))

    assert verify_log(path).ok


def test_a_keyed_chain_catches_the_same_rewrite(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 5, key=KEY)
    rechain(path, 2, forge(2), key=b"attacker-guess-0123456789abcdef")

    result = verify_log(path, key=KEY)
    assert not result.ok
    assert result.bad_line == 3


def test_a_keyed_chain_covers_its_last_line(tmp_path):
    # no later record links to the last one, so it has to carry its own MAC
    path = tmp_path / "audit.jsonl"
    write_log(path, 3, key=KEY)
    lines = path.read_text().splitlines()
    last = json.loads(lines[-1])
    last["data"]["n"] = 999
    lines[-1] = dump(last)
    path.write_text("\n".join(lines) + "\n")

    result = verify_log(path, key=KEY)
    assert not result.ok
    assert result.bad_line == 3


payloads = st.lists(
    st.dictionaries(st.text(max_size=5), st.integers(), max_size=3), min_size=1, max_size=6
)


@given(events=payloads, target=st.integers(min_value=0), forger=st.none() | st.binary(min_size=1))
@settings(max_examples=100, deadline=None)
def test_no_rewrite_verifies_without_the_key(events, target, forger):
    assume(forger != KEY)
    start = target % len(events)
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "audit.jsonl"
        log = AuditLog(path, key=KEY)
        for data in events:
            log.append("event", data)
        log.close()
        assert verify_log(path, key=KEY).ok

        rechain(path, start, forge(start), key=forger)
        result = verify_log(path, key=KEY)

    assert not result.ok
    assert result.bad_line == start + 1


def test_a_keyed_log_verifies_under_its_key(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2, key=KEY)
    write_log(path, 2, key=KEY)

    result = verify_log(path, key=KEY)
    assert result.ok and result.records == 4


def test_a_keyed_log_is_refused_without_its_key(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2, key=KEY)

    result = verify_log(path)
    assert not result.ok
    assert result.bad_line is None
    assert "keyed" in result.why


def test_a_key_refuses_a_log_rewritten_as_unkeyed(tmp_path):
    # the downgrade: strip the MACs, rebuild a plain chain, and hope the
    # verifier checks whatever the file claims to be
    path = tmp_path / "audit.jsonl"
    write_log(path, 3, key=KEY)

    def downgrade(records):
        for record in records:
            record["chain"] = "sha256"

    rechain(path, 0, downgrade)

    assert verify_log(path).ok  # without the key there's no telling
    result = verify_log(path, key=KEY)
    assert not result.ok
    assert result.bad_line is None
    assert "not keyed" in result.why


def test_a_chain_that_switches_partway_is_broken_where_it_switches(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 3)

    def switch(records):
        records[2]["chain"] = "hmac-sha256"

    rechain(path, 2, switch)

    result = verify_log(path)
    assert not result.ok
    assert result.bad_line == 3


def test_a_log_from_before_chains_were_named_still_verifies_and_continues(tmp_path):
    # what earlier versions wrote: plain sha256 links, no `chain` field
    path = tmp_path / "audit.jsonl"
    prev, lines = "0" * 64, []
    for seq in range(2):
        record = {"seq": seq, "ts": "2026-08-01T00:00:00+00:00", "prev": prev}
        lines.append(dump({**record, "session": "old", "kind": "event", "data": {}}))
        prev = hashlib.sha256(lines[-1].encode()).hexdigest()
    path.write_text("\n".join(lines) + "\n")
    assert verify_log(path).ok

    write_log(path, 1)
    result = verify_log(path)
    assert result.ok and result.records == 3


@pytest.mark.parametrize(
    ("first", "then", "why"),
    [
        (None, KEY, "rotate"),
        (KEY, None, "rotate"),
        (KEY, b"some-other-key-0123456789abcdef", "doesn't authenticate"),
    ],
)
def test_a_writer_only_continues_a_chain_it_can_vouch_for(tmp_path, first, then, why):
    path = tmp_path / "audit.jsonl"
    write_log(path, 1, key=first)

    with pytest.raises(AuditWriteError, match=why):
        AuditLog(path, key=then)


def test_the_key_never_reaches_the_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 3, key=KEY)
    assert KEY.decode() not in path.read_text()


# --- key files ---


def test_a_key_file_ignores_its_trailing_newline(tmp_path):
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(KEY + b"\n")
    assert load_key(key_file) == KEY


def test_a_key_file_too_short_to_be_a_key_is_refused_without_echoing_it(tmp_path):
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(b"hunter2\n")
    with pytest.raises(AuditKeyError) as e:
        load_key(key_file)
    assert "hunter2" not in str(e.value)


def test_a_missing_key_file_is_refused(tmp_path):
    with pytest.raises(AuditKeyError):
        load_key(tmp_path / "nope.key")


# --- cli ---


@pytest.fixture
def key_file(tmp_path):
    path = tmp_path / "audit.key"
    path.write_bytes(KEY + b"\n")
    return path


def test_verify_says_what_an_unkeyed_chain_can_and_cannot_catch(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2)

    done = cli("verify", str(path))
    assert done.returncode == 0
    assert "ok: chain intact, 2 records (unkeyed)" in done.stdout
    assert "a line edited or deleted in the middle of the log" in done.stdout
    assert "a rewrite by anyone who can write the file" in done.stdout
    assert "lines cut from the end" in done.stdout


def test_verify_authenticates_a_keyed_log_with_the_key_file(tmp_path, key_file):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2, key=KEY)

    done = cli("verify", "--audit-key-file", str(key_file), str(path))
    assert done.returncode == 0
    assert "2 records (keyed, all authenticated)" in done.stdout
    assert KEY.decode() not in done.stdout + done.stderr


def test_verify_takes_the_key_file_from_the_environment(tmp_path, key_file):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2, key=KEY)

    done = cli("verify", str(path), env={KEY_ENV: str(key_file)})
    assert done.returncode == 0
    assert "keyed, all authenticated" in done.stdout


def test_verify_will_not_check_a_keyed_log_without_the_key(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 2, key=KEY)

    done = cli("verify", str(path))
    assert done.returncode == 1
    assert "cannot verify" in done.stderr
    assert "keyed" in done.stderr
    assert "BROKEN" not in done.stderr


def test_verify_names_an_unusable_key_file_but_not_its_contents(tmp_path):
    path = tmp_path / "audit.jsonl"
    write_log(path, 1)
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(b"tiny-key\n")

    done = cli("verify", "--audit-key-file", str(key_file), str(path))
    assert done.returncode == 1
    assert str(key_file) in done.stderr
    assert "tiny-key" not in done.stderr
    assert "Traceback" not in done.stderr


def test_trace_checks_a_keyed_log_with_the_key_from_the_environment(tmp_path, key_file):
    path = tmp_path / "audit.jsonl"
    write_log(path, 1, key=KEY)

    assert "WARNING" in cli("trace", str(path)).stderr
    done = cli("trace", str(path), env={KEY_ENV: str(key_file)})
    assert done.returncode == 0
    assert "WARNING" not in done.stderr
