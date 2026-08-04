import json

import pytest

from tripwire.tx import AuditLog, AuditWriteError, verify_log


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
