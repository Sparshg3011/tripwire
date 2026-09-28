"""The task file from both ends: the writer the Claude Code hook runs, and
the reader the proxy polls before each evaluation. Every task and prompt
here is synthetic.
"""

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import types
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from tripwire.intent import (
    MAX_TASK_BYTES,
    TaskFile,
    TaskRejected,
    claude_code_hook,
    claude_code_prompt,
    write_task,
)

TASK = "Send the summary to alice@corp.example"


def event(prompt=TASK, **fields):
    # the UserPromptSubmit input, as the Claude Code hooks reference shows it
    return {
        "session_id": "abc123",
        "transcript_path": "/home/user/.claude/projects/p/transcript.jsonl",
        "cwd": "/home/user/project",
        "permission_mode": "default",
        "hook_event_name": "UserPromptSubmit",
        "prompt": prompt,
        **fields,
    }


# --- reading ---


def test_a_missing_file_is_no_task_until_it_appears(tmp_path):
    task = TaskFile(tmp_path / "task")
    assert task.poll() is None
    write_task(tmp_path / "task", TASK)
    assert task.poll() == TASK


def test_a_file_is_read_once_per_change(tmp_path):
    path = tmp_path / "task"
    write_task(path, TASK)
    task = TaskFile(path)
    assert task.poll() == TASK
    assert task.poll() is None
    write_task(path, "and cc bob@corp.example")
    assert task.poll() == "and cc bob@corp.example"
    assert task.poll() is None


@pytest.mark.parametrize("change", ["st_mtime_ns", "st_size", "st_ino"])
def test_any_one_of_mtime_size_and_inode_is_a_change(tmp_path, change):
    path = tmp_path / "task"
    path.write_text("pay 12345")
    before = os.stat(path)
    task = TaskFile(path)
    task.poll()

    if change == "st_ino":
        write_task(path, "pay 54321")
    else:
        path.write_text("pay 123456" if change == "st_size" else "pay 54321")
    mtime = before.st_mtime_ns + (change == "st_mtime_ns")
    os.utime(path, ns=(before.st_atime_ns, mtime))
    after = os.stat(path)
    fields = ("st_mtime_ns", "st_size", "st_ino")
    assert {f for f in fields if getattr(after, f) != getattr(before, f)} == {change}

    assert task.poll() == path.read_text()


def test_a_file_that_goes_and_comes_back_is_read_again(tmp_path):
    path = tmp_path / "task"
    write_task(path, TASK)
    task = TaskFile(path)
    task.poll()
    path.unlink()
    assert task.poll() is None
    write_task(path, TASK)
    assert task.poll() == TASK


@pytest.mark.parametrize(
    ("data", "reason"),
    [(b"x" * (MAX_TASK_BYTES + 1), "too_long"), (b"caf\xe9", "not_utf8")],
)
def test_a_file_it_cant_take_is_refused_once(tmp_path, data, reason):
    path = tmp_path / "task"
    path.write_bytes(data)
    task = TaskFile(path)
    with pytest.raises(TaskRejected, match=reason):
        task.poll()
    assert task.poll() is None  # unchanged: said once
    write_task(path, TASK)
    assert task.poll() == TASK


def test_exactly_64_kib_is_taken(tmp_path):
    (tmp_path / "task").write_bytes(b"x" * MAX_TASK_BYTES)
    assert TaskFile(tmp_path / "task").poll() == "x" * MAX_TASK_BYTES


def test_a_directory_is_refused(tmp_path):
    (tmp_path / "task").mkdir()
    with pytest.raises(TaskRejected, match="not_a_file"):
        TaskFile(tmp_path / "task").poll()


def test_a_fifo_is_refused_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "task"
    os.mkfifo(path)
    outcome = []

    def poll():
        try:
            TaskFile(path).poll()
        except TaskRejected as e:
            outcome.append(str(e))

    reader = threading.Thread(target=poll, daemon=True)
    reader.start()
    reader.join(5)
    assert outcome == ["not_a_file"]


def test_a_platform_without_o_nonblock_still_reads_it(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "O_NONBLOCK")
    write_task(tmp_path / "task", TASK)
    assert TaskFile(tmp_path / "task").poll() == TASK


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads what it likes")
def test_an_unreadable_file_is_refused_once(tmp_path):
    path = tmp_path / "task"
    write_task(path, TASK)
    path.chmod(0)
    task = TaskFile(path)
    with pytest.raises(TaskRejected, match="unreadable"):
        task.poll()
    assert task.poll() is None


def test_a_file_written_to_while_read_is_read_again_once_it_settles(tmp_path, monkeypatch):
    path = tmp_path / "task"
    write_task(path, TASK)
    task = TaskFile(path)
    real = os.fstat
    calls = []

    def moving(fd):
        st = real(fd)
        calls.append(fd)
        if len(calls) == 2:  # after the read: the writer appended meanwhile
            return types.SimpleNamespace(
                st_mode=st.st_mode,
                st_mtime_ns=st.st_mtime_ns + 1,
                st_size=st.st_size + 1,
                st_ino=st.st_ino,
            )
        return st

    monkeypatch.setattr("tripwire.intent.os.fstat", moving)
    assert task.poll() is None
    monkeypatch.undo()
    assert task.poll() == TASK


@given(texts=st.lists(st.text(), min_size=1, max_size=4))
def test_every_text_written_is_read_back_once(texts):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "task"
        task = TaskFile(path)
        for text in texts:
            try:
                write_task(path, text)
            except UnicodeEncodeError:  # a lone surrogate isn't text to write
                continue
            assert task.poll() == text
            assert task.poll() is None


# --- writing ---


def test_the_file_is_the_owners_alone_whatever_the_umask(tmp_path):
    path = tmp_path / "task"
    path.write_text("old")
    path.chmod(0o644)
    old = os.umask(0)
    try:
        write_task(path, TASK)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert path.read_text() == TASK


def test_a_write_replaces_the_file_and_leaves_nothing_else(tmp_path):
    path = tmp_path / "task"
    write_task(path, "first")
    inode = os.stat(path).st_ino
    write_task(path, TASK)
    assert os.stat(path).st_ino != inode  # a new file renamed over, never a rewrite
    assert sorted(p.name for p in tmp_path.iterdir()) == ["task"]


def test_a_write_into_a_missing_directory_fails_and_leaves_nothing(tmp_path):
    with pytest.raises(FileNotFoundError):
        write_task(tmp_path / "nowhere" / "task", TASK)
    assert list(tmp_path.iterdir()) == []


def test_a_write_that_fails_takes_its_temporary_file_with_it(tmp_path, monkeypatch):
    def refuse(src, dst):
        raise PermissionError("no")

    monkeypatch.setattr("tripwire.intent.os.replace", refuse)
    with pytest.raises(PermissionError):
        write_task(tmp_path / "task", TASK)
    assert list(tmp_path.iterdir()) == []


# --- the Claude Code hook ---


def test_the_prompt_is_read_from_a_user_prompt_submit_event():
    assert claude_code_prompt(json.dumps(event()).encode()) == TASK


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"not json",
        b"[1, 2]",
        b"[" * 100_000,
        json.dumps(event(hook_event_name="PostToolUse")).encode(),
        json.dumps({k: v for k, v in event().items() if k != "hook_event_name"}).encode(),
        json.dumps(event(prompt=None)).encode(),
        json.dumps(event(prompt=["x"])).encode(),
    ],
)
def test_anything_else_is_no_prompt(payload):
    assert claude_code_prompt(payload) is None


@given(prompt=st.text())
def test_every_prompt_is_read_as_it_was_submitted(prompt):
    assert claude_code_prompt(json.dumps(event(prompt)).encode()) == prompt


@given(payload=st.binary() | st.text().map(str.encode))
def test_the_reader_never_raises(payload):
    prompt = claude_code_prompt(payload)
    assert prompt is None or isinstance(prompt, str)


def test_the_hook_writes_the_prompt(tmp_path):
    claude_code_hook(tmp_path / "task", io.BytesIO(json.dumps(event()).encode()))
    assert (tmp_path / "task").read_text() == TASK


@pytest.mark.parametrize("payload", [b"not json", json.dumps(event("lone \ud800")).encode()])
def test_a_hook_that_cant_write_leaves_the_file_as_it_was(tmp_path, payload):
    write_task(tmp_path / "task", TASK)
    claude_code_hook(tmp_path / "task", io.BytesIO(payload))
    assert (tmp_path / "task").read_text() == TASK
    assert sorted(p.name for p in tmp_path.iterdir()) == ["task"]


def hook(tmp_path, stdin, target=None):
    target = target if target is not None else tmp_path / "task"
    return subprocess.run(
        [sys.executable, "-m", "tripwire", "hook", "claude-code", "--task-file", str(target)],
        input=stdin,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_the_hook_command_says_nothing_and_exits_0(tmp_path):
    done = hook(tmp_path, json.dumps(event()).encode())
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")
    assert (tmp_path / "task").read_text() == TASK
    assert stat.S_IMODE(os.stat(tmp_path / "task").st_mode) == 0o600


@pytest.mark.parametrize("where", ["here", "nowhere"])
def test_the_hook_command_says_nothing_and_exits_0_when_it_fails(tmp_path, where):
    target = tmp_path / "task" if where == "here" else tmp_path / "nowhere" / "task"
    done = hook(tmp_path, b"\xff not an event", target)
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")
    done = hook(tmp_path, json.dumps(event()).encode(), target)
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")
    assert target.exists() == (where == "here")
