"""The task file: how the user's task text reaches a running proxy.

A host that can run a command when the user submits a prompt writes the
prompt to a file (write_task(); `tripwire hook claude-code` does it for
Claude Code), and `tripwire serve --task-file` reads the file before
each evaluation (TaskFile), adding it as a new task segment whenever it
changed. The file holds the text as UTF-8 and nothing else.

Whoever can write the file decides what anchors, so the agent must not
be able to: the proxy counts it among the protected paths no argument
anchors to, and keeps the TRIPWIRE_ variables that name it from the
upstream. The agent's host is another matter; see docs/claude-code.md.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import sys
import tempfile
from typing import BinaryIO

MAX_TASK_BYTES = 64 * 1024


class TaskRejected(ValueError):
    """Task text that won't be taken. The message is the reason, never
    the text."""


class TaskFile:
    """A task file, read again whenever its (mtime_ns, size, inode)
    changes, including by coming back after it went missing."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = os.fspath(path)
        self._seen: tuple[int, int, int] | str | None = None

    def poll(self) -> str | None:
        """The file's text when it changed since the last poll; None when
        it hasn't, or is missing. Raises TaskRejected, once per change,
        for anything but a regular file of UTF-8 text within
        MAX_TASK_BYTES. Raises nothing else."""
        try:
            now: tuple[int, int, int] | str = _signature(os.stat(self.path))
        except FileNotFoundError:
            now = "missing"
        except (OSError, ValueError):
            now = "unreadable"
        if now == self._seen:
            return None
        self._seen = now
        if now == "missing":
            return None
        if now == "unreadable":
            raise TaskRejected("unreadable")

        try:
            # O_NONBLOCK: a fifo swapped in after the stat can't hang the proxy
            fd = os.open(self.path, os.O_RDONLY | os.O_NONBLOCK)
        except FileNotFoundError:
            self._seen = "missing"
            return None
        except (OSError, ValueError):
            raise TaskRejected("unreadable") from None
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                self._seen = _signature(before)
                raise TaskRejected("not_a_file")
            with open(fd, "rb", closefd=False) as f:
                data = f.read(MAX_TASK_BYTES + 1)
            after = os.fstat(fd)
        except OSError:
            raise TaskRejected("unreadable") from None
        finally:
            os.close(fd)
        if _signature(after) != _signature(before):
            # written to while read: the next poll reads what it settles on
            self._seen = None
            return None
        # what was read, which a replace between the stat and the open changes
        self._seen = _signature(after)
        if len(data) > MAX_TASK_BYTES:
            raise TaskRejected("too_long")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise TaskRejected("not_utf8") from None


def _signature(st: os.stat_result) -> tuple[int, int, int]:
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def write_task(path: str | os.PathLike[str], text: str) -> None:
    """Replace the task file with text, atomically, readable and writable
    by its owner only. The directory must exist already. Raises OSError,
    or UnicodeEncodeError for text that isn't valid Unicode."""
    data = text.encode("utf-8")
    directory, name = os.path.split(os.path.abspath(path))
    # mkstemp creates it 0600, and the rename keeps that
    fd, temporary = tempfile.mkstemp(prefix=f".{name}.", dir=directory)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise


def claude_code_prompt(payload: bytes) -> str | None:
    """The prompt of a Claude Code UserPromptSubmit hook event, given its
    JSON input; None for anything else."""
    # https://code.claude.com/docs/en/hooks: the UserPromptSubmit input
    # holds "hook_event_name": "UserPromptSubmit" and the submitted text
    # as "prompt"
    try:
        event = json.loads(payload)
    except (ValueError, RecursionError):
        return None
    if not isinstance(event, dict) or event.get("hook_event_name") != "UserPromptSubmit":
        return None
    prompt = event.get("prompt")
    return prompt if isinstance(prompt, str) else None


def claude_code_hook(path: str | os.PathLike[str], stdin: BinaryIO | None = None) -> None:
    """Write the prompt of the UserPromptSubmit event on stdin to the task
    file. Never raises: a hook that fails must not keep the user's prompt
    from the model, and one that fails loudly might."""
    with contextlib.suppress(Exception):
        prompt = claude_code_prompt((stdin or sys.stdin.buffer).read())
        if prompt is not None:
            write_task(path, prompt)
