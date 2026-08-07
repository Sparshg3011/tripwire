"""Hash-chained audit log.

Append-only JSONL where every record carries the sha256 of the previous
record's exact bytes. Edit or delete any line and every hash after it
stops matching — you can't rewrite history without it showing.

What the chain does NOT protect against: truncating the tail of the
file. An attacker with write access can drop the last k lines and the
remaining prefix still verifies. (Fixing that needs an external anchor;
out of scope for v0.1, noted in the threat model.)

If a write fails, we raise AuditWriteError and the proxy is expected to
halt: no audit record, no side effect.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64

Redactor = Callable[[dict[str, Any]], dict[str, Any]]


class AuditWriteError(Exception):
    pass


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def _serialize(record: dict[str, Any]) -> str:
    # Compact and key-sorted so the same record always produces the
    # same bytes — the hash chain depends on that.
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


class AuditLog:
    """Appender. Reopening an existing log continues its chain.

    `redact` runs on the data payload before the record is built, so
    the redacted form is what gets hashed and stored — the original
    never touches disk.
    """

    def __init__(self, path: str | Path, session_id: str = "", redact: Redactor | None = None):
        self.path = Path(path)
        self.session_id = session_id
        self._redact = redact
        self._seq, self._prev = self._resume()
        try:
            # held open for the life of the log, closed in close()
            self._fh = open(self.path, "a", encoding="utf-8")  # noqa: SIM115
        except OSError as e:
            raise AuditWriteError(f"cannot open audit log {self.path}: {e}") from e

        # One writer per log, enforced. Each writer caches the chain head
        # at startup, so two proxies appending to one file would each
        # build on a stale hash and shred the chain for both — silently,
        # and only discovered later by someone trying to use it as
        # evidence. Better to refuse the second process outright.
        try:
            fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            self._fh.close()
            raise AuditWriteError(
                f"another process is already writing {self.path} ({e}); "
                f"give each proxy its own audit log"
            ) from e

    def _resume(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = None
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        last = line.rstrip("\n")
        except OSError as e:
            raise AuditWriteError(f"cannot read audit log {self.path}: {e}") from e
        assert last is not None
        try:
            seq = json.loads(last)["seq"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Torn or tampered tail. Refusing to continue the chain is
            # the point — an operator has to look at it.
            raise AuditWriteError(
                f"audit log {self.path} has a corrupt last line; refusing to continue"
            ) from e
        return seq + 1, _hash_line(last)

    def append(self, kind: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        data = data or {}
        if self._redact is not None:
            data = self._redact(data)
        record = {
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(),
            "prev": self._prev,
            # one log file can hold many runs, and an incident is always
            # about one of them
            "session": self.session_id,
            "kind": kind,
            "data": data,
        }
        line = _serialize(record)
        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except (OSError, ValueError) as e:
            raise AuditWriteError(f"cannot write audit log {self.path}: {e}") from e
        self._seq += 1
        self._prev = _hash_line(line)
        return record

    def close(self) -> None:
        self._fh.close()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    bad_line: int | None = None  # 1-based line number of first bad line
    why: str | None = None


def verify_log(path: str | Path) -> VerifyResult:
    """Walk the chain and recompute every hash."""
    prev = GENESIS
    n = 0
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as e:
        return VerifyResult(ok=False, records=0, bad_line=None, why=str(e))

    for i, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return VerifyResult(ok=False, records=n, bad_line=i, why="not valid json")
        if record.get("seq") != n:
            return VerifyResult(
                ok=False, records=n, bad_line=i, why=f"expected seq {n}, got {record.get('seq')}"
            )
        if record.get("prev") != prev:
            return VerifyResult(ok=False, records=n, bad_line=i, why="hash chain broken")
        if _serialize(record) != line:
            # Same content, different bytes — someone re-wrote the line.
            return VerifyResult(ok=False, records=n, bad_line=i, why="non-canonical encoding")
        prev = _hash_line(line)
        n += 1
    return VerifyResult(ok=True, records=n)
