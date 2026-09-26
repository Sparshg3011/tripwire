"""Hash-chained audit log.

Append-only JSONL where every record links to the one before it, so a
line edited or deleted in the middle breaks the chain from there on.
Each record names its chain in `chain`:

  sha256       the default. `prev` is the sha256 of the previous line's
               exact bytes. Anyone who can write the file can recompute
               every hash, so this catches an accident or a careless
               edit, not a rewrite.
  hmac-sha256  keyed. `mac` is an HMAC over the record's own bytes and
               `prev` is the previous record's mac, so without the key
               no line can be edited or rewritten, the last one
               included, and none can go missing except off the end.

Records written before `chain` existed have no such field and are
sha256. A log keeps the chain it started with: the writer won't switch
halfway, and verify won't check a keyed log without its key or accept
an unkeyed one when given a key.

What neither chain protects against: truncating the tail of the file.
An attacker with write access can drop the last k lines and the
remaining prefix still verifies. (Fixing that needs an external anchor;
out of scope for v0.1, noted in the threat model.)

If a write fails, we raise AuditWriteError and the proxy is expected to
halt: no audit record, no side effect.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

GENESIS = "0" * 64

SHA256 = "sha256"
HMAC_SHA256 = "hmac-sha256"

# turns away an empty or placeholder key file; it can't tell a random
# key from a weak one of the same length
MIN_KEY_BYTES = 16

Redactor = Callable[[dict[str, Any]], dict[str, Any]]


class AuditWriteError(Exception):
    pass


class AuditKeyError(Exception):
    """The audit key file can't be used. The message names the file,
    never what is in it."""


def load_key(path: str | Path) -> bytes:
    """Read an audit key from a file.

    Surrounding whitespace is dropped, so the newline an editor or
    `echo` leaves at the end can't quietly become part of the key.
    """
    try:
        key = Path(path).read_bytes().strip()
    except OSError as e:
        raise AuditKeyError(f"cannot read audit key file {path}: {e}") from e
    if len(key) < MIN_KEY_BYTES:
        raise AuditKeyError(
            f"audit key file {path} holds fewer than {MIN_KEY_BYTES} bytes; "
            f"generate one with `openssl rand -hex 32`"
        )
    return key


def _lock_exclusive(fh: IO[str]) -> None:
    """Take a non-blocking exclusive lock, whichever way this OS offers.

    Raises OSError if someone else already holds it. Written per-platform
    rather than with fcntl at import time, because fcntl doesn't exist on
    Windows and importing tripwire has to work everywhere the agent runs.
    """
    if sys.platform == "win32":
        import msvcrt

        # windows locks byte ranges, not files; one byte at the start is
        # enough to make a second writer fail
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        fh.seek(0, 2)
        return

    import fcntl

    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _hash_line(line: str) -> str:
    return hashlib.sha256(line.encode()).hexdigest()


def _serialize(record: dict[str, Any]) -> str:
    # Compact and key-sorted so the same record always produces the
    # same bytes — the hash chain depends on that.
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _mac(key: bytes, body: str) -> str:
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def _authenticated(record: dict[str, Any], key: bytes) -> str | None:
    """The record's mac if `key` made it over exactly these fields, else None."""
    claimed = record.get("mac")
    if not isinstance(claimed, str):
        return None
    body = _serialize({k: v for k, v in record.items() if k != "mac"})
    # as bytes: compare_digest raises on a str that isn't pure ascii, and
    # this one came out of the file
    if hmac.compare_digest(claimed.encode(), _mac(key, body).encode()):
        return claimed
    return None


class AuditLog:
    """Appender. Reopening an existing log continues its chain.

    `redact` runs on the data payload before the record is built, so
    the redacted form is what gets hashed and stored — the original
    never touches disk.

    With `key` the log is an hmac-sha256 chain. The key only ever goes
    into computing MACs; it is never written anywhere.
    """

    def __init__(
        self,
        path: str | Path,
        session_id: str = "",
        redact: Redactor | None = None,
        key: bytes | None = None,
    ):
        self.path = Path(path)
        self.session_id = session_id
        self.chain = SHA256 if key is None else HMAC_SHA256
        self._redact = redact
        self._key = key
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
            _lock_exclusive(self._fh)
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
            record = json.loads(last)
            seq = record["seq"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Torn or tampered tail. Refusing to continue the chain is
            # the point — an operator has to look at it.
            raise AuditWriteError(
                f"audit log {self.path} has a corrupt last line; refusing to continue"
            ) from e

        chain = record.get("chain", SHA256)
        if chain != self.chain:
            # a log that changes chain halfway is one no single verify
            # can vouch for, so switching means rotating
            raise AuditWriteError(
                f"audit log {self.path} is a {chain!r} chain and this writer's is "
                f"{self.chain!r}; continue it as it was started, or rotate it"
            )
        if self._key is None:
            return seq + 1, _hash_line(last)

        mac = _authenticated(record, self._key)
        if mac is None:
            # Chaining onto a head we can't vouch for would make whatever
            # is in it look authentic, and a wrong key would break the
            # chain for good. Either way an operator has to look first.
            raise AuditWriteError(
                f"the last record of {self.path} doesn't authenticate under this key "
                f"(wrong key, or the record was altered); refusing to continue"
            )
        return seq + 1, mac

    def append(self, kind: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
        data = data or {}
        if self._redact is not None:
            data = self._redact(data)
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(UTC).isoformat(),
            "prev": self._prev,
            # one log file can hold many runs, and an incident is always
            # about one of them
            "session": self.session_id,
            "kind": kind,
            "data": data,
            "chain": self.chain,
        }
        if self._key is not None:
            record["mac"] = _mac(self._key, _serialize(record))
        line = _serialize(record)
        try:
            self._fh.write(line + "\n")
            self._fh.flush()
        except (OSError, ValueError) as e:
            raise AuditWriteError(f"cannot write audit log {self.path}: {e}") from e
        self._seq += 1
        self._prev = _hash_line(line) if self._key is None else record["mac"]
        return record

    def close(self) -> None:
        self._fh.close()


@dataclass
class VerifyResult:
    ok: bool
    records: int
    # 1-based line number of the first bad line; None when the log
    # couldn't be checked at all
    bad_line: int | None = None
    why: str | None = None


def _refusal(chain: object) -> str:
    if chain == HMAC_SHA256:
        return "the log is keyed (hmac-sha256) and no key was given"
    if chain == SHA256:
        return (
            "the log is not keyed, so a key vouches for nothing: anyone who can "
            "write the file could have produced this chain"
        )
    return f"unknown chain {chain!r}"


def verify_log(path: str | Path, key: bytes | None = None) -> VerifyResult:
    """Walk the chain and recompute every link.

    With `key`, every record must be hmac-sha256 and authenticate under
    it. Without one, a keyed log is refused outright rather than
    reported as a broken hash chain. Either way a log that switches
    chain partway through is broken where it switches.
    """
    wanted = SHA256 if key is None else HMAC_SHA256
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
        if not isinstance(record, dict):
            return VerifyResult(ok=False, records=n, bad_line=i, why="not a record object")
        chain = record.get("chain", SHA256)
        if chain != wanted:
            if n == 0:
                return VerifyResult(ok=False, records=0, why=_refusal(chain))
            return VerifyResult(ok=False, records=n, bad_line=i, why=f"chain changes to {chain!r}")
        if record.get("seq") != n:
            return VerifyResult(
                ok=False, records=n, bad_line=i, why=f"expected seq {n}, got {record.get('seq')}"
            )
        if record.get("prev") != prev:
            return VerifyResult(ok=False, records=n, bad_line=i, why="hash chain broken")
        if _serialize(record) != line:
            # Same content, different bytes — someone re-wrote the line.
            return VerifyResult(ok=False, records=n, bad_line=i, why="non-canonical encoding")
        if key is None:
            prev = _hash_line(line)
        else:
            mac = _authenticated(record, key)
            if mac is None:
                return VerifyResult(
                    ok=False,
                    records=n,
                    bad_line=i,
                    why="MAC mismatch: altered, or written under a different key",
                )
            prev = mac
        n += 1
    return VerifyResult(ok=True, records=n)
