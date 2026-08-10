"""Intent, forward, completion — the retry problem, solved with a ledger.

Agents retry. A timeout, a dropped pipe, a model deciding to "try that
again" — and the same send_email arrives twice. For a read that's
noise; for a payment it's the incident report. The executor makes a
duplicate call return the first call's result instead of running the
tool a second time.

The key: SHA-256 over (session_id, tool, canonical args serialized as
compact sorted json). Same intent -> same key. Args are the
*canonicalized* form, so two spellings of one value can't dodge the
dedup. Keys include the session id, so nothing replays across sessions
— a fresh session starts with a clean slate even against the same db
file.

Ledger lifecycle, in SQLite (WAL mode, busy_timeout set):

  1. intent row written, state 'in_flight'  — BEFORE anything happens
  2. forward() runs                          — the only side effect
  3. row updated to 'done', result stored    — AFTER we know the outcome

run(tool, args, forward) -> (result, replayed):

  * no row for this key   -> full lifecycle. (result, False).
  * 'done' row            -> forward NOT called. Stored result comes
                             back, (result, True). The caller audits the
                             replay so the log shows it happened.
  * 'in_flight' row       -> raise DuplicateInFlight. The session is
                             serialized, so a live concurrent duplicate
                             is impossible — an in_flight row means a
                             previous attempt died between intent and
                             completion. We do not know whether the side
                             effect happened, and neither does anyone
                             else, so the answer is no, every time,
                             until an operator inspects the ledger.

  * forward returns isError=True -> the intent row is DELETED and the
    error result returned, (result, False). The tool itself told us it
    failed, and we take its word: transient tool failures must stay
    retryable or the executor strangles the agent. This is a trust
    assumption, stated plainly: a tool that does the thing and then
    reports an error will get the thing done twice. THREAT_MODEL.md
    carries it.

  * forward raises -> the row STAYS 'in_flight' and the exception
    propagates. A transport error mid-call is exactly the unknown the
    in_flight state exists for: maybe the tool never heard us, maybe it
    finished and the answer died on the wire. Refuse duplicates until a
    human sorts it out.

  * SQLite refuses (locked, corrupt, disk gone) after its busy_timeout
    -> raise TxError. The interceptor turns that into a block: if the
    ledger can't be written, nothing gets executed — same principle as
    the audit log, one layer down.

Results are stored as CallToolResult JSON (model_dump_json /
model_validate_json round-trip). That means tool results live in the db
file: the audit redaction hook does NOT reach here in v0.1, so the db
deserves the same file permissions as the audit log. Also in
THREAT_MODEL.md.

Known cost, priced in the gym: a *legitimately* repeated identical call
(same session, same tool, byte-identical args) gets the replayed result
instead of a fresh run. add(2, 2) twice is fine — same answer anyway.
"Send the same email again, on purpose" is refused-by-replay; the
model sees the first result repeated and must vary the call (or the
session) to mean it a second time. v0.2 sketches turn-scoped keys if
that cost shows up in the utility numbers.

Contract: no clock games, no randomness, total over whatever args
arrive. The only I/O in this module is the SQLite file. Same key in ->
same row touched, forever.

The spec is executable: tests/test_tx_executor.py. Delete the skip line
and make it green.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import types

Forward = Callable[[], Awaitable[types.CallToolResult]]


class TxError(Exception):
    """The ledger can't be read or written. The caller must block."""


class DuplicateInFlight(Exception):
    """This exact call is already on the ledger with no known outcome."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS intents (
    key      TEXT PRIMARY KEY,
    tool     TEXT NOT NULL,
    state    TEXT NOT NULL,
    result   TEXT
)
"""


def intent_key(session_id: str, tool: str, args: dict[str, Any]) -> str:
    """SHA-256 hex over (session_id, tool, compact-sorted-json args)."""
    body = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    # the separators are part of the key: a differently-spaced encoding
    # of the same call has to hash the same, or dedup silently stops
    material = f"{session_id}\x00{tool}\x00{body}"
    return hashlib.sha256(material.encode()).hexdigest()


class TxExecutor:
    def __init__(self, db_path: str | Path, session_id: str) -> None:
        self.session_id = session_id
        self.path = Path(db_path)
        try:
            self._db = sqlite3.connect(self.path, isolation_level=None)
            # WAL so a reader (an operator inspecting the ledger) never
            # blocks the proxy; busy_timeout so brief contention waits
            # instead of failing the call
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA busy_timeout=5000")
            self._db.execute(SCHEMA)
        except sqlite3.Error as e:
            raise TxError(f"cannot open the ledger at {self.path}: {e}") from e

    async def run(
        self, tool: str, args: dict[str, Any], forward: Forward
    ) -> tuple[types.CallToolResult, bool]:
        key = intent_key(self.session_id, tool, args)
        row = self._one("SELECT state, result FROM intents WHERE key = ?", (key,))

        if row is not None:
            state, stored = row
            if state == "done":
                return self._revive(stored), True
            # in_flight: a previous attempt died between writing its
            # intent and recording an outcome. Nobody knows whether the
            # side effect happened, so nobody gets to guess.
            raise DuplicateInFlight(
                f"{tool} is already on the ledger for this session with no recorded outcome; "
                f"inspect {self.path} before retrying"
            )

        # intent first, always: a side effect with no prior record is the
        # one thing this class exists to prevent
        self._write(
            "INSERT INTO intents (key, tool, state) VALUES (?, ?, 'in_flight')", (key, tool)
        )

        result = await forward()

        if result.isError:
            # the tool says it failed, and we take its word — transient
            # failures have to stay retryable or this strangles the agent
            self._write("DELETE FROM intents WHERE key = ?", (key,))
            return result, False

        self._write(
            "UPDATE intents SET state = 'done', result = ? WHERE key = ?",
            (result.model_dump_json(), key),
        )
        return result, False

    def _revive(self, stored: str | None) -> types.CallToolResult:
        try:
            return types.CallToolResult.model_validate_json(stored or "")
        except Exception as e:
            raise TxError(f"the ledger holds a result we can't read back: {e}") from e

    def _one(self, sql: str, params: tuple[Any, ...]) -> tuple[Any, ...] | None:
        try:
            row: tuple[Any, ...] | None = self._db.execute(sql, params).fetchone()
            return row
        except sqlite3.Error as e:
            raise TxError(f"ledger read failed: {e}") from e

    def _write(self, sql: str, params: tuple[Any, ...]) -> None:
        try:
            self._db.execute(sql, params)
        except sqlite3.Error as e:
            raise TxError(f"ledger write failed: {e}") from e

    def close(self) -> None:
        self._db.close()
