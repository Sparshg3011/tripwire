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
— a fresh session gets fresh results even against the same db file.

In the proxy a session is one process, i.e. one agent connection, so a
restarted proxy is a new session: a call its predecessor completed runs
again if the agent repeats it. That is deliberate. The ledger has no
clock, so replay across sessions would hand every later conversation
the first one's answer, forever. The price: a call that completed just
before the proxy died, with the answer lost on the way to the agent, is
not deduplicated against the retry that reaches its successor. The
audit log shows both. What does cross sessions is an unresolved intent,
below.

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

  * 'in_flight' row for the same call from ANOTHER session -> raise
    DuplicateInFlight too. This is the proxy that died mid-call and came
    back as a new session, and its retry is the duplicate the ledger
    exists to stop. It also refuses a second live session that shares
    the db and happens to be mid-call on the identical thing, even one
    that arrives at the same instant: the ledger holds one unresolved
    row per call. Once that one finishes, the call runs.

  * 'in_flight' row written before sessions were recorded -> raise
    DuplicateInFlight for every call to its tool. Such a row can't say
    which call it was, so none of them can be told apart from it.

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

The spec is executable: tests/test_tx_executor.py.
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
    result   TEXT,
    call_key TEXT,
    session  TEXT
)
"""

# added after the first ledgers were written; a ledger without them keeps
# working, but its old rows can't be matched to a call from another session
LATER_COLUMNS = ("call_key", "session")


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
            # one write transaction, or proxies opening an old ledger
            # together all see a column missing and all but one fail to
            # add it
            with self._db:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute(SCHEMA)
                have = {row[1] for row in self._db.execute("PRAGMA table_info(intents)")}
                for column in LATER_COLUMNS:
                    if column not in have:
                        self._db.execute(f"ALTER TABLE intents ADD COLUMN {column} TEXT")
                # one unresolved row per call across every session; the
                # look in run() and the insert after it are two statements,
                # and this is what keeps two sessions from both passing
                self._db.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS intents_in_flight "
                    "ON intents (call_key) WHERE state = 'in_flight'"
                )
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

        # the same call with no session in it: an unknown outcome outlives
        # the session that lost track of it
        call = intent_key("", tool, args)
        stranded = self._one(
            "SELECT session FROM intents WHERE call_key = ? AND state = 'in_flight'", (call,)
        )
        if stranded is not None:
            raise DuplicateInFlight(
                f"{tool} with these arguments was started by session {stranded[0]} and never "
                f"recorded an outcome; inspect {self.path} before retrying"
            )
        legacy = self._one(
            "SELECT 1 FROM intents WHERE call_key IS NULL AND tool = ? AND state = 'in_flight'",
            (tool,),
        )
        if legacy is not None:
            raise DuplicateInFlight(
                f"a {tool} call from before sessions were recorded never recorded an outcome, "
                f"and nothing says which call it was; inspect {self.path} before retrying"
            )

        # intent first, always: a side effect with no prior record is the
        # one thing this class exists to prevent
        try:
            self._db.execute(
                "INSERT INTO intents (key, tool, state, call_key, session) "
                "VALUES (?, ?, 'in_flight', ?, ?)",
                (key, tool, call, self.session_id),
            )
        except sqlite3.IntegrityError as e:
            raise DuplicateInFlight(
                f"{tool} with these arguments was started by another session at the same "
                f"moment; inspect {self.path} before retrying"
            ) from e
        except sqlite3.Error as e:
            raise TxError(f"ledger write failed: {e}") from e

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
