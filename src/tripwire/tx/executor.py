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

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from mcp import types

Forward = Callable[[], Awaitable[types.CallToolResult]]


class TxError(Exception):
    """The ledger can't be read or written. The caller must block."""


class DuplicateInFlight(Exception):
    """This exact call is already on the ledger with no known outcome."""


def intent_key(session_id: str, tool: str, args: dict[str, Any]) -> str:
    """SHA-256 hex over (session_id, tool, compact-sorted-json args)."""
    raise NotImplementedError("intent_key not written yet — see module docstring")


class TxExecutor:
    def __init__(self, db_path: str | Path, session_id: str) -> None:
        raise NotImplementedError("TxExecutor not written yet — see module docstring")

    async def run(
        self, tool: str, args: dict[str, Any], forward: Forward
    ) -> tuple[types.CallToolResult, bool]:
        """Execute through the ledger. Returns (result, replayed)."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
