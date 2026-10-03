"""One request budget for every benchmark process on a machine.

A provider's rate limit belongs to the account, not to a process. Each
process spacing its own calls still overruns it as soon as a matrix runs
cells side by side, and then every process backs off on its own, so the
account sits idle between retries. Here the budget lives in one small
file: a process takes the next free slot under a lock and waits for it,
and a rate limit pushes the next slot out for everyone at once.

Slots are wall-clock times, since that is the one clock processes share.
POSIX only (fcntl), like the runs that use it.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Self


class SharedPacer:
    def __init__(self, path: str | Path, per_minute: float):
        if not per_minute > 0:
            raise ValueError("per_minute must be positive")
        self.path = Path(path)
        self.gap = 60.0 / per_minute

    def wait(self) -> float:
        """Block until this process may send its next request; return how
        long it waited."""
        now = time.time()
        with self._locked() as slot:
            start = max(now, slot.read())
            slot.write(start + self.gap)
        waited = max(0.0, start - now)
        time.sleep(waited)
        return waited

    def back_off(self, seconds: float) -> None:
        """Hold every process's next request at least `seconds` from now."""
        with self._locked() as slot:
            slot.write(max(slot.read(), time.time() + seconds))

    def _locked(self) -> _Slot:
        return _Slot(self.path)


class _Slot:
    def __init__(self, path: Path):
        self.path = path

    def __enter__(self) -> Self:
        import fcntl

        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "a+", encoding="ascii")
        fcntl.flock(self.fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc: object) -> None:
        import fcntl

        fcntl.flock(self.fh, fcntl.LOCK_UN)
        self.fh.close()

    def read(self) -> float:
        self.fh.seek(0)
        try:
            return float(self.fh.read().strip() or 0.0)
        except ValueError:
            # a torn or foreign file: treat the slot as free rather than stall
            return 0.0

    def write(self, value: float) -> None:
        self.fh.seek(0)
        self.fh.truncate()
        self.fh.write(repr(value))
        self.fh.flush()
