"""Stands in for $PY when a gym script is under test: writes down how it
was called, and runs nothing.

    python fake_python.py LOG ARGS...
"""

import json
import sys
from pathlib import Path

log, argv = Path(sys.argv[1]), sys.argv[2:]
with log.open("a") as calls:
    calls.write(json.dumps(argv) + "\n")

# a gym run leaves results.jsonl where it was told to, and some scripts
# read it straight back
if argv[:2] == ["-m", "tripwire_gym"] and "--out" in argv:
    out = Path(argv[argv.index("--out") + 1])
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.jsonl").touch()
