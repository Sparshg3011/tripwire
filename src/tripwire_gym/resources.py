"""Locate the checked-in benchmark data in a checkout or installed wheel."""

from pathlib import Path

_PACKAGED = Path(__file__).resolve().parent / "data"
GYM = _PACKAGED if _PACKAGED.is_dir() else Path(__file__).resolve().parents[2] / "gym"
