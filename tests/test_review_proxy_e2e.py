"""Run the same wire-level check used for installed-wheel verification."""

import importlib.util
from pathlib import Path


async def test_real_mcp_review_gate_and_effect_ledger():
    script = Path(__file__).resolve().parents[1] / "scripts" / "smoke_review_installed.py"
    spec = importlib.util.spec_from_file_location("review_smoke", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    await module.run_checks()
