import json

import pytest

pytest.importorskip("matplotlib")

from tripwire_benchmarks.chart import heldout_tradeoff


def _metric(hits, total, low, high):
    return {"hits": hits, "total": total, "rate": hits / total, "ci_low": low, "ci_high": high}


def test_heldout_tradeoff_writes_a_png(tmp_path):
    summary = {
        "overall": [
            {
                "condition": "direct",
                "attack_success": _metric(3, 10, 0.1, 0.6),
                "benign_utility": _metric(8, 10, 0.5, 0.95),
            },
            {
                "condition": "tripwire-deny",
                "attack_success": _metric(1, 10, 0.01, 0.4),
                "benign_utility": _metric(4, 10, 0.15, 0.7),
            },
        ]
    }
    source = tmp_path / "summary.json"
    source.write_text(json.dumps(summary), encoding="utf-8")

    path = heldout_tradeoff(source, tmp_path / "nested" / "tradeoff.png")

    assert path.read_bytes().startswith(b"\x89PNG")
