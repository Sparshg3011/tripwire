import hashlib
import json

import pytest

pytest.importorskip(
    "agentdojo",
    reason="ProtectAI held-out planning tests require the publication extra",
)

from tripwire_benchmarks import protectai_heldout
from tripwire_benchmarks.heldout import _command
from tripwire_benchmarks.protectai_heldout import (
    PROTECTAI_MODEL_REVISION,
    HeldoutError,
    _stage_primary_baseline,
    require_frozen_protocol,
)


def test_committed_protectai_protocol_matches_runner_contract():
    protocol = require_frozen_protocol(
        model="nvidia/nemotron-3-super-120b-a12b",
        workers=1,
    )

    assert protocol["status"] == "frozen"
    assert protocol["screening_basis"]["heldout_outcomes_inspected"] is False


def test_protectai_command_pins_detector_revision(tmp_path):
    command = _command(
        suite="slack",
        condition="transformers_pi_detector",
        users=["user_task_2"],
        model="nvidia/nemotron-3-super-120b-a12b",
        destination=tmp_path,
        protectai_model_revision=PROTECTAI_MODEL_REVISION,
    )

    index = command.index("--protectai-model-revision")
    assert command[index + 1] == PROTECTAI_MODEL_REVISION


def test_primary_baseline_staging_fails_closed_when_receipt_is_missing(tmp_path):
    primary = tmp_path / "primary"
    primary.mkdir()

    with pytest.raises(HeldoutError, match="plan is missing or has changed"):
        _stage_primary_baseline(primary, tmp_path / "comparison")


def test_primary_baseline_staging_verifies_and_copies_receipts(tmp_path, monkeypatch):
    primary = tmp_path / "primary"
    plan = (json.dumps({"selection_sha256": "selection"}) + "\n").encode()
    primary.mkdir()
    (primary / "heldout-plan.json").write_bytes(plan)

    result_hashes = {}
    for suite in ("workspace", "banking", "slack", "travel"):
        content = f"{suite}-frozen-direct".encode()
        path = primary / suite / "direct" / "shard-00" / "results.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
        result_hashes[suite] = hashlib.sha256(content).hexdigest()

    monkeypatch.setattr(protectai_heldout, "SELECTION_SHA256", "selection")
    monkeypatch.setattr(protectai_heldout, "PRIMARY_PLAN_SHA256", hashlib.sha256(plan).hexdigest())
    monkeypatch.setattr(protectai_heldout, "PRIMARY_RESULT_SHA256", result_hashes)

    destination = tmp_path / "comparison"
    observed = _stage_primary_baseline(primary, destination)

    assert observed == result_hashes
    assert (
        destination / "workspace" / "direct" / "frozen-primary" / "results.json"
    ).read_bytes() == b"workspace-frozen-direct"
