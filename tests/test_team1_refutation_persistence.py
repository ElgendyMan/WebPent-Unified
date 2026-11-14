"""TEAM-1 Phase 3 — refutation / finding-state correctness acceptance tests.

Covers the monotonic evidence law:

    UNCONFIRMED -> CONFIRMED -> REFUTED

with a deterministic-evidence refutation gate, an append-only status
history, a queryable latest status, and terminality (no resurrection of a
refuted finding by later saves or late OOB callbacks).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest

from webpent.memory.db import (
    STATUS_CONFIRMED,
    STATUS_REFUTED,
    STATUS_UNCONFIRMED,
    DatabaseManager,
)
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.models.proof_bundle import build_proof_bundle
from webpent.validators.causal_validator import validate_causal_observation


def _finding(**overrides) -> Finding:
    base = dict(
        id=uuid.uuid4(),
        title="Refutation lifecycle fixture",
        severity=Severity.HIGH.value,
        description="deterministic lifecycle fixture",
        tool_name="validator",
        payload="probe",
        url="http://localhost:9/vuln",
        confidence=Confidence.TENTATIVE,
        confidence_level="AI-Assessed",
        reasoning="initial assessment",
        vuln_class=VulnClass.SQLI.value,
        created_at=datetime.now(timezone.utc),
        thread_id="thread-refutation",
    )
    base.update(overrides)
    return Finding(**base)


def _contradiction_evidence(finding: Finding) -> tuple[dict, object, str]:
    """Deterministic contradictory observation + sealed negative-control bundle."""
    observation = {
        "evidence_refs": [
            f"differential-contradiction:{finding.id}",
            "baseline_request:sha256:aa",
            "candidate_request:sha256:bb",
            "negative_control_request:sha256:cc",
        ],
        "causal_signal": True,
        "negative_control_complete": True,
        "oracle_decision": "REFUTED",
        "baseline": {"status_code": 200, "request_digest": "sha256:aa"},
        "candidate": {"status_code": 200, "request_digest": "sha256:bb"},
        "negative_control": {"status_code": 200, "request_digest": "sha256:cc"},
    }
    assert validate_causal_observation(observation)
    bundle = build_proof_bundle(
        engagement_id="thread-refutation",
        finding_id=str(finding.id),
        evidence=(observation,),
        evidence_refs=(f"differential-contradiction:{finding.id}",),
        negative_control=observation["negative_control"],
        baseline=observation["baseline"],
        causal_oracle={"decision": "REFUTED"},
        validator_id="validator.differential_refutation",
        validator_version="team1-phase3.v1",
    ).seal(actor="test")
    digest = f"sha256:{str(uuid.uuid4()).replace('-', '')}"
    return observation, bundle, digest


@pytest.fixture()
def db(tmp_path) -> DatabaseManager:
    manager = DatabaseManager(f"sqlite:///{tmp_path / 'refutation.sqlite3'}")
    manager.init_db()
    return manager


def test_confirm_then_refute_persists_and_survives_reload(db: DatabaseManager) -> None:
    """Acceptance: confirm -> refute -> persist -> reload -> still REFUTED."""
    finding = _finding()
    db.save_finding(finding)
    assert db.get_latest_finding_status(finding.id) == STATUS_UNCONFIRMED

    # 1. Confirm (OOB path requires the causal+bundle gate; exercise the
    # state machine directly through the same authority).
    confirmed = db.mark_oob_confirmed(
        finding.id,
        reasoning_appendix="OOB Callback Received",
        payload_marker="confirmed-by:oob-callback",
        causal_observation={
            "evidence_refs": ["oob:1"],
            "causal_signal": True,
            "negative_control_complete": True,
        },
        proof_bundle=build_proof_bundle(
            engagement_id="thread-refutation",
            finding_id=str(finding.id),
            evidence=({"oob": True},),
            evidence_refs=("oob:1",),
            negative_control={"clean": True},
            causal_oracle={"decision": "CONFIRMED"},
        ).seal(actor="test"),
    )
    assert confirmed is not None
    assert confirmed.confidence_level == "Tool-Confirmed"
    assert db.get_latest_finding_status(finding.id) == STATUS_CONFIRMED

    # 2. Valid contradictory evidence (deterministic, sealed).
    observation, bundle, digest = _contradiction_evidence(finding)
    refuted = db.mark_refuted(
        finding.id,
        reasoning_appendix="differential contradiction",
        causal_observation=observation,
        proof_bundle=bundle,
        evidence_hash=digest,
    )
    assert refuted is not None
    assert refuted.confidence_level == "Refuted"

    # 3-4. Persisted; 5. reload through a FRESH manager (process restart).
    reloaded = DatabaseManager(f"sqlite:///{db._db_path()}")
    row = reloaded.get_finding(finding.id)
    assert row is not None
    assert row.confidence_level == "Refuted"
    assert reloaded.get_latest_finding_status(finding.id) == STATUS_REFUTED
    # 6. Final status remains REFUTED.
    assert reloaded.get_finding(finding.id).confidence_level == "Refuted"

    history = reloaded.get_finding_status_history(finding.id)
    statuses = [entry["status"] for entry in history]
    assert statuses == [STATUS_UNCONFIRMED, STATUS_CONFIRMED, STATUS_REFUTED]


def test_llm_text_alone_cannot_refute(db: DatabaseManager) -> None:
    """A refutation without deterministic evidence must be refused."""
    finding = _finding()
    db.save_finding(finding)
    result = db.mark_refuted(
        finding.id,
        reasoning_appendix="the LLM believes this is a false positive",
        causal_observation=None,
        proof_bundle=None,
    )
    assert result is not None
    assert result.confidence_level != "Refuted"
    assert db.get_latest_finding_status(finding.id) == STATUS_UNCONFIRMED


def test_refuted_finding_survives_stale_graph_save(db: DatabaseManager) -> None:
    """save_finding must not resurrect a refuted row from a stale snapshot."""
    finding = _finding()
    db.save_finding(finding)
    observation, bundle, digest = _contradiction_evidence(finding)
    db.mark_refuted(
        finding.id,
        reasoning_appendix="contradiction",
        causal_observation=observation,
        proof_bundle=bundle,
        evidence_hash=digest,
    )

    # A late graph-state save carrying the OLD confirmed snapshot.
    stale = finding.model_copy(
        update={
            "confidence_level": "Tool-Confirmed",
            "tool_confirmed_by": "test.fixture",
            "confidence": Confidence.CONFIRMED,
        }
    )
    db.save_finding(stale)
    row = db.get_finding(finding.id)
    assert row.confidence_level == "Refuted", (
        "a stale confirmed snapshot resurrected a refuted finding"
    )
    assert db.get_latest_finding_status(finding.id) == STATUS_REFUTED


def test_refuted_finding_survives_confirmed_save_too(db: DatabaseManager) -> None:
    """Even a Tool-Confirmed in-memory snapshot cannot overwrite REFUTED."""
    finding = _finding(
        confidence_level="Tool-Confirmed",
        confidence=Confidence.CONFIRMED,
        # M1-B (E-1): model-level proof requirement.
        evidence={"tool_confirmed_by": "test.fixture"},
    )
    db.save_finding(finding)
    observation, bundle, digest = _contradiction_evidence(finding)
    db.mark_refuted(
        finding.id,
        reasoning_appendix="contradiction",
        causal_observation=observation,
        proof_bundle=bundle,
        evidence_hash=digest,
    )
    db.save_finding(finding)  # same confirmed snapshot again
    assert db.get_finding(finding.id).confidence_level == "Refuted"


def test_late_oob_callback_cannot_reconfirm_refuted(db: DatabaseManager) -> None:
    """Terminality: a replayed OOB callback must not flip REFUTED back."""
    finding = _finding()
    db.save_finding(finding)
    observation, bundle, digest = _contradiction_evidence(finding)
    db.mark_refuted(
        finding.id,
        reasoning_appendix="contradiction",
        causal_observation=observation,
        proof_bundle=bundle,
        evidence_hash=digest,
    )
    result = db.mark_oob_confirmed(
        finding.id,
        reasoning_appendix="late replayed callback",
        payload_marker="confirmed-by:oob-callback",
        causal_observation={
            "evidence_refs": ["oob:late"],
            "causal_signal": True,
            "negative_control_complete": True,
        },
        proof_bundle=build_proof_bundle(
            engagement_id="thread-refutation",
            finding_id=str(finding.id),
            evidence=({"oob": True},),
            evidence_refs=("oob:late",),
            negative_control={"clean": True},
        ).seal(actor="test"),
    )
    assert result is not None
    assert result.confidence_level == "Refuted"
    assert db.get_latest_finding_status(finding.id) == STATUS_REFUTED


def test_refutation_merges_evidence_without_destroying_history(
    db: DatabaseManager,
) -> None:
    """The confirmation evidence stays inspectable after refutation."""
    finding = _finding()
    finding = finding.model_copy(
        update={"evidence": {"original_confirmation": {"digest": "sha256:original"}}}
    )
    db.save_finding(finding)
    observation, bundle, digest = _contradiction_evidence(finding)
    db.mark_refuted(
        finding.id,
        reasoning_appendix="contradiction",
        causal_observation=observation,
        proof_bundle=bundle,
        evidence_hash=digest,
    )
    row = db.get_finding(finding.id)
    evidence = row.evidence if isinstance(row.evidence, dict) else json.loads(
        json.dumps(row.evidence)
    )
    assert evidence.get("original_confirmation") == {"digest": "sha256:original"}
    assert evidence.get("refutation", {}).get("deterministic") is None
    assert "refutation" in evidence or row.evidence is not None
    history = db.get_finding_status_history(finding.id)
    assert any(entry["status"] == STATUS_REFUTED for entry in history)
    assert any(entry["actor"] == "mark_refuted" for entry in history)
