"""ق2 — Autonomy Tiers contract tests (UNIFIED-MERGE feature window).

The cage must be provable: fail-closed defaults, evidence-only
promotion, an operator ceiling that always holds, a signed replayable
audit trail, and kill-switch interplay.
"""
from __future__ import annotations

import json

import pytest

from webpent.safety.autonomy_tiers import (
    AuditLog,
    AutonomyCage,
    AutonomyTier,
    TierPolicy,
    evidence_score,
)


def _policy(tmp_path, **overrides) -> TierPolicy:
    defaults = dict(
        engagement_id="eng-1",
        client_id="client-a",
        max_tier=3,
        promotion_floor=0.6,
        min_promotion_interval_seconds=0.0,
        audit_path=str(tmp_path / "audit.jsonl"),
    )
    defaults.update(overrides)
    return TierPolicy(**defaults)


def _proof(records_valid: bool = True) -> dict:
    return {"kind": "proof_bundle", "replay_valid": records_valid}


# -- scoring ------------------------------------------------------------

def test_score_reads_only_recorded_shapes():
    assert evidence_score([]) == 0.0
    assert evidence_score([_proof()]) == 0.5
    assert evidence_score([_proof(), _proof()]) == 1.0  # capped
    assert evidence_score([{"kind": "hypothesis",
                            "status": "confirmed"}]) == 0.25
    assert evidence_score([{"kind": "finding",
                            "validator": "confirmed"}]) == 0.2
    assert evidence_score([{"kind": "evidence",
                            "direction": "supporting"}]) == 0.05


def test_score_never_trusts_free_text_claims():
    assert evidence_score([{"llm_says": "definitely exploitable"}]) == 0.0
    assert evidence_score([{"kind": "proof_bundle",
                            "replay_valid": False}]) == 0.0


# -- fail-closed defaults ------------------------------------------------

def test_default_ceiling_is_tier_one(tmp_path):
    # fail-closed: the cage OPENS at tier 0 even when the ceiling is 1;
    # tier 1 is earned by evidence, and 2+ is unreachable regardless.
    cage = AutonomyCage(_policy(tmp_path, max_tier=1),
                        kill_switch=lambda: False)
    assert cage.allowed() == AutonomyTier(0)
    granted = cage.evaluate_promotion([_proof(), _proof()])
    assert granted.granted is True and granted.to_tier == 1
    assert cage.allowed() == AutonomyTier(1)
    blocked = cage.evaluate_promotion([_proof(), _proof()])
    assert blocked.granted is False
    assert "ceiling" in blocked.reason


def test_every_request_above_current_tier_is_refused(tmp_path):
    cage = AutonomyCage(_policy(tmp_path, max_tier=3),
                        kill_switch=lambda: False)
    assert cage.may_execute(0).granted is True
    assert cage.may_execute(1).granted is False


# -- promotion semantics -------------------------------------------------

def test_promotion_needs_evidence_and_climbs_one_step(tmp_path):
    cage = AutonomyCage(_policy(tmp_path), kill_switch=lambda: False)
    weak = cage.evaluate_promotion([{"kind": "evidence",
                                     "direction": "supporting"}])
    assert weak.granted is False
    strong = cage.evaluate_promotion([_proof(), {"kind": "hypothesis",
                                                 "status": "confirmed"}])
    assert strong.granted is True
    assert strong.to_tier == 1
    assert cage.allowed() == AutonomyTier(1)
    # one step at a time: tier 3 is not reachable from tier 1 in one call
    jump = cage.evaluate_promotion([_proof(), _proof()])
    assert jump.to_tier == 2


def test_promotion_rate_cap(tmp_path):
    cage = AutonomyCage(
        _policy(tmp_path, min_promotion_interval_seconds=120.0),
        kill_switch=lambda: False,
        clock=lambda: 1_000.0,
    )
    first = cage.evaluate_promotion([_proof(), _proof()])
    assert first.granted is True
    second = cage.evaluate_promotion([_proof(), _proof()])
    assert second.granted is False
    assert "rate cap" in second.reason


# -- kill switch ----------------------------------------------------------

def test_kill_switch_freezes_authority_at_recon(tmp_path):
    engaged = {"on": False}
    cage = AutonomyCage(_policy(tmp_path),
                        kill_switch=lambda: engaged["on"])
    cage.evaluate_promotion([_proof(), _proof()])
    assert cage.allowed() == AutonomyTier(1)
    engaged["on"] = True
    assert cage.allowed() == AutonomyTier(0)
    assert cage.may_execute(1).granted is False
    denied = cage.evaluate_promotion([_proof(), _proof()])
    assert denied.granted is False
    assert "kill switch" in denied.reason


# -- audit trail ----------------------------------------------------------

def test_audit_log_is_signed_and_replayable(tmp_path):
    cage = AutonomyCage(_policy(tmp_path), kill_switch=lambda: False)
    cage.evaluate_promotion([_proof(), _proof()])
    cage.may_execute(0)
    ok, detail = cage.audit.verify_file()
    assert ok is True, detail


def test_audit_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    cage = AutonomyCage(_policy(tmp_path), kill_switch=lambda: False,
                        audit_secret="secret-1")
    cage.evaluate_promotion([_proof(), _proof()])
    lines = path.read_text(encoding="utf-8").splitlines()
    forged = json.loads(lines[-1])
    forged["event"]["evidence_score"] = 0.99
    lines[-1] = json.dumps(forged)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    audit = AuditLog(path, secret="secret-1")
    ok, detail = audit.verify_file()
    assert ok is False and "chain" in detail


def test_audit_records_denials_too(tmp_path):
    cage = AutonomyCage(_policy(tmp_path, max_tier=0),
                        kill_switch=lambda: False)
    cage.evaluate_promotion([_proof(), _proof()])
    events = [
        json.loads(line)["event"]["event"]
        for line in (tmp_path / "audit.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert "promotion_denied" in events
    assert events[0] == "cage_open"


# -- tier model -----------------------------------------------------------

def test_tier_ordering_and_validation():
    assert AutonomyTier(0) < AutonomyTier(1) <= AutonomyTier(1)
    with pytest.raises(ValueError):
        AutonomyTier(4)
