# tests/team1_acceptance/test_c_proof_semantic_integrity.py
"""TEAM-1 ACCEPTANCE C+D — ProofBundle semantic integrity + tamper matrix.

Finding 3: Removing the negative control was able to pass verify_seal().
This MUST now fail. We distinguish:
  - Cryptographic integrity (verify_seal): bytes not changed after sealing
  - Semantic completeness: required evidence existed BEFORE sealing
  - Promotion validity: both + strict promotion rules

Part 7: negative control removal MUST FAIL at verification/promotion.
Part 8: tamper matrix — each mutation must fail at the appropriate layer.
"""
from __future__ import annotations

import copy

import pytest

from webpent.models.proof_bundle import build_proof_bundle
from webpent.models.proof_semantics import (
    REQUIRED_SEMANTIC_FIELDS,
    ProofSemanticValidator,
    SemanticValidationError,
    build_promotion_grade_bundle,
    promotion_valid,
)


def _valid_evidence():
    """Build a complete, valid evidence set for a promotion-grade bundle."""
    return dict(
        engagement_id="eng_proof_test",
        finding_id="find_001",
        vulnerability_class="IDOR",
        baseline={"request": "GET /api/users/1", "response": "200 user_data"},
        candidate={"request": "GET /api/users/2", "response": "200 other_user_data"},
        negative_control={"request": "GET /api/users/999999", "response": "404 not_found"},
        evidence_origin="target_runtime",
        causal_result={
            "causal_signal": True,
            "negative_control_complete": True,
            "requires_target_backed": False,
            "oracle_decision": "CONFIRMED",
            "validator_version": "test_v1",
            "request_evidence": ({"req": "GET /api/users/2"},),
            "response_evidence": ({"resp": "200 other_user_data"},),
        },
        execution_identity="validator_test_v1",
        session_context={
            "scope_context": {"target": "https://target.example.com", "scope_digest": "abc123"},
            "identity_context": {"principal": "user_a", "session_id": "sess_001"},
        },
        replay_context={"replayable": True, "replay_id": "rep_001"},
        target_fingerprint="target_fingerprint_sha256_abcdef123456",
        hypothesis_id="hyp_001",
    )


# ---- Part 7: Negative control removal MUST fail ---------------------------

def test_negative_control_removal_fails_semantic_validation():
    """Part 7: build valid -> seal -> remove negative control -> MUST FAIL."""
    ev = _valid_evidence()
    # Build + seal a valid promotion-grade bundle.
    bundle = build_promotion_grade_bundle(**ev)
    assert bundle.sealed is True
    assert bundle.verify_seal() is True  # cryptographic seal intact

    # Now remove/null the negative control (simulate tampering).
    # Because the seal covers negative_control_digest, model_copy with
    # negative_control_digest=None will BREAK the cryptographic seal.
    tampered = bundle.model_copy(update={"negative_control_digest": None})
    # Cryptographic layer: seal must now FAIL (digest mismatch).
    assert tampered.verify_seal() is False, (
        "Removing negative_control_digest must break cryptographic seal"
    )

    # Semantic layer: must also fail.
    validator = ProofSemanticValidator()
    report = validator.validate_bundle(tampered)
    assert report.complete is False
    assert "negative_control" in report.missing_fields

    # Promotion layer: must fail.
    ok, reason = promotion_valid(tampered)
    assert ok is False
    assert "cryptographic_seal_failed" in reason or "semantic_incomplete" in reason


def test_negative_control_removal_before_seal_fails_construction():
    """Building a promotion-grade bundle WITHOUT negative control must fail at construction."""
    ev = _valid_evidence()
    ev["negative_control"] = None  # remove negative control BEFORE sealing
    with pytest.raises(SemanticValidationError):
        build_promotion_grade_bundle(**ev)


def test_verify_seal_does_not_imply_semantic_validity():
    """verify_seal() == PASS must NEVER imply semantic validity."""
    # Build a bundle WITHOUT negative control using the low-level factory
    # (this is what TEAM-2 exploited — all fields optional).
    weak_bundle = build_proof_bundle(
        engagement_id="eng_weak",
        finding_id="find_weak",
        evidence=({"a": 1},),
        # negative_control deliberately omitted
    )
    sealed = weak_bundle.seal()
    # Cryptographic seal passes (bytes not changed after sealing).
    assert sealed.verify_seal() is True
    # BUT semantic validation must FAIL (negative control missing).
    validator = ProofSemanticValidator()
    report = validator.validate_bundle(sealed)
    assert report.complete is False
    assert "negative_control" in report.missing_fields
    # And promotion must FAIL.
    ok, reason = promotion_valid(sealed)
    assert ok is False
    assert "semantic_incomplete" in reason


def test_negative_control_identical_to_baseline_rejected():
    """A negative control that equals the baseline is semantically invalid."""
    ev = _valid_evidence()
    ev["negative_control"] = ev["baseline"]  # identical — no independent control
    with pytest.raises(SemanticValidationError):
        build_promotion_grade_bundle(**ev)


# ---- Part 8: Tamper matrix — each mutation must fail ----------------------

def _sealed_valid_bundle():
    return build_promotion_grade_bundle(**_valid_evidence())


def test_tamper_replace_negative_control():
    """Replace negative control with different content -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={
        "negative_control_digest": "sha256:tampered_digest_value",
    })
    assert tampered.verify_seal() is False
    ok, _ = promotion_valid(tampered)
    assert ok is False


def test_tamper_swap_baseline():
    """Swap baseline digest -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={"baseline_digest": "sha256:swapped_baseline"})
    assert tampered.verify_seal() is False


def test_tamper_swap_candidate_evidence_ref():
    """Swap candidate evidence ref -> seal breaks (in evidence_refs)."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={
        "candidate_evidence_ref": "swapped_ref_from_another_run",
    })
    assert tampered.verify_seal() is False


def test_tamper_swap_vulnerability_class():
    """Swap vulnerability class -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={"vulnerability_class": "XSS"})  # was IDOR
    assert tampered.verify_seal() is False


def test_tamper_alter_target_identity():
    """Alter target fingerprint -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={"target_fingerprint": "attacker_controlled_target"})
    assert tampered.verify_seal() is False


def test_tamper_alter_evidence_origin():
    """Alter evidence_origin from target_runtime to offline -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={"evidence_origin": "offline_fixture"})
    assert tampered.verify_seal() is False


def test_tamper_alter_causal_verdict():
    """Alter causal_oracle (causal_signal False) -> seal breaks + semantic fail."""
    b = _sealed_valid_bundle()
    co = copy.deepcopy(b.causal_oracle)
    co["causal_signal"] = False
    tampered = b.model_copy(update={"causal_oracle": co})
    assert tampered.verify_seal() is False
    # Even if seal were intact, semantic would fail.
    validator = ProofSemanticValidator()
    # Build an unsealed version to test semantic layer alone.
    weak = build_proof_bundle(
        engagement_id="eng_t", finding_id="f_t",
        evidence=({"a": 1},), causal_oracle={"causal_signal": False},
    )
    report = validator.validate_bundle(weak)
    assert report.complete is False
    assert "causal_signal_not_true" in report.invalid_fields


def test_tamper_swap_proof_components_from_another_run():
    """Swap evidence_refs from another run -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={
        "evidence_refs": ("ref_from_run_A", "ref_from_run_B", "ref_from_run_C"),
    })
    assert tampered.verify_seal() is False


def test_tamper_alter_replay_context():
    """Alter replay_metadata -> seal breaks."""
    b = _sealed_valid_bundle()
    rm = copy.deepcopy(b.replay_metadata)
    rm["replayable"] = False
    tampered = b.model_copy(update={"replay_metadata": rm})
    assert tampered.verify_seal() is False


def test_tamper_alter_session_identity():
    """Alter identity_context -> seal breaks."""
    b = _sealed_valid_bundle()
    tampered = b.model_copy(update={
        "identity_context": {"principal": "attacker", "session_id": "hijacked"},
    })
    assert tampered.verify_seal() is False


def test_valid_bundle_passes_all_three_layers():
    """A genuinely valid bundle passes cryptographic, semantic, and promotion."""
    b = _sealed_valid_bundle()
    assert b.verify_seal() is True
    validator = ProofSemanticValidator()
    report = validator.validate_bundle(b)
    assert report.complete is True, f"semantic fail: {report.reason}"
    ok, reason = promotion_valid(b)
    assert ok is True, f"promotion should pass: {reason}"


def test_required_semantic_fields_defined():
    """All required semantic fields must be enumerated."""
    required = set(REQUIRED_SEMANTIC_FIELDS)
    assert "negative_control" in required
    assert "baseline" in required
    assert "candidate" in required
    assert "target_identity" in required
    assert "vulnerability_class" in required
    assert "evidence_origin" in required
    assert "causal_result" in required
    assert "execution_identity" in required
    assert "session_context" in required
    assert "replay_information" in required
