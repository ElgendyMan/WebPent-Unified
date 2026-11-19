"""Deterministic evidence-quality assessment for security findings.

This module separates three concepts that must not be conflated:

* a detector observed a suspicious condition;
* the observation has enough causal and control evidence to be useful;
* the finding is confirmed and reproducible by an auditor.

The assessor never executes requests and never trusts an LLM-emitted score.
It consumes only normalized finding/evidence data and fails closed when proof
signals are missing or contradictory.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.proof_bundle import proof_bundle_promotion_ready, validate_proof_bundle
from webpent.validators.replay_validator import validate_replay


class EvidenceClassification(str, Enum):
    """Closed set of evidence postures exposed to reports and operators."""

    CONFIRMED = "confirmed"
    SUPPORTED = "supported"
    NEEDS_HUMAN_REVIEW = "needs_human_review"
    UNCONFIRMED = "unconfirmed"
    CLEAN = "clean"
    NOT_SCANNED = "not_scanned"


class EvidenceAssessment(BaseModel):
    """Safe, value-free assessment of one finding's evidence posture."""

    model_config = ConfigDict(extra="forbid")

    classification: EvidenceClassification
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    causal_signal: bool = False
    negative_control_complete: bool = False
    proof_bundle_valid: bool = False
    promotion_ready_proof_bundle: bool = False
    reproducible: bool = False
    contradictory_signal: bool = False
    present_signals: list[str] = Field(default_factory=list, max_length=12)
    missing_signals: list[str] = Field(default_factory=list, max_length=12)
    reasons: list[str] = Field(default_factory=list, max_length=12)


class ValidationStatus(BaseModel):
    """Strict, non-promoting view of the complete validation contract."""

    model_config = ConfigDict(extra="forbid")

    classification: EvidenceClassification
    impact_present: bool = False
    root_cause_present: bool = False
    evidence_present: bool = False
    reproducible: bool = False
    causal_signal: bool = False
    negative_control_complete: bool = False
    proof_bundle_valid: bool = False
    promotion_ready_proof_bundle: bool = False
    replay_verified: bool = False
    confirmation_ready: bool = False
    missing_gates: list[str] = Field(default_factory=list, max_length=16)
    reasons: list[str] = Field(default_factory=list, max_length=16)


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump(mode="json")
            return dumped if isinstance(dumped, dict) else {}
        except Exception:
            return {}
    return {}


def _finding_parts(finding: Any) -> tuple[str, dict[str, Any], dict[str, Any]]:
    data = _as_dict(finding)
    evidence = _as_dict(data.get("evidence"))
    evidence_bundle = _as_dict(data.get("evidence_bundle"))
    return str(data.get("confidence_level") or ""), evidence, evidence_bundle


def _has_reproduction(evidence: dict[str, Any], evidence_bundle: dict[str, Any]) -> bool:
    reproduction = evidence.get("reproduction")
    if isinstance(reproduction, dict) and reproduction:
        return True
    if evidence.get("steps_to_reproduce") or evidence.get("proof"):
        return True
    request = evidence_bundle.get("request")
    response = evidence_bundle.get("response")
    if request and response:
        return True
    # Sealed proof bundles contain bounded replay evidence rather than the
    # legacy request/response envelope.
    return bool(evidence_bundle.get("sealed") and evidence_bundle.get("evidence"))


def _proof_bundle(finding_data: dict[str, Any], evidence: dict[str, Any]) -> Any:
    direct = finding_data.get("proof_bundle")
    if direct:
        return direct
    return evidence.get("proof_bundle")


def _has_text(*values: Any) -> bool:
    return any(isinstance(value, str) and value.strip() for value in values)


def _impact_present(finding_data: dict[str, Any], evidence: dict[str, Any]) -> bool:
    return _has_text(
        finding_data.get("business_impact"),
        finding_data.get("impact"),
        evidence.get("business_impact"),
        evidence.get("impact"),
        evidence.get("impact_statement"),
    )


def _root_cause_present(
    finding_data: dict[str, Any],
    evidence: dict[str, Any],
    evidence_bundle: dict[str, Any],
    proof_bundle: Any,
) -> bool:
    if _has_text(
        finding_data.get("root_cause"),
        evidence.get("root_cause"),
        evidence.get("root_cause_analysis"),
        evidence_bundle.get("root_cause"),
    ):
        return True
    proof_data = _as_dict(proof_bundle)
    oracle = _as_dict(proof_data.get("causal_oracle"))
    return _has_text(oracle.get("root_cause"), oracle.get("cause"))


def _replay_inputs(
    evidence: dict[str, Any],
    proof_bundle: Any,
) -> tuple[Sequence[Any], Any, Mapping[str, Any] | None]:
    replay = evidence.get("replay")
    if not isinstance(replay, Mapping):
        return (), None, None
    payloads = replay.get("evidence_payloads")
    if not isinstance(payloads, (list, tuple)):
        payloads = ()
    supplied_context = replay.get("context")
    context = dict(supplied_context) if isinstance(supplied_context, Mapping) else {}

    # Older report envelopes may carry only the scalar IDs. Complete missing
    # binding fields from the sealed bundle; never overwrite supplied values,
    # so stale or cross-target context remains fail-closed in validate_replay.
    bundle_data = _as_dict(proof_bundle)
    for field in (
        "engagement_id",
        "finding_id",
        "hypothesis_id",
        "target_fingerprint",
        "target_package_id",
        "target_package_sha256",
        "target_package_scope_digest",
        "target_package_policy_digest",
        "scope_context",
        "identity_context",
    ):
        if field not in context and bundle_data.get(field) is not None:
            context[field] = bundle_data[field]

    return payloads, replay.get("negative_control"), context or None


def build_validation_status(finding: Any) -> ValidationStatus:
    """Build a strict status view; it never mutates or promotes the finding."""
    finding_data = _as_dict(finding)
    evidence = _as_dict(finding_data.get("evidence"))
    evidence_bundle = _as_dict(finding_data.get("evidence_bundle"))
    proof_bundle = _proof_bundle(finding_data, evidence)
    assessment = assess_finding_evidence(finding)
    payloads, negative_control, replay_context = _replay_inputs(evidence, proof_bundle)
    replay_verified = bool(
        payloads
        and negative_control is not None
        and validate_replay(
            proof_bundle,
            list(payloads),
            negative_control,
            replay_context=replay_context,
        )
    )
    impact_present = _impact_present(finding_data, evidence)
    root_cause_present = _root_cause_present(
        finding_data, evidence, evidence_bundle, proof_bundle
    )
    evidence_present = bool(evidence or evidence_bundle or assessment.proof_bundle_valid)
    missing: list[str] = []
    for name, present in (
        ("impact", impact_present),
        ("root_cause", root_cause_present),
        ("evidence", evidence_present),
        ("reproducible", assessment.reproducible),
        ("causal_signal", assessment.causal_signal),
        ("negative_control", assessment.negative_control_complete),
        ("proof_bundle", assessment.promotion_ready_proof_bundle),
        ("replay", replay_verified),
    ):
        if not present:
            missing.append(name)
    confirmation_ready = bool(
        str(finding_data.get("confidence_level") or "") == "Tool-Confirmed"
        and impact_present
        and root_cause_present
        and evidence_present
        and assessment.reproducible
        and assessment.causal_signal
        and assessment.negative_control_complete
        and assessment.promotion_ready_proof_bundle
        and replay_verified
        and not assessment.contradictory_signal
    )
    reasons = ["all_strict_validation_gates_present"] if confirmation_ready else [
        "confirmation_contract_incomplete"
    ]
    status_classification = (
        EvidenceClassification.CONFIRMED
        if confirmation_ready
        else (
            EvidenceClassification.NEEDS_HUMAN_REVIEW
            if assessment.classification == EvidenceClassification.CONFIRMED
            else assessment.classification
        )
    )
    return ValidationStatus(
        classification=status_classification,
        impact_present=impact_present,
        root_cause_present=root_cause_present,
        evidence_present=evidence_present,
        reproducible=assessment.reproducible,
        causal_signal=assessment.causal_signal,
        negative_control_complete=assessment.negative_control_complete,
        proof_bundle_valid=assessment.proof_bundle_valid,
        promotion_ready_proof_bundle=assessment.promotion_ready_proof_bundle,
        replay_verified=replay_verified,
        confirmation_ready=confirmation_ready,
        missing_gates=missing,
        reasons=reasons,
    )


def _bool_signal(evidence: dict[str, Any], name: str) -> bool:
    if evidence.get(name) is True:
        return True
    assessment = evidence.get("assessment")
    return isinstance(assessment, dict) and assessment.get(name) is True


def annotate_finding_evidence(finding: Any) -> Any:
    """Attach a value-free assessment to a Pydantic finding when possible.

    The annotation is informational and deterministic; it never changes the
    finding's confidence tier. Promotion remains owned by the validator's
    existing proof gates.
    """
    assessment = assess_finding_evidence(finding)
    if not hasattr(finding, "model_copy"):
        return finding
    data = _as_dict(finding)
    evidence = _as_dict(data.get("evidence"))
    evidence["evidence_quality"] = assessment.model_dump(mode="json")
    evidence["validation_status"] = build_validation_status(finding).model_dump(mode="json")
    return finding.model_copy(update={"evidence": evidence})


def assess_finding_evidence(finding: Any) -> EvidenceAssessment:
    """Assess evidence using bounded deterministic signals only.

    ``Tool-Confirmed`` is considered evidence-confirmed only when all of the
        following are present: a causal signal, a completed negative control,
        a promotion-ready sealed proof bundle requiring that control, and reproducible
        evidence.
    A contradictory validator result always wins and produces ``unconfirmed``.
    """
    level, evidence, evidence_bundle = _finding_parts(finding)
    if level == "Clean":
        return EvidenceAssessment(
            classification=EvidenceClassification.CLEAN,
            reasons=["detector_reported_clean"],
        )
    if level == "Not Scanned":
        return EvidenceAssessment(
            classification=EvidenceClassification.NOT_SCANNED,
            reasons=["validation_not_completed"],
        )

    causal_signal = _bool_signal(evidence, "causal_signal")
    negative_control_complete = _bool_signal(evidence, "negative_control_complete")
    proof_bundle = _proof_bundle(_as_dict(finding), evidence)
    proof_bundle_valid = validate_proof_bundle(proof_bundle, require_negative_control=True)
    promotion_ready_proof_bundle = proof_bundle_promotion_ready(proof_bundle)
    reproducible = _has_reproduction(evidence, evidence_bundle) or proof_bundle_valid
    contradictory_signal = bool(
        evidence.get("contradictory_evidence") is True
        or evidence.get("validation_failure_reason") in {"llm_rejected", "contradictory"}
        or (
            isinstance(evidence.get("assessment"), dict)
            and evidence["assessment"].get("status") in {"rejected", "contradictory"}
        )
    )

    present_signals: list[str] = []
    missing_signals: list[str] = []
    for name, present in (
        ("causal_signal", causal_signal),
        ("negative_control_complete", negative_control_complete),
        ("sealed_proof_bundle", proof_bundle_valid),
        ("promotion_ready_proof_bundle", promotion_ready_proof_bundle),
        ("reproducible_evidence", reproducible),
    ):
        (present_signals if present else missing_signals).append(name)

    score = sum(
        weight
        for present, weight in (
            (causal_signal, 0.25),
            (negative_control_complete, 0.25),
            (proof_bundle_valid, 0.30),
            (reproducible, 0.20),
        )
        if present
    )
    reasons: list[str] = []
    if contradictory_signal:
        classification = EvidenceClassification.UNCONFIRMED
        score = 0.0
        reasons.append("contradictory_validation_signal")
    elif (
        level == "Tool-Confirmed"
        and causal_signal
        and negative_control_complete
        and promotion_ready_proof_bundle
        and reproducible
    ):
        classification = EvidenceClassification.CONFIRMED
        reasons.append("causal_signal_negative_control_and_strict_replayable_proof_present")
    elif causal_signal or negative_control_complete or proof_bundle_valid or reproducible:
        classification = (
            EvidenceClassification.NEEDS_HUMAN_REVIEW
            if level == "Tool-Confirmed"
            or causal_signal
            or negative_control_complete
            else EvidenceClassification.SUPPORTED
        )
        reasons.append("evidence_present_but_confirmation_contract_incomplete")
    else:
        classification = EvidenceClassification.UNCONFIRMED
        reasons.append("no_replayable_causal_evidence")

    return EvidenceAssessment(
        classification=classification,
        score=round(min(1.0, max(0.0, score)), 4),
        causal_signal=causal_signal,
        negative_control_complete=negative_control_complete,
        proof_bundle_valid=proof_bundle_valid,
        promotion_ready_proof_bundle=promotion_ready_proof_bundle,
        reproducible=reproducible,
        contradictory_signal=contradictory_signal,
        present_signals=present_signals,
        missing_signals=missing_signals,
        reasons=reasons,
    )


__all__ = [
    "EvidenceAssessment",
    "EvidenceClassification",
    "ValidationStatus",
    "annotate_finding_evidence",
    "assess_finding_evidence",
    "build_validation_status",
]
