"""Advisory research-quality review for the ASROS core.

The controller simulates senior review before and after a bounded task.  It does
not execute requests, approve vulnerabilities, promote hypotheses, or override
policy/oracles.  A positive review only means that the next existing gate may
consider the proposal; it is never a finding or a qualification decision.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.evidence import redact_sensitive


class QualityReviewStatus(StrEnum):
    ACCEPTED_FOR_REVIEW = "accepted_for_review"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    INSUFFICIENT = "insufficient"


class QualityIssue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    code: str = Field(min_length=1, max_length=120)
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    message: str = Field(min_length=3, max_length=500)


class PreExecutionReview(BaseModel):
    """A bounded recommendation before any action is routed elsewhere."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: QualityReviewStatus
    hypothesis_id: str = Field(min_length=1, max_length=200)
    score: float = Field(ge=0.0, le=1.0)
    issues: tuple[QualityIssue, ...] = Field(default=(), max_length=16)
    required_checks: tuple[str, ...] = Field(default=(), max_length=12)
    advisory_only: bool = True
    can_execute: bool = False
    can_create_findings: bool = False
    can_override_policy: bool = False
    can_override_oracle: bool = False


class PostExecutionReview(BaseModel):
    """Evidence-quality assessment, not a vulnerability verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: QualityReviewStatus
    hypothesis_id: str = Field(min_length=1, max_length=200)
    evidence_quality_score: float = Field(ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    issues: tuple[QualityIssue, ...] = Field(default=(), max_length=16)
    causal_proof_present: bool = False
    negative_control_present: bool = False
    proof_sealed: bool = False
    proof_replayable: bool = False
    overclaim_detected: bool = False
    advisory_only: bool = True
    can_approve_vulnerability: bool = False
    can_override_oracle: bool = False
    can_override_policy: bool = False


class ResearchQualityController:
    """Run deterministic preflight and postflight reviews over advisory inputs."""

    def __init__(self, *, minimum_pre_score: float = 0.55) -> None:
        self.minimum_pre_score = max(0.0, min(float(minimum_pre_score), 1.0))

    def review_before(
        self,
        *,
        hypothesis: Mapping[str, Any],
        argument_chain: Any | None = None,
        scope_allowed: bool = True,
    ) -> PreExecutionReview:
        hypothesis_id = _clean_id(hypothesis.get("id") or hypothesis.get("hypothesis_id"))
        issues: list[QualityIssue] = []
        checks: list[str] = []
        if not hypothesis_id:
            hypothesis_id = "unknown-hypothesis"
            issues.append(
                _issue(
                    "hypothesis_id_missing", "high", "A stable hypothesis identifier is required."
                )
            )
        evidence_refs = _string_refs(hypothesis.get("evidence_refs", ()))
        if not evidence_refs:
            issues.append(
                _issue("evidence_missing", "high", "The hypothesis has no evidence references.")
            )
            checks.append("collect_evidence")
        if not _text(hypothesis.get("reason")):
            issues.append(
                _issue(
                    "reason_missing", "medium", "The hypothesis does not explain why it matters."
                )
            )
            checks.append("state_assumption")
        if not _text(hypothesis.get("affected_asset")):
            issues.append(
                _issue("asset_missing", "medium", "The affected asset is not identified.")
            )
            checks.append("identify_asset")
        attack_plan = hypothesis.get("attack_plan", ())
        if not _string_refs(attack_plan):
            issues.append(
                _issue("validation_plan_missing", "high", "No bounded validation path is defined.")
            )
            checks.append("define_bounded_validation")
        if argument_chain is None:
            issues.append(
                _issue(
                    "argument_chain_missing",
                    "medium",
                    "An argument chain is required for senior review.",
                )
            )
            checks.append("build_argument_chain")
        if not scope_allowed:
            issues.append(
                _issue(
                    "scope_denied", "critical", "The proposed path is outside the approved scope."
                )
            )
            checks.append("confirm_scope")

        score = max(0.0, min(1.0, 1.0 - sum(_penalty(item.severity) for item in issues)))
        blocked = any(item.severity == "critical" for item in issues)
        status = (
            QualityReviewStatus.BLOCKED
            if blocked
            else QualityReviewStatus.NEEDS_REVIEW
            if issues or score < self.minimum_pre_score
            else QualityReviewStatus.ACCEPTED_FOR_REVIEW
        )
        return PreExecutionReview(
            status=status,
            hypothesis_id=hypothesis_id,
            score=score,
            issues=tuple(issues),
            required_checks=tuple(dict.fromkeys(checks)),
        )

    def review_after(
        self,
        *,
        hypothesis_id: str,
        evidence_refs: Sequence[str] = (),
        causal_oracle_passed: bool = False,
        negative_control_passed: bool = False,
        proof_sealed: bool = False,
        proof_replayable: bool = False,
        claim: str = "",
        observation_count: int = 0,
    ) -> PostExecutionReview:
        clean_id = _clean_id(hypothesis_id) or "unknown-hypothesis"
        refs = _string_refs(evidence_refs)
        issues: list[QualityIssue] = []
        if observation_count <= 0:
            issues.append(
                _issue("observations_missing", "high", "No explicit observations were produced.")
            )
        if not refs:
            issues.append(
                _issue(
                    "evidence_refs_missing",
                    "high",
                    "No redacted evidence references were supplied.",
                )
            )
        if not causal_oracle_passed:
            issues.append(
                _issue("causal_proof_missing", "high", "The central causal oracle did not pass.")
            )
        if not negative_control_passed:
            issues.append(
                _issue(
                    "negative_control_missing",
                    "high",
                    "An independent negative control did not pass.",
                )
            )
        if not proof_sealed:
            issues.append(
                _issue(
                    "proof_not_sealed",
                    "medium",
                    "Evidence has not been sealed by the central proof authority.",
                )
            )
        if not proof_replayable:
            issues.append(
                _issue("proof_not_replayable", "medium", "The proof procedure is not replayable.")
            )
        clean_claim, redacted = redact_sensitive(claim)
        if redacted:
            issues.append(
                _issue(
                    "claim_redacted", "low", "Sensitive claim content was redacted before review."
                )
            )
        if _overclaims(str(clean_claim)):
            issues.append(
                _issue(
                    "overclaim_detected",
                    "critical",
                    "The claim exceeds the available evidence or review authority.",
                )
            )

        strong = (
            causal_oracle_passed and negative_control_passed and proof_sealed and proof_replayable
        )
        quality = 1.0
        quality -= min(0.45, sum(_penalty(item.severity) for item in issues))
        if not refs:
            quality -= 0.2
        quality = max(0.0, min(1.0, quality))
        if any(item.severity == "critical" for item in issues):
            status = QualityReviewStatus.BLOCKED
        elif not strong or not refs or observation_count <= 0:
            status = QualityReviewStatus.INSUFFICIENT
        else:
            status = QualityReviewStatus.ACCEPTED_FOR_REVIEW
        return PostExecutionReview(
            status=status,
            hypothesis_id=clean_id,
            evidence_quality_score=quality,
            evidence_refs=refs,
            issues=tuple(issues),
            causal_proof_present=causal_oracle_passed,
            negative_control_present=negative_control_passed,
            proof_sealed=proof_sealed,
            proof_replayable=proof_replayable,
            overclaim_detected=any(item.code == "overclaim_detected" for item in issues),
        )


def _issue(code: str, severity: str, message: str) -> QualityIssue:
    return QualityIssue(code=code, severity=severity, message=message)


def _text(value: Any) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(str(clean).split())


def _clean_id(value: Any) -> str:
    return _text(value)[:200]


def _string_refs(values: Any) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    if not isinstance(values, (list, tuple, set)):
        return ()
    result: list[str] = []
    for value in values:
        clean = _text(value)
        if clean:
            result.append(clean[:240])
    return tuple(dict.fromkeys(result))[:32]


def _penalty(severity: str) -> float:
    return {"low": 0.04, "medium": 0.12, "high": 0.25, "critical": 0.6}[severity]


def _overclaims(claim: str) -> bool:
    text = claim.lower()
    markers = (
        "confirmed vulnerability",
        "real-world detection",
        "official qualification",
        "p10 qualified",
        "vip qualified",
        "bug bounty ready",
    )
    return any(marker in text for marker in markers)


__all__ = [
    "PostExecutionReview",
    "PreExecutionReview",
    "QualityIssue",
    "QualityReviewStatus",
    "ResearchQualityController",
]
