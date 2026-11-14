"""Deterministic report quality gates for evidence-first findings.

The quality gate is deliberately independent from LLMs and exporters.  It
accepts live Pydantic findings and checkpoint-shaped dictionaries, reports
missing contract fields without exposing their values, and can optionally
block a strict export.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.proof_bundle import validate_proof_bundle
from webpent.shared.evidence_quality import assess_finding_evidence
from webpent.state.reducers import model_get

_ALLOWED_LEVELS = {
    "Tool-Confirmed",
    "AI-Assessed",
    "Needs Human Review",
    "Pending",
    "Not Scanned",
    "Clean",
}


class FindingQualityResult(BaseModel):
    """Quality result for one finding; contains field names, never values."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = ""
    lifecycle_stage: str
    blocking_issues: list[str] = Field(default_factory=list)
    advisory_issues: list[str] = Field(default_factory=list)
    evidence_classification: str = "unconfirmed"
    evidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    evidence_present_signals: list[str] = Field(default_factory=list)
    evidence_missing_signals: list[str] = Field(default_factory=list)
    evidence_reasons: list[str] = Field(default_factory=list)

    @property
    def ready(self) -> bool:
        return not self.blocking_issues


class ReportQualityResult(BaseModel):
    """Aggregate quality-gate result for a report."""

    model_config = ConfigDict(extra="forbid")

    status: str
    finding_count: int = 0
    ready_finding_count: int = 0
    blocked_finding_count: int = 0
    findings: list[FindingQualityResult] = Field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.status == "ready"


class ReportQualityGateError(ValueError):
    """Raised only when an operator explicitly requests a strict export."""

    def __init__(self, result: ReportQualityResult) -> None:
        self.result = result
        blocked = [
            f"{item.finding_id or '<unknown>'}: {', '.join(item.blocking_issues)}"
            for item in result.findings
            if item.blocking_issues
        ]
        super().__init__(
            "Report quality gate blocked export: " + "; ".join(blocked[:8])
        )


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        try:
            dumped = value.model_dump()
            return dumped if isinstance(dumped, dict) else {}
        except Exception:
            return {}
    return {}


def _nested_value(container: Any, *keys: str) -> Any:
    data = _as_dict(container)
    for key in keys:
        value = data.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _evidence_dict(finding: Any) -> dict[str, Any]:
    evidence = model_get(finding, "evidence")
    return _as_dict(evidence)


def _has_reproduction(finding: Any, evidence: dict[str, Any], bundle: Any) -> bool:
    if _nested_value(evidence, "reproduction", "steps_to_reproduce", "proof"):
        return True
    bundle_data = _as_dict(bundle)
    request = _nested_value(bundle_data, "request")
    response = _nested_value(bundle_data, "response")
    return bool(request and response)


def lifecycle_stage(finding: Any) -> str:
    """Map legacy categorical fields to the shared evidence lifecycle."""
    level = str(model_get(finding, "confidence_level", "") or "")
    evidence = _evidence_dict(finding)
    bundle = model_get(finding, "evidence_bundle")
    has_evidence = bool(evidence or bundle)
    has_reproduction = _has_reproduction(finding, evidence, bundle)

    if level == "Clean":
        return "Clean"
    if level == "Not Scanned":
        return "Not Scanned"
    assessment = assess_finding_evidence(finding)
    if (
        level == "Tool-Confirmed"
        and has_reproduction
        and assessment.classification.value == "confirmed"
    ):
        return "Confirmed"
    if has_reproduction:
        return "Reproduction"
    if has_evidence:
        return "Evidence"
    if model_get(finding, "hypothesis_id") or _nested_value(
        evidence, "hypothesis", "hypothesis_id", "hypothesis_ref"
    ):
        return "Hypothesis"
    if level == "Pending":
        return "Potential"
    return "Potential"


def validate_finding_quality(
    finding: Any,
    *,
    require_proof_bundle: bool = False,
) -> FindingQualityResult:
    """Validate the report contract without making a security claim.

    Missing fields are deterministic contract defects, not vulnerability
    verdicts.  The function never prints or returns request values, cookies,
    tokens, payloads, or evidence bodies.
    """
    finding_id = str(model_get(finding, "id", "") or "")
    level = str(model_get(finding, "confidence_level", "") or "")
    evidence = _evidence_dict(finding)
    bundle = model_get(finding, "evidence_bundle")
    proof_bundle = model_get(finding, "proof_bundle")
    blocking: list[str] = []
    advisory: list[str] = []
    assessment = assess_finding_evidence(finding)

    if level not in _ALLOWED_LEVELS:
        blocking.append("confidence_level")
    if not str(model_get(finding, "url", "") or "").strip():
        blocking.append("endpoint_or_asset")

    # Clean/Not Scanned are coverage signals, not vulnerability submissions.
    if level in {"Clean", "Not Scanned"}:
        advisory.append("non-finding lifecycle status")
        return FindingQualityResult(
            finding_id=finding_id,
            lifecycle_stage=lifecycle_stage(finding),
            blocking_issues=blocking,
            advisory_issues=advisory,
            evidence_classification=assessment.classification.value,
            evidence_score=assessment.score,
            evidence_present_signals=assessment.present_signals,
            evidence_missing_signals=assessment.missing_signals,
            evidence_reasons=assessment.reasons,
        )

    if not (
        model_get(finding, "hypothesis_id")
        or _nested_value(evidence, "hypothesis", "hypothesis_id", "hypothesis_ref")
    ):
        blocking.append("hypothesis")
    if not evidence and not _as_dict(bundle):
        blocking.append("evidence_refs")
    if not _has_reproduction(finding, evidence, bundle):
        blocking.append("reproduction")
    if not str(model_get(finding, "business_impact", "") or "").strip():
        blocking.append("business_impact")
    if not str(model_get(finding, "cvss_score", "") or "").strip():
        blocking.append("cvss")
    if require_proof_bundle and level == "Tool-Confirmed" and not validate_proof_bundle(
        proof_bundle, require_negative_control=True
    ):
        blocking.append("sealed_proof_bundle")
    if level == "Tool-Confirmed" and assessment.classification != "confirmed":
        advisory.append(f"evidence_classification:{assessment.classification.value}")
    if not (
        _nested_value(
            evidence,
            "scope_status",
            "scope_decision",
            "policy_result",
            "scope_policy_result",
        )
        or _nested_value(_as_dict(bundle), "scope_status", "scope_decision", "policy_result")
    ):
        advisory.append("scope_or_policy_result")
    if not (
        _nested_value(evidence, "related_findings", "related_paths", "attack_path")
        or _nested_value(_as_dict(bundle), "related_findings", "related_paths", "attack_path")
    ):
        advisory.append("related_findings_or_paths")

    return FindingQualityResult(
        finding_id=finding_id,
        lifecycle_stage=lifecycle_stage(finding),
        blocking_issues=sorted(set(blocking)),
        advisory_issues=sorted(set(advisory)),
        evidence_classification=assessment.classification.value,
        evidence_score=assessment.score,
        evidence_present_signals=assessment.present_signals,
        evidence_missing_signals=assessment.missing_signals,
        evidence_reasons=assessment.reasons,
    )


def normalize_report_finding(finding: Any) -> Any:
    """Return a report-safe finding without promoting unsupported claims.

    A validator may emit ``Tool-Confirmed`` before the final evidence-quality
    assessment is available.  The report boundary is the last common path for
    JSON/HTML/PDF consumers, so it demotes such an unsupported claim to
    ``Needs Human Review`` without mutating the live Finding or discarding its
    evidence.  Candidates and clean lifecycle records are left unchanged.
    """
    level = str(model_get(finding, "confidence_level", "") or "")
    if level != "Tool-Confirmed":
        return finding
    assessment = assess_finding_evidence(finding)
    if assessment.classification == "confirmed":
        return finding
    data = _as_dict(finding)
    if not data:
        return finding
    normalized = dict(data)
    normalized["confidence_level"] = "Needs Human Review"
    if str(normalized.get("confidence", "") or "").lower() in {
        "confirmed",
        "high",
    }:
        normalized["confidence"] = "tentative"
    return normalized


def evaluate_report_quality(
    findings: Iterable[Any],
    *,
    require_proof_bundle: bool = False,
) -> ReportQualityResult:
    """Evaluate all findings and return a serializable report gate result."""
    results = [
        validate_finding_quality(finding, require_proof_bundle=require_proof_bundle)
        for finding in findings
    ]
    blocked = sum(not result.ready for result in results)
    return ReportQualityResult(
        status="ready" if blocked == 0 else "blocked",
        finding_count=len(results),
        ready_finding_count=len(results) - blocked,
        blocked_finding_count=blocked,
        findings=results,
    )


def enforce_report_quality(
    findings: Iterable[Any],
    *,
    require_proof_bundle: bool = False,
) -> ReportQualityResult:
    """Raise ``ReportQualityGateError`` when strict export is requested."""
    result = evaluate_report_quality(findings, require_proof_bundle=require_proof_bundle)
    if not result.ready:
        raise ReportQualityGateError(result)
    return result


__all__ = [
    "FindingQualityResult",
    "ReportQualityGateError",
    "ReportQualityResult",
    "enforce_report_quality",
    "evaluate_report_quality",
    "lifecycle_stage",
    "normalize_report_finding",
    "validate_finding_quality",
]
