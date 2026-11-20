"""Submission-ready bug-bounty reports derived from promoted ProofBundles.

This module is deliberately a read-only boundary. It never promotes, mutates, or
revalidates a finding through a second authority. A report can be built only when
the supplied finding is already promoted, carries a sealed/authentic ProofBundle,
has CVSS evidence, has executed request metadata, and exposes the eight-gate
promotion record.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from webpent.models.evidence import redact_sensitive, sha256_text
from webpent.models.proof_bundle import (
    ProofBundle,
    proof_bundle_promotion_ready,
    validate_proof_bundle,
)


class BountyReportError(ValueError):
    """Raised when a finding cannot safely become a submission report."""


class ReproductionStep(BaseModel):
    """One request-backed, secret-free reproduction step."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    number: int = Field(ge=1)
    method: str = Field(min_length=1, max_length=12)
    url: str = Field(min_length=1, max_length=2000)
    request_digest: str = ""
    response_status: int | None = None
    response_digest: str = ""
    description: str = Field(min_length=1, max_length=500)


class CausalEvidence(BaseModel):
    """Redacted baseline/candidate/control evidence from the sealed bundle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str
    status_code: int | None = None
    request_digest: str = ""
    response_digest: str = ""
    evidence_ref: str | None = None


class BountyReport(BaseModel):
    """Platform-neutral HackerOne/Bugcrowd/Intigriti submission record."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "webpent.bounty-report.v1"
    report_id: str
    finding_id: str
    campaign_id: str
    title: str
    severity: str
    cvss_score: float
    cvss_vector: str | None = None
    cvss_justification: str
    description: str
    steps_to_reproduce: list[ReproductionStep]
    evidence: dict[str, Any]
    impact: str
    remediation: str
    supporting_material: dict[str, Any]
    generated_at: str

    def to_json(self) -> dict[str, Any]:
        """Return JSON-safe structured output."""
        return self.model_dump(mode="json")

    def to_markdown(self) -> str:
        """Render a platform-neutral Markdown submission."""
        lines = [
            f"# {_clean_text(self.title)}",
            "",
            f"**Report ID:** `{_clean_text(self.report_id)}`  ",
            f"**Finding ID:** `{_clean_text(self.finding_id)}`  ",
            f"**Campaign:** `{_clean_text(self.campaign_id)}`  ",
            f"**Severity:** **{_clean_text(self.severity)}**  ",
            f"**CVSS v3.1:** `{self.cvss_score:.1f}`"
            + (f" (`{_clean_text(self.cvss_vector)}`)" if self.cvss_vector else ""),
            "",
            "**CVSS rationale:**",
            "",
            _clean_text(self.cvss_justification),
            "",
            "## Description",
            "",
            _clean_text(self.description),
            "",
            "## Steps to Reproduce",
            "",
        ]
        for step in self.steps_to_reproduce:
            status = (
                f"; observed response status `{step.response_status}`"
                if step.response_status is not None
                else ""
            )
            lines.append(
                f"{step.number}. {_clean_text(step.description)} Send "
                f"`{_clean_text(step.method)} {_clean_text(step.url)}`{status}. "
                f"Request digest: `{_clean_text(step.request_digest)}`; response digest: "
                f"`{_clean_text(step.response_digest)}`."
            )
        lines.extend(
            [
                "",
                "## Evidence",
                "",
                "The following causal chain is derived from the sealed ProofBundle. "
                "Response bodies, headers, credentials, and tokens are intentionally omitted.",
                "",
                "| Role | Status | Request digest | Response digest | Evidence ref |",
                "| --- | ---: | --- | --- | --- |",
            ]
        )
        for item in self.evidence.get("causal_chain", []):
            lines.append(
                f"| {_clean_text(item.get('role'))} | {item.get('status_code', '')} | "
                f"`{_clean_text(item.get('request_digest'))}` | "
                f"`{_clean_text(item.get('response_digest'))}` | "
                f"`{_clean_text(item.get('evidence_ref'), default='n/a')}` |"
            )
        lines.extend(
            [
                "",
                "## Impact",
                "",
                _clean_text(self.impact),
                "",
                "## Remediation",
                "",
                _clean_text(self.remediation),
                "",
                "## Supporting Material",
                "",
                f"- ProofBundle: `{self.supporting_material.get('proof_bundle_id', '')}`",
                f"- ProofBundle seal: `{self.supporting_material.get('seal_digest', '')}`",
                f"- Audit chain: `{self.supporting_material.get('audit_chain_status', '')}`",
                f"- Promotion gates passed: "
                f"{', '.join(self.supporting_material.get('gates_passed', []))}",
                "",
                f"_Generated at {self.generated_at}. This report is read-only output._",
                "",
            ]
        )
        return "\n".join(lines)

    # -- platform-specific renderers (Track 9.4 / 11.6, 0.26.0) ----------
    #
    # The roadmap asked for "قوالب تقارير جاهزة: دعم تنسيقات المنصات
    # الشائعة" — ready templates for the common platforms. Until now the
    # module had ONE neutral Markdown shape; these renderers map the same
    # promotion-gated content onto the field structures HackerOne and
    # Bugcrowd expect. Read-only boundary unchanged: same gates, same
    # redaction, same sealed bundle — only the field arrangement differs.

    def to_hackerone_markdown(self) -> str:
        """HackerOne-shaped submission (title / VIM / impact sections).

        Mirrors the H1 report form fields: ``title``,
        ``vulnerability_information`` (severity + CVSS + description +
        steps), ``impact``. Supporting material is appended because H1
        reviewers expect the evidence provenance.
        """
        steps = [
            f"{step.number}. {_clean_text(step.description)} Send "
            f"`{_clean_text(step.method)} {_clean_text(step.url)}`"
            + (
                f" — observed response status `{step.response_status}`"
                if step.response_status is not None
                else ""
            )
            + f". Request digest `{_clean_text(step.request_digest)}`; "
            f"response digest `{_clean_text(step.response_digest)}`."
            for step in self.steps_to_reproduce
        ]
        lines = [
            "## Title",
            "",
            _clean_text(self.title),
            "",
            "## Severity (H1 scale)",
            "",
            f"**{_clean_text(self.severity)}** — CVSS v3.1 `{self.cvss_score:.1f}`"
            + (f" (`{_clean_text(self.cvss_vector)}`)" if self.cvss_vector else ""),
            "",
            "## Vulnerability Information",
            "",
            _clean_text(self.description),
            "",
            "### Steps to Reproduce",
            "",
            *steps,
            "",
            "### CVSS rationale",
            "",
            _clean_text(self.cvss_justification),
            "",
            "## Impact",
            "",
            _clean_text(self.impact),
            "",
            "## Supporting Material",
            "",
            f"- ProofBundle: `{self.supporting_material.get('proof_bundle_id', '')}`",
            f"- ProofBundle seal: `{self.supporting_material.get('seal_digest', '')}`",
            f"- Audit chain: `{self.supporting_material.get('audit_chain_status', '')}`",
            f"- Promotion gates passed: "
            f"{', '.join(self.supporting_material.get('gates_passed', []))}",
            "",
            f"_Report ID `{_clean_text(self.report_id)}` "
            f"(campaign `{_clean_text(self.campaign_id)}`), generated at "
            f"{self.generated_at}. Read-only output; submit only after human review.",
            "",
        ]
        return "\n".join(lines)

    def to_bugcrowd_markdown(self) -> str:
        """Bugcrowd-shaped submission (description / steps / impact + P-scale).

        Bugcrowd uses the P1..P5 priority vocabulary; the CVSS band maps
        P1 >= 9, P2 >= 7, P3 >= 4, P4 > 0, P5 informational.
        """
        priority = _bugcrowd_priority(self.cvss_score)
        # The neutral model deliberately carries no top-level target
        # field; the first reproduction step's URL is the real, sealed
        # target reference this report was built from.
        target_ref = (
            _clean_text(self.steps_to_reproduce[0].url) if self.steps_to_reproduce else ""
        )
        lines = [
            "## Target",
            "",
            f"`{target_ref}`",
            "",
            "## Description",
            "",
            _clean_text(self.description),
            "",
            "## Steps to Reproduce",
            "",
        ]
        for step in self.steps_to_reproduce:
            status = (
                f"; observed response status `{step.response_status}`"
                if step.response_status is not None
                else ""
            )
            lines.append(
                f"{step.number}. {_clean_text(step.description)} Send "
                f"`{_clean_text(step.method)} {_clean_text(step.url)}`{status}. "
                f"Request digest: `{_clean_text(step.request_digest)}`; response digest: "
                f"`{_clean_text(step.response_digest)}`."
            )
        lines.extend(
            [
                "",
                "## Impact",
                "",
                _clean_text(self.impact),
                "",
                "## Severity",
                "",
                f"**Bugcrowd priority: {priority}** (neutral label `{_clean_text(self.severity)}`, "
                f"CVSS v3.1 `{self.cvss_score:.1f}`"
                + (f" `{_clean_text(self.cvss_vector)}`" if self.cvss_vector else "")
                + ")",
                "",
                "## Evidence provenance",
                "",
                f"- ProofBundle: `{self.supporting_material.get('proof_bundle_id', '')}` "
                f"(seal `{self.supporting_material.get('seal_digest', '')}`)",
                f"- Audit chain: `{self.supporting_material.get('audit_chain_status', '')}`",
                f"- Promotion gates passed: "
                f"{', '.join(self.supporting_material.get('gates_passed', []))}",
                "",
                f"_Report ID `{_clean_text(self.report_id)}` "
                f"(campaign `{_clean_text(self.campaign_id)}`), generated at "
                f"{self.generated_at}. Read-only output; submit only after human review.",
                "",
            ]
        )
        return "\n".join(lines)

    def to_platform_markdown(self, platform: str) -> str:
        """Render for one of the supported platforms (default neutral)."""
        normalized = (platform or "neutral").strip().lower()
        if normalized == "hackerone":
            return self.to_hackerone_markdown()
        if normalized == "bugcrowd":
            return self.to_bugcrowd_markdown()
        return self.to_markdown()


def _bugcrowd_priority(score: float) -> str:
    """CVSS band -> Bugcrowd P1..P5 vocabulary (documented mapping)."""
    if score >= 9.0:
        return "P1"
    if score >= 7.0:
        return "P2"
    if score >= 4.0:
        return "P3"
    if score > 0.0:
        return "P4"
    return "P5"


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "model_dump"):
        try:
            result = value.model_dump(mode="json")
            return dict(result) if isinstance(result, Mapping) else {}
        except Exception:
            return {}
    return {}


def _clean(value: Any, *, key: str = "") -> Any:
    """Redact secrets before any value crosses into the submission report."""
    result, _ = redact_sensitive(value, key_hint=key)
    return result


def _clean_text(value: Any, *, default: str = "") -> str:
    """Return a redacted string for user-controlled report prose."""
    text = str(value or "").strip()
    if not text:
        return default
    clean, _ = redact_sensitive(text)
    return str(clean).strip()


def _finding_data(finding: Any) -> dict[str, Any]:
    data = _as_dict(finding)
    if not data:
        raise BountyReportError("finding_mapping_required")
    return data


def _proof_bundle(finding: Mapping[str, Any]) -> ProofBundle:
    evidence = _as_dict(finding.get("evidence"))
    candidates = [
        finding.get("proof_bundle"),
        evidence.get("proof_bundle"),
        finding.get("evidence_bundle"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            bundle = candidate if isinstance(candidate, ProofBundle) else ProofBundle.model_validate(candidate)
        except Exception:
            continue
        if validate_proof_bundle(bundle, require_negative_control=True) and proof_bundle_promotion_ready(bundle):
            return bundle
    raise BountyReportError("sealed_promotion_ready_proof_bundle_required")


def _promotion_status(finding: Mapping[str, Any], evidence: Mapping[str, Any]) -> str:
    for container in (finding, evidence, evidence.get("promotion"), evidence.get("promotion_decision")):
        item = _as_dict(container)
        for key in ("decision", "status", "promotion"):
            value = str(item.get(key) or "").strip().upper()
            if value in {"PROMOTED", "TOOL-CONFIRMED", "TOOL_CONFIRMED"}:
                return "PROMOTED"
            if value in {"REFUTED", "REJECTED"}:
                return value
    if str(finding.get("confidence_level") or "").strip().lower() == "tool-confirmed":
        return "PROMOTED"
    return ""


def _extract_cvss_score(value: Any) -> float | None:
    """Extract the final numeric CVSS score from free-form score text."""
    raw = str(value or "").strip()
    if not raw:
        return None
    if re.fullmatch(r"(?:10(?:\.0+)?|\d+(?:\.\d+))", raw):
        score_text = raw
    else:
        matches = re.findall(r"(?<!\d)(?:10(?:\.0+)?|\d+\.\d+)(?!\d)", raw)
        if not matches:
            return None
        # A CVSS vector contains its version (3.1); the score is the final
        # numeric token in the human-readable representation.
        score_text = matches[-1]
    try:
        score = float(score_text)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _cvss(finding: Mapping[str, Any] | str) -> tuple[float, str | None, str] | float | None:
    """Parse a report finding, or directly extract a score from score text."""
    if isinstance(finding, str):
        return _extract_cvss_score(finding)
    raw = str(finding.get("cvss_score") or "").strip()
    if not raw:
        raise BountyReportError("cvss_justification_required")
    vector_match = re.search(r"CVSS:3\.1/[A-Z0-9:/.-]+", raw, re.IGNORECASE)
    vector = vector_match.group(0) if vector_match else None
    score = _extract_cvss_score(raw)
    if score is None:
        raise BountyReportError("cvss_numeric_score_required")
    justification = _clean_text(finding.get("reasoning"))
    if not justification:
        raise BountyReportError("cvss_justification_required")
    return score, vector, justification[:1000]


def _platform_severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


def _role_exchange(evidence: Mapping[str, Any], role: str) -> dict[str, Any]:
    for container in (
        evidence.get(role),
        _as_dict(evidence.get("experiment")).get(role),
        _as_dict(evidence.get("causal_chain")).get(role),
    ):
        item = _as_dict(container)
        if item:
            return item
    return {}


def _redacted_digest(value: Any) -> str:
    """Compute the same digest used by ProofBundle request/response evidence."""
    return f"sha256:{sha256_text(redact_sensitive(value)[0])}"


def _authoritative_status(bundle: ProofBundle, index: int, role: str) -> int | None:
    """Return a response status sealed in causal-oracle/validator metadata."""
    oracle = _as_dict(bundle.causal_oracle)
    role_keys = {
        "baseline": ("baseline_access_result", "baseline_status_code"),
        "candidate": ("candidate_access_result", "candidate_status_code"),
        "negative_control": ("negative_control_result", "negative_control_status_code"),
    }.get(role, ())
    for key in role_keys:
        value = oracle.get(key)
        if value is not None:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    statuses = bundle.validator_result.get("response_statuses")
    if isinstance(statuses, (list, tuple)) and index < len(statuses):
        try:
            return int(statuses[index])
        except (TypeError, ValueError):
            return None
    return None


def _executed_requests(
    finding: Mapping[str, Any], evidence: Mapping[str, Any], bundle: ProofBundle
) -> list[ReproductionStep]:
    sequence: Any = evidence.get("request_sequence")
    if sequence is None:
        sequence = _as_dict(evidence.get("experiment")).get("request_sequence")
    if sequence is None:
        sequence = evidence.get("requests")
    if sequence is None:
        request = _as_dict(evidence.get("request"))
        sequence = [request] if request else []
    if isinstance(sequence, Mapping):
        sequence = [sequence]
    if not isinstance(sequence, Sequence) or isinstance(sequence, (str, bytes)):
        raise BountyReportError("executed_request_sequence_required")

    responses: Any = evidence.get("response_sequence")
    if responses is None:
        responses = _as_dict(evidence.get("experiment")).get("response_sequence")
    if responses is None:
        responses = evidence.get("responses")
    if isinstance(responses, Mapping):
        responses = [responses]
    if not isinstance(responses, Sequence) or isinstance(responses, (str, bytes)):
        raise BountyReportError("executed_response_sequence_required")
    if len(sequence) != len(bundle.request_digests) or len(responses) != len(bundle.response_digests):
        raise BountyReportError("executed_request_response_sequence_length_mismatch")
    if len(sequence) != len(responses) or not sequence:
        raise BountyReportError("executed_request_response_sequence_length_mismatch")

    steps: list[ReproductionStep] = []
    for index, raw_request in enumerate(sequence[:32]):
        request = _as_dict(raw_request)
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or finding.get("url") or "").strip()
        if not url:
            raise BountyReportError("executed_request_url_required")
        response = _as_dict(responses[index])
        if not response:
            raise BountyReportError("executed_response_required")
        status = response.get("status_code", response.get("status"))
        try:
            status_code = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_code = None
        expected_request_digest = bundle.request_digests[index]
        declared_request_digest = str(request.get("request_digest") or "")
        request_digest = declared_request_digest or _redacted_digest(request)
        if request_digest != expected_request_digest:
            raise BountyReportError("request_digest_not_bound_to_proof_bundle")
        expected_response_digest = bundle.response_digests[index]
        declared_response_digest = str(response.get("response_digest") or "")
        response_digest = declared_response_digest or _redacted_digest(response)
        if response_digest != expected_response_digest:
            raise BountyReportError("response_digest_not_bound_to_proof_bundle")
        role = str(request.get("role") or ("baseline", "candidate", "negative_control")[index])
        authoritative_status = _authoritative_status(bundle, index, role)
        if status_code is None or authoritative_status is None or status_code != authoritative_status:
            raise BountyReportError("response_status_not_bound_to_proof_bundle")
        if not request_digest or not response_digest:
            raise BountyReportError("request_response_digest_binding_required")
        safe_url = str(_clean(url, key="url"))[:2000]
        steps.append(
            ReproductionStep(
                number=index + 1,
                method=method,
                url=safe_url,
                request_digest=request_digest,
                response_status=status_code,
                response_digest=response_digest,
                description=(
                    f"Replay the sealed {role.replace('_', ' ')} request and compare "
                    "the redacted response metadata."
                ),
            )
        )
    if not steps:
        raise BountyReportError("executed_request_sequence_required")
    return steps


def _causal_chain(evidence: Mapping[str, Any], bundle: ProofBundle) -> list[dict[str, Any]]:
    roles = ("baseline", "candidate", "negative_control")
    result: list[dict[str, Any]] = []
    for index, role in enumerate(roles):
        exchange = _role_exchange(evidence, role)
        response = _as_dict(exchange.get("response"))
        request = _as_dict(exchange.get("request"))
        request_digest = str(request.get("request_digest") or "")
        if not request_digest and index < len(bundle.request_digests):
            request_digest = bundle.request_digests[index]
        response_digest = str(response.get("response_digest") or "")
        if not response_digest and index < len(bundle.response_digests):
            response_digest = bundle.response_digests[index]
        if role == "baseline" and not response_digest:
            response_digest = bundle.baseline_digest or ""
        if role == "negative_control" and not response_digest:
            response_digest = bundle.negative_control_digest or ""
        status = _authoritative_status(bundle, index, role)
        explicit_ref = {
            "baseline": bundle.baseline_evidence_ref,
            "candidate": bundle.candidate_evidence_ref,
            "negative_control": bundle.negative_control_evidence_ref,
        }[role]
        evidence_ref = explicit_ref or (
            bundle.evidence_refs[index] if index < len(bundle.evidence_refs) else None
        )
        result.append(
            CausalEvidence(
                role=role,
                status_code=status,
                request_digest=request_digest,
                response_digest=response_digest,
                evidence_ref=_clean_text(evidence_ref) or None,
            ).model_dump(mode="json")
        )
    return result


def _gates(finding: Mapping[str, Any], evidence: Mapping[str, Any], bundle: ProofBundle) -> list[str]:
    candidates = [
        evidence.get("gates_passed"),
        _as_dict(evidence.get("promotion")).get("gates_passed"),
        _as_dict(evidence.get("promotion_decision")).get("gates_passed"),
        bundle.validator_result.get("gates_passed"),
    ]
    for candidate in candidates:
        if isinstance(candidate, Sequence) and not isinstance(candidate, (str, bytes)):
            gates = [_clean_text(item)[:160] for item in candidate if str(item).strip()]
            if len(gates) >= 8:
                return list(dict.fromkeys(gates))
    raise BountyReportError("eight_promotion_gates_required")


def build_bounty_report(
    finding: Any,
    *,
    audit_chain: Any = None,
    report_id: str | None = None,
) -> BountyReport:
    """Build one submission-ready report without creating a second promotion path."""
    data = _finding_data(finding)
    evidence = _as_dict(data.get("evidence"))
    status = _promotion_status(data, evidence)
    if status in {"REFUTED", "REJECTED"}:
        raise BountyReportError("refuted_findings_are_not_reportable")
    if status != "PROMOTED":
        raise BountyReportError("promoted_finding_required")
    bundle = _proof_bundle(data)
    score, vector, justification = _cvss(data)
    steps = _executed_requests(data, evidence, bundle)
    gates = _gates(data, evidence, bundle)

    chain_status = "proof_bundle_chain_of_custody_present" if bundle.chain_of_custody else "not_provided"
    chain_payload: Any = audit_chain
    if chain_payload is None:
        chain_payload = evidence.get("audit_chain") or evidence.get("audit_trail")
    if chain_payload is not None:
        verify = getattr(chain_payload, "verify_chain", None)
        if callable(verify):
            try:
                chain_status = "verified" if bool(verify()) else "verification_failed"
            except Exception:
                chain_status = "verification_failed"
        elif isinstance(chain_payload, Mapping):
            chain_status = "verified" if chain_payload.get("verified") is True else "recorded"

    campaign_id = _clean_text(
        data.get("campaign_id")
        or data.get("engagement_id")
        or bundle.campaign_id
        or bundle.engagement_id
        or "unknown-campaign",
    )
    vuln_type = _clean_text(
        data.get("vuln_class") or bundle.vulnerability_class or "Security Vulnerability"
    )
    brief = _clean_text(
        data.get("title") or f"{vuln_type} at {data.get('url') or 'target endpoint'}",
        default=f"{vuln_type} at target endpoint",
    )
    severity = _platform_severity(score)
    prefix = f"[{severity.upper()}] {vuln_type} — "
    title = brief if brief.upper().startswith(prefix.upper()) else f"{prefix}{brief}"
    impact = _clean_text(
        data.get("business_impact"),
        default="Business impact was not provided in the source finding.",
    )
    remediation = _clean_text(
        data.get("remediation")
        or evidence.get("remediation")
        or "Remediation guidance was not provided in the source finding."
    )
    description = _clean_text(
        data.get("description"),
        default="Finding description was not provided in the source finding.",
    )

    supporting = {
        "proof_bundle_id": bundle.bundle_id,
        "seal_digest": bundle.seal_digest,
        "authenticity_verified": bool(bundle.verify_seal()),
        "replayable": bool(bundle.replay_metadata.get("replayable") is True),
        "audit_chain_status": chain_status,
        "gates_passed": gates,
        "validator_id": bundle.validator_id,
        "validator_version": bundle.validator_version,
        "oracle_decision": bundle.oracle_decision,
        "evidence_origin": bundle.evidence_origin,
    }
    if not supporting["authenticity_verified"] or not supporting["replayable"]:
        raise BountyReportError("proof_bundle_authenticity_and_replay_required")
    return BountyReport(
        report_id=report_id or f"bounty_report_{uuid4().hex}",
        finding_id=str(data.get("id") or bundle.finding_id),
        campaign_id=campaign_id,
        title=title,
        severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        cvss_justification=justification,
        description=description,
        steps_to_reproduce=steps,
        evidence={
            "causal_chain": _causal_chain(evidence, bundle),
            "target_backed": bundle.target_backed,
            "negative_control_independent": bundle.negative_control_independent,
            "oracle": _clean(bundle.causal_oracle),
            "response_digests": list(bundle.response_digests),
        },
        impact=impact,
        remediation=remediation,
        supporting_material=supporting,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )


def generate_bounty_reports(findings: Sequence[Any], *, campaign_id: str = "") -> list[BountyReport]:
    """Return only submission-ready promoted reports; refuted/incomplete items are skipped."""
    reports: list[BountyReport] = []
    for finding in findings:
        try:
            report = build_bounty_report(finding)
            if campaign_id:
                report = report.model_copy(update={"campaign_id": campaign_id})
            reports.append(report)
        except BountyReportError:
            continue
    return reports


# Explicit aliases for callers that prefer submission terminology.
build_submission_report = build_bounty_report
render_bounty_markdown = lambda report: report.to_markdown() if isinstance(report, BountyReport) else BountyReport.model_validate(report).to_markdown()

__all__ = [
    "BountyReport",
    "BountyReportError",
    "CausalEvidence",
    "ReproductionStep",
    "build_bounty_report",
    "build_submission_report",
    "generate_bounty_reports",
    "render_bounty_markdown",
]
