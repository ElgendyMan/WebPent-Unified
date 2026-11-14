"""Family promotion pipeline — closes the D2-style merge gap.

Converts a CONFIRMED :class:`FamilyValidationResult` (plus the candidate that
generated it) into a real :class:`webpent.models.findings.Finding`, with all
five required fields (title/severity/description/tool_name/url), vuln_class
set, and the proof-bundle spec carried in evidence. The caller merges the
returned Finding into ``state["findings"]`` — exactly the fix applied to AVI
promoted findings in graph/builder.py (see REMEDIATION_REPORT Phase 1.2).

Fail-closed: only CONFIRMED results produce a Finding. Anything else returns
None (never auto-promotes).
"""
from __future__ import annotations

from typing import Any

from webpent.agents.validator.family_checks import FamilyValidationResult, FamilyVerdict
from webpent.families.base import FamilyCandidate
from webpent.models.findings import Confidence, Finding, Severity, VulnClass

# Per-family default severity (overridable by scenario).
_FAMILY_SEVERITY: dict[str, str] = {
    "race_condition": "high",
    "tenant_isolation": "critical",
    "multi_step_auth_bypass": "critical",
    "exploit_chain": "critical",
    "business_logic": "high",
    "oauth": "critical",
}

_FAMILY_TOOL: dict[str, str] = {
    "race_condition": "family_validator:race_condition",
    "tenant_isolation": "family_validator:tenant_isolation",
    "multi_step_auth_bypass": "family_validator:multi_step_auth_bypass",
    "exploit_chain": "family_validator:exploit_chain",
    "business_logic": "family_validator:business_logic",
    "oauth": "family_validator:oauth",
}

# Map vuln_class string -> VulnClass enum member (fail-closed fallback UNKNOWN).
def _vuln_class_enum(vuln_class: str) -> VulnClass:
    try:
        return VulnClass(str(vuln_class).lower())
    except ValueError:
        return VulnClass.UNKNOWN


def promote_confirmed_finding(
    result: FamilyValidationResult,
    candidate: FamilyCandidate | None = None,
    *,
    engagement_id: str = "",
) -> Finding | None:
    """Promote ONLY a CONFIRMED result to a Finding. Returns None otherwise."""
    if result.verdict != FamilyVerdict.CONFIRMED:
        return None
    vuln_class = str(result.vuln_class)
    severity = _FAMILY_SEVERITY.get(vuln_class, "medium")
    title = f"[{vuln_class}] {result.scenario_id}: {result.rationale[:80]}"
    description = (
        f"Family validator confirmed {result.scenario_id} ({vuln_class}). "
        f"Rationale: {result.rationale}. "
        f"Evidence refs: {list(result.evidence_refs)}. "
        f"Promotion gate: causal replay + negative control (fail-closed)."
    )
    raw_url = candidate.affected_endpoint if candidate and candidate.affected_endpoint else ""
    # affected_endpoint may be "METHOD /path" — extract path; must be absolute http(s).
    if " " in raw_url:
        raw_url = raw_url.split(" ", 1)[-1]
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        url = raw_url
    elif raw_url.startswith("/"):
        url = f"https://family-validated-target.local{raw_url}"
    else:
        url = "https://family-validated-target.local/"
    evidence: dict[str, Any] = {
        "family_promoted": True,
        "family": vuln_class,
        "scenario_id": result.scenario_id,
        "rationale": result.rationale,
        "evidence_refs": list(result.evidence_refs),
        "proof_bundle_spec": result.proof_bundle_spec,
        "source_candidate": candidate.model_dump() if candidate else None,
        "engagement_id": engagement_id,
    }
    return Finding(
        title=title[:120],
        severity=Severity(severity),
        description=description,
        tool_name=_FAMILY_TOOL.get(vuln_class, "family_validator"),
        url=str(url)[:2048],
        vuln_class=_vuln_class_enum(vuln_class),
        confidence=Confidence.FIRM,
        evidence=evidence,
    )


def promote_confirmed_batch(
    results: list[tuple[FamilyValidationResult, FamilyCandidate | None]],
    *,
    engagement_id: str = "",
) -> list[Finding]:
    """Promote a batch; returns only CONFIRMED findings (fail-closed)."""
    out: list[Finding] = []
    for result, candidate in results:
        finding = promote_confirmed_finding(result, candidate, engagement_id=engagement_id)
        if finding is not None:
            out.append(finding)
    return out


__all__ = ["promote_confirmed_batch", "promote_confirmed_finding"]
