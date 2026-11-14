"""Family promotion — NON-AUTHORITATIVE candidate insertion (UM-DR-36.1 §5.5).

The family validators' deterministic CONFIRMED verdict is real evidence,
but it is NOT a technical confirmation authority. This module inserts a
real :class:`Finding` for confirmed scenarios while keeping the sole
authority contract enforced:

* WITH a passed ``verification`` (a
  :class:`webpent.shared.verifier.VerificationResult` from the strict
  replay verifier — which itself mandates CausalGuard adjudication,
  seals a ProofBundle and replays it) the finding is inserted as
  Tool-Confirmed with the sealed bundle attached.
* WITHOUT canonical verification the finding is inserted ONLY as a
  TENTATIVE / ``Pending`` candidate, explicitly marked as awaiting the
  canonical chain. The family verdict alone can never produce
  Tool-Confirmed, CONFIRMED confidence, or a promotion claim.

CausalGuard remains the sole technical confirmation authority;
PromotionPipeline remains the sole promotion decision authority. This
module performs neither.
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
    verification: Any | None = None,
) -> Finding | None:
    """Insert a Finding for a CONFIRMED family result — candidate by default.

    ``verification`` must be a passed VerificationResult from
    ``webpent.shared.verifier.verify_replay_evidence`` for the finding to
    carry Tool-Confirmed; anything else (including a failed verification)
    yields an explicit Pending candidate. Returns None for non-CONFIRMED
    results (fail-closed).
    """
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
    # UM-DR-36.1 §5.5 authority contract: the family verdict alone is a
    # CANDIDATE, never a technical confirmation. Only a passed strict
    # replay verification (CausalGuard-mandated, sealed ProofBundle,
    # replayed) may attach Tool-Confirmed.
    verified = bool(getattr(verification, "passed", False))
    if verified:
        confidence = Confidence.CONFIRMED
        confidence_level = "Tool-Confirmed"
        evidence["canonical_verification"] = "verify_replay_evidence:passed"
        evidence["verification_reason"] = str(
            getattr(verification, "reason", ""))
    else:
        confidence = Confidence.TENTATIVE
        confidence_level = "Pending"
        evidence["family_candidate_pending_canonical_confirmation"] = True
        evidence["canonical_verification"] = (
            "absent" if verification is None else "failed")
    kwargs: dict[str, Any] = {
        "title": title[:120],
        "severity": Severity(severity),
        "description": description,
        "tool_name": _FAMILY_TOOL.get(vuln_class, "family_validator"),
        "url": str(url)[:2048],
        "vuln_class": _vuln_class_enum(vuln_class),
        "confidence": confidence,
        "confidence_level": confidence_level,
        "evidence": evidence,
    }
    if verified:
        bundle = getattr(verification, "proof_bundle", None)
        if bundle is not None:
            if hasattr(bundle, "model_dump"):
                bundle = bundle.model_dump(mode="json")
            elif not isinstance(bundle, dict):
                bundle = {"bundle_id": getattr(bundle, "bundle_id", None)}
            kwargs["evidence_bundle"] = bundle
    return Finding(**kwargs)


def promote_confirmed_batch(
    results: list[tuple[FamilyValidationResult, FamilyCandidate | None]],
    *,
    engagement_id: str = "",
    verifications: list[Any | None] | None = None,
) -> list[Finding]:
    """Promote a batch; returns only CONFIRMED findings (fail-closed)."""
    out: list[Finding] = []
    verifications = verifications or [None] * len(results)
    for (result, candidate), verification in zip(results, verifications):
        finding = promote_confirmed_finding(
            result, candidate, engagement_id=engagement_id,
            verification=verification)
        if finding is not None:
            out.append(finding)
    return out


__all__ = ["promote_confirmed_batch", "promote_confirmed_finding"]
