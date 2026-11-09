"""Bridge — DEEP findings into the campaign and Prism layers.

Pure conversion functions, zero network, zero mutation:

- DEEP_FAMILY_TO_CAMPAIGN: the documented family map (a DEEP family
  enters the campaign only under the campaign family it actually
  tests).
- finding_to_hypothesis / findings_to_hypotheses: one finding becomes
  ONE disposable probe hypothesis (cost bounded: 1 request, 0 LLM
  calls), ordered deterministically by severity.
- finding_to_evidence_profile: the finding's recorded evidence becomes
  a full-dimension Prism EvidenceProfile — source ``probe``,
  deterministic, single-source (PRISM-L-1: a hash and a rationale, no
  invented evidence).
- finding_to_prism_finding: wraps profiles into a Prism Finding.
  PRISM-L-2 holds: the Prism advises, it never blocks.

No auto-exploitation is added anywhere in this module (DEEP-L-8).
"""
from __future__ import annotations

import hashlib

from webpent.campaign.schemas import Family, Hypothesis
from webpent.deep.cache_deception import CacheDeceptionFinding
from webpent.deep.host_header import HostHeaderFinding
from webpent.deep.mass_assignment import MassAssignmentFinding


class DeepBridgeError(ValueError):
    """Raised when a DEEP finding carries a family the documented
    bridge map does not cover (typed, naming the family — never a
    raw KeyError). Full Tier-2..4 mapping is roadmap work."""
# Documented family map: DEEP family -> campaign Family.
DEEP_FAMILY_TO_CAMPAIGN: dict[str, Family] = {
    "MASS_ASSIGNMENT": Family.AUTH_BYPASS,
    "HOST_HEADER_INJECTION": Family.AUTH_BYPASS,
    "CACHE_DECEPTION": Family.INFO_DISCLOSURE,
}

# Host-header findings carry the spec's own severity (critical for
# password reset poisoning); the other Tier-1 families use a fixed,
# documented default per family.
_FAMILY_SEVERITY: dict[str, str] = {
    "MASS_ASSIGNMENT": "high",
    "CACHE_DECEPTION": "medium",
}

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3,
}

_FAILURE_INDICATOR: dict[str, str] = {
    "MASS_ASSIGNMENT": (
        "no injected field is reflected and no privileged state "
        "changes for any payload in the corpus"),
    "HOST_HEADER_INJECTION": (
        "the injected Host values produce behavior identical to the "
        "clean baseline on every surface"),
    "CACHE_DECEPTION": (
        "no crafted static-extension path returns the cookie-bearing "
        "body of the victim endpoint"),
}

_ADVISORY_NOTE = "advisory; verify against an authorized target"


def severity_of(finding) -> str:
    """Deterministic severity for any Tier-1 DEEP finding."""
    if isinstance(finding, HostHeaderFinding):
        return finding.severity
    return _FAMILY_SEVERITY[finding.family]


def _injection_line(finding) -> str:
    """The one request artifact the finding was raised on."""
    if isinstance(finding, MassAssignmentFinding):
        return repr(finding.payload)
    if isinstance(finding, HostHeaderFinding):
        return finding.request_header
    if isinstance(finding, CacheDeceptionFinding):
        return finding.crafted_path
    raise TypeError(
        f"unsupported DEEP finding type: {type(finding).__name__}")


def _deterministic_id(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def finding_to_hypothesis(finding, order: int) -> Hypothesis:
    """One finding -> one disposable, falsifiable probe hypothesis.

    Cost is bounded by construction: replaying a single recorded probe
    is one request, no LLM calls, seconds.
    """
    if finding.family not in DEEP_FAMILY_TO_CAMPAIGN:
        raise DeepBridgeError(
            f"DEEP finding family {finding.family!r} is not covered by "
            "the documented bridge map (Tier-1 only); extending the "
            "map is roadmap work (full-sweep 2026-10-20, F-02).")
    family = DEEP_FAMILY_TO_CAMPAIGN[finding.family]
    line = _injection_line(finding)
    probe_strategy = (
        "[advisory-only] replay the single recorded probe and observe "
        f"the documented success indicator. Injection: {line}. "
        f"{_ADVISORY_NOTE}."
    )
    return Hypothesis(
        hypothesis_id=_deterministic_id(
            f"{finding.family}|{finding.statement}"),
        family=family,
        statement=finding.statement,
        success_indicator=finding.success_indicator,
        failure_indicator=_FAILURE_INDICATOR[finding.family],
        probe_strategy=probe_strategy,
        estimated_requests=1,
        estimated_llm_calls=0,
        estimated_duration_seconds=2,
        order=order,
    )


def _sort_key(finding) -> tuple:
    return (
        _SEVERITY_RANK[severity_of(finding)],
        finding.family,
        _injection_line(finding),
        finding.statement,
    )


def findings_to_hypotheses(findings) -> list[Hypothesis]:
    """Convert findings to hypotheses, sorted critical-first.

    Ordering is on finding-intrinsic keys only, so the output is
    identical for any input permutation.
    """
    ordered = sorted(findings, key=_sort_key)
    return [finding_to_hypothesis(f, order=i)
            for i, f in enumerate(ordered)]


def finding_to_evidence_profile(finding, taxonomy):
    """The finding's recorded evidence as a full-dimension profile.

    Source is ``probe`` (the finding came from a direct injected
    request), the signal is a direct response, reproducibility is
    deterministic (recorded request/response pair), and corroboration
    is single_source until an independent surface agrees.
    """
    evidence_hash = hashlib.sha256(
        "\n".join((finding.statement, *finding.evidence))
        .encode("utf-8")).hexdigest()
    return taxonomy.profile(
        evidence_hash=evidence_hash,
        source="probe",
        signal_kind="direct_response",
        strength="decisive",
        reproducibility="deterministic",
        corroboration="single_source",
        rationale=finding.statement,
    )


def finding_to_prism_finding(finding, profiles):
    """Wrap profiles into a Prism Finding (advisory-only by law)."""
    from webpent.prism.integration import Finding
    return Finding(
        finding_id=_deterministic_id(
            f"prism|{finding.family}|{finding.statement}"),
        title=finding.family,
        anomaly_type=finding.family,
        profiles=tuple(profiles),
    )
