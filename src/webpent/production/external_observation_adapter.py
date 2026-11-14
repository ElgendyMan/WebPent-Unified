"""TEAM-1 — External Observation Adapter (Wapiti integration seam).

External scanner output = UNTRUSTED/ADVISORY observation. It CANNOT directly
become Tool-Confirmed, IN_SCOPE, TARGET_BACKED, or establish authority.
It feeds advisory hypotheses/evidence into ResearchLoop, which then runs
canonical experiments → validators → ProofBundle.

This is a SEAM, not live Wapiti integration. No second scheduler/authority.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

# External scanner claims that MUST be stripped/neutralized — they are data,
# not authority.
FORBIDDEN_AUTHORITY_CLAIMS = frozenset({
    "CONFIRMED", "IN_SCOPE", "TARGET_BACKED", "OWNER_VERIFIED",
    "NEGATIVE_CONTROL_PASSED", "OPERATOR_APPROVED", "REPLAY_VALID",
    "TOOL_CONFIRMED", "PROMOTION_READY", "CAUSAL_SIGNAL_TRUE",
})

ADVISORY_PROVENANCE = "external_scanner_untrusted_advisory"


@dataclass
class ExternalObservation:
    """Normalized external scanner observation — ALWAYS advisory."""
    source: str  # e.g. "wapiti", "nuclei", "custom"
    raw_fingerprint: str  # hash of raw output, not raw itself
    target: str
    endpoint: str | None = None
    vulnerability_class_hint: str | None = None
    advisory_severity: str = "unknown"  # advisory only, not authoritative
    provenance: str = ADVISORY_PROVENANCE
    advisory_only: bool = True
    trust_level: str = "untrusted_external"
    authority_claims_stripped: list[str] = field(default_factory=list)

    def is_authority(self) -> bool:
        return False  # NEVER authoritative

    def as_research_context(self) -> dict[str, Any]:
        return {
            "source": self.source, "target": self.target, "endpoint": self.endpoint,
            "vulnerability_class_hint": self.vulnerability_class_hint,
            "advisory_severity": self.advisory_severity,
            "provenance": self.provenance, "advisory_only": True,
            "trust_level": self.trust_level,
            "usage_constraint": "may_inform_hypothesis_generation_only",
            "authority_claims_stripped": self.authority_claims_stripped,
        }


def ingest_external_observation(raw: dict[str, Any], *, source: str,
                                expected_target: str) -> ExternalObservation:
    """Ingest external scanner output. Strip ALL authority claims.
    If raw claims authority for a different target → reject (fail closed)."""
    # Target binding check — external result for wrong target cannot apply.
    raw_target = str(raw.get("target", raw.get("url", "")))
    if expected_target and expected_target not in raw_target and raw_target not in expected_target:
        raise ValueError(
            f"External observation target mismatch: {raw_target!r} vs expected {expected_target!r}. "
            "Cross-target evidence cannot be silently applied.")

    # Strip authority claims — they are data, not authority.
    stripped = []
    upper_raw = {str(k).upper(): v for k, v in raw.items()}
    for claim in FORBIDDEN_AUTHORITY_CLAIMS:
        if claim in upper_raw or claim in str(raw.get("status", "")).upper():
            stripped.append(claim)

    # Fingerprint raw (never store raw hostile content as trusted).
    raw_fp = hashlib.sha256(str(raw).encode()).hexdigest()[:16]

    return ExternalObservation(
        source=source, raw_fingerprint=raw_fp,
        target=raw_target, endpoint=raw.get("endpoint", raw.get("path")),
        vulnerability_class_hint=raw.get("vulnerability_class", raw.get("type")),
        advisory_severity=str(raw.get("severity", "unknown")).lower(),
        authority_claims_stripped=stripped,
    )


def convert_admitted_fixture_to_advisory(
    admitted_fixture: dict[str, Any], route_shape: dict[str, Any],
    active_engagement_instance_id: str, active_target_fingerprint: str,
    *, rejection_register: Any = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Convert one admitted fixture through the M2 artifact/intake boundary."""
    from webpent.production.fixture_intake import (
        build_intake_record,
        convert_fixture_to_advisory_artifact,
    )
    artifact = convert_fixture_to_advisory_artifact(
        admitted_fixture, route_shape, active_engagement_instance_id,
        active_target_fingerprint, rejection_register=rejection_register,
    )
    intake = build_intake_record(
        artifact,
        admitted_fixture.get("object_reference_plan") or {},
        admitted_fixture.get("baseline_candidate_control_plan") or {},
        rejection_register=rejection_register,
    )
    return artifact, intake


__all__ = ["ExternalObservation", "ingest_external_observation",
           "convert_admitted_fixture_to_advisory",
           "FORBIDDEN_AUTHORITY_CLAIMS", "ADVISORY_PROVENANCE"]
