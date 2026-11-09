"""WebPent Milestone 2 — advisory ingestion boundary: artifact conversion,
intake record, rejection register, dedupe key.

Remediation (Team-Red audit):
  D2 — route_shape restricted to Table 4-1 artifact fields; intake-only plans
       (object_reference_plan, baseline_candidate_control_plan) passed
       separately (deny-by-default preserved).
  D6 — C-01 executable-command strip-and-retain on all free-text artifact fields.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

ARTIFACT_SCHEMA_VERSION = 1
INTAKE_SCHEMA_VERSION = 1
TRUST_MARKER = "external-advisory"
STATUS_QUEUED = "queued-for-validation"

PRINCIPAL_USER_A = "User_A_Ref"
PRINCIPAL_USER_B = "User_B_Ref"

# D6 FIX — M5 FIX-14 / M2 C-01: executable-command strip-and-retain.
_C01_PATTERNS = [
    re.compile(";\\s*(rm|wget|curl|nc|bash|sh|python|perl|ruby|chmod|chown|dd)\\b[^\"']{0,200}?", re.IGNORECASE),
    re.compile("\\|\\s*(bash|sh|nc|python|perl|ruby|tee)\\b", re.IGNORECASE),
    re.compile("`[^`]{1,200}`"),
    re.compile("\\$\\([^)]{1,200}\\)"),
    re.compile("&&\\s*(curl|wget)\\b[^\"']{0,200}\\|\\s*(bash|sh)\\b", re.IGNORECASE),
    re.compile("\\b(chmod\\s+777|chown\\s+-R)\\b[^\"']{0,100}?", re.IGNORECASE),
]
C01_REDACTED = "<redacted-executable-shape>"


def c01_strip_executable_content(value: str) -> tuple[str, int]:
    if not isinstance(value, str) or not value:
        return value, 0
    count = 0
    out = value
    for pat in _C01_PATTERNS:
        out, n = pat.subn(C01_REDACTED, out)
        count += n
    return out, count


# M2 ingress sanitization: foreign authority fields stripped/rejected (§4.3).
AUTHORITY_FIELDS = frozenset({
    "confirmed", "verdict", "severity", "severity_as_authority", "scope_approved",
    "target_backed", "replay_valid", "proof_bundle", "promotion_ready",
    "owner_verified", "finding_id", "hypothesis_id", "canonical_finding_id",
    "canonical_hypothesis_id", "validation_outcome", "promoted",
    "causal_guard_result",
})
CALLER_SUPPLIED_ID_FIELDS = frozenset({
    "artifact_id", "intake_id", "status", "dedupe_key", "engagement_instance_id",
    "target_fingerprint",
})

ARTIFACT_PERMITTED_FIELDS = frozenset({
    "artifact_schema_version", "artifact_id", "source_type", "source_fingerprint",
    "engagement_id", "engagement_instance_id", "target_fingerprint",
    "endpoint_template", "method", "parameter_names", "response_shape",
    "authorization_hints", "candidate_rationale", "trust_marker",
    "redaction_metadata", "defect_family_hint", "fixture_id",
})

REJECT_UNKNOWN_FIELD = "unknown_field_rejected"
REJECT_AUTHORITY_CLAIM = "authority_claim_rejected"
REJECT_CANONICAL_ID = "caller_supplied_canonical_id_rejected"
REJECT_MISSING_BINDING = "binding_missing_rejected"
REJECT_FOREIGN_ENGAGEMENT = "foreign_engagement_rejected"
REJECT_FOREIGN_TARGET = "foreign_target_rejected"


@dataclass
class IntakeRejection(Exception):
    reason: str
    detail: str
    source_fingerprint: Optional[str] = None

    def __str__(self) -> str:
        return f"{self.reason}: {self.detail}"


@dataclass
class RejectionRegister:
    rejections: list[dict[str, Any]] = field(default_factory=list)
    entries: list[dict[str, Any]] = field(default_factory=list)

    def reject(self, reason: str, detail: str, source_fingerprint: Optional[str] = None) -> IntakeRejection:
        rej = IntakeRejection(reason, detail, source_fingerprint)
        self.rejections.append({"reason": reason, "detail": detail, "source_fingerprint": source_fingerprint})
        self.entries.append(rej)
        return rej


def _mint(prefix: str) -> str:
    import secrets
    return f"{prefix}_{secrets.token_hex(8)}"


def compute_dedupe_key(engagement_instance_id: str, target_fingerprint: str,
                       defect_family: str, endpoint_template: str,
                       allowed_method: str, object_reference_plan: dict[str, Any]) -> str:
    canonical_plan = json.dumps(object_reference_plan or {}, sort_keys=True, separators=(",", ":"))
    material = "|".join([
        str(engagement_instance_id), str(target_fingerprint),
        str(defect_family).upper(), str(endpoint_template),
        str(allowed_method).upper(), canonical_plan,
    ])
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def convert_fixture_to_advisory_artifact(
    admitted_fixture: dict[str, Any], route_shape: dict[str, Any],
    active_engagement_instance_id: str, active_target_fingerprint: str,
    rejection_register: Optional[RejectionRegister] = None,
) -> dict[str, Any]:
    """M2 Table 4-1 field dictionary. Immutable after creation; raw payload
    remains quarantined. Deny-by-default on unknown fields and authority claims."""
    reg = rejection_register or RejectionRegister()

    for key in route_shape:
        if key in AUTHORITY_FIELDS:
            raise reg.reject(REJECT_AUTHORITY_CLAIM, f"route_shape.{key}",
                             admitted_fixture.get("content_digest"))
        if key in CALLER_SUPPLIED_ID_FIELDS:
            raise reg.reject(REJECT_CANONICAL_ID, f"route_shape.{key}",
                             admitted_fixture.get("content_digest"))
        if key not in ARTIFACT_PERMITTED_FIELDS and key not in (
                "path", "parameters", "response", "auth_hint", "rationale"):
            raise reg.reject(REJECT_UNKNOWN_FIELD, f"route_shape.{key}",
                             admitted_fixture.get("content_digest"))

    if admitted_fixture.get("engagement_instance_id") not in (None, active_engagement_instance_id):
        raise reg.reject(REJECT_FOREIGN_ENGAGEMENT,
                         admitted_fixture.get("engagement_instance_id", "none"),
                         admitted_fixture.get("content_digest"))
    if admitted_fixture.get("target_fingerprint") not in (None, active_target_fingerprint):
        raise reg.reject(REJECT_FOREIGN_TARGET,
                         admitted_fixture.get("target_fingerprint", "none"),
                         admitted_fixture.get("content_digest"))

    endpoint_template = route_shape.get("endpoint_template") or route_shape.get("path")
    if not endpoint_template or not isinstance(endpoint_template, str):
        raise reg.reject(REJECT_MISSING_BINDING, "endpoint_template",
                         admitted_fixture.get("content_digest"))
    method = str(route_shape.get("method", "GET")).upper()
    parameter_names = list(route_shape.get("parameter_names") or route_shape.get("parameters") or [])

    response_shape, c01_1 = c01_strip_executable_content(
        str(route_shape.get("response_shape") or "redacted-unknown"))
    authorization_hints, c01_2 = c01_strip_executable_content(
        str(route_shape.get("authorization_hints") or route_shape.get("auth_hint") or "principal-bound-resource"))
    candidate_rationale, c01_3 = c01_strip_executable_content(
        str(route_shape.get("candidate_rationale") or route_shape.get("rationale")
            or "static-fixture-route-shape-advisory-only"))
    c01_stripped_count = c01_1 + c01_2 + c01_3

    artifact = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "artifact_id": _mint("adv"),
        "source_type": admitted_fixture.get("source_type", "static_json"),
        "source_fingerprint": admitted_fixture["content_digest"],
        "engagement_id": admitted_fixture.get("engagement_id"),
        "engagement_instance_id": active_engagement_instance_id,
        "target_fingerprint": active_target_fingerprint,
        "endpoint_template": endpoint_template,
        "method": method,
        "parameter_names": parameter_names,
        "response_shape": response_shape,
        "authorization_hints": authorization_hints,
        "candidate_rationale": candidate_rationale,
        "trust_marker": TRUST_MARKER,
        "redaction_metadata": {"values_retained": False,
                               "categories": admitted_fixture.get("secret_scan_result", {}).get("categories", []),
                               "source": admitted_fixture.get("fixture_id"),
                               "c01_executable_shapes_stripped": c01_stripped_count},
        "defect_family_hint": route_shape.get("defect_family_hint", "IDOR"),
        "fixture_id": admitted_fixture.get("fixture_id"),
    }
    assert not (set(artifact) & AUTHORITY_FIELDS), "authority field leaked into artifact"
    return artifact


def build_intake_record(
    artifact: dict[str, Any], object_reference_plan: dict[str, Any],
    baseline_candidate_control_plan: dict[str, Any],
    rejection_register: Optional[RejectionRegister] = None,
) -> dict[str, Any]:
    """M2 Table 4-2 intake record. Framework-minted IDs; queued for validation."""
    reg = rejection_register or RejectionRegister()
    if not artifact.get("endpoint_template"):
        raise reg.reject(REJECT_MISSING_BINDING, "endpoint_template", artifact.get("source_fingerprint"))
    if not artifact.get("engagement_instance_id"):
        raise reg.reject(REJECT_MISSING_BINDING, "engagement_instance_id", artifact.get("source_fingerprint"))
    if not artifact.get("target_fingerprint"):
        raise reg.reject(REJECT_MISSING_BINDING, "target_fingerprint", artifact.get("source_fingerprint"))

    record = {
        "intake_schema_version": INTAKE_SCHEMA_VERSION,
        "intake_id": _mint("intk"),
        "source_artifact_ref": artifact["artifact_id"],
        "engagement_instance_id": artifact["engagement_instance_id"],
        "target_fingerprint": artifact["target_fingerprint"],
        "defect_family": artifact.get("defect_family_hint", "IDOR"),
        "endpoint_template": artifact["endpoint_template"],
        "allowed_method": artifact["method"],
        "object_reference_plan": dict(object_reference_plan or {}),
        "required_principal_aliases": [PRINCIPAL_USER_A, PRINCIPAL_USER_B],
        "baseline_candidate_control_plan": dict(baseline_candidate_control_plan or {}),
        "status": STATUS_QUEUED,
        "trust_marker": TRUST_MARKER,
        "advisory_kwargs": {"distinct_actor": True, "independent_negative_control": True},
    }
    record["dedupe_key"] = compute_dedupe_key(
        record["engagement_instance_id"], record["target_fingerprint"],
        record["defect_family"], record["endpoint_template"],
        record["allowed_method"], record["object_reference_plan"])
    assert not (set(record) & AUTHORITY_FIELDS), "authority field leaked into intake record"
    return record
