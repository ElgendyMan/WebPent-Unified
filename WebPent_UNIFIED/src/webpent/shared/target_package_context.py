"""Redaction-safe Target Package v2 admission for WebPent.

The package is authorization metadata, not an execution command.  This module
performs deterministic validation only and never performs provider/target I/O.
Live credentials, cookies, tokens and raw provider responses are rejected from
the state projection.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_SAFE_METADATA_KEYS = frozenset({"secret_scan"})

_SECRET_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "cookie",
    "credential",
    "private_key",
    "authorization_header",
)


class TargetPackageAdmissionError(ValueError):
    """Raised when package metadata cannot safely authorize an engagement."""


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _secret_paths(value: Any, path: str = "$") -> list[str]:
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key).lower()
            child_path = f"{path}.{key}"
            if key_text in _SAFE_METADATA_KEYS:
                continue
            if any(part in key_text for part in _SECRET_KEY_PARTS):
                found.append(child_path)
            else:
                found.extend(_secret_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_secret_paths(child, f"{path}[{index}]"))
    return found


def _parse_expiry(value: Any) -> datetime:
    if not value:
        raise TargetPackageAdmissionError("package_expiry_missing")
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
    except (TypeError, ValueError) as exc:
        raise TargetPackageAdmissionError("package_expiry_invalid") from exc


@dataclass(frozen=True)
class TargetPackageContext:
    package_id: str
    package_sha256: str
    schema_version: str
    provider: str
    program_id: str
    program_handle: str
    program_name: str
    scope_status: str
    scope_digest: str
    policy_digest: str
    capability_digest: str
    source_sha256: str
    signature_state: str
    scope_rules: tuple[Mapping[str, Any], ...]
    policy_constraints: Mapping[str, Any]
    capability_profile: Mapping[str, Any]
    selection: Mapping[str, Any]
    expires_at: str
    revocation_state: str

    def as_state(self) -> dict[str, Any]:
        """Return the only projection allowed to enter checkpoint state."""
        return {
            "package_id": self.package_id,
            "package_sha256": self.package_sha256,
            "status": "ready",
            "target_package_status": "ready",
            "schema_version": self.schema_version,
            "provider": self.provider,
            "program_id": self.program_id,
            "program_handle": self.program_handle,
            "program_name": self.program_name,
            "scope_status": self.scope_status,
            "scope_digest": self.scope_digest,
            "policy_digest": self.policy_digest,
            "capability_digest": self.capability_digest,
            "source_sha256": self.source_sha256,
            "signature_state": self.signature_state,
            "scope_rules": [dict(rule) for rule in self.scope_rules],
            "policy_constraints": dict(self.policy_constraints),
            "capability_profile": dict(self.capability_profile),
            "selection": dict(self.selection),
            "expires_at": self.expires_at,
            "revocation_state": self.revocation_state,
        }


def _package_content_digest(package: Mapping[str, Any]) -> str:
    """Recompute bbscout's canonical digest without trusting integrity fields."""
    unsigned = deepcopy(dict(package))
    integrity = dict(unsigned.get("integrity") or {})
    integrity.pop("content_sha256", None)
    integrity.pop("detached_signature", None)
    unsigned["integrity"] = integrity
    return _canonical_digest(unsigned)


def _is_sha256(value: Any) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text.lower())


def admit_target_package(
    package: Mapping[str, Any],
    *,
    now: datetime | None = None,
    require_signature: bool = False,
) -> TargetPackageContext:
    """Validate and project a package without retaining raw package content."""
    if _secret_paths(package):
        raise TargetPackageAdmissionError("package_contains_secret_like_fields")
    schema_version = str(package.get("schema_version") or package.get("package_version") or "")
    if schema_version != "target-package.schema.v2":
        raise TargetPackageAdmissionError("unsupported_package_schema")
    package_id = str(package.get("package_id") or "").strip()
    integrity = package.get("integrity")
    if not package_id or not isinstance(integrity, Mapping):
        raise TargetPackageAdmissionError("package_identity_or_integrity_missing")
    package_sha256 = str(integrity.get("content_sha256") or "")
    if not _is_sha256(package_sha256):
        raise TargetPackageAdmissionError("package_digest_invalid")
    if _package_content_digest(package) != package_sha256:
        raise TargetPackageAdmissionError("content_digest_mismatch")
    authorization = package.get("authorization")
    policy = package.get("policy")
    scope = package.get("scope")
    capability_profile = package.get("capability_profile")
    selection = package.get("selection")
    source = package.get("source")
    if not all(
        isinstance(item, Mapping)
        for item in (authorization, policy, scope, capability_profile, selection, source)
    ):
        raise TargetPackageAdmissionError("package_sections_missing")
    if not bool(authorization.get("user_confirmed")):
        raise TargetPackageAdmissionError("user_confirmation_missing")
    if bool(authorization.get("revoked")) or authorization.get("revocation_state") == "revoked":
        raise TargetPackageAdmissionError("package_revoked")
    expires_at = _parse_expiry(
        authorization.get("package_expires_at") or authorization.get("expiry")
    )
    if expires_at <= (now or datetime.now(UTC)):
        raise TargetPackageAdmissionError("package_expired")
    if scope.get("status") != "ready":
        raise TargetPackageAdmissionError("scope_not_ready")
    if not bool(policy.get("policy_present")):
        raise TargetPackageAdmissionError("policy_missing")
    source_sha256 = str(source.get("source_response_sha256") or "")
    if not _is_sha256(source_sha256):
        raise TargetPackageAdmissionError("source_digest_invalid")
    signature_state = str(integrity.get("signature_state") or "missing")
    if signature_state not in {"verified", "unsigned-local-mvp"}:
        raise TargetPackageAdmissionError("integrity_signature_invalid")
    if require_signature and signature_state != "verified":
        raise TargetPackageAdmissionError("detached_signature_not_verified")
    if package.get("redaction", {}).get("secret_scan") != "passed":
        raise TargetPackageAdmissionError("redaction_not_passed")
    return TargetPackageContext(
        package_id=package_id,
        package_sha256=package_sha256,
        schema_version=schema_version,
        provider=str(package.get("provider") or ""),
        program_id=str(
            package.get("program_id")
            or package.get("program", {}).get("stable_program_id")
            or ""
        ),
        program_handle=str(
            package.get("program_handle") or package.get("program", {}).get("handle") or ""
        ),
        program_name=str(
            package.get("program_name") or package.get("program", {}).get("name") or ""
        ),
        scope_status=str(scope.get("status")),
        scope_digest=_canonical_digest(scope),
        policy_digest=_canonical_digest(policy),
        capability_digest=_canonical_digest(capability_profile),
        source_sha256=source_sha256,
        signature_state=signature_state,
        scope_rules=tuple(
            dict(rule)
            for rule in list(scope.get("normalized_rules") or [])
            if isinstance(rule, Mapping)
        ),
        policy_constraints={
            key: value
            for key, value in policy.items()
            if key in {
                "prohibited_actions",
                "required_headers",
                "rate_limits",
                "enforcement_state",
                "safe_harbor",
            }
        },
        capability_profile=dict(capability_profile),
        selection=dict(selection),
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
        revocation_state=str(authorization.get("revocation_state") or "active"),
    )


def package_continuity_kwargs(
    source: Mapping[str, Any] | TargetPackageContext | None,
) -> dict[str, str]:
    """Return only verifier-safe package identity and digest fields."""
    if source is None:
        return {}
    if isinstance(source, TargetPackageContext):
        values = {
            "target_package_id": source.package_id,
            "target_package_sha256": source.package_sha256,
            "target_package_scope_digest": source.scope_digest,
            "target_package_policy_digest": source.policy_digest,
        }
    else:
        values = {
            "target_package_id": (
                source.get("target_package_id") or source.get("package_id")
            ),
            "target_package_sha256": (
                source.get("target_package_sha256") or source.get("package_sha256")
            ),
            "target_package_scope_digest": (
                source.get("target_package_scope_digest")
                or source.get("scope_digest")
            ),
            "target_package_policy_digest": (
                source.get("target_package_policy_digest")
                or source.get("policy_digest")
            ),
        }
    return {key: str(value) for key, value in values.items() if value not in (None, "")}


def assert_package_continuity(
    context: TargetPackageContext,
    evidence: Mapping[str, Any],
) -> None:
    """Reject evidence/proof records whose package identity or digest drifts."""
    if str(evidence.get("target_package_id") or "") != context.package_id:
        raise TargetPackageAdmissionError("target_package_id_continuity_failure")
    if str(evidence.get("target_package_sha256") or "") != context.package_sha256:
        raise TargetPackageAdmissionError("target_package_digest_continuity_failure")
    if evidence.get("scope_digest") not in {None, context.scope_digest}:
        raise TargetPackageAdmissionError("scope_digest_continuity_failure")
    if evidence.get("policy_digest") not in {None, context.policy_digest}:
        raise TargetPackageAdmissionError("policy_digest_continuity_failure")
