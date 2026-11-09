"""Evidence-first multi-identity BAC/IDOR primitives.

The module is intentionally transport-light: it accepts identity profiles and
observed resource candidates, performs only read-only requests, and returns
sanitised observations suitable for LangGraph state.  It never returns raw
Cookie/Authorization values and never treats a URL permutation as proof by
itself.
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urlunparse

from webpent.models.evidence import RelationalEvidence

logger = logging.getLogger(__name__)

_SENSITIVE_HEADER_RE = re.compile(
    r"^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|"
    r"x-auth-token|.*secret.*|.*password.*|.*token.*)$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class IdentityProfile:
    """Runtime identity context used for a read-only differential probe."""

    name: str
    role: str = "unknown"
    cookies: dict[str, str] = field(default_factory=dict, repr=False)
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    owned_object_ids: frozenset[str] = frozenset()
    owned_urls: frozenset[str] = frozenset()
    metadata: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def public_metadata(self) -> dict[str, Any]:
        """Return report-safe identity metadata; no credentials are included."""
        return {
            "identity": self.name,
            "role": self.role,
            "owned_object_ids_count": len(self.owned_object_ids),
            "owned_urls_count": len(self.owned_urls),
            "metadata": {
                k: v
                for k, v in self.metadata.items()
                if not _SENSITIVE_HEADER_RE.match(str(k))
                and k not in {"cookies", "headers", "authorization"}
            },
        }


def _clean_label(value: Any, fallback: str) -> str:
    label = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(value or "")).strip("-")
    return label[:80] or fallback


def _string_set(value: Any) -> frozenset[str]:
    if isinstance(value, (list, tuple, set, frozenset)):
        return frozenset(str(item) for item in value if item is not None)
    if value is None:
        return frozenset()
    return frozenset({str(value)})


def _safe_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if v not in (None, "")}


def cookies_from_auth_state(auth_state: Any) -> dict[str, str]:
    """Extract validated runtime cookies from the canonical auth-state shape.

    ``auth_node`` exposes cookies in two intentionally different forms:
    ``session_cookies`` is a request-ready mapping, while ``auth_state`` keeps
    Playwright-style cookie records for browser consumers.  This helper makes
    the relationship explicit without treating an unvalidated or malformed
    auth state as authenticated.
    """
    if not isinstance(auth_state, dict) or auth_state.get("validated") is not True:
        return {}
    raw = auth_state.get("cookies")
    if isinstance(raw, dict):
        return _safe_dict(raw)
    if not isinstance(raw, list):
        return {}
    cookies: dict[str, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        value = item.get("value")
        if name not in (None, "") and value not in (None, ""):
            cookies[str(name)] = str(value)
    return cookies


def normalise_identity_profiles(
    raw: Any,
    *,
    fallback_cookies: dict[str, str] | None = None,
) -> list[IdentityProfile]:
    """Convert state/config identity material into deterministic profiles.

    Accepted shapes are a mapping ``name -> profile`` or a list of profile
    mappings.  A legacy single ``session_cookies`` dict becomes the explicit
    ``session-1`` profile, preserving backward compatibility while making the
    coverage limitation visible to the caller.
    """
    entries: list[tuple[str, Any]] = []
    if isinstance(raw, dict):
        entries = [(str(name), value) for name, value in raw.items()]
    elif isinstance(raw, list):
        for index, value in enumerate(raw, start=1):
            if isinstance(value, dict):
                identity_name = value.get("name") or value.get("identity") or f"identity-{index}"
                entries.append((str(identity_name), value))

    profiles: list[IdentityProfile] = []
    seen: set[str] = set()
    for index, (name, value) in enumerate(entries, start=1):
        data = value if isinstance(value, dict) else {}
        label = _clean_label(data.get("name") or data.get("identity") or name, f"identity-{index}")
        if label in seen:
            label = f"{label}-{index}"
        seen.add(label)
        profiles.append(
            IdentityProfile(
                name=label,
                role=str(data.get("role") or data.get("privilege") or "unknown"),
                cookies=_safe_dict(data.get("cookies") or data.get("session_cookies")),
                headers=_safe_dict(data.get("headers")),
                owned_object_ids=_string_set(data.get("owned_object_ids") or data.get("owned_ids")),
                owned_urls=_string_set(data.get("owned_urls")),
                metadata=data.get("metadata") if isinstance(data.get("metadata"), dict) else {},
            )
        )

    if not profiles and fallback_cookies:
        profiles.append(
            IdentityProfile(
                name="session-1",
                role="authenticated",
                cookies=_safe_dict(fallback_cookies),
            )
        )
    return profiles


def extract_object_id(url: str) -> str | None:
    """Extract a stable path/query object identifier for ownership matching."""
    parsed = urlparse(url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if path_parts:
        candidate = path_parts[-1]
        if re.fullmatch(r"[A-Za-z0-9_-]{1,128}", candidate):
            return candidate
    return None


def profile_owns_resource(profile: IdentityProfile, url: str, object_id: str | None = None) -> bool:
    """Return whether explicit observed metadata associates a resource to profile."""
    canonical = url.rstrip("/")
    return canonical in {item.rstrip("/") for item in profile.owned_urls} or bool(
        object_id and object_id in profile.owned_object_ids
    )


def _cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{key}={value}" for key, value in cookies.items() if value)


def _sanitised_headers(headers: dict[str, Any]) -> dict[str, str]:
    return {
        str(key).lower(): "[REDACTED]" if _SENSITIVE_HEADER_RE.match(str(key)) else str(value)[:256]
        for key, value in headers.items()
    }


def response_fingerprint(
    status_code: int,
    content: bytes | str = b"",
    headers: dict[str, Any] | None = None,
) -> str:
    """Create a non-reversible response fingerprint for differential evidence."""
    body = content.encode(errors="replace") if isinstance(content, str) else bytes(content or b"")
    material = f"{status_code}|{len(body)}|{hashlib.sha256(body).hexdigest()}|".encode()
    if headers:
        header_items = sorted((str(k).lower(), str(v)[:128]) for k, v in headers.items())
        material += repr(header_items).encode()
    return hashlib.sha256(material).hexdigest()


def target_fingerprint(url: str) -> str:
    """Return a stable, non-reversible fingerprint for the declared target URL."""
    parsed = urlparse(str(url or ""))
    canonical = urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            "",
            "",
            "",
        )
    )
    return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()}"


def sanitise_probe_result(
    *,
    profile: IdentityProfile,
    url: str,
    status_code: int,
    content_length: int,
    response_headers: dict[str, Any] | None = None,
    body_hash: str | None = None,
    request_digest: str | None = None,
    response_digest: str | None = None,
    target_backed: bool | None = None,
    observation_role: str | None = None,
    target_url: str | None = None,
    target_fingerprint_value: str | None = None,
) -> dict[str, Any]:
    """Build report-safe observation data from a probe result.

    The optional transport provenance fields are intentionally additive so old
    tuple-based test probes remain valid but can never satisfy strict proof.
    """
    headers = response_headers or {}
    safe_headers = repr(sorted(_sanitised_headers(headers).items()))
    fingerprint_material = f"{status_code}|{content_length}|{body_hash or ''}|{safe_headers}"
    result: dict[str, Any] = {
        "identity": profile.name,
        "role": profile.role,
        "url": url,
        "status_code": int(status_code),
        "content_length": int(max(0, content_length)),
        "accessible": 200 <= int(status_code) < 300 and int(content_length) > 0,
        "response_fingerprint": hashlib.sha256(fingerprint_material.encode()).hexdigest(),
        "headers": _sanitised_headers(headers),
    }
    if request_digest:
        result["request_digest"] = str(request_digest)
    if response_digest:
        result["response_digest"] = str(response_digest)
    if target_backed is not None:
        result["target_backed"] = bool(target_backed)
    if observation_role:
        result["observation_role"] = str(observation_role)
    if target_fingerprint_value:
        result["target_fingerprint"] = str(target_fingerprint_value)
    elif target_url:
        result["target_fingerprint"] = target_fingerprint(target_url)
    return result


def build_relational_evidence(
    observations: Iterable[dict[str, Any]],
    *,
    owner_identity: str | None = None,
    object_id: str | None = None,
) -> list[dict[str, Any]]:
    """Create pairwise identity-to-resource comparison edges.

    The edge is an observation, not a finding.  Confirmation requires an
    explicit owner identity and a reproducible success for a different identity.
    """
    rows = list(observations)
    edges: list[dict[str, Any]] = []
    for left in rows:
        for right in rows:
            if left is right or left.get("identity") == right.get("identity"):
                continue
            if str(left.get("identity")) > str(right.get("identity")):
                continue
            differential = bool(left.get("accessible")) != bool(right.get("accessible"))
            # Keep the edge even when access is equal: relational evidence
            # must document both the positive and the negative comparison.
            evidence_refs = [
                f"identity:{left.get('identity')}:response:{left.get('response_fingerprint')}",
                f"identity:{right.get('identity')}:response:{right.get('response_fingerprint')}",
            ]
            # The ID is deterministic for the same pair of redacted response
            # fingerprints, which prevents duplicate edges on checkpoint
            # resume while retaining the legacy relational fields.
            relation_key = "|".join(
                [
                    "identity_resource_access",
                    str(left.get("identity")),
                    str(right.get("identity")),
                    str(left.get("response_fingerprint")),
                    str(right.get("response_fingerprint")),
                ]
            )
            relation = RelationalEvidence(
                id=f"rel_{hashlib.sha256(relation_key.encode()).hexdigest()[:32]}",
                type="identity_resource_access",
                relation_type="identity_resource_access",
                source_id=f"identity:{left.get('identity')}",
                target_id=f"identity:{right.get('identity')}",
                resource_url=left.get("url") or right.get("url"),
                object_id=object_id,
                from_identity=left.get("identity"),
                to_identity=right.get("identity"),
                from_accessible=bool(left.get("accessible")),
                to_accessible=bool(right.get("accessible")),
                owner_identity=owner_identity,
                differential=differential,
                status="observed",
                confidence_level="Needs Human Review",
                evidence_refs=evidence_refs,
            )
            edges.append(relation.model_dump(mode="json", exclude_none=True))
    return edges


def assess_access_control(
    observations: list[dict[str, Any]],
    *,
    owner_identity: str | None = None,
) -> dict[str, Any]:
    """Classify a differential without promoting ambiguous evidence."""
    accessible = [row for row in observations if row.get("accessible")]
    non_anonymous = {
        row.get("identity")
        for row in observations
        if row.get("identity") not in {None, "anonymous"}
    }
    if owner_identity is None and len(non_anonymous) < 2:
        return {
            "status": "coverage_gap",
            "confidence_level": "Needs Human Review",
            "reason": (
                "Two authenticated identities are required for cross-owner "
                "authorization comparison."
            ),
        }
    if not owner_identity:
        if len(accessible) >= 2:
            return {
                "status": "needs_review",
                "confidence_level": "Needs Human Review",
                "reason": (
                    "Multiple identities can read the resource, but ownership "
                    "provenance is not explicit."
                ),
            }
        return {
            "status": "inconclusive",
            "confidence_level": "Inconclusive",
            "reason": "No explicit owner relationship was observed.",
        }

    owner_access = any(
        row.get("identity") == owner_identity and row.get("accessible")
        for row in observations
    )
    foreign_access = any(
        row.get("identity") != owner_identity and row.get("accessible")
        for row in observations
    )
    negative_control_complete = any(
        row.get("identity") not in {None, owner_identity}
        and not row.get("accessible")
        and (
            int(row.get("status_code") or 0) in {401, 403}
            or (
                row.get("identity") == "anonymous"
                and 300 <= int(row.get("status_code") or 0) < 400
            )
        )
        for row in observations
    )
    if owner_access and foreign_access and negative_control_complete:
        return {
            "status": "confirmed",
            "confidence_level": "Tool-Confirmed",
            "negative_control_complete": True,
            # M1-B (E-1): explicit writer provenance for the model-level
            # Tool-Confirmed proof requirement (models/findings.py).
            "tool_confirmed_by": "bac.identity_differential_gate",
            "reason": (
                "The owner and a different identity both received reproducible "
                "successful access, while a separate non-owner control was denied."
            ),
        }
    if owner_access and foreign_access:
        return {
            "status": "needs_review",
            "confidence_level": "Needs Human Review",
            "negative_control_complete": False,
            "reason": (
                "Owner and foreign access both succeeded, but a denied non-owner "
                "negative control was not observed."
            ),
        }
    if owner_access and not foreign_access:
        return {
            "status": "denied_as_expected",
            "confidence_level": "Clean",
            "reason": (
                "The owner could access the resource while other tested "
                "identities could not."
            ),
        }
    return {
        "status": "inconclusive",
        "confidence_level": "Needs Human Review",
        "reason": "The explicit owner did not produce a successful baseline response.",
    }


ProbeCallable = Callable[[str, IdentityProfile], dict[str, Any]]

__all__ = [
    "IdentityProfile",
    "ProbeCallable",
    "assess_access_control",
    "build_relational_evidence",
    "cookies_from_auth_state",
    "extract_object_id",
    "normalise_identity_profiles",
    "profile_owns_resource",
    "response_fingerprint",
    "sanitise_probe_result",
]
