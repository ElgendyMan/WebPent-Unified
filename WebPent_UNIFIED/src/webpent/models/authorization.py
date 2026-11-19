# src/webpent/models/authorization.py
"""Structured, tamper-evident Authorization Manifest (CANONICAL_PHASE_REGISTRY M2).

Part 4 §4 replaces the free-text ``--authorization`` pointer with a
structured manifest whose integrity can be verified and whose material
fields cannot drift silently. This module is that manifest:

* **Structured** — a versioned pydantic model (``extra="forbid"``): the
  engagement identity (``client_id`` + ``engagement_id`` — the same
  isolation root ``models/contracts.py::EngagementContract`` enforces),
  the operator, the written-authorization reference, the authorized
  origins, optional excluded hosts and path rules, and the validity
  window.
* **Tamper-evident** — ``manifest_sha256`` is the sha256 of the
  canonical JSON of every OTHER field. The loader recomputes the digest
  and refuses the document on ANY mismatch, so a flipped byte in an
  origin, a silently extended expiry, or a swapped reference cannot
  pass unnoticed. The digest also becomes the stable identifier later
  phases bind approvals to (M9: an approval is bound to the manifest;
  a material change voids it).
* **Fail-closed** — every failure mode (missing file, bad JSON, wrong
  schema version, placeholder reference, digest mismatch, expired
  window, out-of-scope origin, excluded host) raises
  :class:`AuthorizationManifestError` with an operator-readable reason.
  There is no "unknown → proceed" path.

The free-text ``--authorization`` value survives as the operator's
pointer INTO the manifest: it must equal the manifest's
``authorization_reference`` byte-for-byte, which keeps the existing
command surface while making the reference verifiable instead of
self-asserted.

No network, no filesystem beyond the manifest file the operator hands
us. Placeholder detection deliberately echoes the H-2 contract (the
M1-A `.env.example` CHANGE-ME rule): a manifest whose reference still
says CHANGE-ME is not an authorization.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

MANIFEST_SCHEMA_VERSION = "webpent-authorization-manifest-v1"

#: The sha256 field itself is excluded from the canonical payload — it
#: is the digest OF the payload, not part of it.
_DIGEST_FIELD = "manifest_sha256"

#: Placeholder reference patterns (H-2 echo). A manifest whose
#: authorization_reference still carries a template placeholder is a
#: template, not an authorization.
_PLACEHOLDER_MARKERS = (
    "change-me",
    "changeme",
    "placeholder",
    "xxx",
    "todo",
    "your-",
    "example-token",
    "insert-",
    "<",
    ">",
)

_DEFAULT_PORTS = {"http": "80", "https": "443"}


class AuthorizationManifestError(ValueError):
    """Raised with a specific, operator-readable refusal reason."""


def normalize_origin(url: str) -> str:
    """Origin of a URL: scheme://host[:port], userinfo stripped.

    Host case normalized to lowercase (RFC 3986 §3.2.2) and the scheme's
    default port dropped, so ``https://LAB.Example:443`` and
    ``https://lab.example`` are one origin. Returns ``""`` for anything
    that is not an absolute HTTP(S) URL — callers treat that as a refusal.
    """
    parts = urlsplit(str(url or "").strip())
    if parts.scheme.lower() not in {"http", "https"} or not parts.netloc:
        return ""
    netloc = parts.netloc.rpartition("@")[2].lower()
    if not netloc:
        return ""
    host, sep, port = netloc.partition(":")
    if sep and port == _DEFAULT_PORTS.get(parts.scheme.lower(), ""):
        netloc = host
    return f"{parts.scheme.lower()}://{netloc}"


def _looks_like_placeholder(reference: str) -> bool:
    lowered = str(reference or "").strip().lower()
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def _parse_datetime(value: Any, field_name: str) -> datetime | None:
    if value is None or value == "":
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise AuthorizationManifestError(
            f"authorization manifest field {field_name!r} is not an ISO datetime: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _normalize_origin_list(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        raise AuthorizationManifestError(
            f"authorization manifest field {field_name!r} must be a URL or list of URLs"
        )
    origins: list[str] = []
    for item in value:
        origin = normalize_origin(str(item))
        if not origin:
            raise AuthorizationManifestError(
                f"authorization manifest field {field_name!r} contains an entry that "
                f"is not an absolute http(s) URL: {item!r}"
            )
        origins.append(origin)
    return tuple(origins)


class AuthorizationManifest(BaseModel):
    """One engagement's structured authorization — the M2 release gate."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = MANIFEST_SCHEMA_VERSION
    client_id: str = Field(..., min_length=1)
    engagement_id: str = Field(..., min_length=1)
    operator: str = Field(..., min_length=1)
    authorization_reference: str = Field(..., min_length=1)
    authorized_origins: tuple[str, ...] = Field(..., min_length=1)
    excluded_hosts: tuple[str, ...] = Field(default_factory=tuple)
    include_paths: tuple[str, ...] = Field(default_factory=tuple)
    exclude_paths: tuple[str, ...] = Field(default_factory=tuple)
    not_before: datetime | None = None
    expires_at: datetime | None = None
    notes: str = ""
    manifest_sha256: str

    @model_validator(mode="after")
    def _validate_shapes(self) -> "AuthorizationManifest":
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise AuthorizationManifestError(
                f"unsupported manifest schema_version {self.schema_version!r} "
                f"(expected {MANIFEST_SCHEMA_VERSION!r})"
            )
        if _looks_like_placeholder(self.authorization_reference):
            raise AuthorizationManifestError(
                "authorization_reference still carries a placeholder marker — "
                "a manifest template is not an authorization (H-2 contract)"
            )
        # excluded_hosts are host names, not origins — normalize loosely.
        hosts = []
        for item in self.excluded_hosts:
            host = str(item or "").strip().lower().rstrip(".")
            if not host:
                raise AuthorizationManifestError("excluded_hosts contains an empty entry")
            hosts.append(host)
        object.__setattr__(self, "excluded_hosts", tuple(hosts))
        for field_name in ("include_paths", "exclude_paths"):
            paths = getattr(self, field_name)
            for path in paths:
                if not str(path).startswith("/"):
                    raise AuthorizationManifestError(
                        f"{field_name} entries must start with '/': {path!r}"
                    )
        return self

    # ------------------------------------------------------------------
    # Tamper evidence
    # ------------------------------------------------------------------

    def canonical_payload(self) -> dict[str, Any]:
        """Every field EXCEPT the digest, canonically ordered."""
        payload = self.model_dump(mode="json")
        payload.pop(_DIGEST_FIELD, None)
        return payload

    def computed_digest(self) -> str:
        canonical = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def verify_integrity(self) -> str:
        """Recompute and compare the digest; return it on success.

        Fail-closed: a mismatch raises with both digests so the operator
        can see WHAT diverged. This is the check that makes the manifest
        tamper-evident rather than merely structured.
        """
        computed = self.computed_digest()
        if not self.manifest_sha256 or computed != self.manifest_sha256:
            raise AuthorizationManifestError(
                "authorization manifest FAILED its integrity check "
                f"(declared sha256 {self.manifest_sha256!r} != computed {computed!r}) "
                "— the document was modified after signing or is corrupted"
            )
        return computed

    # ------------------------------------------------------------------
    # Authorization decisions
    # ------------------------------------------------------------------

    def covers_origin(self, target_url: str) -> tuple[bool, str]:
        """Origin-level coverage check (excluded hosts win)."""
        origin = normalize_origin(target_url)
        if not origin:
            return False, f"target URL has no usable origin: {target_url!r}"
        host = urlsplit(origin).hostname or ""
        if host and host in self.excluded_hosts:
            return False, f"target host {host} is explicitly excluded by the manifest"
        if origin not in self.authorized_origins:
            entries = "entry" if len(self.authorized_origins) == 1 else "entries"
            return (
                False,
                f"target origin {origin} is outside the manifest's authorized origins "
                f"({len(self.authorized_origins)} {entries})",
            )
        return True, "covered"

    def validity_error(self, now: datetime | None = None) -> str | None:
        """Return a refusal reason when the manifest is not valid NOW."""
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if self.not_before is not None and current < self.not_before:
            return (
                f"manifest is not valid before {self.not_before.isoformat()} "
                f"(now {current.isoformat()})"
            )
        if self.expires_at is not None and current >= self.expires_at:
            return (
                f"manifest {self.authorization_reference} expired at "
                f"{self.expires_at.isoformat()}"
            )
        return None

    def as_redacted_dict(self) -> dict[str, Any]:
        """Checkpoint/report-safe projection (counts and digests, no prose)."""
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "client_id": self.client_id,
            "operator": self.operator,
            "authorization_reference": self.authorization_reference,
            "manifest_sha256": self.manifest_sha256,
            "authorized_origin_count": len(self.authorized_origins),
            "excluded_host_count": len(self.excluded_hosts),
            "include_path_count": len(self.include_paths),
            "exclude_path_count": len(self.exclude_paths),
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class AuthorizationDecision(BaseModel):
    """Typed outcome of checking one target against one manifest."""

    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str
    manifest_sha256: str = ""
    engagement_id: str = ""
    target_origin: str = ""


def sign_manifest_document(fields: dict[str, Any]) -> dict[str, Any]:
    """Build the canonical signed manifest document from operator fields.

    The digest is computed over the CANONICAL form the loader reconstructs
    (the full model with defaults filled), so signing and verification are
    self-consistent: operators never hand-compute the sha256. Unknown keys
    are refused here too (``extra="forbid"`` at the model level would catch
    them only after the digest existed).
    """
    fields = dict(fields or {})
    if fields.get("schema_version") is None:
        fields["schema_version"] = MANIFEST_SCHEMA_VERSION
    try:
        probe = AuthorizationManifest(
            manifest_sha256="0" * 64,
            authorized_origins=_normalize_origin_list(
                fields.get("authorized_origins") or [], "authorized_origins"
            ),
            **{k: v for k, v in fields.items() if k != "authorized_origins"},
        )
    except AuthorizationManifestError:
        raise
    except ValidationError as exc:
        raise AuthorizationManifestError(
            f"authorization manifest fields are invalid: {exc}"
        ) from exc
    document = probe.model_dump(mode="json")
    document.pop(_DIGEST_FIELD, None)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    document[_DIGEST_FIELD] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return document


def load_authorization_manifest(path: str | Path) -> AuthorizationManifest:
    """Parse, digest-verify and return the manifest (fail-closed)."""
    file_path = Path(path)
    if not file_path.is_file():
        raise AuthorizationManifestError(f"authorization manifest not found: {file_path}")
    try:
        document = json.loads(file_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise AuthorizationManifestError(
            f"authorization manifest is not readable JSON: {file_path} ({exc})"
        ) from exc
    if not isinstance(document, dict):
        raise AuthorizationManifestError("authorization manifest must be a JSON object")

    version = str(document.get("schema_version") or "")
    if version != MANIFEST_SCHEMA_VERSION:
        raise AuthorizationManifestError(
            f"unsupported manifest schema_version {version!r} "
            f"(expected {MANIFEST_SCHEMA_VERSION!r})"
        )
    required = ("client_id", "engagement_id", "operator", "authorization_reference", "manifest_sha256")
    missing = [name for name in required if not str(document.get(name) or "").strip()]
    if missing:
        raise AuthorizationManifestError(
            "authorization manifest is missing required field(s): " + ", ".join(missing)
        )
    if not document.get("authorized_origins"):
        raise AuthorizationManifestError(
            "authorization manifest field 'authorized_origins' resolved to no usable "
            "origins; an empty manifest authorizes nothing"
        )

    try:
        manifest = AuthorizationManifest(
            schema_version=version,
            client_id=str(document["client_id"]).strip(),
            engagement_id=str(document["engagement_id"]).strip(),
            operator=str(document["operator"]).strip(),
            authorization_reference=str(document["authorization_reference"]).strip(),
            authorized_origins=_normalize_origin_list(
                document["authorized_origins"], "authorized_origins"
            ),
            excluded_hosts=tuple(str(h) for h in (document.get("excluded_hosts") or ())),
            include_paths=tuple(str(p) for p in (document.get("include_paths") or ())),
            exclude_paths=tuple(str(p) for p in (document.get("exclude_paths") or ())),
            not_before=_parse_datetime(document.get("not_before"), "not_before"),
            expires_at=_parse_datetime(document.get("expires_at"), "expires_at"),
            notes=str(document.get("notes") or ""),
            manifest_sha256=str(document["manifest_sha256"]).strip(),
        )
    except AuthorizationManifestError:
        raise
    except (ValidationError, TypeError, ValueError) as exc:  # shape errors → typed refusal
        raise AuthorizationManifestError(
            f"authorization manifest is not a valid v1 document: {exc}"
        ) from exc

    manifest.verify_integrity()
    return manifest


def authorize_target(
    manifest: AuthorizationManifest,
    target_url: str,
    *,
    authorization_reference: str | None = None,
    now: datetime | None = None,
) -> AuthorizationDecision:
    """Check one target (and optionally the free-text ref) against the manifest.

    Fail-closed decision with an exact reason on every refusal. When
    ``authorization_reference`` is supplied it must EQUAL the manifest's
    reference — the free-text pointer has to point at THIS manifest.
    """
    digest = manifest.verify_integrity()

    if authorization_reference is not None:
        provided = str(authorization_reference or "").strip()
        if not provided:
            return AuthorizationDecision(
                allowed=False,
                reason="authorization reference is empty; the manifest requires the "
                "operator's written-authorization pointer",
                manifest_sha256=digest,
                engagement_id=manifest.engagement_id,
            )
        if provided != manifest.authorization_reference:
            return AuthorizationDecision(
                allowed=False,
                reason=(
                    "authorization reference mismatch: the --authorization value does "
                    "not match the manifest's authorization_reference "
                    f"({manifest.authorization_reference!r})"
                ),
                manifest_sha256=digest,
                engagement_id=manifest.engagement_id,
            )

    validity = manifest.validity_error(now=now)
    if validity is not None:
        return AuthorizationDecision(
            allowed=False,
            reason=validity,
            manifest_sha256=digest,
            engagement_id=manifest.engagement_id,
        )

    covered, reason = manifest.covers_origin(target_url)
    if not covered:
        return AuthorizationDecision(
            allowed=False,
            reason=reason,
            manifest_sha256=digest,
            engagement_id=manifest.engagement_id,
        )

    return AuthorizationDecision(
        allowed=True,
        reason="authorized",
        manifest_sha256=digest,
        engagement_id=manifest.engagement_id,
        target_origin=normalize_origin(target_url),
    )


def require_authorization_manifest(
    target_url: str,
    manifest_path: str | Path,
    *,
    authorization_reference: str | None = None,
    now: datetime | None = None,
) -> tuple[AuthorizationManifest, AuthorizationDecision]:
    """Load, verify and check — the single entry point the CLI uses.

    Raises :class:`AuthorizationManifestError` on every refusal so the
    command stops before any state is built or any request is planned.
    """
    manifest = load_authorization_manifest(manifest_path)
    decision = authorize_target(
        manifest,
        target_url,
        authorization_reference=authorization_reference,
        now=now,
    )
    if not decision.allowed:
        raise AuthorizationManifestError(decision.reason)
    return manifest, decision


__all__ = [
    "AuthorizationDecision",
    "AuthorizationManifest",
    "AuthorizationManifestError",
    "MANIFEST_SCHEMA_VERSION",
    "authorize_target",
    "load_authorization_manifest",
    "normalize_origin",
    "require_authorization_manifest",
    "sign_manifest_document",
]
