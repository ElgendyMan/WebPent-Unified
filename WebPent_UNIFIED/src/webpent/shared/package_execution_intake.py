"""Trusted execution intake for bbscout Target Package v2.

This module is deliberately transport-neutral. It performs no target/provider I/O
and keeps the raw package transient: only the redacted projection and the
one-time engagement binding may cross the graph/checkpoint boundary.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from webpent.shared.engagement_factory import (
    EngagementAdmissionError,
    EngagementBinding,
    EngagementFactory,
)
from webpent.shared.target_package_context import TargetPackageContext

MAX_PACKAGE_BYTES = 512 * 1024
MAX_TRUST_KEYS = 32
MAX_KEY_ID_LENGTH = 128
MAX_PUBLIC_KEY_VALUE_LENGTH = 16 * 1024


class PackageExecutionIntakeError(ValueError):
    """Raised when an executable package handoff cannot be trusted."""


@dataclass(frozen=True)
class PackageExecutionIntake:
    """Redaction-safe result of package admission and lease binding."""

    binding: EngagementBinding

    @property
    def context(self) -> TargetPackageContext:
        return self.binding.context

    @property
    def projection(self) -> dict[str, Any]:
        return self.context.as_state()

    @property
    def binding_projection(self) -> dict[str, Any]:
        return self.binding.as_dict()


def load_json_mapping(path: str | Path, *, label: str, max_bytes: int) -> dict[str, Any]:
    """Load one bounded JSON object from a local operator-controlled file."""
    file_path = Path(path).expanduser()
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise PackageExecutionIntakeError(f"{label}_file_unreadable") from exc
    if size <= 0 or size > max_bytes:
        raise PackageExecutionIntakeError(f"{label}_file_size_exceeded")
    try:
        value = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PackageExecutionIntakeError(f"{label}_json_invalid") from exc
    if not isinstance(value, dict):
        raise PackageExecutionIntakeError(f"{label}_must_be_object")
    return value


def _reject_private_key_material(value: Any) -> None:
    text = value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)
    upper = text.upper()
    if "PRIVATE KEY" in upper or "BEGIN OPENSSH PRIVATE" in upper:
        raise PackageExecutionIntakeError("private_key_material_is_not_accepted")


def _normalize_public_key(value: Any) -> bytes | str:
    """Accept PEM, raw 32-byte material, hex, or explicit base64 public keys."""
    _reject_private_key_material(value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        if len(raw) != 32 and not raw.startswith(b"-----BEGIN PUBLIC KEY-----"):
            raise PackageExecutionIntakeError("public_key_material_invalid")
        return raw
    if not isinstance(value, str) or not value.strip():
        raise PackageExecutionIntakeError("public_key_material_invalid")
    text = value.strip()
    if len(text) > MAX_PUBLIC_KEY_VALUE_LENGTH:
        raise PackageExecutionIntakeError("public_key_material_too_large")
    if "-----BEGIN PUBLIC KEY-----" in text:
        return text
    candidate = text[7:] if text.lower().startswith("base64:") else text
    if len(candidate) == 64:
        try:
            raw = bytes.fromhex(candidate)
        except ValueError:
            raw = b""
        if len(raw) == 32:
            return raw
    try:
        raw = base64.b64decode(candidate.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError, binascii.Error):
        raw = b""
    if len(raw) == 32:
        return raw
    raise PackageExecutionIntakeError("public_key_material_invalid")


def normalize_trusted_public_keys(value: Mapping[str, Any]) -> dict[str, bytes | str]:
    """Validate a runtime trust map; package content never supplies trust roots."""
    if not isinstance(value, Mapping) or not value:
        raise PackageExecutionIntakeError("trusted_public_keys_required")
    if len(value) > MAX_TRUST_KEYS:
        raise PackageExecutionIntakeError("trusted_public_keys_limit_exceeded")
    normalized: dict[str, bytes | str] = {}
    for key_id, key_material in value.items():
        key_text = str(key_id).strip()
        if not key_text or len(key_text) > MAX_KEY_ID_LENGTH or any(
            char in key_text for char in "\r\n"
        ):
            raise PackageExecutionIntakeError("trusted_key_id_invalid")
        normalized[key_text] = _normalize_public_key(key_material)
    return normalized


def build_signature_verifier(trusted_public_keys: Mapping[str, Any]):
    """Build a real Ed25519 verifier from caller-supplied public trust roots."""
    normalized = normalize_trusted_public_keys(trusted_public_keys)
    try:
        from bbscout.signatures import verify_detached_signature
    except (ImportError, ModuleNotFoundError) as exc:
        raise PackageExecutionIntakeError("bbscout_signature_runtime_unavailable") from exc

    def verify(package: Mapping[str, Any]) -> None:
        verify_detached_signature(package, trusted_public_keys=normalized)

    return verify


def _validate_package_shape(package: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(package, Mapping):
        raise PackageExecutionIntakeError("target_package_must_be_object")
    try:
        encoded = json.dumps(
            dict(package), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PackageExecutionIntakeError("target_package_json_invalid") from exc
    if len(encoded) > MAX_PACKAGE_BYTES:
        raise PackageExecutionIntakeError("target_package_size_exceeded")
    return dict(package)


def validate_package_for_dispatch(
    package: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, Any],
) -> tuple[dict[str, Any], TargetPackageContext, str]:
    """Validate an executable handoff without mutating the lease database."""
    safe_package = _validate_package_shape(package)
    if not isinstance(confirmation, Mapping):
        raise PackageExecutionIntakeError("confirmation_required")
    verifier = build_signature_verifier(trusted_public_keys)
    # Reuse the factory's exact non-mutating checks without constructing a
    # SQLite connection. This validation path must not create files or leases.
    factory = object.__new__(EngagementFactory)
    factory.signature_verifier = verifier
    factory.clock = lambda: datetime.now(UTC)
    try:
        context, engagement_id = factory._admit_and_validate(safe_package, confirmation)
    except EngagementAdmissionError as exc:
        raise PackageExecutionIntakeError(str(exc)) from exc
    return safe_package, context, engagement_id


def admit_and_bind_package(
    package: Mapping[str, Any],
    confirmation: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, Any],
    lease_path: str | Path,
    allow_existing_binding: bool = False,
) -> PackageExecutionIntake:
    """Verify, admit, and consume once—or restore the exact existing binding."""
    safe_package = _validate_package_shape(package)
    if not isinstance(confirmation, Mapping):
        raise PackageExecutionIntakeError("confirmation_required")
    verifier = build_signature_verifier(trusted_public_keys)
    factory = EngagementFactory(lease_path, signature_verifier=verifier)
    try:
        if allow_existing_binding and safe_package.get("package_id"):
            existing = factory.get_binding(str(safe_package.get("package_id")))
            if existing is not None:
                binding = factory.restore_existing_binding(safe_package, confirmation)
            else:
                binding = factory.create_from_package(safe_package, confirmation)
        else:
            binding = factory.create_from_package(safe_package, confirmation)
    except EngagementAdmissionError as exc:
        raise PackageExecutionIntakeError(str(exc)) from exc
    return PackageExecutionIntake(binding=binding)


def verify_existing_binding_projection(
    binding_projection: Mapping[str, Any],
    *,
    lease_path: str | Path,
) -> dict[str, Any]:
    """Verify checkpoint binding continuity without raw package admission."""
    factory = EngagementFactory(lease_path)
    try:
        return factory.restore_binding_projection(binding_projection)
    except EngagementAdmissionError as exc:
        raise PackageExecutionIntakeError(str(exc)) from exc


def ensure_package_request_fields(
    package: Mapping[str, Any] | None,
    confirmation: Mapping[str, Any] | None,
    trusted_public_keys: Mapping[str, Any] | None,
) -> None:
    """Validate API-level presence and bounded shape without consuming a lease."""
    if package is None and confirmation is None and trusted_public_keys is None:
        return
    if package is None or confirmation is None or trusted_public_keys is None:
        raise PackageExecutionIntakeError(
            "target_package_confirmation_and_trust_map_are_required_together"
        )
    _validate_package_shape(package)
    if not isinstance(confirmation, Mapping):
        raise PackageExecutionIntakeError("confirmation_must_be_object")
    if not isinstance(trusted_public_keys, Mapping):
        raise PackageExecutionIntakeError("trusted_public_keys_must_be_object")
    if confirmation.get("user_confirmed") is not True:
        raise PackageExecutionIntakeError("explicit_user_confirmation_required")
    normalize_trusted_public_keys(trusted_public_keys)


__all__ = [
    "MAX_PACKAGE_BYTES",
    "PackageExecutionIntake",
    "PackageExecutionIntakeError",
    "admit_and_bind_package",
    "build_signature_verifier",
    "ensure_package_request_fields",
    "load_json_mapping",
    "normalize_trusted_public_keys",
    "validate_package_for_dispatch",
    "verify_existing_binding_projection",
]


# Keep the public helper's import-time contract explicit for static analyzers.
__all__ += ["EngagementBinding"]


# ``load_json_mapping`` is intentionally file-only; package values from HTTP
# requests use ``admit_and_bind_package``'s bounded mapping validation directly.
JSON_MAPPING_TYPE = dict[str, Any]
