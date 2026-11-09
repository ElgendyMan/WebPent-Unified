# src/webpent/utils/crypto.py
"""webpent.utils.crypto

V5 Sprint 11/14 — Cryptographic audit trail utilities.

V5 Sprint 14 P0: Replaced unkeyed SHA-256 with HMAC-SHA256 to prevent
hash substitution attacks. The HMAC key is ``Settings.audit_secret_key``,
which is validated at startup to prevent insecure defaults.

Provides HMAC-SHA256 hashing for evidence bundles and final reports so
that post-exploitation tampering can be detected AND the hash itself
cannot be forged without the secret key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def _compute_hmac(key: bytes, msg: bytes) -> str:
    """Portable HMAC-SHA256 that works on Python 3.8 through 3.13+.

    V9 FIX-1: ``hmac.new()`` is deprecated and removed in Python 3.13.
    The portable replacement is ``hmac.HMAC(key, msg, digestmod)``
    followed by ``.hexdigest()``. This helper centralises the call so
    both ``hash_evidence_bundle`` and ``hash_report`` use the same
    portable path.
    """
    return hmac.HMAC(key, msg, hashlib.sha256).hexdigest()


def _get_audit_key() -> bytes:
    """Retrieve the HMAC secret key from settings.

    V5 Sprint 14: Uses ``Settings.audit_secret_key`` (validated to be
    >= 32 chars by the Pydantic field_validator in settings.py).

    Dev-mode fallback (fix): the out-of-the-box dev/lab configuration
    leaves ``audit_secret_key`` empty (``Field(default="")``). Before this
    fix, ``_get_audit_key()`` returned ``b""`` in that case, so
    ``_compute_authenticity_tag`` failed closed and *every* sealed
    ``ProofBundle`` had ``authenticity_tag=None`` — meaning
    ``verify_seal()`` returned ``False`` for every bundle, in dev and in
    tests, which silently disabled the entire proof/evidence spine.

    The settings layer already treats an empty/known-insecure audit key as
    acceptable *only* in dev mode (``auth_enabled=False``); it hard-stops
    at startup when ``auth_enabled=True`` or a strict profile is active.
    So when we reach here with no operator-supplied key we are, by
    construction, in dev mode. We derive a stable, deterministic,
    clearly-labelled dev key so sealing is reproducible across runs while
    remaining obviously insecure — exactly what the existing runtime
    warning already tells the operator ("HMAC'd with a publicly-known
    key"). Production never reaches this branch: it either has a real key
    or it refused to start.
    """
    from webpent.config.settings import get_settings

    settings = get_settings()
    key = (settings.audit_secret_key or "").encode("utf-8")
    if len(key) >= 32:
        return key
    # Dev-mode deterministic fallback. Not a secret; the settings layer has
    # already guaranteed we are not in a production-intent deployment.
    return b"webpent-dev-audit-key-change-in-production-v1"


def hash_evidence_bundle(evidence_bundle: dict[str, Any] | None) -> str | None:
    """Compute the HMAC-SHA256 hash of an evidence bundle.

    V5 Sprint 14: Now uses HMAC-SHA256 (keyed) instead of plain
    SHA-256 (unkeyed). This prevents an attacker who can modify the
    evidence bundle from also recomputing the hash — they would need
    the ``audit_secret_key`` to produce a valid HMAC.

    Args:
        evidence_bundle: The ``evidence_bundle`` dict from a
            :class:`Finding`. ``None`` returns ``None``.

    Returns:
        A 64-character lowercase hex HMAC-SHA256 digest, or ``None``.
    """
    if evidence_bundle is None:
        return None
    canonical = json.dumps(
        evidence_bundle, sort_keys=True, separators=(",", ":"), default=str
    )
    return _compute_hmac(_get_audit_key(), canonical.encode("utf-8"))


def _without_master_report_hash(value: Any) -> Any:
    """Copy report data while excluding generated master hash fields."""
    if isinstance(value, dict):
        return {
            key: _without_master_report_hash(item)
            for key, item in value.items()
            if key != "master_report_hash"
        }
    if isinstance(value, list):
        return [_without_master_report_hash(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_without_master_report_hash(item) for item in value)
    return value


def hash_report(report_data: dict[str, Any]) -> str:
    """Compute the HMAC-SHA256 hash of canonical report content.

    Generated ``master_report_hash`` fields are excluded recursively, so
    exporting the same report twice does not create a circular hash change.

    V5 Sprint 14: Now uses HMAC-SHA256 (keyed) so the master report
    hash cannot be forged without the ``audit_secret_key``.

    Args:
        report_data: The final report dict.

    Returns:
        A 64-character lowercase hex HMAC-SHA256 digest.
    """
    canonical = json.dumps(
        _without_master_report_hash(report_data),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return _compute_hmac(_get_audit_key(), canonical.encode("utf-8"))


def verify_report(report_data: dict[str, Any], expected_hash: str | None) -> bool:
    """Verify a report against its canonical HMAC without trusting its hash field."""
    if not expected_hash:
        return False
    return _constant_time_eq(hash_report(report_data), expected_hash)


def build_audit_trail(
    findings: list[dict[str, Any]],
    report_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the Audit Trail section for the final report.

    V5 Sprint 14: All hashes are now HMAC-SHA256 (keyed).
    """
    per_finding: list[dict[str, Any]] = []
    for f in findings:
        per_finding.append(
            {
                "finding_id": f.get("id", ""),
                "title": f.get("title", ""),
                "evidence_hash": f.get("evidence_hash"),
            }
        )

    audit_trail: dict[str, Any] = {
        "per_finding_hashes": per_finding,
        "algorithm": "HMAC-SHA256",
        "note": (
            "These hashes are computed using HMAC-SHA256 with a "
            "secret key (audit_secret_key). Recompute with the same "
            "key to verify no post-exploitation tampering has occurred. "
            "An attacker cannot forge a valid hash without the key."
        ),
    }

    if report_data is not None:
        audit_trail["master_report_hash"] = hash_report(report_data)

    return audit_trail


def verify_evidence_bundle(
    evidence_bundle: dict[str, Any] | None,
    expected_hash: str | None,
) -> bool:
    """Verify that an evidence bundle matches its recorded HMAC hash.

    V5 Sprint 14: Uses HMAC-SHA256 verification.
    """
    if expected_hash is None:
        return False
    actual = hash_evidence_bundle(evidence_bundle)
    if actual is None:
        return False
    return _constant_time_eq(actual, expected_hash)


def _constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison (timing-attack resistant)."""
    import secrets as _secrets
    return _secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
