"""Frozen proof metadata with explicit sealing and deterministic replay.

The bundle stores only redacted references and deterministic digests. It is a
proof artifact contract, not a finding promoter: callers still need a
validator result before claiming confirmation.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.models.evidence import redact_sensitive, sha256_text


class CustodyEvent(BaseModel):
    """One append-only custody event for a proof bundle."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    actor: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    note: str = Field(default="", max_length=240)

    @field_validator("actor", "action", "note", mode="before")
    @classmethod
    def _redact_text(cls, value: Any) -> str:
        clean, _ = redact_sensitive(str(value or ""))
        return clean



def _compute_authenticity_tag(seal_digest: str) -> tuple[str | None, str | None, str | None]:
    """Compute HMAC-SHA256 authenticity tag over seal_digest using trusted secret.

    Trust boundary (explicit, ordered):
      1. WEBPENT_AUDIT_SECRET_KEY env var — explicit runtime override (dev/test).
         Visible in code; cannot silently become production (requires explicit set).
      2. Settings.audit_secret_key — production trusted configuration.
    Never exposed in the bundle. Returns (tag, algorithm, key_version).
    If secret unavailable/weak (<32 chars) → (None, None, None) — fail-closed.
    """
    import os as _os
    key: bytes | None = None
    key_ver = "env_override_v1"
    env_key = _os.environ.get("WEBPENT_AUDIT_SECRET_KEY")
    if env_key and len(env_key) >= 32:
        key = env_key.encode("utf-8")
    else:
        try:
            from webpent.utils.crypto import _get_audit_key
            k = _get_audit_key()
            if k and len(k) >= 32:
                key = k
                key_ver = "settings_audit_key_v1"
        except Exception:
            key = None
    if not key or len(key) < 32:
        return None, None, None  # fail-closed: weak/missing key
    try:
        from webpent.utils.crypto import _compute_hmac
        tag = _compute_hmac(key, seal_digest.encode("utf-8"))
        return f"hmac_sha256:{tag}", "hmac_sha256_v1", key_ver
    except Exception:
        return None, None, None  # fail-closed on any HMAC error


class ProofBundle(BaseModel):
    """Frozen proof metadata with explicit sealing and deterministic replay."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    bundle_id: str = Field(default_factory=lambda: f"proof_bundle_{uuid4().hex}", min_length=1)
    engagement_id: str = Field(min_length=1, max_length=160)
    finding_id: str = Field(min_length=1, max_length=160)
    hypothesis_id: str | None = Field(default=None, max_length=160)
    target_fingerprint: str | None = Field(default=None, max_length=200)
    target_package_id: str | None = Field(default=None, max_length=160)
    target_package_sha256: str | None = Field(default=None, max_length=64)
    target_package_scope_digest: str | None = None
    target_package_policy_digest: str | None = None
    scope_context: dict[str, Any] = Field(default_factory=dict)
    identity_context: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    evidence_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    request_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    response_digests: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    baseline_digest: str | None = None
    negative_control_digest: str | None = None
    causal_oracle: dict[str, Any] = Field(default_factory=dict)
    target_backed: bool = False
    negative_control_independent: bool = False
    validator_id: str | None = Field(default=None, max_length=120)
    validator_version: str | None = Field(default=None, max_length=80)
    validator_config_digest: str | None = None
    replay_metadata: dict[str, Any] = Field(default_factory=dict)
    cleanup_status: str = Field(default="not_recorded", max_length=80)
    redaction_manifest: tuple[str, ...] = Field(default_factory=tuple, max_length=64)
    chain_of_custody: tuple[CustodyEvent, ...] = Field(default_factory=tuple, max_length=64)
    sealed: bool = False
    seal_digest: str | None = None

    # vNext additive fields
    target_identity: str | None = Field(default=None, max_length=240)
    target_context_hash: str | None = Field(default=None, max_length=64)
    campaign_id: str | None = Field(default=None, max_length=160)
    run_id: str | None = Field(default=None, max_length=160)
    vulnerability_class: str | None = Field(default=None, max_length=120)
    baseline_evidence_ref: str | None = Field(default=None, max_length=240)
    candidate_evidence_ref: str | None = Field(default=None, max_length=240)
    negative_control_evidence_ref: str | None = Field(default=None, max_length=240)
    oracle_decision: str | None = Field(default=None, max_length=32)
    invariant_analysis: dict[str, Any] = Field(default_factory=dict)
    validator_result: dict[str, Any] = Field(default_factory=dict)
    evidence_origin: Literal["offline_fixture", "target_runtime"] = "offline_fixture"
    # HMAC authenticity (TEAM-1 consolidation): dual-layer SHA-256 integrity + HMAC-SHA256 authenticity.
    # authenticity_tag = HMAC(secret, seal_digest). Never contains the secret itself.
    authenticity_tag: str | None = Field(default=None, max_length=128)
    authenticity_algorithm: str | None = Field(default=None, max_length=32)
    authenticity_key_version: str | None = Field(default=None, max_length=32)

    @field_validator(
        "engagement_id",
        "finding_id",
        "hypothesis_id",
        "target_fingerprint",
        "target_package_id",
        "validator_id",
        "validator_version",
        "cleanup_status",
        "evidence_refs",
        "redaction_manifest",
        "target_identity",
        "campaign_id",
        "run_id",
        "vulnerability_class",
        "baseline_evidence_ref",
        "candidate_evidence_ref",
        "negative_control_evidence_ref",
        mode="before",
    )
    @classmethod
    def _redact_identity_or_refs(cls, value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    @field_validator(
        "scope_context",
        "identity_context",
        "causal_oracle",
        "replay_metadata",
        "invariant_analysis",
        "validator_result",
        mode="before",
    )
    @classmethod
    def _redact_metadata(cls, value: Any) -> dict[str, Any]:
        clean, _ = redact_sensitive(value if isinstance(value, dict) else {})
        return clean

    @field_validator(
        "target_package_sha256",
        "target_package_scope_digest",
        "target_package_policy_digest",
        "target_context_hash",
        mode="before",
    )
    @classmethod
    def _validate_package_digest_text(cls, value: Any) -> Any:
        if value is None:
            return None
        text = str(value)
        if len(text) != 64:
            raise ValueError("digest must be 64 hex characters")
        int(text, 16)
        return text.lower()

    @field_validator(
        "evidence_digests",
        "request_digests",
        "response_digests",
        "baseline_digest",
        "negative_control_digest",
        "validator_config_digest",
        "seal_digest",
        mode="before",
    )
    @classmethod
    def _validate_digest_text(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (tuple, list)):
            for item in value:
                cls._validate_digest_text(item)
            return value
        text = str(value)
        if not text.startswith("sha256:") or len(text) != 71:
            raise ValueError("digest must be sha256:<64 hex characters>")
        int(text[7:], 16)
        return text

    def _seal_payload(self) -> dict[str, Any]:
        payload = {
            "bundle_id": self.bundle_id,
            "engagement_id": self.engagement_id,
            "finding_id": self.finding_id,
            "hypothesis_id": self.hypothesis_id,
            "target_fingerprint": self.target_fingerprint,
            "target_package_id": self.target_package_id,
            "target_package_sha256": self.target_package_sha256,
            "target_package_scope_digest": self.target_package_scope_digest,
            "target_package_policy_digest": self.target_package_policy_digest,
            "scope_context": self.scope_context,
            "identity_context": self.identity_context,
            "evidence_refs": list(self.evidence_refs),
            "evidence_digests": list(self.evidence_digests),
            "request_digests": list(self.request_digests),
            "response_digests": list(self.response_digests),
            "baseline_digest": self.baseline_digest,
            "negative_control_digest": self.negative_control_digest,
            "causal_oracle": self.causal_oracle,
            "target_backed": self.target_backed,
            "negative_control_independent": self.negative_control_independent,
            "validator_id": self.validator_id,
            "validator_version": self.validator_version,
            "validator_config_digest": self.validator_config_digest,
            "replay_metadata": self.replay_metadata,
            "cleanup_status": self.cleanup_status,
            "redaction_manifest": list(self.redaction_manifest),
            "chain_of_custody": [event.model_dump(mode="json") for event in self.chain_of_custody],
        }
        # Add vNext fields to payload if present
        vnext = {
            "target_identity": self.target_identity,
            "target_context_hash": self.target_context_hash,
            "campaign_id": self.campaign_id,
            "run_id": self.run_id,
            "vulnerability_class": self.vulnerability_class,
            "baseline_evidence_ref": self.baseline_evidence_ref,
            "candidate_evidence_ref": self.candidate_evidence_ref,
            "negative_control_evidence_ref": self.negative_control_evidence_ref,
            "oracle_decision": self.oracle_decision,
            "invariant_analysis": self.invariant_analysis,
            "validator_result": self.validator_result,
            "evidence_origin": self.evidence_origin,
        }
        payload.update({k: v for k, v in vnext.items() if v is not None or isinstance(v, dict)})
        return payload

    def seal(self, *, actor: str = "system") -> ProofBundle:
        """Return a new sealed bundle; the existing instance is never mutated.

        Dual-layer: SHA-256 integrity (seal_digest) + HMAC-SHA256 authenticity
        (authenticity_tag) computed over seal_digest using the trusted runtime
        secret. The secret is never stored in or exposed by the bundle.
        Fail-closed: if secret unavailable, authenticity_tag is None and
        promotion will be blocked (integrity-only bundles are NOT promotable).
        """
        if self.sealed:
            return self
        event = CustodyEvent(actor=actor, action="seal")
        with_event = self.model_copy(update={"chain_of_custody": (*self.chain_of_custody, event)})
        digest = f"sha256:{sha256_text(with_event._seal_payload())}"
        # HMAC authenticity over the integrity digest (trusted secret from config boundary).
        auth_tag, auth_algo, key_ver = _compute_authenticity_tag(digest)
        return with_event.model_copy(update={
            "sealed": True, "seal_digest": digest,
            "authenticity_tag": auth_tag, "authenticity_algorithm": auth_algo,
            "authenticity_key_version": key_ver,
        })

    def verify_seal(self) -> bool:
        """Verify dual-layer: SHA-256 integrity AND HMAC-SHA256 authenticity.

        Fail-closed: if authenticity_tag is missing or HMAC verification fails,
        the bundle is NOT authentic (even if SHA integrity passes). A bundle
        with valid SHA but missing/forged HMAC is rejected.
        """
        if not self.sealed or not self.seal_digest:
            return False
        expected = f"sha256:{sha256_text(self._seal_payload())}"
        if expected != self.seal_digest:
            return False  # integrity check failed
        # Authenticity check: HMAC(secret, recomputed seal_digest) must match stored tag.
        if not self.authenticity_tag or not self.authenticity_algorithm:
            return False  # no authenticity tag → not authentic
        recomputed_tag, _, _ = _compute_authenticity_tag(expected)
        if not recomputed_tag:
            return False  # secret unavailable → fail closed
        import hmac as _hmac
        return _hmac.compare_digest(recomputed_tag, self.authenticity_tag)

    def verify_seal_integrity_only(self) -> bool:
        """SHA-256 integrity ONLY (no HMAC). For advisory/non-promotion use.
        Promotion requires verify_seal() (dual-layer)."""
        if not self.sealed or not self.seal_digest:
            return False
        expected = f"sha256:{sha256_text(self._seal_payload())}"
        return expected == self.seal_digest

    def verify_replay_binding(self, replay_context: Mapping[str, Any]) -> bool:
        """Require replay to remain bound to the original campaign and target."""
        if not isinstance(replay_context, Mapping):
            return False

        package_fields = (
            "target_package_id",
            "target_package_sha256",
            "target_package_scope_digest",
            "target_package_policy_digest",
        )
        vnext_fields = (
            "target_identity",
            "target_context_hash",
            "campaign_id",
            "run_id",
            "vulnerability_class",
        )
        oracle_fields = {"oracle_decision", "evidence_origin"}
        scalar_fields = {
            "engagement_id",
            "finding_id",
            "hypothesis_id",
            "target_fingerprint",
            *package_fields,
            *vnext_fields,
        }
        metadata_fields = {"scope_context", "identity_context", "invariant_analysis"}
        sequence_fields = {"evidence_refs"}
        special_fields = {"sealed_digest"}
        allowed_fields = (
            scalar_fields | oracle_fields | metadata_fields | sequence_fields | special_fields
        )
        if set(replay_context) - allowed_fields:
            return False

        required = {"engagement_id", "finding_id"}
        if self.hypothesis_id:
            required.add("hypothesis_id")
        if self.target_fingerprint:
            required.add("target_fingerprint")
        if self.target_package_id:
            required.update(package_fields)
        if self.scope_context:
            required.add("scope_context")
        if self.identity_context:
            required.add("identity_context")

        # vNext requirements
        for field in vnext_fields:
            if getattr(self, field, None):
                required.add(field)

        for field in required:
            if field not in replay_context:
                return False
            expected = replay_context[field]
            stored = getattr(self, field, None)
            if expected is None or stored is None:
                return False
            if field in metadata_fields:
                if not isinstance(expected, Mapping):
                    return False
                clean_expected, _ = redact_sensitive(dict(expected))
                clean_stored, _ = redact_sensitive(stored)
                if sha256_text(clean_expected) != sha256_text(clean_stored):
                    return False
            elif str(expected) != str(stored):
                return False

        for field, expected in replay_context.items():
            if field in metadata_fields:
                stored = getattr(self, field, None)
                if not isinstance(expected, Mapping) or stored is None:
                    return False
                clean_expected, _ = redact_sensitive(dict(expected))
                clean_stored, _ = redact_sensitive(stored)
                if sha256_text(clean_expected) != sha256_text(clean_stored):
                    return False
            elif field in sequence_fields:
                if tuple(str(item) for item in expected) != tuple(self.evidence_refs):
                    return False
            elif field in special_fields:
                if not self.seal_digest or str(expected) != self.seal_digest:
                    return False
            elif field in scalar_fields or field in oracle_fields:
                stored = getattr(self, field, None)
                if stored is None or str(expected) != str(stored):
                    return False
        return True

    def replay(
        self,
        evidence_payloads: tuple[Any, ...] | list[Any],
        negative_control: Any = None,
        *,
        replay_context: Mapping[str, Any] | None = None,
    ) -> bool:
        """Verify evidence digests and optional campaign/target replay binding."""
        if not self.sealed or not self.verify_seal():
            return False
        if replay_context is not None and not self.verify_replay_binding(replay_context):
            return False
        digests = tuple(
            f"sha256:{sha256_text(redact_sensitive(item)[0])}"
            for item in evidence_payloads
        )
        if (
            len(digests) == 2
            and len(self.evidence_digests) == 3
            and not self.causal_oracle.get("requires_target_backed")
            and negative_control is not None
        ):
            digests = (*digests, f"sha256:{sha256_text(redact_sensitive(negative_control)[0])}")
        if digests != self.evidence_digests:
            return False
        if self.negative_control_digest is None:
            return negative_control is None
        if negative_control is None:
            return False
        actual = f"sha256:{sha256_text(redact_sensitive(negative_control)[0])}"
        return actual == self.negative_control_digest

    def append_custody(self, *, actor: str, action: str, note: str = "") -> ProofBundle:
        """Return a new unsealed bundle with one custody event."""
        if self.sealed:
            raise ValueError("sealed_proof_bundle_is_immutable")
        event = CustodyEvent(actor=actor, action=action, note=note)
        return self.model_copy(update={"chain_of_custody": (*self.chain_of_custody, event)})


def build_proof_bundle(
    *,
    engagement_id: str,
    finding_id: str,
    evidence: tuple[Any, ...] | list[Any] = (),
    evidence_refs: tuple[str, ...] | list[str] = (),
    negative_control: Any = None,
    hypothesis_id: str | None = None,
    target_fingerprint: str | None = None,
    target_package_id: str | None = None,
    target_package_sha256: str | None = None,
    target_package_scope_digest: str | None = None,
    target_package_policy_digest: str | None = None,
    scope_context: dict[str, Any] | None = None,
    identity_context: dict[str, Any] | None = None,
    baseline: Any = None,
    request_evidence: tuple[Any, ...] | list[Any] = (),
    response_evidence: tuple[Any, ...] | list[Any] = (),
    causal_oracle: dict[str, Any] | None = None,
    target_backed: bool = False,
    negative_control_independent: bool = False,
    validator_id: str | None = None,
    validator_version: str | None = None,
    validator_config: Any = None,
    replay_metadata: dict[str, Any] | None = None,
    cleanup_status: str = "not_recorded",
    redaction_manifest: tuple[str, ...] | list[str] = (),
    # vNext fields
    target_identity: str | None = None,
    target_context_hash: str | None = None,
    campaign_id: str | None = None,
    run_id: str | None = None,
    vulnerability_class: str | None = None,
    baseline_evidence_ref: str | None = None,
    candidate_evidence_ref: str | None = None,
    negative_control_evidence_ref: str | None = None,
    oracle_decision: str | None = None,
    invariant_analysis: dict[str, Any] | None = None,
    validator_result: dict[str, Any] | None = None,
    evidence_origin: Literal["offline_fixture", "target_runtime"] = "offline_fixture",
) -> ProofBundle:
    """Build a redaction-safe bundle from deterministic evidence payloads."""
    clean_evidence = tuple(redact_sensitive(item)[0] for item in evidence)
    negative_digest = (
        f"sha256:{sha256_text(redact_sensitive(negative_control)[0])}"
        if negative_control is not None
        else None
    )

    def _digests(items: tuple[Any, ...] | list[Any]) -> tuple[str, ...]:
        return tuple(
            f"sha256:{sha256_text(redact_sensitive(item)[0])}" for item in items
        )[:32]

    baseline_digest = (
        f"sha256:{sha256_text(redact_sensitive(baseline)[0])}"
        if baseline is not None
        else None
    )
    validator_config_digest = (
        f"sha256:{sha256_text(redact_sensitive(validator_config)[0])}"
        if validator_config is not None
        else None
    )
    return ProofBundle(
        engagement_id=engagement_id,
        finding_id=finding_id,
        hypothesis_id=hypothesis_id,
        target_fingerprint=target_fingerprint,
        target_package_id=target_package_id,
        target_package_sha256=target_package_sha256,
        target_package_scope_digest=target_package_scope_digest,
        target_package_policy_digest=target_package_policy_digest,
        scope_context=scope_context or {},
        identity_context=identity_context or {},
        evidence_refs=tuple(str(ref)[:500] for ref in evidence_refs)[:32],
        evidence_digests=tuple(f"sha256:{sha256_text(item)}" for item in clean_evidence)[:32],
        request_digests=_digests(request_evidence),
        response_digests=_digests(response_evidence),
        baseline_digest=baseline_digest,
        negative_control_digest=negative_digest,
        causal_oracle=causal_oracle or {},
        target_backed=bool(target_backed),
        negative_control_independent=bool(negative_control_independent),
        validator_id=validator_id,
        validator_version=validator_version,
        validator_config_digest=validator_config_digest,
        replay_metadata=replay_metadata or {},
        cleanup_status=cleanup_status,
        redaction_manifest=tuple(redaction_manifest)[:64],
        target_identity=target_identity,
        target_context_hash=target_context_hash,
        campaign_id=campaign_id,
        run_id=run_id,
        vulnerability_class=vulnerability_class,
        baseline_evidence_ref=baseline_evidence_ref,
        candidate_evidence_ref=candidate_evidence_ref,
        negative_control_evidence_ref=negative_control_evidence_ref,
        oracle_decision=oracle_decision,
        invariant_analysis=invariant_analysis or {},
        validator_result=validator_result or {},
        evidence_origin=evidence_origin,
    )


def proof_bundle_promotion_ready(value: Any) -> bool:
    """Return whether a bundle meets the strict promotion contract."""
    try:
        bundle = value if isinstance(value, ProofBundle) else ProofBundle.model_validate(value)
    except Exception:
        return False

    # vNext strict confirmation and origin rule. Offline confirmations are
    # engine-validation artifacts only and can never enter scoring promotion.
    if bundle.oracle_decision:
        if bundle.oracle_decision != "CONFIRMED":
            return False
        if bundle.evidence_origin != "target_runtime" or not bundle.target_backed:
            return False

    return bool(
        validate_proof_bundle(bundle, require_negative_control=True)
        and bundle.hypothesis_id
        and bundle.target_fingerprint
        and bundle.scope_context
        and bundle.identity_context
        and bundle.baseline_digest
        and bundle.request_digests
        and bundle.response_digests
        and bundle.causal_oracle.get("causal_signal") is True
        and bundle.causal_oracle.get("negative_control_complete") is True
        and (
            not bundle.causal_oracle.get("requires_target_backed")
            or (
                bundle.target_backed is True
                and bundle.negative_control_independent is True
            )
        )
        and bundle.validator_id
        and bundle.validator_version
        and bundle.replay_metadata.get("replayable") is True
        and bundle.cleanup_status in {"complete", "not_applicable"}
        and (
            not bundle.target_package_id
            or (
                bool(bundle.target_package_sha256)
                and bool(bundle.target_package_scope_digest)
                and bool(bundle.target_package_policy_digest)
            )
        )
    )


def validate_proof_bundle(
    value: Any,
    *,
    require_negative_control: bool = False,
) -> bool:
    """Return whether a serialized or live bundle is sealed and structurally usable."""
    try:
        bundle = value if isinstance(value, ProofBundle) else ProofBundle.model_validate(value)
    except Exception:
        return False
    if not bundle.verify_seal() or not bundle.evidence_digests:
        return False
    if not bundle.evidence_refs:
        return False
    return not require_negative_control or bundle.negative_control_digest is not None


__all__ = [
    "CustodyEvent",
    "ProofBundle",
    "build_proof_bundle",
    "proof_bundle_promotion_ready",
    "validate_proof_bundle",
]
