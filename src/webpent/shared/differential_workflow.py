"""Fail-closed differential workflow comparison contracts.

The runner compares caller-supplied observations only.  It never performs I/O,
authorizes actions, or promotes a vulnerability.  Promotion remains owned by
the existing oracle, negative-control, validator, and ProofBundle chain.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.shared.control_plane import IdentityProfileRef, ScopeDecisionType

VariantKind = Literal["owner_vs_foreign", "role_a_vs_role_b", "tenant_a_vs_tenant_b"]

_SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "cookie",
        "cookies",
        "otp",
        "raw_otp",
        "body",
        "raw_body",
        "message_body",
        "headers",
    }
)


def _contains_secret_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if str(key).strip().lower().replace("-", "_") in _SECRET_KEYS:
                return True
            if _contains_secret_key(child):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_contains_secret_key(child) for child in value)
    return False


def _safe_mapping(value: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    if _contains_secret_key(value):
        raise ValueError(f"{label}_contains_secret")
    clean, _ = redact_sensitive(dict(value))
    if not isinstance(clean, Mapping):
        raise ValueError(f"{label}_invalid")
    return dict(clean)


def _digest(value: Any) -> str:
    clean, _ = redact_sensitive(value)
    return "sha256:" + hashlib.sha256(canonical_json(clean).encode()).hexdigest()


@dataclass(frozen=True)
class DifferentialVariant:
    """One identity/role/tenant execution context, without credentials."""

    label: str
    identity: IdentityProfileRef
    role: str = "unknown"
    tenant_ref: str = ""

    def __post_init__(self) -> None:
        if not self.label.strip():
            raise ValueError("variant_label_required")
        if not self.identity.engagement_id.strip():
            raise ValueError("variant_identity_invalid")
        if self.role.strip() == "":
            raise ValueError("variant_role_required")
        if self.tenant_ref and len(self.tenant_ref) > 160:
            raise ValueError("variant_tenant_ref_too_long")


@dataclass(frozen=True)
class DifferentialObservation:
    """Redacted result of one variant execution."""

    variant_label: str
    status: str
    response_fingerprint: str
    state_fingerprint: str = ""
    evidence_refs: tuple[str, ...] = ()
    clean: bool = False
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "variant_label": self.variant_label[:120],
            "status": self.status[:80],
            "response_fingerprint": self.response_fingerprint,
            "state_fingerprint": self.state_fingerprint,
            "evidence_refs": list(self.evidence_refs)[:24],
            "clean": self.clean,
            "reason": self.reason[:240],
        }


@dataclass(frozen=True)
class DifferentialResult:
    """Comparison output; ``differential_signal`` is not a confirmation."""

    engagement_id: str
    target_url: str
    variant_kind: VariantKind
    baseline: DifferentialObservation | None
    variant: DifferentialObservation | None
    differential_signal: bool
    negative_control_complete: bool
    replayable: bool
    status: str
    reason: str
    comparison_fingerprint: str

    @property
    def promotion_eligible(self) -> bool:
        """Always false: this class cannot replace the proof/validator chain."""
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "variant_kind": self.variant_kind,
            "baseline": self.baseline.as_dict() if self.baseline else None,
            "variant": self.variant.as_dict() if self.variant else None,
            "differential_signal": self.differential_signal,
            "negative_control_complete": self.negative_control_complete,
            "replayable": self.replayable,
            "status": self.status,
            "reason": self.reason[:240],
            "comparison_fingerprint": self.comparison_fingerprint,
            "promotion_eligible": False,
        }


class DifferentialWorkflowRunner:
    """Run a supplied observation function for two explicitly bound variants."""

    def __init__(self, *, engagement_id: str, target_url: str, scope_decision: Any) -> None:
        self.engagement_id = str(engagement_id or "").strip()[:160]
        self.target_url = str(target_url or "").strip()[:2048]
        self.scope_decision = scope_decision
        if not self.engagement_id:
            raise ValueError("engagement_id_required")
        if not self.target_url:
            raise ValueError("target_url_required")
        if getattr(scope_decision, "decision", None) != ScopeDecisionType.ALLOWED:
            raise ValueError("differential_scope_not_allowed")

    @staticmethod
    def _validate_pair(
        baseline: DifferentialVariant,
        variant: DifferentialVariant,
        kind: VariantKind,
        engagement_id: str,
    ) -> None:
        if baseline.label == variant.label:
            raise ValueError("differential_variant_labels_must_differ")
        for item in (baseline, variant):
            if item.identity.engagement_id != engagement_id:
                raise ValueError("differential_identity_engagement_mismatch")
        if baseline.identity.identity_id == variant.identity.identity_id:
            raise ValueError("differential_identities_must_differ")
        if kind == "owner_vs_foreign" and (
            baseline.tenant_ref == variant.tenant_ref
            or baseline.role == variant.role
        ):
            raise ValueError("owner_foreign_contexts_must_differ")
        if kind == "role_a_vs_role_b" and baseline.role == variant.role:
            raise ValueError("role_contexts_must_differ")
        if kind == "tenant_a_vs_tenant_b" and (
            not baseline.tenant_ref
            or not variant.tenant_ref
            or baseline.tenant_ref == variant.tenant_ref
        ):
            raise ValueError("tenant_contexts_must_differ")

    @staticmethod
    def _observation(label: str, raw: Mapping[str, Any]) -> DifferentialObservation:
        safe = _safe_mapping(raw, label=f"{label}_observation")
        status = str(safe.get("status") or "inconclusive").strip().lower()
        response = safe.get("response")
        state = safe.get("state")
        evidence_refs = safe.get("evidence_refs", ())
        if isinstance(evidence_refs, str):
            evidence_refs = (evidence_refs,)
        if not isinstance(evidence_refs, (list, tuple)):
            evidence_refs = ()
        return DifferentialObservation(
            variant_label=label,
            status=status,
            response_fingerprint=str(safe.get("response_fingerprint") or _digest(response)),
            state_fingerprint=str(safe.get("state_fingerprint") or _digest(state)),
            evidence_refs=tuple(str(item)[:240] for item in evidence_refs[:24]),
            clean=bool(safe.get("clean", False)),
            reason=str(safe.get("reason") or "")[:240],
        )

    def compare(
        self,
        *,
        baseline: DifferentialVariant,
        variant: DifferentialVariant,
        variant_kind: VariantKind,
        observe: Callable[[DifferentialVariant], Mapping[str, Any]],
        negative_control_complete: bool = False,
        replayable: bool = False,
    ) -> DifferentialResult:
        self._validate_pair(baseline, variant, variant_kind, self.engagement_id)
        if not callable(observe):
            raise ValueError("differential_observer_required")
        if not negative_control_complete:
            return self._blocked(variant_kind, "negative_control_required")
        if not replayable:
            return self._blocked(variant_kind, "replayability_required")
        try:
            baseline_observation = self._observation(
                baseline.label, observe(baseline)
            )
            variant_observation = self._observation(variant.label, observe(variant))
        except (TypeError, ValueError, KeyError) as exc:
            return self._blocked(variant_kind, f"observation_rejected:{type(exc).__name__}")
        signal = (
            baseline_observation.response_fingerprint != variant_observation.response_fingerprint
            or baseline_observation.state_fingerprint != variant_observation.state_fingerprint
        )
        status = "differential_signal" if signal else "no_differential_signal"
        reason = "variant_observations_differ" if signal else "variant_observations_match"
        fingerprint = _digest(
            {
                "engagement_id": self.engagement_id,
                "target_url": self.target_url,
                "kind": variant_kind,
                "baseline": baseline_observation.as_dict(),
                "variant": variant_observation.as_dict(),
            }
        )
        return DifferentialResult(
            engagement_id=self.engagement_id,
            target_url=self.target_url,
            variant_kind=variant_kind,
            baseline=baseline_observation,
            variant=variant_observation,
            differential_signal=signal,
            negative_control_complete=True,
            replayable=True,
            status=status,
            reason=reason,
            comparison_fingerprint=fingerprint,
        )

    def _blocked(self, variant_kind: VariantKind, reason: str) -> DifferentialResult:
        fingerprint = _digest(
            {
                "engagement_id": self.engagement_id,
                "target_url": self.target_url,
                "kind": variant_kind,
                "reason": reason,
            }
        )
        return DifferentialResult(
            engagement_id=self.engagement_id,
            target_url=self.target_url,
            variant_kind=variant_kind,
            baseline=None,
            variant=None,
            differential_signal=False,
            negative_control_complete=False,
            replayable=False,
            status="blocked_by_precondition",
            reason=reason,
            comparison_fingerprint=fingerprint,
        )


__all__ = [
    "DifferentialObservation",
    "DifferentialResult",
    "DifferentialVariant",
    "DifferentialWorkflowRunner",
]
