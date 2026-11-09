"""Typed, redacted artifacts used by governed planning and reflection.

These records are advisory state.  They do not authorize actions, expand scope,
or promote findings.  External target content is stored only as redacted,
provenance-linked observations.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive


def _safe(value: Any, limit: int = 500) -> Any:
    clean, _ = redact_sensitive(value)
    if isinstance(clean, str):
        return clean[:limit]
    return clean


@dataclass(frozen=True)
class SurfaceObservation:
    observation_id: str
    target_ref: str
    source: str
    observed_at: str
    fields: Mapping[str, Any]
    provenance_refs: tuple[str, ...] = ()
    confidence: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "observation_id": self.observation_id,
                "target_ref": self.target_ref,
                "source": self.source,
                "observed_at": self.observed_at,
                "fields": dict(self.fields),
                "provenance_refs": list(self.provenance_refs),
                "confidence": max(0.0, min(1.0, self.confidence)),
            }
        )
        return clean


@dataclass(frozen=True)
class IdentityContext:
    identity_id: str
    role: str
    tenant: str
    auth_state: str
    provenance_refs: tuple[str, ...] = ()
    isolated_store_ref: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity_id": _safe(self.identity_id, 160),
            "role": _safe(self.role, 120),
            "tenant": _safe(self.tenant, 120),
            "auth_state": _safe(self.auth_state, 120),
            "provenance_refs": list(self.provenance_refs[:32]),
            "isolated_store_ref": _safe(self.isolated_store_ref, 200),
        }


@dataclass(frozen=True)
class WorkflowModel:
    workflow_id: str
    states: tuple[str, ...]
    transitions: tuple[tuple[str, str, str], ...]
    current_state: str
    provenance_refs: tuple[str, ...] = ()
    version: str = "1"

    def as_dict(self) -> dict[str, Any]:
        return {
            "workflow_id": _safe(self.workflow_id, 160),
            "states": [_safe(item, 100) for item in self.states[:64]],
            "transitions": [
                [_safe(item, 100) for item in transition[:3]]
                for transition in self.transitions[:128]
            ],
            "current_state": _safe(self.current_state, 100),
            "provenance_refs": list(self.provenance_refs[:32]),
            "version": _safe(self.version, 40),
        }


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    vulnerability_class: str
    objective: str
    evidence_refs: tuple[str, ...] = ()
    status: str = "candidate"
    confidence: float = 0.0
    novelty_score: float = 0.0
    required_capabilities: tuple[str, ...] = ()

    def fingerprint(self) -> str:
        return hashlib.sha256(
            canonical_json(
                {
                    "vulnerability_class": self.vulnerability_class,
                    "objective": self.objective,
                    "evidence_refs": list(self.evidence_refs),
                }
            ).encode()
        ).hexdigest()[:32]

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "hypothesis_id": self.hypothesis_id,
                "vulnerability_class": self.vulnerability_class,
                "objective": self.objective,
                "evidence_refs": list(self.evidence_refs[:32]),
                "status": self.status,
                "confidence": max(0.0, min(1.0, self.confidence)),
                "novelty_score": max(0.0, min(1.0, self.novelty_score)),
                "required_capabilities": list(self.required_capabilities[:32]),
                "fingerprint": self.fingerprint(),
            }
        )
        return clean


@dataclass(frozen=True)
class ExperimentPlan:
    plan_id: str
    hypothesis_id: str
    action_ids: tuple[str, ...]
    preconditions: tuple[str, ...]
    budget: float
    proof_path: tuple[str, ...]
    mode: str = "discovery"
    expected_information_gain: float = 0.0
    risk: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return {
            "plan_id": _safe(self.plan_id, 160),
            "hypothesis_id": _safe(self.hypothesis_id, 160),
            "action_ids": list(self.action_ids[:32]),
            "preconditions": list(self.preconditions[:32]),
            "budget": max(0.0, self.budget),
            "proof_path": list(self.proof_path[:32]),
            "mode": _safe(self.mode, 40),
            "expected_information_gain": max(0.0, min(1.0, self.expected_information_gain)),
            "risk": max(0.0, min(1.0, self.risk)),
        }


@dataclass(frozen=True)
class ActionOutcome:
    action_id: str
    status: str
    observation_refs: tuple[str, ...] = ()
    causal_signal: bool = False
    negative_control: bool = False
    proof_bundle_ref: str = ""
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_id": _safe(self.action_id, 160),
            "status": _safe(self.status, 80),
            "observation_refs": list(self.observation_refs[:32]),
            "causal_signal": bool(self.causal_signal),
            "negative_control": bool(self.negative_control),
            "proof_bundle_ref": _safe(self.proof_bundle_ref, 200),
            "reason": _safe(self.reason, 300),
        }


@dataclass(frozen=True)
class ValidationResult:
    finding_id: str
    vulnerability_class: str
    target_backed: bool
    causal_link: bool
    independent_negative_control: bool
    reproducible: bool
    proof_bundle_ref: str
    duplicate_similarity: float = 0.0
    status: str = "candidate"
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "finding_id": self.finding_id,
                "vulnerability_class": self.vulnerability_class,
                "target_backed": self.target_backed,
                "causal_link": self.causal_link,
                "independent_negative_control": self.independent_negative_control,
                "reproducible": self.reproducible,
                "proof_bundle_ref": self.proof_bundle_ref,
                "duplicate_similarity": max(0.0, min(1.0, self.duplicate_similarity)),
                "status": self.status,
                "reason": self.reason,
            }
        )
        return clean


@dataclass(frozen=True)
class ProofBundleRef:
    bundle_id: str
    sealed: bool
    replayable: bool
    target_fingerprint: str
    digest: str


@dataclass(frozen=True)
class ReflectionRecord:
    reflection_id: str
    observation_refs: tuple[str, ...]
    changed_model: tuple[str, ...]
    remaining_unknowns: tuple[str, ...]
    falsified_assumptions: tuple[str, ...]
    justified_next_actions: tuple[str, ...]
    replanning_decision: str
    created_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "reflection_id": self.reflection_id,
                "observation_refs": list(self.observation_refs[:32]),
                "changed_model": list(self.changed_model[:32]),
                "remaining_unknowns": list(self.remaining_unknowns[:32]),
                "falsified_assumptions": list(self.falsified_assumptions[:32]),
                "justified_next_actions": list(self.justified_next_actions[:32]),
                "replanning_decision": self.replanning_decision,
                "created_at": self.created_at or datetime.now(UTC).isoformat(),
            }
        )
        return clean


@dataclass(frozen=True)
class MemoryPromotionDecision:
    allowed: bool
    reasons: tuple[str, ...]
    expires_at: str = ""
    version_scope: str = ""


class MemoryPromotionPolicy:
    """Allow durable promotion only for redacted, provenance-backed facts."""

    def evaluate(self, fact: Mapping[str, Any]) -> MemoryPromotionDecision:
        reasons: list[str] = []
        if not fact.get("provenance_refs"):
            reasons.append("memory:provenance_required")
        try:
            confidence = float(fact.get("confidence"))
        except (TypeError, ValueError):
            confidence = -1.0
        if not 0.0 <= confidence <= 1.0:
            reasons.append("memory:confidence_invalid")
        if not str(fact.get("source_digest") or "").strip():
            reasons.append("memory:source_digest_required")
        if str(fact.get("redaction_status") or "").lower() != "redacted":
            reasons.append("memory:redaction_required")
        if not str(fact.get("expires_at") or fact.get("version_scope") or "").strip():
            reasons.append("memory:expiration_or_version_scope_required")
        return MemoryPromotionDecision(
            allowed=not reasons,
            reasons=tuple(reasons),
            expires_at=str(fact.get("expires_at") or "")[:80],
            version_scope=str(fact.get("version_scope") or "")[:120],
        )


class TrajectoryStore:
    """Bounded short-term store; values are redacted at insertion."""

    def __init__(self, *, max_records: int = 500) -> None:
        self.max_records = max(1, min(5000, int(max_records)))
        self._records: list[Mapping[str, Any]] = []

    def append(self, record: Mapping[str, Any]) -> None:
        clean, _ = redact_sensitive(dict(record))
        self._records.append(clean if isinstance(clean, Mapping) else {"value": str(clean)[:500]})
        if len(self._records) > self.max_records:
            del self._records[: len(self._records) - self.max_records]

    def snapshot(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self._records)


class DiversityController:
    """Bounded anti-anchoring score adjustment for hypothesis ranking."""

    def rank(
        self,
        hypotheses: Sequence[Hypothesis],
        *,
        attempted_by_class: Mapping[str, int] | None = None,
    ) -> tuple[Hypothesis, ...]:
        attempts = {
            str(key).lower(): max(0, int(value or 0))
            for key, value in (attempted_by_class or {}).items()
        }
        return tuple(
            sorted(
                hypotheses,
                key=lambda item: (
                    item.confidence
                    + item.novelty_score
                    - min(0.5, attempts.get(item.vulnerability_class.lower(), 0) * 0.05),
                    item.novelty_score,
                    item.hypothesis_id,
                ),
                reverse=True,
            )
        )


__all__ = [
    "ActionOutcome",
    "DiversityController",
    "ExperimentPlan",
    "Hypothesis",
    "IdentityContext",
    "MemoryPromotionDecision",
    "MemoryPromotionPolicy",
    "ProofBundleRef",
    "ReflectionRecord",
    "SurfaceObservation",
    "TrajectoryStore",
    "ValidationResult",
    "WorkflowModel",
]
