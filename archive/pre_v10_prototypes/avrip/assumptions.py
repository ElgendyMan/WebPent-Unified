"""AVRIP v2 security-assumption discovery.

Assumptions are potential validation targets, never findings.  The engine is
bounded, deterministic, redacted, and scoped to one world model.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from webpent.asros.world_model import SecurityWorldModel
from webpent.avrip.intent import ApplicationIntentV2


class AssumptionKind(str, Enum):
    AUTHORIZATION = "authorization"
    OWNERSHIP = "ownership"
    ROLE_SEPARATION = "role_separation"
    WORKFLOW = "workflow"
    TENANT_ISOLATION = "tenant_isolation"
    DATA_ACCESS = "data_access"
    STATE_INTEGRITY = "state_integrity"


class SecurityAssumption(BaseModel):
    """A falsifiable statement and its proposed validation target."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    assumption_id: str = Field(min_length=1, max_length=200)
    kind: AssumptionKind
    statement: str = Field(min_length=8, max_length=700)
    subject: str = Field(min_length=1, max_length=200)
    protected_resource: str = Field(min_length=1, max_length=200)
    validation_target: str = Field(min_length=8, max_length=500)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    missing_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    advisory_only: bool = True

    def __hash__(self) -> int:
        return hash(self.assumption_id)


class AssumptionDiscoveryReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    assumptions: tuple[SecurityAssumption, ...] = Field(default=(), max_length=512)
    source_model_hash: str = Field(min_length=16, max_length=128)
    advisory_only: bool = True


class SecurityAssumptionDiscoveryEngine:
    """Mine bounded assumptions from existing business semantics and invariants."""

    def discover(
        self,
        *,
        world_model: SecurityWorldModel,
        intent: ApplicationIntentV2 | None = None,
    ) -> AssumptionDiscoveryReport:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        if intent is not None and (
            intent.engagement_id != world_model.engagement_id
            or intent.target_id != world_model.target_id
        ):
            raise ValueError("intent_world_model_scope_mismatch")
        projected = intent or ApplicationIntentV2.from_world_model(world_model)
        assumptions: dict[str, SecurityAssumption] = {}
        for invariant in world_model.invariants:
            kind = _kind_for_invariant(invariant.kind.value)
            assumption = SecurityAssumption(
                assumption_id=_stable_id("invariant", invariant.invariant_id),
                kind=kind,
                statement=invariant.statement,
                subject=invariant.subject,
                protected_resource=invariant.protected_resource,
                validation_target=(
                    f"Compare authorized and independently controlled negative observations "
                    f"for {invariant.protected_resource}."
                ),
                evidence_refs=invariant.lineage.evidence_refs,
                missing_evidence=(
                    "causal_oracle",
                    "independent_negative_control",
                    "sealed_replayable_proof",
                ),
                confidence=invariant.lineage.confidence,
            )
            assumptions[assumption.assumption_id] = assumption
        for boundary in projected.security_boundaries:
            key = _stable_id("boundary", boundary.element_id)
            if key in assumptions:
                continue
            kind = _kind_for_boundary(boundary.name, boundary.rule)
            assumptions[key] = SecurityAssumption(
                assumption_id=key,
                kind=kind,
                statement=boundary.rule,
                subject=boundary.subject,
                protected_resource=boundary.protected_resource,
                validation_target=(
                    f"Test the stated {kind.value} boundary using recorded evidence only; "
                    "execution remains delegated and bounded."
                ),
                evidence_refs=boundary.lineage.evidence_refs,
                missing_evidence=("causal_oracle", "negative_control"),
                confidence=boundary.lineage.confidence,
            )
        for workflow in projected.workflows:
            if not workflow.transition_ids:
                continue
            key = _stable_id("workflow", workflow.element_id)
            assumptions.setdefault(
                key,
                SecurityAssumption(
                    assumption_id=key,
                    kind=AssumptionKind.WORKFLOW,
                    statement=f"Critical workflow {workflow.name} enforces every state transition.",
                    subject="workflow actor",
                    protected_resource=workflow.name,
                    validation_target=(
                        "Compare permitted and disallowed transition observations while "
                        "preserving the central oracle and negative control."
                    ),
                    evidence_refs=workflow.lineage.evidence_refs,
                    missing_evidence=("transition_observation", "causal_oracle"),
                    confidence=workflow.lineage.confidence,
                ),
            )
        ordered = tuple(assumptions[key] for key in sorted(assumptions))
        return AssumptionDiscoveryReport(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            assumptions=ordered,
            source_model_hash=world_model.content_hash(),
        )


def _stable_id(kind: str, value: str) -> str:
    return f"assumption:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:20]}"


def _kind_for_invariant(value: str) -> AssumptionKind:
    return {
        "ownership": AssumptionKind.OWNERSHIP,
        "role_boundary": AssumptionKind.ROLE_SEPARATION,
        "transaction": AssumptionKind.WORKFLOW,
        "data_flow": AssumptionKind.DATA_ACCESS,
        "workflow": AssumptionKind.STATE_INTEGRITY,
    }.get(value, AssumptionKind.AUTHORIZATION)


def _kind_for_boundary(name: str, rule: str) -> AssumptionKind:
    text = f"{name} {rule}".lower()
    if "tenant" in text:
        return AssumptionKind.TENANT_ISOLATION
    if "owner" in text:
        return AssumptionKind.OWNERSHIP
    if "role" in text or "admin" in text or "privilege" in text:
        return AssumptionKind.ROLE_SEPARATION
    if "state" in text or "transition" in text:
        return AssumptionKind.STATE_INTEGRITY
    return AssumptionKind.AUTHORIZATION


__all__ = [
    "AssumptionDiscoveryReport",
    "AssumptionKind",
    "SecurityAssumption",
    "SecurityAssumptionDiscoveryEngine",
]
