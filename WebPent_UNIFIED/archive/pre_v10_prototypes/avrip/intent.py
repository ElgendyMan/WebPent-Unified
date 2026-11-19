"""AVRIP v2 application-intent projection.

This module is a passive, target-scoped projection over the existing ASROS
world model.  It records business semantics and provenance; it never grants
execution authority, creates findings, or treats inference as proof.
"""

from __future__ import annotations

import hashlib
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.asros.world_model import (
    EvidenceLineage,
    SecurityInvariant,
    SecurityWorldModel,
)


class IntentValidationStatus(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    VALIDATED = "validated"
    BLOCKED = "blocked"


class IntentElement(BaseModel):
    """Common redacted metadata for one semantic element."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    element_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=240)
    description: str = Field(min_length=3, max_length=700)
    lineage: EvidenceLineage
    validation_status: IntentValidationStatus = IntentValidationStatus.INFERRED


class BusinessEntityV2(IntentElement):
    kind: str = Field(min_length=1, max_length=80)
    owner_boundary: str | None = Field(default=None, max_length=320)


class UserGoalV2(IntentElement):
    actor: str = Field(min_length=1, max_length=160)


class WorkflowV2(IntentElement):
    goal: str = Field(min_length=3, max_length=500)
    critical: bool = False
    transition_ids: tuple[str, ...] = Field(default=(), max_length=32)


class StateTransitionV2(IntentElement):
    source_state: str = Field(min_length=1, max_length=160)
    target_state: str = Field(min_length=1, max_length=160)
    actor_boundary: str = Field(min_length=1, max_length=240)
    sensitive: bool = False


class SecurityBoundaryV2(IntentElement):
    subject: str = Field(min_length=1, max_length=200)
    protected_resource: str = Field(min_length=1, max_length=200)
    rule: str = Field(min_length=8, max_length=700)


class SensitiveOperationV2(IntentElement):
    operation: str = Field(min_length=1, max_length=200)
    required_boundary: str = Field(min_length=3, max_length=320)
    impact_hint: str = Field(min_length=3, max_length=320)


class ApplicationIntentV2(BaseModel):
    """Deterministic semantic model for one exact engagement/target scope."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    application_goal: str = Field(min_length=3, max_length=700)
    entities: tuple[BusinessEntityV2, ...] = Field(default=(), max_length=256)
    user_goals: tuple[UserGoalV2, ...] = Field(default=(), max_length=256)
    workflows: tuple[WorkflowV2, ...] = Field(default=(), max_length=256)
    transitions: tuple[StateTransitionV2, ...] = Field(default=(), max_length=512)
    security_boundaries: tuple[SecurityBoundaryV2, ...] = Field(default=(), max_length=512)
    sensitive_operations: tuple[SensitiveOperationV2, ...] = Field(default=(), max_length=256)
    policy_assumptions: tuple[str, ...] = Field(default=(), max_length=32)
    lineage: EvidenceLineage
    authoritative: bool = False
    execution_capability: bool = False

    @model_validator(mode="after")
    def _safe_projection(self) -> ApplicationIntentV2:
        ids = [
            item.element_id
            for group in (
                self.entities,
                self.user_goals,
                self.workflows,
                self.transitions,
                self.security_boundaries,
                self.sensitive_operations,
            )
            for item in group
        ]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_intent_element_id")
        if self.authoritative or self.execution_capability:
            raise ValueError("intent_model_cannot_grant_authority")
        return self

    def content_hash(self) -> str:
        import json

        payload = self.model_dump(mode="json")
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @classmethod
    def from_world_model(cls, world_model: SecurityWorldModel) -> ApplicationIntentV2:
        """Project existing intent/invariant contracts without inventing evidence."""
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        entities: list[BusinessEntityV2] = []
        goals: list[UserGoalV2] = []
        workflows: list[WorkflowV2] = []
        transitions: list[StateTransitionV2] = []
        boundaries: list[SecurityBoundaryV2] = []
        operations: list[SensitiveOperationV2] = []
        all_refs: list[str] = []
        for intent in world_model.business_intents:
            all_refs.extend(intent.lineage.evidence_refs)
            workflow_id = _stable_id("workflow", intent.intent_id)
            transition_ids = tuple(
                _stable_id("transition", f"{intent.intent_id}|{transition}")
                for transition in intent.state_transitions
            )
            for transition, transition_id in zip(
                intent.state_transitions, transition_ids, strict=True
            ):
                source, target = _split_transition(transition)
                transitions.append(
                    StateTransitionV2(
                        element_id=transition_id,
                        name=transition,
                        description=f"Observed workflow transition for {intent.workflow}.",
                        source_state=source,
                        target_state=target,
                        actor_boundary="workflow actor boundary",
                        sensitive=True,
                        lineage=intent.lineage,
                    )
                )
            workflows.append(
                WorkflowV2(
                    element_id=workflow_id,
                    name=intent.workflow,
                    description=f"Business workflow: {intent.workflow}.",
                    goal=intent.goal,
                    critical=bool(intent.transaction or intent.trust_assumptions),
                    transition_ids=transition_ids,
                    lineage=intent.lineage,
                )
            )
            goals.append(
                UserGoalV2(
                    element_id=_stable_id("goal", intent.intent_id),
                    name=f"goal:{intent.workflow}",
                    description=intent.goal,
                    actor="observed application actor",
                    lineage=intent.lineage,
                )
            )
            for rule in intent.ownership_rules or intent.trust_assumptions:
                boundaries.append(
                    SecurityBoundaryV2(
                        element_id=_stable_id("boundary", f"{intent.intent_id}|{rule}"),
                        name=f"boundary:{intent.workflow}",
                        description="Security boundary inferred from business intent.",
                        subject="workflow actor",
                        protected_resource=intent.transaction or intent.workflow,
                        rule=rule,
                        lineage=intent.lineage,
                    )
                )
        for invariant in world_model.invariants:
            all_refs.extend(invariant.lineage.evidence_refs)
            boundaries.append(_boundary_from_invariant(invariant))
            operations.append(
                SensitiveOperationV2(
                    element_id=_stable_id("operation", invariant.invariant_id),
                    name=f"operation:{invariant.protected_resource}",
                    description="Sensitive operation linked to a security invariant.",
                    operation=invariant.protected_resource,
                    required_boundary=invariant.statement,
                    impact_hint=f"Potential impact to {invariant.kind.value} boundary.",
                    lineage=invariant.lineage,
                )
            )
        refs = tuple(dict.fromkeys(all_refs))
        lineage = EvidenceLineage(
            source="asros.security_world_model",
            evidence_refs=refs or (f"world-model:{world_model.content_hash()[:16]}",),
            confidence=_mean_confidence(world_model),
        )
        goal = (
            world_model.business_intents[0].goal
            if world_model.business_intents
            else "Protect resources, identities, and workflow boundaries."
        )
        assumptions = tuple(
            dict.fromkeys(invariant.kind.value for invariant in world_model.invariants)
        )
        return cls(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            application_goal=goal,
            entities=tuple(entities),
            user_goals=tuple(goals),
            workflows=tuple(workflows),
            transitions=tuple(transitions),
            security_boundaries=tuple(boundaries),
            sensitive_operations=tuple(operations),
            policy_assumptions=assumptions,
            lineage=lineage,
        )


def _stable_id(kind: str, value: str) -> str:
    return f"intent:{kind}:{hashlib.sha256(value.encode()).hexdigest()[:20]}"


def _split_transition(value: str) -> tuple[str, str]:
    parts = [part.strip() for part in value.replace("→", "->").split("->")]
    if len(parts) >= 2:
        return parts[0][:160], parts[-1][:160]
    return "unknown", value[:160]


def _boundary_from_invariant(invariant: SecurityInvariant) -> SecurityBoundaryV2:
    return SecurityBoundaryV2(
        element_id=_stable_id("boundary", invariant.invariant_id),
        name=f"boundary:{invariant.invariant_id}",
        description="Security boundary projected from an existing invariant.",
        subject=invariant.subject,
        protected_resource=invariant.protected_resource,
        rule=invariant.statement,
        lineage=invariant.lineage,
    )


def _mean_confidence(world_model: SecurityWorldModel) -> float:
    values = [
        item.lineage.confidence
        for item in (
            *world_model.business_intents,
            *world_model.invariants,
            *world_model.behaviours,
        )
    ]
    return round(sum(values) / len(values), 3) if values else 0.0


__all__ = [
    "ApplicationIntentV2",
    "BusinessEntityV2",
    "IntentElement",
    "IntentValidationStatus",
    "SensitiveOperationV2",
    "SecurityBoundaryV2",
    "StateTransitionV2",
    "UserGoalV2",
    "WorkflowV2",
]
