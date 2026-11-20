"""Typed, bounded, advisory-only contracts for ABHIP v5.

The platform layer is deliberately passive.  These records describe research
reasoning and evidence requirements; they do not execute actions, create
findings, seal proof, or grant qualification authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.models.evidence import redact_sensitive


class MissionStatus(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    STOPPED = "stopped"
    ADVISORY = "advisory"


class DifferentialDimension(StrEnum):
    IDENTITY = "identity"
    ROLE = "role"
    STATE = "state"
    ACTION = "action"
    TENANT = "tenant"


class LoopPhase(StrEnum):
    OBSERVE = "observe"
    UNDERSTAND = "understand"
    QUESTION = "question"
    HYPOTHESIS = "hypothesis"
    EXPERIMENT = "experiment"
    EVIDENCE = "evidence"
    EVALUATE = "evaluate"
    LEARN = "learn"
    UPDATE = "update"
    STOP = "stop"


def _clean(value: Any, limit: int = 320) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _items(values: Any, limit: int = 16) -> tuple[str, ...]:
    if isinstance(values, str):
        values = (values,)
    if values is None:
        return ()
    return tuple(dict.fromkeys(_clean(item) for item in values if _clean(item)))[:limit]


def _hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MissionObjective:
    objective_id: str
    objective: str
    reasoning: str
    expected_value: float
    required_capabilities: tuple[str, ...] = ()
    validation_criteria: tuple[str, ...] = ()
    stopping_conditions: tuple[str, ...] = ()
    priority: float = 0.0
    dependencies: tuple[str, ...] = ()
    blocked_reasons: tuple[str, ...] = ()
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.expected_value <= 1.0:
            raise ValueError("expected_value_out_of_range")
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("priority_out_of_range")

    @property
    def eligible(self) -> bool:
        return not self.blocked_reasons and self.advisory_only

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ResearchMissionPlan:
    engagement_id: str
    target_id: str
    objectives: tuple[MissionObjective, ...] = ()
    status: MissionStatus = MissionStatus.ADVISORY
    budget_reason: str = ""
    stop_reason: str = ""
    source_refs: tuple[str, ...] = ()
    plan_digest: str = ""
    execution_attempted: bool = False
    can_create_findings: bool = False
    can_override_policy: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted or self.can_create_findings or self.can_override_policy:
            raise ValueError("mission_plan_cannot_grant_authority")
        if not self.plan_digest:
            object.__setattr__(
                self,
                "plan_digest",
                _hash(
                    {
                        "engagement_id": self.engagement_id,
                        "target_id": self.target_id,
                        "objectives": [item.as_dict() for item in self.objectives],
                        "status": self.status.value,
                        "budget_reason": self.budget_reason,
                        "stop_reason": self.stop_reason,
                        "source_refs": self.source_refs,
                    }
                ),
            )

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "objectives": [item.as_dict() for item in self.objectives],
            "status": self.status.value,
            "budget_reason": _clean(self.budget_reason),
            "stop_reason": _clean(self.stop_reason),
            "source_refs": list(self.source_refs),
            "plan_digest": self.plan_digest,
            "execution_attempted": False,
            "can_create_findings": False,
            "can_override_policy": False,
        }


@dataclass(frozen=True, slots=True)
class IntelligenceNode:
    node_id: str
    kind: str
    label: str
    evidence_source: str
    confidence: float
    lifecycle_state: str
    validation_status: str
    evidence_refs: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("node_confidence_out_of_range")

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "node_id": _clean(self.node_id, 200),
                "kind": _clean(self.kind, 80),
                "label": _clean(self.label),
                "evidence_source": _clean(self.evidence_source, 200),
                "confidence": self.confidence,
                "lifecycle_state": _clean(self.lifecycle_state, 40),
                "validation_status": _clean(self.validation_status, 40),
                "evidence_refs": list(self.evidence_refs),
                "metadata": dict(self.metadata),
            }
        )
        return clean


@dataclass(frozen=True, slots=True)
class IntelligenceRelation:
    relation_id: str
    relation: str
    source_node: str
    destination_node: str
    evidence_source: str
    confidence: float
    lifecycle_state: str
    validation_status: str
    evidence_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("relation_confidence_out_of_range")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TargetIntelligenceGraph:
    engagement_id: str
    target_id: str
    knowledge_hash: str
    nodes: tuple[IntelligenceNode, ...] = ()
    relations: tuple[IntelligenceRelation, ...] = ()
    coverage_gaps: tuple[str, ...] = ()
    authoritative: bool = False
    execution_capability: bool = False

    def __post_init__(self) -> None:
        if self.authoritative or self.execution_capability:
            raise ValueError("intelligence_graph_cannot_grant_authority")
        node_ids = [node.node_id for node in self.nodes]
        if len(node_ids) != len(set(node_ids)):
            raise ValueError("duplicate_intelligence_node")

    @classmethod
    def from_target_knowledge(cls, knowledge: TargetKnowledgeV2) -> TargetIntelligenceGraph:
        if not isinstance(knowledge, TargetKnowledgeV2):
            raise TypeError("target_knowledge_v2_required")
        nodes = tuple(
            IntelligenceNode(
                node_id=entity.entity_id,
                kind=entity.kind.value,
                label=entity.canonical_key,
                evidence_source=entity.source_observation,
                confidence=entity.confidence,
                lifecycle_state=entity.lifecycle.value,
                validation_status=(
                    "validated" if entity.lifecycle.value == "validated" else "pending"
                ),
                evidence_refs=entity.evidence_refs,
                metadata=entity.metadata,
            )
            for entity in sorted(knowledge.entities.values(), key=lambda item: item.entity_id)
        )
        relations = tuple(
            IntelligenceRelation(
                relation_id=relation.relation_id,
                relation=relation.relation,
                source_node=relation.source_entity,
                destination_node=relation.target_entity,
                evidence_source=relation.source_observation,
                confidence=relation.confidence,
                lifecycle_state=relation.lifecycle.value,
                validation_status=(
                    "validated" if relation.lifecycle.value == "validated" else "pending"
                ),
                evidence_refs=relation.evidence_refs,
            )
            for relation in sorted(knowledge.relations, key=lambda item: item.relation_id)
        )
        return cls(
            engagement_id=knowledge.engagement_id,
            target_id=knowledge.target_id,
            knowledge_hash=knowledge.content_hash(),
            nodes=nodes,
            relations=relations,
        )

    def digest(self) -> str:
        return _hash(
            {
                "engagement_id": self.engagement_id,
                "target_id": self.target_id,
                "knowledge_hash": self.knowledge_hash,
                "nodes": [node.as_dict() for node in self.nodes],
                "relations": [relation.as_dict() for relation in self.relations],
                "coverage_gaps": self.coverage_gaps,
            }
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "knowledge_hash": self.knowledge_hash,
            "nodes": [node.as_dict() for node in self.nodes],
            "relations": [relation.as_dict() for relation in self.relations],
            "coverage_gaps": list(self.coverage_gaps),
            "digest": self.digest(),
            "authoritative": False,
            "execution_capability": False,
        }


@dataclass(frozen=True, slots=True)
class SecurityQuestion:
    question_id: str
    question: str
    affected_assets: tuple[str, ...]
    security_assumption: str
    expected_evidence: tuple[str, ...]
    validation_strategy: tuple[str, ...]
    source_refs: tuple[str, ...] = ()
    priority: float = 0.0
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("question_priority_out_of_range")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


ResearchObjective = SecurityQuestion


@dataclass(frozen=True, slots=True)
class DifferentialComparison:
    comparison_id: str
    dimension: DifferentialDimension
    left_context: str
    right_context: str
    observed_difference: str
    observation_source: str
    reasoning: str
    possible_security_impact: str
    validation_requirement: str
    differential_signal: bool = False
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if self.promotion_eligible:
            raise ValueError("differential_cannot_promote")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DifferentialReasoningReport:
    engagement_id: str
    target_id: str
    comparisons: tuple[DifferentialComparison, ...] = ()
    blocked_reasons: tuple[str, ...] = ()
    observation_count: int = 0
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if self.promotion_eligible:
            raise ValueError("differential_report_cannot_promote")

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "comparisons": [item.as_dict() for item in self.comparisons],
            "blocked_reasons": list(self.blocked_reasons),
            "observation_count": self.observation_count,
            "promotion_eligible": False,
        }


@dataclass(frozen=True, slots=True)
class LoopEvent:
    sequence: int
    phase: LoopPhase
    summary: str
    input_refs: tuple[str, ...] = ()
    output_refs: tuple[str, ...] = ()
    status: str = "advisory"


@dataclass(frozen=True, slots=True)
class ResearchLoopCheckpoint:
    engagement_id: str
    target_id: str
    events: tuple[LoopEvent, ...] = ()
    attempted_action_ids: tuple[str, ...] = ()
    failed_paths: tuple[str, ...] = ()
    stop_reason: str = ""
    cycle_count: int = 0
    execution_attempted: bool = False
    promotion_eligible: bool = False

    def __post_init__(self) -> None:
        if self.execution_attempted or self.promotion_eligible:
            raise ValueError("loop_checkpoint_cannot_execute_or_promote")

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "events": [asdict(event) for event in self.events],
            "attempted_action_ids": list(self.attempted_action_ids),
            "failed_paths": list(self.failed_paths),
            "stop_reason": _clean(self.stop_reason),
            "cycle_count": self.cycle_count,
            "execution_attempted": False,
            "promotion_eligible": False,
        }


@dataclass(frozen=True, slots=True)
class VulnerabilityReasoningReport:
    hypothesis_id: str
    security_boundary: str
    attacker_capability: str
    required_conditions: tuple[str, ...]
    impact: str
    alternative_explanations: tuple[str, ...]
    evidence_strength: float
    evidence_refs: tuple[str, ...] = ()
    causal_oracle_present: bool = False
    validation_requirements: tuple[str, ...] = ()
    disposition: str = "advisory"
    advisory_only: bool = True
    finding_created: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.evidence_strength <= 1.0:
            raise ValueError("evidence_strength_out_of_range")
        if self.finding_created or not self.advisory_only:
            raise ValueError("reasoning_report_cannot_create_finding")


@dataclass(frozen=True, slots=True)
class ResearchLesson:
    lesson_id: str
    engagement_id: str
    target_id: str
    category: str
    summary: str
    evidence_refs: tuple[str, ...] = ()
    rationale: str = ""
    version: str = "abhip-memory-v3"
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.advisory_only:
            raise ValueError("memory_lesson_must_be_advisory")


@dataclass(frozen=True, slots=True)
class ABHIPMetrics:
    autonomy: float | None = None
    decision_quality: float | None = None
    hypothesis_quality: float | None = None
    evidence_completeness: float | None = None
    investigation_efficiency: float | None = None
    coverage_improvement: float | None = None
    learning_effectiveness: float | None = None
    production_detection_rate: None = None
    valid_ground_truth: bool = False
    benchmark_case_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AutonomousSecurityAssessment:
    engagement_id: str
    target_id: str
    hypothesis_id: str
    validity_challenges: tuple[str, ...]
    evidence_challenges: tuple[str, ...]
    impact_challenges: tuple[str, ...]
    reasoning_challenges: tuple[str, ...]
    reproducibility_challenges: tuple[str, ...]
    status: str
    central_review_status: str = "not_run"
    qualification_approved: bool = False
    oracle_overridden: bool = False
    policy_overridden: bool = False
    finding_created: bool = False
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if any(
            (
                self.qualification_approved,
                self.oracle_overridden,
                self.policy_overridden,
                self.finding_created,
            )
        ) or not self.advisory_only:
            raise ValueError("assessment_cannot_grant_authority")


__all__ = [
    "ABHIPMetrics",
    "AutonomousSecurityAssessment",
    "DifferentialComparison",
    "DifferentialDimension",
    "DifferentialReasoningReport",
    "IntelligenceNode",
    "IntelligenceRelation",
    "LoopEvent",
    "LoopPhase",
    "MissionObjective",
    "MissionStatus",
    "ResearchLesson",
    "ResearchMissionPlan",
    "ResearchLoopCheckpoint",
    "ResearchObjective",
    "SecurityQuestion",
    "TargetIntelligenceGraph",
    "VulnerabilityReasoningReport",
]
