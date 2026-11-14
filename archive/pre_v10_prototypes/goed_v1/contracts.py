"""
GOED v1 — Phase 2: Generative Research Contract
Defines the core output primitive for open-ended discovery.

A GenerativeResearchOpportunity is produced WITHOUT receiving any
vulnerability label. It represents a security-research direction
derived purely from observed target behavior.

ADDITIVE ONLY — does not modify any existing CQA/RTA/IRTA behavior.
"""
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class OpportunityType(Enum):
    AUTH_WEAKNESS = "authorization_weakness"
    BOUNDARY_VIOLATION = "boundary_violation"
    INVARIANT_BREAK = "invariant_break"
    DATA_EXPOSURE = "data_exposure"
    WORKFLOW_GAP = "workflow_gap"
    STATE_MANIPULATION = "state_manipulation"
    UNEXPLAINED_DIFFERENCE = "unexplained_difference"
    RESEARCH_DIRECTION = "research_direction"


class ConfidenceLevel(Enum):
    SPECULATIVE = "speculative"
    SUGGESTIVE = "suggestive"
    SUBSTANTIAL = "substantial"
    CONFIRMED = "confirmed"


@dataclass
class Hypothesis:
    """A single competing explanation for an observation."""
    hypothesis_id: str = field(default_factory=lambda: "H-" + uuid.uuid4().hex[:8])
    description: str = ""
    hypothesis_type: OpportunityType = OpportunityType.RESEARCH_DIRECTION
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    discriminating_experiment: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.SPECULATIVE
    security_relevant: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "description": self.description,
            "type": self.hypothesis_type.value,
            "supporting": self.supporting_evidence,
            "contradicting": self.contradicting_evidence,
            "discriminating_experiment": self.discriminating_experiment,
            "confidence": self.confidence.value,
            "security_relevant": self.security_relevant,
        }


@dataclass
class GenerativeResearchOpportunity:
    """
    The core generative discovery primitive.

    Produced WITHOUT vulnerability labels. Derived from observed behavior only.
    """
    opportunity_id: str = field(default_factory=lambda: "GRO-" + uuid.uuid4().hex[:10])
    source_observation: str = ""
    security_assumption: str = ""
    affected_entity: str = ""
    inferred_relationship: str = ""
    hypothesis: Hypothesis = field(default_factory=Hypothesis)
    alternative_hypotheses: list[Hypothesis] = field(default_factory=list)
    expected_signal: str = ""
    validation_plan: str = ""
    confidence: ConfidenceLevel = ConfidenceLevel.SPECULATIVE
    evidence_dependencies: list[str] = field(default_factory=list)
    generation_reason: str = ""
    context_differences: dict[str, Any] = field(default_factory=dict)
    exploration_priority: float = 0.5
    investigated: bool = False
    investigation_result: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "opportunity_id": self.opportunity_id,
            "source_observation": self.source_observation,
            "security_assumption": self.security_assumption,
            "affected_entity": self.affected_entity,
            "inferred_relationship": self.inferred_relationship,
            "hypothesis": self.hypothesis.to_dict(),
            "alternative_hypotheses": [h.to_dict() for h in self.alternative_hypotheses],
            "expected_signal": self.expected_signal,
            "validation_plan": self.validation_plan,
            "confidence": self.confidence.value,
            "evidence_dependencies": self.evidence_dependencies,
            "generation_reason": self.generation_reason,
            "context_differences": self.context_differences,
            "exploration_priority": self.exploration_priority,
            "investigated": self.investigated,
            "investigation_result": self.investigation_result,
        }

    def all_hypotheses(self) -> list[Hypothesis]:
        return [self.hypothesis] + self.alternative_hypotheses

    def security_hypotheses(self) -> list[Hypothesis]:
        return [h for h in self.all_hypotheses() if h.security_relevant]


def create_opportunity_from_observation(
    observation_summary: str,
    entity: str,
    context_diff: dict[str, Any],
    generation_reason: str,
) -> GenerativeResearchOpportunity:
    """
    Create a research opportunity from a raw observation.
    No vulnerability labels are used or consulted.
    Always generates COMPETING hypotheses (Phase 5 pattern).
    """
    gro = GenerativeResearchOpportunity(
        source_observation=observation_summary,
        affected_entity=entity,
        context_differences=context_diff,
        generation_reason=generation_reason,
    )

    gro.hypothesis = Hypothesis(
        description="Observed difference may indicate an authorization boundary weakness",
        hypothesis_type=OpportunityType.AUTH_WEAKNESS,
        supporting_evidence=["Response differs across actor contexts"],
        discriminating_experiment="Test with additional actor/role combinations",
        confidence=ConfidenceLevel.SPECULATIVE,
    )

    gro.alternative_hypotheses = [
        Hypothesis(
            description="Legitimate role-based content variation",
            hypothesis_type=OpportunityType.RESEARCH_DIRECTION,
            supporting_evidence=["Different roles may legitimately see different content"],
            discriminating_experiment="Verify with same-role different-identity test",
            confidence=ConfidenceLevel.SPECULATIVE,
            security_relevant=False,
        ),
        Hypothesis(
            description="Tenant-scoped data difference",
            hypothesis_type=OpportunityType.BOUNDARY_VIOLATION,
            supporting_evidence=["Different tenants may legitimately have different data"],
            discriminating_experiment="Test cross-tenant access patterns",
            confidence=ConfidenceLevel.SPECULATIVE,
        ),
        Hypothesis(
            description="Public-resource behavior with personalization",
            hypothesis_type=OpportunityType.RESEARCH_DIRECTION,
            supporting_evidence=["Endpoint may be public but personalized"],
            discriminating_experiment="Test with unauthenticated context",
            confidence=ConfidenceLevel.SPECULATIVE,
            security_relevant=False,
        ),
    ]

    gro.security_assumption = "Actors without authorization should not access or infer protected data"
    gro.expected_signal = "Authorization differential between candidate and control paths"
    gro.validation_plan = "Execute same-context comparison across candidate and negative control"
    gro.inferred_relationship = "Actor context correlates with response content variation"

    return gro


GOED_V1_GOVERNANCE = {
    "no_vulnerability_labels_used": True,
    "no_target_specific_knowledge": True,
    "no_benchmark_imports": True,
    "additive_only": True,
    "preserves_cqa_rta_irta": True,
    "causal_guard_mandatory": True,
}
