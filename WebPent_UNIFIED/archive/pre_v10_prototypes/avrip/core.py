"""AVRIP v2 bounded research-intelligence composition layer."""

from __future__ import annotations

from collections.abc import Iterable

from pydantic import BaseModel, ConfigDict, Field

from webpent.asros.adaptive_strategy import ResearchDirection
from webpent.asros.world_model import SecurityWorldModel
from webpent.avrip.assumptions import (
    AssumptionDiscoveryReport,
    SecurityAssumptionDiscoveryEngine,
)
from webpent.avrip.cross_domain import (
    CrossDomainAttackReasoner,
    CrossDomainReasoningReport,
)
from webpent.avrip.evidence import EvidenceAssessment, EvidenceIntelligenceV2, EvidenceItem
from webpent.avrip.intent import ApplicationIntentV2
from webpent.avrip.memory import AutonomousResearchMemoryV2, ResearchMemorySnapshotV2
from webpent.avrip.optimizer import (
    ResearchStrategyOptimizerV2,
    StrategyObservation,
    StrategyOptimizationReport,
)
from webpent.avrip.reasoning import DeepReasoningReport, DeepVulnerabilityReasoner
from webpent.avrip.review import SeniorResearchAssessment, SeniorResearchReviewerV2
from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.models.attack_graph import AttackGraph


class AVRIPAnalysisReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    intent: ApplicationIntentV2
    assumptions: AssumptionDiscoveryReport
    reasoning: DeepReasoningReport
    cross_domain: CrossDomainReasoningReport
    evidence_assessments: tuple[EvidenceAssessment, ...] = Field(default=(), max_length=512)
    optimization: StrategyOptimizationReport
    reviews: tuple[SeniorResearchAssessment, ...] = Field(default=(), max_length=512)
    memory: ResearchMemorySnapshotV2
    requests_emitted: bool = False
    findings_created: int = Field(default=0, ge=0)
    qualification_effect: bool = False
    advisory_only: bool = True


class AVRIPCoreV2:
    """Run one deterministic, offline analysis over caller-supplied projections."""

    def __init__(self) -> None:
        self._assumptions = SecurityAssumptionDiscoveryEngine()
        self._reasoner = DeepVulnerabilityReasoner()
        self._cross_domain = CrossDomainAttackReasoner()
        self._evidence = EvidenceIntelligenceV2()
        self._optimizer = ResearchStrategyOptimizerV2()
        self._reviewer = SeniorResearchReviewerV2()

    def analyze(
        self,
        *,
        world_model: SecurityWorldModel,
        knowledge: TargetKnowledgeV2 | None = None,
        attack_graph: AttackGraph | None = None,
        current_direction: ResearchDirection = ResearchDirection.RELATIONSHIP,
        strategy_observations: Iterable[StrategyObservation] = (),
        evidence_items: Iterable[EvidenceItem] = (),
        memory_lessons: Iterable[tuple[str, str, str, tuple[str, ...]]] = (),
    ) -> AVRIPAnalysisReport:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        intent = ApplicationIntentV2.from_world_model(world_model)
        assumptions = self._assumptions.discover(world_model=world_model, intent=intent)
        reasoning = self._reasoner.reason(
            world_model=world_model,
            assumptions=assumptions.assumptions,
            knowledge=knowledge,
            attack_graph=attack_graph,
        )
        if knowledge is not None and attack_graph is not None:
            cross_domain = self._cross_domain.reason(
                knowledge=knowledge,
                attack_graph=attack_graph,
                assumptions=assumptions.assumptions,
            )
        else:
            cross_domain = CrossDomainReasoningReport(
                engagement_id=world_model.engagement_id,
                target_id=world_model.target_id,
                blocked_reasons=("knowledge_and_attack_graph_required_for_cross_domain_join",),
            )
        supplied_evidence = tuple(evidence_items)
        assessments = tuple(
            self._evidence.assess(
                hypothesis_id=hypothesis.hypothesis_id,
                items=supplied_evidence,
            )
            for hypothesis in reasoning.hypotheses
        )
        candidates = tuple(
            (f"assumption:{item.assumption_id}", _direction_for_assumption(item.kind.value))
            for item in assumptions.assumptions
        )
        optimization = self._optimizer.optimize(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            current_direction=current_direction,
            observations=tuple(strategy_observations),
            candidate_strategies=candidates,
        )
        reviews = tuple(
            self._reviewer.assess(
                hypothesis=hypothesis,
                evidence=assessment,
                alternative_explanations=(),
                central_review_passed=False,
            )
            for hypothesis, assessment in zip(
                reasoning.hypotheses, assessments, strict=True
            )
        )
        memory = AutonomousResearchMemoryV2(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
        )
        for category, summary, outcome, refs in memory_lessons:
            memory.remember_lesson(
                category=category,
                summary=summary,
                outcome=outcome,
                evidence_refs=refs,
            )
        return AVRIPAnalysisReport(
            intent=intent,
            assumptions=assumptions,
            reasoning=reasoning,
            cross_domain=cross_domain,
            evidence_assessments=assessments,
            optimization=optimization,
            reviews=reviews,
            memory=memory.snapshot(),
        )


def _direction_for_assumption(kind: str) -> ResearchDirection:
    return {
        "workflow": ResearchDirection.WORKFLOW,
        "state_integrity": ResearchDirection.WORKFLOW,
        "ownership": ResearchDirection.RELATIONSHIP,
        "tenant_isolation": ResearchDirection.TRUST_BOUNDARY,
        "role_separation": ResearchDirection.TRUST_BOUNDARY,
        "data_access": ResearchDirection.EVIDENCE,
    }.get(kind, ResearchDirection.RELATIONSHIP)


__all__ = ["AVRIPAnalysisReport", "AVRIPCoreV2"]
