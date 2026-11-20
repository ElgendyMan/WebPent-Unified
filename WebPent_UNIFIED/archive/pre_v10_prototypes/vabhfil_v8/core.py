"""VABH-FIL v8 composition root; research reasoning only."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import VABHFILV8Result
from .executive import AutonomousResearchExecutiveV8
from .hypotheses import AutonomousHypothesisEvolutionV8
from .memory import AutonomousResearchMemoryIntelligenceV8
from .reasoning import ExpertSecurityReasoningModelV8
from .skepticism import ExpertFalsePositiveDefenseV8
from .strategy_graph import AdaptiveHuntingStrategyEngineV8, DynamicAttackGraphIntelligenceV8
from .utils import get_value, stable_id, strings


@dataclass(frozen=True, slots=True)
class VABHFILV8Core:
    executive: AutonomousResearchExecutiveV8 = AutonomousResearchExecutiveV8()
    reasoning: ExpertSecurityReasoningModelV8 = ExpertSecurityReasoningModelV8()
    hypothesis_evolution: AutonomousHypothesisEvolutionV8 = AutonomousHypothesisEvolutionV8()
    strategy_engine: AdaptiveHuntingStrategyEngineV8 = AdaptiveHuntingStrategyEngineV8()
    graph_intelligence: DynamicAttackGraphIntelligenceV8 = DynamicAttackGraphIntelligenceV8()
    skepticism: ExpertFalsePositiveDefenseV8 = ExpertFalsePositiveDefenseV8()
    memory: AutonomousResearchMemoryIntelligenceV8 | None = None

    VERSION = "vabh-fil-v8"

    def run(
        self,
        *,
        engagement_id: str,
        target_id: str,
        mental_model: object | None = None,
        knowledge_graph: object | None = None,
        attack_graph: object | None = None,
        invariants: object | None = None,
        memory: object | None = None,
        previous_findings: object | None = None,
        coverage: object | None = None,
        evidence_refs: tuple[str, ...] = (),
        previous_failures: tuple[str, ...] = (),
    ) -> VABHFILV8Result:
        executive = self.executive.decide(
            engagement_id=engagement_id,
            target_id=target_id,
            mental_model=mental_model,
            knowledge_graph=knowledge_graph,
            attack_graph=attack_graph,
            invariants=invariants,
            memory=memory,
            coverage=coverage,
            previous_findings=previous_findings,
        )
        investigations = self.reasoning.investigate(
            engagement_id=engagement_id,
            target_id=target_id,
            mental_model=mental_model,
            evidence_refs_input=evidence_refs,
        )
        hypotheses = self.hypothesis_evolution.create(investigations)
        hypotheses = self.hypothesis_evolution.compare(hypotheses)
        strategy = self.strategy_engine.choose(
            engagement_id=engagement_id,
            target_id=target_id,
            investigations=investigations,
            hypotheses=hypotheses,
            previous_failures=previous_failures,
            available_capability=strings(
                get_value(coverage, "available_capability", "capabilities")
            ),
        )
        graph_update = self.graph_intelligence.update(
            graph_id=stable_id("graph", engagement_id, target_id),
            mental_model=mental_model,
            attack_graph=attack_graph,
            investigations=investigations,
        )
        confidence_reports = tuple(
            self.skepticism.assess(
                subject_id=item.hypothesis_id,
                intended_behavior_possible=True,
                attacker_capability_realistic=False,
                impact_proven=False,
                alternative_explanations=("intended behavior or incomplete observation",),
                reproducible_by_another_researcher=False,
                evidence_refs=item.source_refs,
            )
            for item in hypotheses
        )
        memory_engine = (
            memory if isinstance(memory, AutonomousResearchMemoryIntelligenceV8) else self.memory
        )
        if memory_engine is None:
            memory_engine = AutonomousResearchMemoryIntelligenceV8()
        lessons = (
            memory_engine.learn(
                engagement_id=engagement_id,
                target_id=target_id,
                pattern="v8 advisory research cycle",
                failed_approaches=previous_failures,
                rejected_theories=tuple(
                    item.statement for item in hypotheses if item.disposition.value == "rejected"
                ),
                important_assumptions=tuple(item.assumption for item in investigations),
                validation_lesson=(
                    "do not promote without causal oracle, negative control, and replay"
                ),
                update_reason="deterministic recorded-state cycle",
                source_refs=evidence_refs,
            ),
        )
        return VABHFILV8Result(
            engagement_id=engagement_id,
            target_id=target_id,
            executive_decision=executive,
            investigations=investigations,
            strategy=strategy,
            graph_update=graph_update,
            hypotheses=hypotheses,
            confidence_reports=confidence_reports,
            memory_lessons=lessons,
        )


__all__ = ["VABHFILV8Core"]
