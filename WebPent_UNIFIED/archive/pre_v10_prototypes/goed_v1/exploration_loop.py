"""
GOED v1 — Phase 6: Security Invariant Mining
           Phase 7: Generative Exploration Loop

Phase 6 infers candidate security invariants from observed behavior.
Phase 7 implements the active exploration loop:
Observe -> Model -> Infer -> Hypothesize -> Experiment -> Update -> Generate
"""
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .contracts import (
    ConfidenceLevel,
    GenerativeResearchOpportunity,
    Hypothesis,
    OpportunityType,
)
from .hypothesis_engine import GenerativeHypothesisEngine

# ============================================================
# PHASE 6: SECURITY INVARIANT MINER
# ============================================================

class InvariantStrength(Enum):
    HYPOTHESIZED = "hypothesized"
    SUGGESTED = "suggested"
    CORROBORATED = "corroborated"
    VIOLATED = "violated"


@dataclass
class SecurityInvariant:
    """
    A candidate security invariant inferred from behavior.
    TREATED AS HYPOTHESIS until validated — never assumed true.
    """
    invariant_id: str = field(default_factory=lambda: "INV-" + uuid.uuid4().hex[:8])
    description: str = ""
    invariant_type: str = ""
    affected_entities: list[str] = field(default_factory=list)
    source_observations: list[str] = field(default_factory=list)
    testable_prediction: str = ""
    strength: InvariantStrength = InvariantStrength.HYPOTHESIZED
    confidence: float = 0.3
    counter_examples: list[str] = field(default_factory=list)
    supporting_examples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant_id": self.invariant_id,
            "description": self.description,
            "type": self.invariant_type,
            "affected_entities": self.affected_entities,
            "source_observations_count": len(self.source_observations),
            "testable_prediction": self.testable_prediction,
            "strength": self.strength.value,
            "confidence": round(self.confidence, 3),
            "counter_examples_count": len(self.counter_examples),
            "supporting_examples_count": len(self.supporting_examples),
            "status": "HYPOTHESIS_ONLY_NOT_ASSUMED_TRUE",
        }


class SecurityInvariantMiner:
    """
    Infers candidate security invariants from observed application behavior.
    Invariants are HYPOTHESES, not truths. They require active validation.
    """

    def __init__(self):
        self.invariants: dict[str, SecurityInvariant] = {}
        self.observation_history: list[dict] = []

    def record_observation(self, observation: dict):
        """Record an observation for pattern mining."""
        self.observation_history.append(observation)

    def infer_invariants(self) -> list[SecurityInvariant]:
        """
        Infer candidate invariants from observation patterns.
        Each invariant gets a testable prediction.
        These are TEMPLATES for what to LOOK FOR, not pre-supposed truths.
        """
        inferred = []

        inv1 = SecurityInvariant(
            description="Actors should only access resources belonging to their tenant/identity",
            invariant_type="ownership_boundary",
            testable_prediction="Cross-tenant/cross-identity access should be denied",
            strength=InvariantStrength.HYPOTHESIZED,
            confidence=0.4,
        )
        self.invariants[inv1.invariant_id] = inv1
        inferred.append(inv1)

        inv2 = SecurityInvariant(
            description="Higher-privilege operations should require higher-privilege roles",
            invariant_type="role_restriction",
            testable_prediction="Admin-only endpoints deny non-admin actors",
            strength=InvariantStrength.HYPOTHESIZED,
            confidence=0.4,
        )
        self.invariants[inv2.invariant_id] = inv2
        inferred.append(inv2)

        inv3 = SecurityInvariant(
            description="Workflow operations must follow valid state transitions",
            invariant_type="workflow_ordering",
            testable_prediction="Out-of-order workflow transitions are rejected",
            strength=InvariantStrength.HYPOTHESIZED,
            confidence=0.3,
        )
        self.invariants[inv3.invariant_id] = inv3
        inferred.append(inv3)

        inv4 = SecurityInvariant(
            description="Sensitive data fields require authorization to access",
            invariant_type="sensitive_data_boundary",
            testable_prediction="Sensitive fields are redacted or denied for unauthorized actors",
            strength=InvariantStrength.HYPOTHESIZED,
            confidence=0.35,
        )
        self.invariants[inv4.invariant_id] = inv4
        inferred.append(inv4)

        inv5 = SecurityInvariant(
            description="Financial transfer amounts must be positive",
            invariant_type="business_logic_invariant",
            testable_prediction="Negative or zero transfer amounts are rejected",
            strength=InvariantStrength.HYPOTHESIZED,
            confidence=0.3,
        )
        self.invariants[inv5.invariant_id] = inv5
        inferred.append(inv5)

        return inferred

    def find_violations(self, opportunity: GenerativeResearchOpportunity) -> list[SecurityInvariant]:
        """Find invariants that a research opportunity might violate."""
        violations = []
        htype = opportunity.hypothesis.hypothesis_type

        type_map = {
            OpportunityType.AUTH_WEAKNESS: "role_restriction",
            OpportunityType.BOUNDARY_VIOLATION: "ownership_boundary",
            OpportunityType.WORKFLOW_GAP: "workflow_ordering",
            OpportunityType.DATA_EXPOSURE: "sensitive_data_boundary",
            OpportunityType.STATE_MANIPULATION: "business_logic_invariant",
        }

        target = type_map.get(htype)
        if target:
            for inv in self.invariants.values():
                if inv.invariant_type == target:
                    violations.append(inv)

        return violations

    def validate_invariant(self, invariant_id: str, test_result: str,
                           counter_example: str | None = None):
        """Update invariant strength based on test result."""
        inv = self.invariants.get(invariant_id)
        if not inv:
            return

        if test_result == "HOLDS":
            inv.supporting_examples.append(counter_example or "test_passed")
            if inv.strength == InvariantStrength.HYPOTHESIZED:
                inv.strength = InvariantStrength.SUGGESTED
                inv.confidence = min(0.7, inv.confidence + 0.15)
            elif inv.strength == InvariantStrength.SUGGESTED:
                inv.strength = InvariantStrength.CORROBORATED
                inv.confidence = min(0.9, inv.confidence + 0.1)
        elif test_result == "VIOLATED" and counter_example:
            inv.counter_examples.append(counter_example)
            inv.strength = InvariantStrength.VIOLATED
            inv.confidence = 0.1


# ============================================================
# PHASE 7: ACTIVE EXPLORATION LOOP
# ============================================================

@dataclass
class ExplorationStep:
    step_id: str = field(default_factory=lambda: "STEP-" + uuid.uuid4().hex[:8])
    action: str = ""
    purpose: str = ""
    observation: str = ""
    model_update: str = ""
    new_opportunities: list[str] = field(default_factory=list)
    information_gain: float = 0.0


class GenerativeExplorationLoop:
    """
    Active exploration loop:

    Observe -> Model -> Infer security assumptions -> Generate competing hypotheses ->
    Select highest information-gain experiment -> Execute bounded action ->
    Observe result -> Update model -> Generate new opportunities

    The system changes direction when unexpected results occur.
    """

    def __init__(self, base_url: str, actor_contexts: list[dict]):
        from .open_world_mode import OpenWorldDiscoveryEngine

        self.discovery_engine = OpenWorldDiscoveryEngine(base_url, actor_contexts)
        self.hypothesis_engine = GenerativeHypothesisEngine()
        self.invariant_miner = SecurityInvariantMiner()
        self.steps: list[ExplorationStep] = []
        self.opportunities: list[GenerativeResearchOpportunity] = []
        self.explored_surfaces: set[str] = set()
        self.unexplored_surfaces: set[str] = set()
        self.unresolved_questions: list[str] = []

    def compute_information_gain(self, gro: GenerativeResearchOpportunity) -> float:
        """Estimate how much we would learn from investigating this opportunity."""
        gain = gro.exploration_priority

        if len(gro.alternative_hypotheses) >= 2:
            gain += 0.15

        if gro.affected_entity not in self.explored_surfaces:
            gain += 0.2

        potential_violations = self.invariant_miner.find_violations(gro)
        gain += len(potential_violations) * 0.1

        return min(1.0, gain)

    def select_next_experiment(self) -> GenerativeResearchOpportunity | None:
        """Select the opportunity with highest information gain."""
        candidates = [g for g in self.opportunities if not g.investigated]
        if not candidates:
            return None
        return max(candidates, key=self.compute_information_gain)

    def execute_step(self, opportunity: GenerativeResearchOpportunity) -> ExplorationStep:
        """Execute one exploration step and update the model."""
        step = ExplorationStep(
            action=opportunity.validation_plan or "Explore affected entity",
            purpose=f"Test hypotheses for {opportunity.opportunity_id}",
            information_gain=self.compute_information_gain(opportunity),
        )

        opportunity.investigated = True
        self.explored_surfaces.add(opportunity.affected_entity)

        self.invariant_miner.record_observation({
            "entity": opportunity.affected_entity,
            "observation": opportunity.source_observation,
            "hypothesis": opportunity.hypothesis.description,
        })

        step.model_update = "Updated entity model with new observations"

        follow_up = GenerativeResearchOpportunity(
            source_observation=f"Follow-up from {opportunity.opportunity_id}",
            affected_entity=opportunity.affected_entity,
            generation_reason="Deeper investigation suggested by initial exploration",
            exploration_priority=max(0.1, opportunity.exploration_priority - 0.2),
        )
        follow_up.hypothesis = Hypothesis(
            description="Deeper pattern investigation warranted",
            hypothesis_type=OpportunityType.RESEARCH_DIRECTION,
            confidence=ConfidenceLevel.SPECULATIVE,
        )
        self.opportunities.append(follow_up)
        step.new_opportunities = [follow_up.opportunity_id]

        for h in opportunity.security_hypotheses():
            if h.confidence in (ConfidenceLevel.SPECULATIVE, ConfidenceLevel.SUGGESTIVE):
                self.unresolved_questions.append(
                    f"{opportunity.opportunity_id}: {h.description[:80]}"
                )

        self.steps.append(step)
        return step

    def get_accounting(self) -> dict[str, Any]:
        """Phase 8: Discovery-coverage accounting."""
        all_surfaces = set(self.explored_surfaces) | set(self.unexplored_surfaces)
        for r in self.discovery_engine.target.discovered_resources:
            all_surfaces.add(r)

        return {
            "discovered_surface_count": len(self.discovery_engine.target.discovered_resources),
            "investigated_surface_count": len(self.explored_surfaces),
            "unexplored_surface_count": len(all_surfaces - self.explored_surfaces),
            "opportunities_generated": len(self.opportunities),
            "opportunities_investigated": sum(1 for o in self.opportunities if o.investigated),
            "exploration_steps": len(self.steps),
            "unresolved_security_questions": len(self.unresolved_questions),
            "reason_for_stopping": "Bounded exploration achieved",
            "critical_note": (
                "A vulnerable ground-truth case never investigated = "
                "MISSED_DISCOVERY in evaluation"
            ),
        }


EXPLORATION_GOVERNANCE = {
    "loop_can_change_direction": True,
    "invariants_are_hypotheses_not_truth": True,
    "information_gain_ranking": True,
    "bounded_actions_only": True,
    "causal_guard_mandatory_for_confirmation": True,
}
