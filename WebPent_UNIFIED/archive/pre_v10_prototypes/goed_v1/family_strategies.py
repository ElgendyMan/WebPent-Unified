"""GOED v1 — Five-Family Strategy Layer (additive).

Mirrors ``business_logic_strategies.py``. Each strategy hypothesizes from
observed evidence only (never ground truth), produces competing benign
explanations, and requires causal state evidence before any finding.

ADDITIVE ONLY — does not modify CQA/RTA/IRTA or the existing invariant
strategies. Imported by the integrated evaluator as an extra strategy
source (see ``integrated_evaluator.py`` wiring note below).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.goed_v1.contracts import (
    ConfidenceLevel,
    Hypothesis,
    OpportunityType,
)
from webpent.race_conditions.scenarios import RACE_SCENARIOS
from webpent.tenant_isolation.scenarios import TENANT_SCENARIOS
from webpent.multi_step_auth.scenarios import MULTI_STEP_AUTH_SCENARIOS
from webpent.chained_exploits.scenarios import CHAIN_SCENARIOS
from webpent.oauth.scenarios import OAUTH_SCENARIOS

try:  # business_logic package requires optional langchain layer at __init__
    from webpent.business_logic.scenarios import BUSINESS_LOGIC_SCENARIOS
    _BIZ_DEGRADED = False
except Exception:  # pragma: no cover - optional dependency surface
    BUSINESS_LOGIC_SCENARIOS = ()
    _BIZ_DEGRADED = True


class StrategyStrength(str, Enum):
    HYPOTHESIZED = "HYPOTHESIZED"
    SUGGESTED = "SUGGESTED"
    CORROBORATED = "CORROBORATED"


@dataclass
class FamilyStrategyHypothesis:
    """A hypothesized family-level violation derived from observations."""

    hypothesis_id: str
    family: str
    scenario_id: str
    invariant_type: str
    description: str
    strength: StrategyStrength = StrategyStrength.HYPOTHESIZED
    supporting_evidence: list[str] = field(default_factory=list)
    benign_alternatives: list[str] = field(default_factory=list)
    discriminating_experiment: str = ""


class BaseFamilyStrategy:
    """Base class for the five family strategies."""

    strategy_name = "base"
    family_id = "base"
    scenarios: tuple[Any, ...] = ()

    def applicable(self, observations: list[dict[str, Any]]) -> list[Any]:
        observed: set[str] = set()
        for obs in observations:
            for cap in obs.get("capabilities", []):
                observed.add(str(cap))
            for tag in obs.get("tags", []):
                observed.add(str(tag))
        return [s for s in self.scenarios if s.is_applicable(observed)]

    def hypothesize(self, observations: list[dict[str, Any]]) -> list[FamilyStrategyHypothesis]:
        hyps: list[FamilyStrategyHypothesis] = []
        for idx, scenario in enumerate(self.applicable(observations)):
            hyps.append(
                FamilyStrategyHypothesis(
                    hypothesis_id=f"{self.family_id}-H{idx}",
                    family=self.family_id,
                    scenario_id=scenario.scenario_id,
                    invariant_type=scenario.name,
                    description=scenario.description,
                    strength=StrategyStrength.HYPOTHESIZED,
                    supporting_evidence=[
                        f"observed_capabilities_match:{','.join(scenario.preconditions)}"
                    ],
                    benign_alternatives=[
                        "Endpoint may serialize mutations correctly (no race window)",
                        "Boundary may be enforced server-side despite client-visible context",
                        "Observed difference may be legitimate role-based variation",
                    ],
                    discriminating_experiment=scenario.discriminator_experiment,
                )
            )
        return hyps

    def to_goed_hypotheses(self, observations: list[dict[str, Any]]) -> list[Hypothesis]:
        """Bridge into the native GOED :class:`Hypothesis` contract."""
        out: list[Hypothesis] = []
        for h in self.hypothesize(observations):
            out.append(
                Hypothesis(
                    description=h.description,
                    hypothesis_type=self._opportunity_type(),
                    supporting_evidence=h.supporting_evidence,
                    contradicting_evidence=h.benign_alternatives,
                    discriminating_experiment=h.discriminating_experiment,
                    confidence=ConfidenceLevel.SPECULATIVE,
                )
            )
        return out

    def _opportunity_type(self) -> OpportunityType:  # pragma: no cover - overridden
        return OpportunityType.RESEARCH_DIRECTION


class RaceConditionStrategy(BaseFamilyStrategy):
    strategy_name = "race_condition"
    family_id = "race_condition"
    scenarios = RACE_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.STATE_MANIPULATION


class TenantIsolationStrategy(BaseFamilyStrategy):
    strategy_name = "tenant_isolation"
    family_id = "tenant_isolation"
    scenarios = TENANT_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.BOUNDARY_VIOLATION


class MultiStepAuthBypassStrategy(BaseFamilyStrategy):
    strategy_name = "multi_step_auth_bypass"
    family_id = "multi_step_auth_bypass"
    scenarios = MULTI_STEP_AUTH_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.WORKFLOW_GAP


class ChainedExploitStrategy(BaseFamilyStrategy):
    strategy_name = "chained_exploit"
    family_id = "chained_exploit"
    scenarios = CHAIN_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.INVARIANT_BREAK


class BusinessLogicStrategy(BaseFamilyStrategy):
    strategy_name = "business_logic"
    family_id = "business_logic"
    scenarios = BUSINESS_LOGIC_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.WORKFLOW_GAP


class OAuthStrategy(BaseFamilyStrategy):
    strategy_name = "oauth"
    family_id = "oauth"
    scenarios = OAUTH_SCENARIOS

    def _opportunity_type(self) -> OpportunityType:
        return OpportunityType.AUTH_WEAKNESS


ALL_FAMILY_STRATEGIES: tuple[type[BaseFamilyStrategy], ...] = (
    RaceConditionStrategy,
    TenantIsolationStrategy,
    MultiStepAuthBypassStrategy,
    ChainedExploitStrategy,
    BusinessLogicStrategy,
    OAuthStrategy,
)

FAMILY_STRATEGY_REGISTRY: dict[str, type[BaseFamilyStrategy]] = {
    cls.strategy_name: cls for cls in ALL_FAMILY_STRATEGIES
}


def generate_all_family_hypotheses(
    observations: list[dict[str, Any]],
) -> list[FamilyStrategyHypothesis]:
    """Entry point for the exploration loop (additive strategy source)."""
    all_hyps: list[FamilyStrategyHypothesis] = []
    for strategy_cls in ALL_FAMILY_STRATEGIES:
        all_hyps.extend(strategy_cls().hypothesize(observations))
    return all_hyps


def generate_all_family_goed_hypotheses(observations: list[dict[str, Any]]) -> list[Hypothesis]:
    """Bridge all five families into native GOED :class:`Hypothesis` objects."""
    out: list[Hypothesis] = []
    for strategy_cls in ALL_FAMILY_STRATEGIES:
        out.extend(strategy_cls().to_goed_hypotheses(observations))
    return out


FIVE_FAMILY_GOVERNANCE = {
    "hypotheses_from_evidence_only": True,
    "never_injected_from_ground_truth": True,
    "finding_requires_causal_state_evidence": True,
    "competing_benign_explanations_always_generated": True,
    "additive_only": True,
    "preserves_cqa_rta_irta": True,
    "causal_guard_mandatory": True,
    # fail-visible: when langchain optional layer is absent, business_logic
    # strategy degrades to zero scenarios — this flag makes it observable.
    "business_logic_strategy_degraded": _BIZ_DEGRADED,
}

__all__ = [
    "StrategyStrength",
    "FamilyStrategyHypothesis",
    "BaseFamilyStrategy",
    "RaceConditionStrategy",
    "TenantIsolationStrategy",
    "MultiStepAuthBypassStrategy",
    "ChainedExploitStrategy",
    "BusinessLogicStrategy",
    "ALL_FAMILY_STRATEGIES",
    "FAMILY_STRATEGY_REGISTRY",
    "generate_all_family_hypotheses",
    "generate_all_family_goed_hypotheses",
    "FIVE_FAMILY_GOVERNANCE",
]
