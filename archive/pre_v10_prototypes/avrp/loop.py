"""Bounded autonomous research loop facade for AVRP."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.asros.adaptive_strategy import (
    AdaptiveStrategyEngine,
    OutcomeKind,
    ResearchDirection,
    StrategyDecision,
)
from webpent.asros.adaptive_strategy import (
    ResearchOutcome as AdaptiveResearchOutcome,
)
from webpent.asros.world_model import SecurityWorldModel
from webpent.avde.behavior import BehavioralSurface, BehavioralSurfaceDiscovery
from webpent.avde.discovery import DiscoveryHypothesis, DiscoveryHypothesisEngine
from webpent.avde.exploration import (
    AttackPath,
    AttackPathExplorer,
    AutonomousValidationStrategy,
    ValidationPlan,
)
from webpent.avrp.correlation import EvidenceCorrelationEngine, EvidenceRelationshipGraph
from webpent.avrp.coverage import CoverageIntelligence, CoverageRecord
from webpent.avrp.patterns import VulnerabilityPatternLibrary
from webpent.avrp.state import ResearchMemoryState
from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.models.research import InformationObservation


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _items(value: Any, limit: int = 30) -> tuple[str, ...]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return ()
    result: list[str] = []
    for item in value:
        clean = _clean(item, 240)
        if clean and clean not in result:
            result.append(clean)
    return tuple(result[:limit])


class ResearchStep(BaseModel):
    """One bounded loop step with explicit status and evidence lineage."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    step_id: str = Field(min_length=3, max_length=120)
    step_type: Literal[
        "state_restore",
        "discover",
        "correlate",
        "prioritize",
        "plan",
        "review",
        "learn",
        "adjust_strategy",
        "blocked",
    ]
    status: Literal["completed", "blocked", "skipped"]
    input_refs: tuple[str, ...] = Field(default=(), max_length=50)
    output_refs: tuple[str, ...] = Field(default=(), max_length=50)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=50)
    reason: str = Field(min_length=3, max_length=500)
    advisory_only: bool = True

    @field_validator("step_id", "step_type", "status", "reason", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> str:
        return _clean(value)

    @field_validator("input_refs", "output_refs", "evidence_refs", mode="before")
    @classmethod
    def _redact_refs(cls, value: Any) -> tuple[str, ...]:
        return _items(value, 50)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        return clean


class AutonomousResearchReport(BaseModel):
    """Complete report of a bounded AVRP research pass."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    report_id: str = Field(min_length=3, max_length=120)
    target_ref: str = Field(min_length=3, max_length=500)
    engagement_id: str = Field(min_length=3, max_length=160)
    hypotheses: tuple[DiscoveryHypothesis, ...] = Field(default=(), max_length=200)
    behavioral_surfaces: tuple[BehavioralSurface, ...] = Field(default=(), max_length=200)
    coverage: CoverageRecord | None = None
    evidence_graph: EvidenceRelationshipGraph | None = None
    selected_plan: ValidationPlan | None = None
    strategy_decision: StrategyDecision | None = None
    updated_memory_state: ResearchMemoryState | None = None
    steps: tuple[ResearchStep, ...] = Field(default=(), max_length=100)
    patterns_considered: tuple[str, ...] = Field(default=(), max_length=100)
    execution_performed: bool = False
    finding_created: bool = False
    policy_overridden: bool = False
    status: Literal["advisory", "blocked", "empty"] = "advisory"

    @field_validator("report_id", "target_ref", "engagement_id", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> str:
        return _clean(value)

    @field_validator("patterns_considered", mode="before")
    @classmethod
    def _redact_patterns(cls, value: Any) -> tuple[str, ...]:
        return _items(value, 100)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        return clean

    def stable_hash(self) -> str:
        return hashlib.sha256(canonical_json(self.as_dict()).encode()).hexdigest()


class AutonomousResearchLoopV2:
    """Compose existing AVDE contracts into a no-I/O advisory loop."""

    def __init__(
        self,
        *,
        discovery: DiscoveryHypothesisEngine | None = None,
        path_explorer: AttackPathExplorer | None = None,
        validation_strategy: AutonomousValidationStrategy | None = None,
        surface_discovery: BehavioralSurfaceDiscovery | None = None,
        coverage: CoverageIntelligence | None = None,
        patterns: VulnerabilityPatternLibrary | None = None,
        correlation: EvidenceCorrelationEngine | None = None,
        adaptive_strategy: AdaptiveStrategyEngine | None = None,
    ) -> None:
        self.discovery = discovery or DiscoveryHypothesisEngine()
        self.path_explorer = path_explorer or AttackPathExplorer()
        self.validation_strategy = validation_strategy or AutonomousValidationStrategy()
        self.surface_discovery = surface_discovery or BehavioralSurfaceDiscovery()
        self.coverage = coverage or CoverageIntelligence()
        self.patterns = patterns or VulnerabilityPatternLibrary()
        self.correlation = correlation or EvidenceCorrelationEngine()
        self.adaptive_strategy = adaptive_strategy or AdaptiveStrategyEngine()

    def run(
        self,
        world_model: SecurityWorldModel,
        *,
        target_ref: str,
        observations: Iterable[Mapping[str, Any]] = (),
        behavioral_observations: Iterable[Mapping[str, Any]] = (),
        attack_graph: Iterable[Mapping[str, Any]] = (),
        historical_evidence: Iterable[Mapping[str, Any]] = (),
        previous_failures: Iterable[Mapping[str, Any]] = (),
        prior_hypotheses: Iterable[DiscoveryHypothesis] = (),
        available_capabilities: Iterable[str] = (),
        memory_state: ResearchMemoryState | None = None,
        evidence_observations: Iterable[InformationObservation] = (),
    ) -> AutonomousResearchReport:
        """Run discovery/planning/review only; never performs transport or mutation."""
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        target = _clean(target_ref)
        if not target or target != world_model.target_id:
            raise ValueError("target scope mismatch")
        observations_tuple = tuple(observations)
        behavior_tuple = tuple(behavioral_observations)
        history_tuple = tuple(historical_evidence)
        failures_tuple = tuple(previous_failures)
        steps: list[ResearchStep] = []
        if memory_state is not None:
            if (
                memory_state.target_ref != target
                or memory_state.engagement_id != world_model.engagement_id
            ):
                raise ValueError("memory scope mismatch")
            steps.append(
                ResearchStep(
                    step_id="step:state-restore",
                    step_type="state_restore",
                    status="completed",
                    input_refs=("memory_state",),
                    output_refs=("memory_state:scoped",),
                    evidence_refs=tuple(
                        memory_state.updates[-3:][i].evidence_refs[0]
                        for i in range(len(memory_state.updates[-3:]))
                    ),
                    reason="Scoped historical state accepted for advisory context.",
                )
            )
        hypotheses = self.discovery.generate(
            world_model,
            observations=observations_tuple,
            attack_graph=attack_graph,
            prior_hypotheses=prior_hypotheses,
            historical_evidence=history_tuple,
            previous_failures=failures_tuple,
        )
        steps.append(
            ResearchStep(
                step_id="step:discover",
                step_type="discover",
                status="completed" if hypotheses else "blocked",
                output_refs=tuple(item.hypothesis_id for item in hypotheses),
                evidence_refs=tuple(item for item in _items(history_tuple, 10)),
                reason=(
                    "Generated deterministic hypotheses from the supplied world model "
                    "and evidence context."
                    if hypotheses
                    else "No eligible hypotheses were generated from the supplied context."
                ),
            )
        )
        surfaces = self.surface_discovery.discover(behavior_tuple)
        steps.append(
            ResearchStep(
                step_id="step:surface",
                step_type="correlate",
                status="completed" if surfaces else "blocked",
                output_refs=tuple(item.surface_id for item in surfaces),
                evidence_refs=tuple(sorted({ref for item in surfaces for ref in item.source_refs})),
                reason="Extracted report-safe behavioral surfaces from recorded observations.",
            )
        )
        coverage = self.coverage.summarize(observations_tuple, target_ref=target)
        evidence_items = tuple(evidence_observations)
        evidence_graph = (
            self.correlation.correlate(evidence_items, target_ref=target)
            if evidence_items
            else None
        )
        if evidence_items:
            steps.append(
                ResearchStep(
                    step_id="step:evidence-correlation",
                    step_type="correlate",
                    status="completed"
                    if evidence_graph and evidence_graph.relationships
                    else "blocked",
                    output_refs=tuple(
                        item.relationship_id
                        for item in (evidence_graph.relationships if evidence_graph else ())
                    ),
                    evidence_refs=tuple(
                        ref for item in evidence_items for ref in item.evidence_refs
                    ),
                    reason=(
                        "Correlated typed recorded observations into advisory relationships."
                        if evidence_graph and evidence_graph.relationships
                        else "No relationship satisfied the explicit correlation rules."
                    ),
                )
            )
        paths: tuple[AttackPath, ...] = self.path_explorer.explore(
            tuple(attack_graph),
            target_id=target,
            available_capabilities=tuple(available_capabilities),
        )
        plan: ValidationPlan | None = None
        if paths and hypotheses:
            plan = self.validation_strategy.choose(
                hypotheses[0],
                paths,
                available_capabilities=tuple(available_capabilities),
            )
        steps.append(
            ResearchStep(
                step_id="step:prioritize",
                step_type="prioritize",
                status="completed" if hypotheses else "blocked",
                input_refs=tuple(item.hypothesis_id for item in hypotheses),
                output_refs=tuple(item.path_id for item in paths),
                evidence_refs=tuple(coverage.evidence_refs),
                reason=(
                    "Ranked advisory paths using impact, confidence, cost, and capability "
                    "availability."
                ),
            )
        )
        if plan is not None:
            steps.append(
                ResearchStep(
                    step_id="step:plan",
                    step_type="plan",
                    status="completed" if plan.decision != "blocked" else "blocked",
                    input_refs=tuple(item.path_id for item in paths),
                    output_refs=((plan.selected_path_id,) if plan.selected_path_id else ()),
                    evidence_refs=tuple(coverage.evidence_refs),
                    reason=(
                        "Produced a bounded validation plan; execution remains delegated "
                        "to central controls."
                    ),
                )
            )
        adaptive_outcomes = tuple(
            AdaptiveResearchOutcome(
                task_id=f"failure:{index}",
                hypothesis_id=str(item.get("hypothesis_id", "unknown")),
                direction=ResearchDirection.ENDPOINT,
                outcome=OutcomeKind.FAILED,
                evidence_refs=tuple(_items(item.get("evidence_refs", ()), 20)),
                reason=_clean(item.get("reason", "Recorded prior failure"), 320),
            )
            for index, item in enumerate(failures_tuple)
            if isinstance(item, Mapping)
        )
        strategy_decision = self.adaptive_strategy.decide(
            current_direction=ResearchDirection.ENDPOINT,
            outcomes=adaptive_outcomes,
            hypothesis_failures=0,
        )
        steps.append(
            ResearchStep(
                step_id="step:adjust-strategy",
                step_type="adjust_strategy",
                status="completed",
                input_refs=tuple(item.task_id for item in adaptive_outcomes),
                output_refs=tuple(item.value for item in strategy_decision.next_directions),
                evidence_refs=tuple(
                    ref for item in adaptive_outcomes for ref in item.evidence_refs
                ),
                reason=strategy_decision.rationale,
            )
        )
        updated_memory_state = memory_state
        if memory_state is not None and coverage.unknown_areas and coverage.evidence_refs:
            updated_memory_state = memory_state.apply_update(
                field_name="unknown_areas",
                value=coverage.unknown_areas,
                evidence_refs=coverage.evidence_refs,
                confidence=coverage.completeness,
                reason="Coverage intelligence recorded remaining unexplored dimensions.",
                timestamp="2026-08-27T00:00:00+00:00",
            )
        pattern_names: set[str] = set()
        for hypothesis in hypotheses:
            for pattern in self.patterns.match(evidence_kinds=list(hypothesis.expected_evidence)):
                pattern_names.add(pattern.pattern_id)
        steps.append(
            ResearchStep(
                step_id="step:review",
                step_type="review",
                status="completed",
                input_refs=tuple(item.hypothesis_id for item in hypotheses),
                output_refs=tuple(sorted(pattern_names)),
                evidence_refs=tuple(coverage.evidence_refs),
                reason=(
                    "Advisory patterns and coverage were reviewed; no promotion or finding "
                    "creation is allowed."
                ),
            )
        )
        report_id = (
            "report:"
            + hashlib.sha256(
                canonical_json(
                    {
                        "target_ref": target,
                        "engagement_id": world_model.engagement_id,
                        "hypothesis_ids": [item.hypothesis_id for item in hypotheses],
                        "coverage": coverage.record_id,
                    }
                ).encode()
            ).hexdigest()[:24]
        )
        return AutonomousResearchReport(
            report_id=report_id,
            target_ref=target,
            engagement_id=world_model.engagement_id,
            hypotheses=hypotheses,
            behavioral_surfaces=surfaces,
            coverage=coverage,
            evidence_graph=evidence_graph,
            selected_plan=plan,
            strategy_decision=strategy_decision,
            updated_memory_state=updated_memory_state,
            steps=tuple(steps),
            patterns_considered=tuple(sorted(pattern_names)),
            status="advisory" if hypotheses or surfaces else "empty",
        )


__all__ = ["AutonomousResearchLoopV2", "AutonomousResearchReport", "ResearchStep"]
