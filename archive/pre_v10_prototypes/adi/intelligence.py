"""Adaptive Discovery Intelligence (ADI) over existing ASROS/AVDE contracts.

ADI enriches bounded research decisions with historical context and failure
learning. It is deliberately advisory: it does not execute transport, create
findings, approve vulnerabilities, or override policy/oracles.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from webpent.asros.adaptive_strategy import OutcomeKind
from webpent.asros.quality_controller import PostExecutionReview, QualityReviewStatus
from webpent.asros.world_model import SecurityWorldModel
from webpent.avde.discovery import DiscoveryHypothesis, DiscoveryHypothesisEngine
from webpent.avde.exploration import (
    AttackPath,
    AttackPathExplorer,
    AutonomousValidationStrategy,
    ValidationPlan,
)

Outcome = Literal[
    "evidence",
    "no_evidence",
    "blocked",
    "failed",
    "inconclusive",
]


class HistoricalEvidence(BaseModel):
    """A redacted, already-recorded result used for ranking only."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    evidence_id: str = Field(min_length=1, max_length=180)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    asset: str = Field(min_length=1, max_length=240)
    outcome: Outcome
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    information_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator("evidence_refs")
    @classmethod
    def _unique_refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(str(value).strip()[:240] for value in values if str(value).strip())
        )


class FailureMemoryRecord(BaseModel):
    """Scoped learning record; it is not an execution or suppression rule."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    failure_id: str = Field(min_length=16, max_length=128)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    affected_hypothesis_id: str = Field(min_length=1, max_length=200)
    affected_asset: str = Field(min_length=1, max_length=240)
    failure_reason: str = Field(min_length=3, max_length=320)
    rejection_reason: str = Field(min_length=3, max_length=500)
    future_avoidance_rule: str = Field(min_length=3, max_length=500)
    outcome: Outcome
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    advisory_only: bool = True

    @model_validator(mode="after")
    def _cannot_be_authoritative(self) -> FailureMemoryRecord:
        if not self.advisory_only:
            raise ValueError("failure_memory_must_be_advisory")
        return self


class ResearchDecisionRecord(BaseModel):
    """Why a proposed research path is preferred before any routing occurs."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    decision_id: str = Field(min_length=16, max_length=128)
    hypothesis_id: str = Field(min_length=1, max_length=200)
    selected_action: str = Field(min_length=3, max_length=240)
    reasoning_chain: tuple[str, ...] = Field(min_length=1, max_length=12)
    alternatives_considered: tuple[str, ...] = Field(default=(), max_length=32)
    expected_information_gain: float = Field(ge=0.0, le=1.0)
    risk: str = Field(pattern="^(low|medium|high|blocked)$")
    cost: int = Field(ge=0, le=1000)
    confirming_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    rejecting_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    advisory_only: bool = True
    execution_delegated: bool = True

    @model_validator(mode="after")
    def _boundary(self) -> ResearchDecisionRecord:
        if not self.advisory_only or not self.execution_delegated:
            raise ValueError("decision_record_boundary_invalid")
        return self


class ResearchSurfaceSignal(BaseModel):
    """Redacted surface context used by Dynamic Research Map."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    asset: str = Field(min_length=1, max_length=240)
    business_impact: float = Field(default=0.0, ge=0.0, le=1.0)
    data_importance: float = Field(default=0.0, ge=0.0, le=1.0)
    trust_boundary_proximity: float = Field(default=0.0, ge=0.0, le=1.0)
    unknown_behavior: float = Field(default=0.0, ge=0.0, le=1.0)
    direction: str = Field(default="evidence", max_length=80)
    source_refs: tuple[str, ...] = Field(default=(), max_length=16)


class DynamicResearchNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    node_id: str = Field(min_length=16, max_length=128)
    asset: str = Field(min_length=1, max_length=240)
    direction: str = Field(min_length=1, max_length=80)
    priority_score: float = Field(ge=0.0, le=1.0)
    historical_success_rate: float = Field(ge=0.0, le=1.0)
    repeated_failure_count: int = Field(ge=0, le=100000)
    source_refs: tuple[str, ...] = Field(default=(), max_length=32)


class DynamicResearchMap(BaseModel):
    """Deterministic advisory map that can be rebuilt after every observation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    observation_sequence: int = Field(ge=0)
    nodes: tuple[DynamicResearchNode, ...] = Field(default=(), max_length=256)
    advisory_only: bool = True
    changes_policy: bool = False
    executes_transport: bool = False


class ResearchConfidenceReport(BaseModel):
    """Senior-style review output; never a finding or oracle replacement."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=1, max_length=200)
    status: str = Field(pattern="^(accepted_for_review|needs_review|blocked|insufficient)$")
    security_boundary_exists: bool
    evidence_sufficient: bool
    alternative_explanation_considered: bool
    impact_demonstrated: bool
    replay_possible: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    advisory_only: bool = True
    can_create_confirmed_finding: bool = False
    can_override_oracle: bool = False
    can_override_policy: bool = False


class FailureIntelligence:
    """In-process, scope-isolated learning from unsuccessful investigations."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], list[FailureMemoryRecord]] = defaultdict(list)

    def learn(
        self,
        *,
        engagement_id: str,
        target_id: str,
        hypothesis_id: str,
        affected_asset: str,
        outcome: Outcome | OutcomeKind,
        reason: str,
        evidence_refs: Iterable[str] = (),
    ) -> FailureMemoryRecord | None:
        normalized = outcome.value if isinstance(outcome, OutcomeKind) else str(outcome)
        if normalized == "evidence":
            return None
        if normalized not in {"no_evidence", "blocked", "failed", "inconclusive"}:
            raise ValueError("unsupported_failure_outcome")
        clean_reason = " ".join(str(reason).split())[:320] or "unspecified_failure"
        payload = json.dumps(
            {
                "engagement": engagement_id,
                "target": target_id,
                "hypothesis": hypothesis_id,
                "asset": affected_asset,
                "outcome": normalized,
                "reason": clean_reason,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        clean_refs = tuple(
            dict.fromkeys(str(ref).strip()[:240] for ref in evidence_refs if str(ref).strip())
        )[:32]
        record = FailureMemoryRecord(
            failure_id=hashlib.sha256(payload.encode()).hexdigest(),
            engagement_id=engagement_id,
            target_id=target_id,
            affected_hypothesis_id=hypothesis_id,
            affected_asset=affected_asset,
            failure_reason=clean_reason,
            rejection_reason=(
                "The bounded research path did not produce sufficient evidence; "
                "this record is not a vulnerability verdict."
            ),
            future_avoidance_rule=(
                "Deprioritize the same path and verify its missing precondition before reuse."
            ),
            outcome=normalized,
            evidence_refs=clean_refs,
        )
        key = (engagement_id, target_id)
        if record.failure_id not in {item.failure_id for item in self._records[key]}:
            self._records[key].append(record)
        return record

    def records(self, *, engagement_id: str, target_id: str) -> tuple[FailureMemoryRecord, ...]:
        return tuple(
            sorted(self._records[(engagement_id, target_id)], key=lambda item: item.failure_id)
        )

    def records_for_other_scope(
        self, *, engagement_id: str, target_id: str
    ) -> tuple[FailureMemoryRecord, ...]:
        return tuple(
            record
            for (record_engagement, record_target), records in self._records.items()
            if (record_engagement, record_target) != (engagement_id, target_id)
            for record in records
        )


class ADIIntelligenceEngine:
    """Compose ADI context around the existing AVDE advisory components."""

    def __init__(self, *, failure_intelligence: FailureIntelligence | None = None) -> None:
        self.failures = failure_intelligence or FailureIntelligence()

    def build_research_map(
        self,
        world_model: SecurityWorldModel,
        *,
        signals: Iterable[ResearchSurfaceSignal] = (),
        historical_evidence: Iterable[HistoricalEvidence] = (),
    ) -> DynamicResearchMap:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        signal_by_asset = {item.asset: item for item in signals}
        history = tuple(historical_evidence)
        evidence_by_asset: dict[str, list[HistoricalEvidence]] = defaultdict(list)
        for item in history:
            if (
                item.engagement_id == world_model.engagement_id
                and item.target_id == world_model.target_id
            ):
                evidence_by_asset[item.asset].append(item)
        nodes: list[DynamicResearchNode] = []
        for invariant in world_model.invariants:
            signal = signal_by_asset.get(invariant.protected_resource)
            evidence = evidence_by_asset[invariant.protected_resource]
            successes = sum(item.outcome == "evidence" for item in evidence)
            success_rate = successes / len(evidence) if evidence else 0.0
            failure_count = sum(
                item.affected_asset == invariant.protected_resource
                for item in self.failures.records(
                    engagement_id=world_model.engagement_id, target_id=world_model.target_id
                )
            )
            signal = signal or ResearchSurfaceSignal(asset=invariant.protected_resource)
            priority = (
                0.28 * signal.business_impact
                + 0.22 * signal.data_importance
                + 0.2 * signal.trust_boundary_proximity
                + 0.18 * signal.unknown_behavior
                + 0.12 * success_rate
            )
            priority = max(0.0, min(1.0, priority - min(0.25, 0.05 * failure_count)))
            payload = f"{world_model.target_id}|{invariant.protected_resource}|{signal.direction}"
            nodes.append(
                DynamicResearchNode(
                    node_id=hashlib.sha256(payload.encode()).hexdigest(),
                    asset=invariant.protected_resource,
                    direction=signal.direction,
                    priority_score=round(priority, 6),
                    historical_success_rate=round(success_rate, 6),
                    repeated_failure_count=failure_count,
                    source_refs=tuple(
                        dict.fromkeys((*invariant.lineage.evidence_refs, *signal.source_refs))
                    )[:32],
                )
            )
        return DynamicResearchMap(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            observation_sequence=len(history),
            nodes=tuple(sorted(nodes, key=lambda item: (-item.priority_score, item.node_id))),
        )

    def build_decisions(
        self,
        hypotheses: Iterable[DiscoveryHypothesis],
        plans: Iterable[ValidationPlan],
        paths: Iterable[AttackPath],
    ) -> tuple[ResearchDecisionRecord, ...]:
        path_items = tuple(paths)
        plan_items = tuple(plans)
        hypothesis_items = tuple(hypotheses)
        records: list[ResearchDecisionRecord] = []
        for hypothesis, plan in zip(hypothesis_items, plan_items, strict=True):
            alternatives = tuple(
                path.path_id for path in path_items if path.path_id != plan.selected_path_id
            )[:32]
            action = (
                f"validate:{plan.selected_path_id}"
                if plan.decision == "selected" and plan.selected_path_id
                else "defer:collect_missing_evidence"
            )
            gain = min(
                1.0,
                0.45 * hypothesis.novelty_score
                + 0.3 * hypothesis.confidence
                + 0.25 * hypothesis.expected_impact,
            )
            payload = f"{hypothesis.hypothesis_id}|{action}|{plan.estimated_cost}"
            records.append(
                ResearchDecisionRecord(
                    decision_id=hashlib.sha256(payload.encode()).hexdigest(),
                    hypothesis_id=hypothesis.hypothesis_id,
                    selected_action=action,
                    reasoning_chain=tuple(hypothesis.reasoning_chain)
                    + (f"validation_decision={plan.decision}",),
                    alternatives_considered=alternatives,
                    expected_information_gain=round(
                        gain if plan.decision == "selected" else 0.0, 6
                    ),
                    risk=plan.risk,
                    cost=plan.estimated_cost,
                    confirming_evidence=hypothesis.expected_evidence,
                    rejecting_evidence=hypothesis.contradicting_evidence,
                )
            )
        return tuple(records)

    @staticmethod
    def confidence_review(
        *,
        post_review: PostExecutionReview,
        security_boundary_exists: bool,
        alternative_explanation_considered: bool,
        impact_demonstrated: bool,
    ) -> ResearchConfidenceReport:
        if not isinstance(post_review, PostExecutionReview):
            raise TypeError("post_execution_review_required")
        evidence_sufficient = post_review.status == QualityReviewStatus.ACCEPTED_FOR_REVIEW
        replay_possible = post_review.proof_replayable
        complete = all(
            (
                security_boundary_exists,
                evidence_sufficient,
                alternative_explanation_considered,
                impact_demonstrated,
                replay_possible,
            )
        )
        if post_review.status == QualityReviewStatus.BLOCKED or post_review.overclaim_detected:
            status = "blocked"
        elif complete:
            status = "accepted_for_review"
        else:
            status = "insufficient"
        confidence = post_review.evidence_quality_score
        confidence *= (
            sum(
                bool(value)
                for value in (
                    security_boundary_exists,
                    evidence_sufficient,
                    alternative_explanation_considered,
                    impact_demonstrated,
                    replay_possible,
                )
            )
            / 5
        )
        return ResearchConfidenceReport(
            hypothesis_id=post_review.hypothesis_id,
            status=status,
            security_boundary_exists=security_boundary_exists,
            evidence_sufficient=evidence_sufficient,
            alternative_explanation_considered=alternative_explanation_considered,
            impact_demonstrated=impact_demonstrated,
            replay_possible=replay_possible,
            confidence=round(confidence, 6),
            evidence_refs=post_review.evidence_refs,
        )

    def run_advisory(
        self,
        world_model: SecurityWorldModel,
        *,
        observations: Iterable[Mapping[str, Any]] = (),
        attack_graph: Iterable[Mapping[str, Any]] = (),
        signals: Iterable[ResearchSurfaceSignal] = (),
        historical_evidence: Iterable[HistoricalEvidence] = (),
        available_capabilities: Iterable[str] = (),
        max_cost: int = 100,
    ) -> tuple[
        tuple[DiscoveryHypothesis, ...],
        tuple[ValidationPlan, ...],
        tuple[ResearchDecisionRecord, ...],
        DynamicResearchMap,
    ]:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        surface_signals = tuple(signals)
        history = tuple(historical_evidence)
        failures = self.failures.records(
            engagement_id=world_model.engagement_id, target_id=world_model.target_id
        )
        hypotheses = DiscoveryHypothesisEngine().generate(
            world_model,
            observations=observations,
            attack_graph=attack_graph,
            historical_evidence=(item.model_dump() for item in history),
            previous_failures=(item.model_dump() for item in failures),
        )
        # AVDE remains the only path construction surface; no request is issued.
        paths = AttackPathExplorer().explore(
            attack_graph,
            target_id=world_model.target_id,
            available_capabilities=available_capabilities,
        )
        plans = tuple(
            AutonomousValidationStrategy().choose(
                hypothesis,
                paths,
                available_capabilities=available_capabilities,
                max_cost=max_cost,
            )
            for hypothesis in hypotheses
        )
        decisions = self.build_decisions(hypotheses, plans, paths)
        research_map = self.build_research_map(
            world_model,
            signals=surface_signals,
            historical_evidence=history,
        )
        return hypotheses, plans, decisions, research_map


__all__ = [
    "ADIIntelligenceEngine",
    "DynamicResearchMap",
    "DynamicResearchNode",
    "FailureIntelligence",
    "FailureMemoryRecord",
    "HistoricalEvidence",
    "ResearchConfidenceReport",
    "ResearchDecisionRecord",
    "ResearchSurfaceSignal",
]
