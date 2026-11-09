"""Bounded autonomous research loop for IRTA v2.

This module plans observations only. Execution remains delegated to the
existing hardened RTA/DCVU boundaries and is never performed here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from webpent.irta.generator.models import GeneratedRoute, GeneratedTarget


class ResearchStage(StrEnum):
    DISCOVER = "discover"
    HYPOTHESIZE = "hypothesize"
    PLAN = "plan"
    VALIDATE = "validate"
    REVIEW = "review"


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    route_id: str
    vulnerability_class: str
    rationale: str
    evidence_requirements: tuple[str, ...]
    priority: int


@dataclass(frozen=True)
class ResearchPlan:
    campaign_id: str
    stages: tuple[ResearchStage, ...]
    hypotheses: tuple[Hypothesis, ...]
    stop_conditions: tuple[str, ...]


class HypothesisStore:
    def __init__(self) -> None:
        self._items: dict[str, Hypothesis] = {}

    def add(self, hypothesis: Hypothesis) -> None:
        if not hypothesis.hypothesis_id or not hypothesis.evidence_requirements:
            raise ValueError("hypotheses require identity and evidence requirements")
        self._items[hypothesis.hypothesis_id] = hypothesis

    def ranked(self) -> tuple[Hypothesis, ...]:
        return tuple(
            sorted(
                self._items.values(),
                key=lambda item: (-item.priority, item.hypothesis_id),
            )
        )


class ResearchController:
    """Translate a generated target into an evidence-aware, bounded plan."""

    def build_plan(self, target: GeneratedTarget, campaign_id: str) -> ResearchPlan:
        if not campaign_id:
            raise ValueError("campaign id is required")
        target.validate()
        store = HypothesisStore()
        for index, route in enumerate(target.routes, start=1):
            self._add_route_hypothesis(store, route, index)
        return ResearchPlan(
            campaign_id=campaign_id,
            stages=tuple(ResearchStage),
            hypotheses=store.ranked(),
            stop_conditions=(
                "loopback_scope_violation",
                "non_read_only_request",
                "missing_causal_oracle",
                "missing_independent_negative_control",
                "unredacted_observation",
            ),
        )

    @staticmethod
    def _add_route_hypothesis(store: HypothesisStore, route: GeneratedRoute, index: int) -> None:
        if route.vulnerability_class is None:
            return
        store.add(
            Hypothesis(
                hypothesis_id=f"h-{index:03d}-{route.route_id}",
                route_id=route.route_id,
                vulnerability_class=route.vulnerability_class.value,
                rationale=f"route {route.path_template} exposes an authorization-sensitive surface",
                evidence_requirements=(
                    "candidate_observation",
                    "independent_negative_control",
                    "causal_oracle_result",
                    "redacted_proof_or_block_reason",
                ),
                priority=max(1, 100 - index),
            )
        )
