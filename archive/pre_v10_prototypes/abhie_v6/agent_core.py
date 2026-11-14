"""Unified autonomous research controller for ABHIE v6."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from webpent.abhip.contracts import TargetIntelligenceGraph

from .contracts import AgentResearchState, ResearchDecision


class ResearchAgentCoreV6:
    """Plan research decisions from recorded intelligence without executing them."""

    VERSION = "abhie-agent-core-v6"

    def __init__(self, *, max_decisions: int = 12) -> None:
        self.max_decisions = max(1, min(int(max_decisions), 64))

    def plan(
        self,
        *,
        graph: TargetIntelligenceGraph,
        attack_graph: Any | None = None,
        security_boundaries: Sequence[str] = (),
        research_memory: Sequence[str] = (),
        evidence_state: Mapping[str, Any] | None = None,
        coverage_state: Mapping[str, Any] | None = None,
    ) -> tuple[ResearchDecision, ...]:
        if not isinstance(graph, TargetIntelligenceGraph):
            raise TypeError("target_intelligence_graph_required")
        evidence_state = evidence_state or {}
        coverage_state = coverage_state or {}
        gaps = tuple(sorted(set(graph.coverage_gaps)))
        decisions: list[ResearchDecision] = []
        for index, gap in enumerate(gaps):
            gap_text = str(gap).strip()
            if not gap_text:
                continue
            evidence_count = int(evidence_state.get(gap_text, 0) or 0)
            covered = int(coverage_state.get(gap_text, 0) or 0)
            decisions.append(
                ResearchDecision(
                    decision_id=f"v6-gap-{index + 1:03d}",
                    objective=f"Investigate security assumption behind {gap_text}",
                    reasoning=(
                        "The intelligence graph records a coverage gap; investigate the "
                        "assumption with bounded evidence before considering any conclusion."
                    ),
                    expected_value=max(0.0, min(1.0, 0.75 - 0.05 * covered)),
                    confidence=0.35 if evidence_count == 0 else 0.55,
                    cost=0.25 + min(0.5, 0.05 * covered),
                    risk=0.0,
                    validation_criteria=(
                        "identify affected asset",
                        "record candidate and alternative explanation",
                        "require causal oracle and independent negative control",
                    ),
                    dependencies=("recorded_evidence", "approved_scope"),
                )
            )
        if not decisions:
            decisions.append(
                ResearchDecision(
                    decision_id="v6-review-coverage",
                    objective="Review validated intelligence for hidden security assumptions",
                    reasoning=(
                        "No explicit gap is available; a bounded review of existing evidence "
                        "is safer than inventing a target-specific test."
                    ),
                    expected_value=0.4,
                    confidence=0.5 if graph.nodes else 0.2,
                    cost=0.2,
                    risk=0.0,
                    validation_criteria=(
                        "link every proposed question to recorded evidence",
                        "stop when evidence is insufficient",
                    ),
                    dependencies=("recorded_evidence",),
                )
            )
        return tuple(
            sorted(decisions, key=lambda item: (-item.expected_value, item.decision_id))[
                : self.max_decisions
            ]
        )

    def build_state(
        self,
        *,
        graph: TargetIntelligenceGraph,
        decisions: Sequence[ResearchDecision],
        stop_reason: str = "",
    ) -> AgentResearchState:
        return AgentResearchState(
            engagement_id=graph.engagement_id,
            target_id=graph.target_id,
            decisions=tuple(decisions),
            stop_reason=str(stop_reason).strip(),
        )

    def stop(self, *, reason: str) -> AgentResearchState:
        return AgentResearchState(
            engagement_id="unbound",
            target_id="unbound",
            stop_reason=str(reason).strip() or "bounded_stop",
        )


__all__ = ["ResearchAgentCoreV6"]
