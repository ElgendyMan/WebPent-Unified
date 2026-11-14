"""Autonomous executive research decisions, strictly advisory."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import ExecutiveResearchDecisionV8, V8Status
from .utils import evidence_refs, gap_values, get_value, stable_id, strings


@dataclass(frozen=True, slots=True)
class AutonomousResearchExecutiveV8:
    max_directions: int = 3

    def decide(
        self,
        *,
        engagement_id: str,
        target_id: str,
        mental_model: object | None = None,
        knowledge_graph: object | None = None,
        attack_graph: object | None = None,
        invariants: object | None = None,
        memory: object | None = None,
        coverage: object | None = None,
        previous_findings: object | None = None,
    ) -> ExecutiveResearchDecisionV8:
        gaps = gap_values(
            mental_model,
            knowledge_graph,
            attack_graph,
            invariants,
            memory,
            coverage,
            previous_findings,
        )
        failures = strings(
            get_value(previous_findings, "failed_approaches", "failures", "rejected_theories")
        )
        refs = evidence_refs(mental_model) + evidence_refs(coverage)
        if gaps:
            direction = "investigate recorded coverage and assumption gaps"
            priority = "high" if len(gaps) >= 2 else "medium"
            strategy_change = "prioritize the highest-information unresolved gap"
        elif failures:
            direction = "test an alternative explanation after prior failure"
            priority = "medium"
            strategy_change = "pivot away from the failed path"
        else:
            direction = "broaden recorded-state exploration before narrowing"
            priority = "low"
            strategy_change = "keep exploration broad until evidence differentiates paths"
        confidence = min(0.85, 0.35 + (0.1 * min(len(gaps), 5)))
        uncertainty = round(1.0 - confidence, 3)
        reasoning = (
            "read only recorded engagement state",
            f"identified {len(gaps)} unresolved information gap(s)",
            f"identified {len(failures)} prior failed/rejected path(s)",
            "ranked information gain before impact claims",
            "require causal evidence and independent reproduction before any conclusion",
        )
        evidence = (
            "target-neutral recorded observation",
            "explicit causal oracle contract",
            "independent negative control",
            "sealed and replayable evidence bundle",
        )
        stops = (
            "stop when the oracle or required evidence is unavailable",
            "stop when only route reachability or intended behavior is observed",
            "stop on any request, mutation, credential, or external-scope requirement",
        )
        return ExecutiveResearchDecisionV8(
            decision_id=stable_id("exec", engagement_id, target_id, gaps, failures),
            direction=direction,
            investigation_priority=priority,
            reasoning_chain=reasoning,
            confidence=confidence,
            expected_value=min(1.0, 0.55 + 0.08 * len(gaps)),
            uncertainty=uncertainty,
            cost=0.2 if gaps else 0.35,
            risk=0.0,
            evidence_requirements=evidence,
            strategy_change=strategy_change,
            stop_decision=stops[0],
            source_refs=tuple(sorted(set(refs))),
            status=V8Status.ADVISORY,
        )


__all__ = ["AutonomousResearchExecutiveV8"]
