"""Bounded experiment planning for ABHC v3."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import replace
from hashlib import sha256

from .contracts import EvolvingHypothesis, ExperimentPlan, HypothesisStatus, SecurityBoundaryMap


class BoundedExperimentPlanner:
    """Plan read-only/offline evidence acquisition; never execute a plan."""

    _blocked_tokens = (
        "credential",
        "login",
        "token",
        "cookie",
        "mutation",
        "delete",
        "post",
        "put",
        "external",
        "callback",
    )

    def plan(
        self,
        hypotheses: Sequence[EvolvingHypothesis],
        boundaries: SecurityBoundaryMap,
        *,
        available_capabilities: Iterable[str] = (),
        budget: float = 4.0,
    ) -> tuple[ExperimentPlan, ...]:
        capabilities = {str(item).lower() for item in available_capabilities}
        result: list[ExperimentPlan] = []
        for hypothesis in hypotheses:
            required = tuple(hypothesis.required_validation)
            experiment_id = (
                "experiment:" + sha256(hypothesis.hypothesis_id.encode()).hexdigest()[:16]
            )
            purpose = f"Collect bounded evidence for {hypothesis.hypothesis_id}"
            expected = "candidate/control observations distinguishable by a causal oracle"
            requested = " ".join((*required, *capabilities)).lower()
            blocked = ""
            if any(token in requested for token in self._blocked_tokens):
                blocked = "capability_or_scope_requires_owner_decision"
            if not boundaries.boundaries:
                blocked = blocked or "no_modeled_security_boundary"
            if hypothesis.status not in {
                HypothesisStatus.SUPPORTED,
                HypothesisStatus.INVESTIGATING,
                HypothesisStatus.VALIDATING,
            }:
                blocked = blocked or "hypothesis_not_ready_for_experiment"
            info_gain = min(1.0, 0.50 + 0.10 * len(boundaries.boundaries))
            evidence_value = 0.85 if hypothesis.evidence_refs else 0.55
            risk = 0.05 if not blocked else 0.0
            result.append(
                ExperimentPlan(
                    experiment_id=experiment_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    purpose=purpose,
                    expected_result=expected,
                    success_criteria=(
                        "candidate/control pair exists",
                        "causal oracle distinguishes them",
                    ),
                    failure_criteria=(
                        "precondition absent",
                        "oracle inconclusive",
                        "proof/replay incomplete",
                    ),
                    information_gain=round(info_gain, 6),
                    evidence_value=round(evidence_value, 6),
                    cost=0.30,
                    risk=risk,
                    required_capabilities=("offline_recorded_observations",),
                    selected=False,
                    blocked_reason=blocked,
                )
            )
        available = [item for item in result if not item.blocked_reason]
        selected: set[str] = set()
        remaining = budget
        for item in sorted(available, key=lambda value: (-value.utility, value.experiment_id)):
            if remaining < item.cost:
                continue
            selected.add(item.experiment_id)
            remaining -= item.cost
        return tuple(
            item if item.experiment_id not in selected else replace(item, selected=True)
            for item in result
        )


__all__ = ["BoundedExperimentPlanner"]
