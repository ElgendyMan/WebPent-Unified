"""Bounded research strategy selection."""

from __future__ import annotations

from .contracts import ResearchStrategyDecision, StrategyCandidate


class ExpertStrategySelector:
    FORBIDDEN = (
        "credential",
        "login",
        "token",
        "cookie",
        "post",
        "put",
        "delete",
        "mutation",
        "external",
    )

    def select(
        self, *, hypothesis_id: str, available_capabilities: tuple[str, ...] = ()
    ) -> ResearchStrategyDecision:
        candidates = (
            StrategyCandidate(
                strategy_id=f"{hypothesis_id}:recorded-correlation",
                description=(
                    "Correlate existing typed observations and identify "
                    "missing causal evidence."
                ),
                information_gain=0.72,
                evidence_value=0.65,
                cost=0.10,
                risk=0.02,
                capabilities=available_capabilities,
            ),
            StrategyCandidate(
                strategy_id=f"{hypothesis_id}:read-only-local",
                description=(
                    "Use a pre-authorized read-only local fixture only if a "
                    "safe scope is already present."
                ),
                information_gain=0.88,
                evidence_value=0.82,
                cost=0.32,
                risk=0.12,
                capabilities=available_capabilities,
            ),
            StrategyCandidate(
                strategy_id=f"{hypothesis_id}:state-changing",
                description="Attempt a state-changing or credential-dependent check.",
                information_gain=0.96,
                evidence_value=0.90,
                cost=0.80,
                risk=0.90,
                blocked_reasons=("policy prohibits mutation or credential-dependent execution",),
                capabilities=available_capabilities,
            ),
        )
        eligible = [item for item in candidates if item.eligible]
        eligible.sort(
            key=lambda item: (
                -(item.information_gain + item.evidence_value - item.cost),
                item.strategy_id,
            )
        )
        chosen = eligible[0] if eligible else None
        rationale = (
            "ranked by information gain and evidence value minus cost",
            "risk gate excludes mutation, credentials, login, and external scope",
            "selection is a proposal delegated to existing execution authority",
            f"selected={chosen.strategy_id if chosen else 'none'}",
        )
        return ResearchStrategyDecision(
            selected_strategy_id=chosen.strategy_id if chosen else None,
            rationale=rationale,
            candidates=tuple(candidates),
            delegated_only=True,
        )
