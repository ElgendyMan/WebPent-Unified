"""THE ORACLE — U-ORACLE-9, the Impact Maximizer (v88).

Re-estimates every chain hypothesis by what it would cost the owner if
realised — impact, not CVSS severity (ORACLE-L-9). Strategies are
passive reasoning frames from config/oracle/impact_strategies.yaml;
they adjust numbers already on the table and touch nothing else
(ORACLE-L-10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from webpent.oracle.chain_composer import ChainProposal
from webpent.oracle.graph_builder import AttackGraph
from webpent.oracle.models import OracleLawError

CONDITION_KINDS = {"always", "category_present", "min_nodes", "payout_above"}


@dataclass
class ImpactEstimate:
    proposal_id: str
    impact_category: str
    base_payout: float
    adjusted_payout: float
    strategies_applied: list[str] = field(default_factory=list)
    rationale: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "impact_category": self.impact_category,
            "base_payout": round(self.base_payout, 3),
            "adjusted_payout": round(self.adjusted_payout, 3),
            "strategies_applied": list(self.strategies_applied),
            "rationale": list(self.rationale),
        }


def _validate_strategy(raw: Any, index: int) -> dict:
    if not isinstance(raw, dict):
        raise OracleLawError(f"impact strategy #{index} must be a mapping")
    for key in ("strategy_id", "name", "description", "condition",
                "payout_multiplier"):
        if key not in raw:
            raise OracleLawError(
                f"impact strategy {raw.get('strategy_id', index)} missing "
                f"{key!r}"
            )
    condition = raw["condition"]
    if not isinstance(condition, dict) or condition.get("kind") not in \
            CONDITION_KINDS:
        raise OracleLawError(
            f"{raw['strategy_id']}: condition kind must be one of "
            f"{sorted(CONDITION_KINDS)}"
        )
    kind = condition["kind"]
    if kind == "category_present" and not condition.get("categories"):
        raise OracleLawError(
            f"{raw['strategy_id']}: category_present needs categories"
        )
    if kind == "min_nodes" and int(condition.get("count", 0)) < 1:
        raise OracleLawError(
            f"{raw['strategy_id']}: min_nodes needs a positive count"
        )
    if kind == "payout_above" and not 0.0 <= float(
        condition.get("threshold", -1)
    ) <= 1.0:
        raise OracleLawError(
            f"{raw['strategy_id']}: payout_above needs a threshold in "
            f"[0, 1]"
        )
    if float(raw["payout_multiplier"]) <= 0.0:
        raise OracleLawError(
            f"{raw['strategy_id']}: payout_multiplier must be positive"
        )
    return raw


class ImpactMaximizer:
    def __init__(self, strategies_path: Path) -> None:
        data = yaml.safe_load(
            Path(strategies_path).read_text(encoding="utf-8")
        ) or {}
        raw_strategies = data.get("impact_strategies")
        if not raw_strategies or not isinstance(raw_strategies, list):
            raise OracleLawError(
                "impact_strategies.yaml missing a non-empty "
                "'impact_strategies' list"
            )
        self._strategies = [
            _validate_strategy(raw, i)
            for i, raw in enumerate(raw_strategies)
        ]

    # -- condition evaluation (pure functions of the estimate's inputs) -------

    def _applies(self, strategy: dict, graph: AttackGraph,
                 proposal: ChainProposal, base_payout: float) -> bool:
        condition = strategy["condition"]
        kind = condition["kind"]
        if kind == "always":
            return True
        if kind == "category_present":
            types = {
                graph.nodes[n].node_type
                for n in proposal.nodes if n in graph.nodes
            }
            return types & set(condition["categories"]) != set()
        if kind == "min_nodes":
            return len(proposal.nodes) >= int(condition["count"])
        if kind == "payout_above":
            return base_payout > float(condition["threshold"])
        return False

    # -- public surface ----------------------------------------------------------

    def maximize(
        self, graph: AttackGraph, proposals: list[ChainProposal]
    ) -> list[ImpactEstimate]:
        estimates: list[ImpactEstimate] = []
        for proposal in proposals:
            nodes = [
                graph.nodes[n] for n in proposal.nodes if n in graph.nodes
            ]
            confidence = (
                sum(n.confidence for n in nodes) / len(nodes) if nodes
                else 0.0
            )
            base = proposal.payout_delta * confidence
            payout = base
            applied: list[str] = []
            rationale: list[str] = []
            for strategy in self._strategies:
                if not self._applies(strategy, graph, proposal, base):
                    continue
                payout *= float(strategy["payout_multiplier"])
                applied.append(strategy["strategy_id"])
                rationale.append(
                    f"{strategy['strategy_id']} ({strategy['name']}): "
                    f"{strategy['description']}"
                )
            estimates.append(
                ImpactEstimate(
                    proposal_id=proposal.proposal_id,
                    impact_category=proposal.impact_category,
                    base_payout=base,
                    adjusted_payout=min(payout, 1.0),
                    strategies_applied=applied,
                    rationale=rationale,
                )
            )
        estimates.sort(
            key=lambda e: (-e.adjusted_payout, e.proposal_id)
        )
        return estimates


__all__ = ["ImpactEstimate", "ImpactMaximizer"]
