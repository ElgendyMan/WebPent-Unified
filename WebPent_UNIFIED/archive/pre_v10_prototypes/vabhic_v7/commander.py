"""VABHIC v7 autonomous research commander."""

from __future__ import annotations

from hashlib import sha256

from .contracts import ResearchCommand, ResearchCommandPlan, V7Status
from .utils import field, refs, score, text, values


class AutonomousResearchCommanderV7:
    """Choose high-value questions, never route actions."""

    def __init__(self, *, budget: float = 8.0, max_commands: int = 16) -> None:
        if budget < 0:
            raise ValueError("research_budget_must_be_non_negative")
        self.budget = float(budget)
        self.max_commands = max(1, min(64, int(max_commands)))

    def plan(
        self,
        *,
        engagement_id: str,
        target_id: str,
        world_model: object | None = None,
        attack_graph: object | None = None,
        invariants: object | None = None,
        memory: object | None = None,
        coverage: object | None = None,
        previous_results: object | None = None,
    ) -> ResearchCommandPlan:
        candidates: list[tuple[float, str, str, str, tuple[str, ...], tuple[str, ...]]] = []
        for item in values(attack_graph, "nodes"):
            identifier = text(item, "node_id", "id", default="graph-node")
            label = text(item, "label", "name", default=identifier)
            kind = text(item, "kind", "category", default="asset")
            criticality = text(item, "criticality", default="medium").lower()
            priority = {"critical": 0.95, "high": 0.85, "medium": 0.60, "low": 0.35}.get(
                criticality, 0.45
            )
            capability = (
                "bounded_boundary_analysis"
                if kind.lower()
                in {"permission", "privilege", "identity", "workflow", "state", "tenant"}
                else "read_only_observation"
            )
            candidates.append(
                (
                    priority,
                    identifier,
                    f"Investigate the security assumptions around {label}",
                    f"graph:{kind}",
                    refs(item),
                    (capability,),
                )
            )
        for item in values(world_model, "invariants", "observations", "business_intents", "assets"):
            identifier = text(item, "invariant_id", "id", "name", default="world-observation")
            description = text(item, "statement", "description", "name", default=identifier)
            candidates.append(
                (
                    0.72,
                    identifier,
                    f"Challenge modeled invariant: {description}",
                    "world-model",
                    refs(item),
                    ("invariant_analysis",),
                )
            )
        for item in values(invariants, "items", "invariants", "assessments"):
            identifier = text(item, "invariant_id", "id", "name", default="invariant")
            candidates.append(
                (
                    0.78,
                    identifier,
                    f"Review invariant boundary: {identifier}",
                    "invariant",
                    refs(item),
                    ("invariant_analysis",),
                )
            )
        for item in values(coverage, "unexplored", "low_confidence", "gaps", "coverage_gaps"):
            identifier = text(item, "id", "name", default=str(item))
            candidates.append(
                (
                    0.80,
                    identifier,
                    f"Explore uncovered research surface {identifier}",
                    "coverage-gap",
                    refs(item),
                    ("surface_discovery",),
                )
            )
        if values(memory, "failed_paths", "blocked_paths", "lessons") or values(
            previous_results, "results", "observations"
        ):
            candidates.append(
                (
                    0.64,
                    "prior-results",
                    "Reassess prior blocked paths for new evidence",
                    "learning",
                    refs(memory),
                    ("failure_analysis",),
                )
            )
        unique: dict[str, tuple[float, str, str, str, tuple[str, ...], tuple[str, ...]]] = {}
        for candidate in candidates:
            if candidate[1] not in unique or candidate[0] > unique[candidate[1]][0]:
                unique[candidate[1]] = candidate
        ordered = sorted(unique.values(), key=lambda item: (-item[0], item[1]))[: self.max_commands]
        commands: list[ResearchCommand] = []
        remaining = self.budget
        for rank, (priority, identifier, objective, area, source_refs, capabilities) in enumerate(
            ordered, start=1
        ):
            cost = min(1.0, 0.35 + (1.0 - priority) * 0.5)
            if remaining < cost:
                break
            command_id = (
                "command:"
                + sha256(
                    f"{engagement_id}|{target_id}|{identifier}|{objective}".encode()
                ).hexdigest()[:16]
            )
            missing = (
                "target-backed observation",
                "independent negative control",
                "causal oracle",
                "sealed replayable proof",
            )
            commands.append(
                ResearchCommand(
                    command_id=command_id,
                    objective=objective,
                    reasoning=f"area={area}; rank={rank}; capabilities={','.join(capabilities)}",
                    expected_value=priority,
                    confidence=score(
                        field(previous_results, "confidence", default=priority), priority
                    ),
                    cost=round(cost, 3),
                    risk=0.0,
                    success_criteria=(
                        "record canonical evidence",
                        "map evidence to a causal oracle",
                        "preserve replayability",
                    ),
                    stop_criteria=(
                        "stop when evidence is insufficient",
                        "stop when scope or budget is exhausted",
                        "stop before any mutation or external scope",
                    ),
                    missing_evidence=missing,
                    pivot_if=(
                        "pivot when the assumption is supported",
                        "pivot when a duplicate path adds no evidence",
                    ),
                    source_refs=source_refs,
                )
            )
            remaining -= cost
        status = V7Status.READY if commands else V7Status.BLOCKED
        stop_reason = "" if commands else "no bounded research objective available"
        return ResearchCommandPlan(
            engagement_id=engagement_id,
            target_id=target_id,
            commands=tuple(commands),
            status=status,
            stop_reason=stop_reason,
            budget_reason=f"budget={self.budget:.3f}; remaining={remaining:.3f}",
        )


__all__ = ["AutonomousResearchCommanderV7"]
