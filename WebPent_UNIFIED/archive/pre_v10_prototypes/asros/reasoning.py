"""Bounded research reasoning over the ASROS world model.

Reasoning artifacts explain why a hypothesis matters and what would prove or
disprove it.  They are advisory only: transport, authority, causal oracles, and
finding creation remain owned by the existing WebPent contracts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.asros.world_model import SecurityWorldModel
from webpent.attack_graph.chain_reasoning import VulnerabilityChain
from webpent.intelligence.contracts import ResearchHypothesis
from webpent.models.attack_graph import AttackGraph
from webpent.models.evidence import redact_sensitive


class ArgumentStepKind(str, Enum):
    OBSERVATION = "observation"
    REASONING = "reasoning"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"


class ArgumentStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    step_id: str = Field(min_length=1, max_length=180)
    kind: ArgumentStepKind
    statement: str = Field(min_length=3, max_length=700)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def _safe_statement(self) -> ArgumentStep:
        clean, _ = redact_sensitive(self.statement)
        if clean != self.statement:
            return self.model_copy(update={"statement": clean})
        return self


class ResearchArgumentChain(BaseModel):
    """Ordered argument from an observation to a bounded validation plan."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    chain_id: str = Field(min_length=1, max_length=180)
    target_id: str = Field(min_length=1, max_length=200)
    hypothesis_id: str = Field(min_length=1, max_length=200)
    why_it_matters: str = Field(min_length=3, max_length=700)
    assumption_tested: str = Field(min_length=3, max_length=700)
    steps: tuple[ArgumentStep, ...] = Field(min_length=4, max_length=4)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)
    cheapest_validation_path: tuple[str, ...] = Field(min_length=1, max_length=8)
    graph_chain_ids: tuple[str, ...] = Field(default=(), max_length=16)
    memory_hints: tuple[str, ...] = Field(default=(), max_length=8)
    status: str = Field(default="potential", pattern="^(potential|blocked|validated)$")
    validation_required: bool = True

    @model_validator(mode="after")
    def _integrity(self) -> ResearchArgumentChain:
        expected = (
            ArgumentStepKind.OBSERVATION,
            ArgumentStepKind.REASONING,
            ArgumentStepKind.HYPOTHESIS,
            ArgumentStepKind.VALIDATION,
        )
        if tuple(step.kind for step in self.steps) != expected:
            raise ValueError("argument_chain_order_invalid")
        ids = [step.step_id for step in self.steps]
        if len(ids) != len(set(ids)):
            raise ValueError("argument_chain_step_ids_not_unique")
        if self.status == "validated":
            raise ValueError("argument_chain_cannot_self_validate")
        return self

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def content_hash(self) -> str:
        payload = self.model_dump_json(indent=None, exclude_none=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ResearchDecision(BaseModel):
    """A next-step recommendation that must be routed by existing policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    decision_id: str = Field(min_length=1, max_length=180)
    action: str = Field(min_length=3, max_length=180)
    rationale: str = Field(min_length=3, max_length=700)
    expected_gain: float = Field(default=0.0, ge=0.0, le=1.0)
    estimated_cost: int = Field(default=1, ge=0, le=100)
    required_capability: str = Field(default="analysis", max_length=120)
    blocked: bool = False
    execution_delegated: bool = True


class ResearchReasoningEngine:
    """Create bounded argument chains from already available projections."""

    def __init__(self, *, max_memory_hints: int = 8) -> None:
        self.max_memory_hints = max(0, min(int(max_memory_hints), 8))

    def build_argument_chain(
        self,
        *,
        world_model: SecurityWorldModel,
        hypothesis: ResearchHypothesis,
        observation: str,
        assumption_tested: str,
        validation_plan: Iterable[str] | None = None,
        attack_graph: AttackGraph | Mapping[str, Any] | None = None,
        past_chains: Iterable[VulnerabilityChain] = (),
        memory_hints: Iterable[str] = (),
    ) -> ResearchArgumentChain:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        if not isinstance(hypothesis, ResearchHypothesis):
            raise TypeError("research_hypothesis_required")
        clean_observation = _clean(observation, 700)
        clean_assumption = _clean(assumption_tested, 700)
        plan = tuple(
            _clean(item, 240)
            for item in (validation_plan or hypothesis.attack_plan)
            if str(item).strip()
        )[:8]
        if not clean_observation or not clean_assumption or not plan:
            raise ValueError("research_argument_inputs_required")

        related_invariant = _related_invariant(world_model, hypothesis)
        invariant_text = (
            related_invariant.statement
            if related_invariant is not None
            else "The relevant security invariant is not yet represented in the world model."
        )
        reason = (
            "The observation matters because it intersects a security expectation: "
            f"{invariant_text}"
            if related_invariant
            else (
                "The observation matters because the target security expectation "
                "remains uncertain and must be tested without overclaiming."
            )
        )
        refs = tuple(
            dict.fromkeys(
                ref
                for item in world_model.invariants
                if related_invariant is None or item.invariant_id == related_invariant.invariant_id
                for ref in item.lineage.evidence_refs
            )
        )
        graph_ids = tuple(
            sorted({chain.chain_id for chain in past_chains if chain.eligible_for_validation})
        )[:16]
        hints = tuple(_clean(item, 240) for item in memory_hints if str(item).strip())[
            : self.max_memory_hints
        ]
        chain_id = (
            "argument:"
            + hashlib.sha256(
                f"{world_model.target_id}|{hypothesis.id}|{clean_observation}|{clean_assumption}|{'|'.join(plan)}".encode()
            ).hexdigest()[:24]
        )
        steps = (
            ArgumentStep(
                step_id=f"{chain_id}:observation",
                kind=ArgumentStepKind.OBSERVATION,
                statement=clean_observation,
                evidence_refs=refs,
            ),
            ArgumentStep(
                step_id=f"{chain_id}:reasoning",
                kind=ArgumentStepKind.REASONING,
                statement=reason,
                evidence_refs=refs,
            ),
            ArgumentStep(
                step_id=f"{chain_id}:hypothesis",
                kind=ArgumentStepKind.HYPOTHESIS,
                statement=_clean(hypothesis.reason, 700),
                evidence_refs=tuple(hypothesis.evidence_refs)[:32],
            ),
            ArgumentStep(
                step_id=f"{chain_id}:validation",
                kind=ArgumentStepKind.VALIDATION,
                statement="; ".join(plan),
                evidence_refs=tuple(hypothesis.evidence_refs)[:32],
            ),
        )
        return ResearchArgumentChain(
            chain_id=chain_id,
            target_id=world_model.target_id,
            hypothesis_id=str(hypothesis.id),
            why_it_matters=reason,
            assumption_tested=clean_assumption,
            steps=steps,
            evidence_refs=tuple(dict.fromkeys((*refs, *hypothesis.evidence_refs)))[:32],
            cheapest_validation_path=plan,
            graph_chain_ids=graph_ids,
            memory_hints=hints,
        )

    def decide(self, chain: ResearchArgumentChain, *, prior_failures: int = 0) -> ResearchDecision:
        if not isinstance(chain, ResearchArgumentChain):
            raise TypeError("research_argument_chain_required")
        failures = max(0, int(prior_failures))
        blocked = not chain.evidence_refs or not chain.cheapest_validation_path
        gain = max(0.05, 0.75 - min(failures, 5) * 0.12)
        return ResearchDecision(
            decision_id=f"decision:{chain.chain_id}",
            action="validate_hypothesis" if not blocked else "collect_missing_evidence",
            rationale=(
                "Use the cheapest bounded validation path; central authority and "
                "causal proof remain required."
                if not blocked
                else "Do not execute: the argument lacks the minimum evidence or validation plan."
            ),
            expected_gain=0.0 if blocked else gain,
            estimated_cost=len(chain.cheapest_validation_path),
            required_capability="analysis" if blocked else "http_read",
            blocked=blocked,
        )


def _clean(value: Any, limit: int) -> str:
    clean, _ = redact_sensitive(str(value))
    return " ".join(clean.split())[:limit]


def _related_invariant(world_model: SecurityWorldModel, hypothesis: ResearchHypothesis):
    asset = hypothesis.affected_asset.strip().lower()
    if asset:
        for invariant in world_model.invariants:
            if asset in {invariant.protected_resource.lower(), invariant.subject.lower()}:
                return invariant
    return world_model.invariants[0] if world_model.invariants else None


__all__ = [
    "ArgumentStep",
    "ArgumentStepKind",
    "ResearchArgumentChain",
    "ResearchDecision",
    "ResearchReasoningEngine",
]
