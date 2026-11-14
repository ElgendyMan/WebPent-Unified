"""AVRIP v2 contextual vulnerability reasoning contracts."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from webpent.asros.world_model import SecurityWorldModel
from webpent.avrip.assumptions import SecurityAssumption
from webpent.knowledge.model_v2 import TargetKnowledgeV2
from webpent.models.attack_graph import AttackGraph


class ReasoningStepKind(str, Enum):
    OBSERVATION = "observation"
    CONTEXT = "context"
    ASSUMPTION = "assumption"
    HYPOTHESIS = "hypothesis"
    VALIDATION = "validation"


class ReasoningStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    step_id: str = Field(min_length=1, max_length=240)
    kind: ReasoningStepKind
    statement: str = Field(min_length=3, max_length=700)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=32)


class DeepHypothesis(BaseModel):
    """A high-value hypothesis, never a finding or confirmation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=1, max_length=240)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    title: str = Field(min_length=3, max_length=300)
    affected_asset: str = Field(min_length=1, max_length=240)
    reasoning_chain: tuple[ReasoningStep, ...] = Field(min_length=5, max_length=5)
    supporting_observations: tuple[str, ...] = Field(default=(), max_length=32)
    missing_evidence: tuple[str, ...] = Field(default=(), max_length=16)
    validation_strategy: tuple[str, ...] = Field(min_length=1, max_length=8)
    expected_impact: str = Field(min_length=3, max_length=320)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: str = Field(default="potential", pattern="^(potential|blocked)$")
    advisory_only: bool = True

    @model_validator(mode="after")
    def _ordered_chain(self) -> DeepHypothesis:
        expected = (
            ReasoningStepKind.OBSERVATION,
            ReasoningStepKind.CONTEXT,
            ReasoningStepKind.ASSUMPTION,
            ReasoningStepKind.HYPOTHESIS,
            ReasoningStepKind.VALIDATION,
        )
        if tuple(step.kind for step in self.reasoning_chain) != expected:
            raise ValueError("deep_reasoning_chain_order_invalid")
        if not self.advisory_only:
            raise ValueError("deep_hypothesis_must_be_advisory")
        return self


class DeepReasoningReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    schema_version: int = Field(default=2, frozen=True)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    hypotheses: tuple[DeepHypothesis, ...] = Field(default=(), max_length=512)
    model_hash: str = Field(min_length=16, max_length=128)
    advisory_only: bool = True


class DeepVulnerabilityReasoner:
    """Generate deterministic contextual hypotheses from passive projections."""

    def reason(
        self,
        *,
        world_model: SecurityWorldModel,
        assumptions: Iterable[SecurityAssumption],
        knowledge: TargetKnowledgeV2 | None = None,
        attack_graph: AttackGraph | None = None,
        memory_hints: Iterable[str] = (),
    ) -> DeepReasoningReport:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        if knowledge is not None and (
            knowledge.engagement_id != world_model.engagement_id
            or knowledge.target_id != world_model.target_id
        ):
            raise ValueError("knowledge_world_model_scope_mismatch")
        assumptions_tuple = tuple(assumptions)
        if any(not isinstance(item, SecurityAssumption) for item in assumptions_tuple):
            raise TypeError("security_assumption_required")
        hints = tuple(
            str(item).strip()[:240] for item in memory_hints if str(item).strip()
        )[:8]
        memory_context = (
            f"{len(hints)} scoped memory hint(s) are available"
            if hints
            else "no scoped memory hints are available"
        )
        graph_context = _graph_context(attack_graph)
        model_hash = _model_hash(world_model, knowledge, attack_graph)
        hypotheses: list[DeepHypothesis] = []
        for assumption in sorted(assumptions_tuple, key=lambda item: item.assumption_id):
            refs = tuple(dict.fromkeys(assumption.evidence_refs))[:32]
            observation = (
                f"Observed evidence references support a {assumption.kind.value} boundary "
                f"for {assumption.protected_resource}."
            )
            context = (
                f"World model contains {len(world_model.invariants)} invariant(s), "
                f"{len(world_model.business_intents)} business intent(s), and "
                f"{graph_context}; {memory_context}."
            )
            assumption_text = f"Security assumption: {assumption.statement}"
            hypothesis_text = (
                f"A boundary-relevant path may violate the assumption for "
                f"{assumption.protected_resource}; this remains unconfirmed."
            )
            validation = (
                "Use an authorized candidate/control pair, a causal oracle, and sealed replay; "
                "do not infer a finding from reachability or status alone."
            )
            chain_id = _stable_id(
                f"{world_model.target_id}|{assumption.assumption_id}|{graph_context}"
            )
            steps = tuple(
                ReasoningStep(
                    step_id=f"{chain_id}:{kind.value}",
                    kind=kind,
                    statement=statement,
                    evidence_refs=refs,
                )
                for kind, statement in (
                    (ReasoningStepKind.OBSERVATION, observation),
                    (ReasoningStepKind.CONTEXT, context),
                    (ReasoningStepKind.ASSUMPTION, assumption_text),
                    (ReasoningStepKind.HYPOTHESIS, hypothesis_text),
                    (ReasoningStepKind.VALIDATION, validation),
                )
            )
            confidence = min(
                0.9,
                round(
                    0.35
                    + assumption.confidence * 0.45
                    + (0.08 if graph_context != "no attack-graph context" else 0.0)
                    + (0.02 if hints else 0.0),
                    3,
                ),
            )
            missing = tuple(
                dict.fromkeys(
                    (*assumption.missing_evidence, "alternative_explanation_review")
                )
            )[:16]
            hypotheses.append(
                DeepHypothesis(
                    hypothesis_id=f"deep:{chain_id}",
                    engagement_id=world_model.engagement_id,
                    target_id=world_model.target_id,
                    title=f"Boundary review: {assumption.protected_resource}",
                    affected_asset=assumption.protected_resource,
                    reasoning_chain=steps,
                    supporting_observations=refs,
                    missing_evidence=missing,
                    validation_strategy=(
                        *assumption.validation_target.split(".")[:2],
                        "central verification remains required",
                    )[:8],
                    expected_impact=(
                        f"Potential impact to the {assumption.kind.value} boundary; "
                        "impact is not established by this projection."
                    ),
                    confidence=confidence,
                    status="potential" if refs else "blocked",
                )
            )
        return DeepReasoningReport(
            engagement_id=world_model.engagement_id,
            target_id=world_model.target_id,
            hypotheses=tuple(hypotheses),
            model_hash=model_hash,
        )


def _graph_context(attack_graph: AttackGraph | None) -> str:
    if attack_graph is None:
        return "no attack-graph context"
    return f"{len(attack_graph.nodes)} attack-graph node(s) and {len(attack_graph.edges)} edge(s)"


def _model_hash(
    world_model: SecurityWorldModel,
    knowledge: TargetKnowledgeV2 | None,
    attack_graph: AttackGraph | None,
) -> str:
    values: dict[str, Any] = {"world": world_model.content_hash()}
    if knowledge is not None:
        values["knowledge"] = knowledge.content_hash()
    if attack_graph is not None:
        values["attack_graph"] = attack_graph.model_dump(mode="json")
    import json

    return hashlib.sha256(
        json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _stable_id(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:28]


__all__ = [
    "DeepHypothesis",
    "DeepReasoningReport",
    "DeepVulnerabilityReasoner",
    "ReasoningStep",
    "ReasoningStepKind",
]
