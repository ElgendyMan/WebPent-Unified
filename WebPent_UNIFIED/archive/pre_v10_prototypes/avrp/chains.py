"""Advanced attack-chain reasoning for AVRP.

Chains are structured hypotheses only. This module never executes a path,
creates a finding, or changes an oracle or policy decision.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.avde.discovery import DiscoveryHypothesis
from webpent.avrp.correlation import EvidenceRelationshipGraph
from webpent.models.evidence import canonical_json, redact_sensitive


def _clean(value: Any, limit: int = 500) -> str:
    clean, _ = redact_sensitive(str(value or ""))
    return " ".join(clean.split())[:limit]


def _refs(values: Iterable[Any], limit: int = 30) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        clean = _clean(value, 240)
        if clean and clean not in result:
            result.append(clean)
    return tuple(result[:limit])


class AttackChainHypothesis(BaseModel):
    """A four-part security chain awaiting causal validation."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    chain_id: str = Field(min_length=3, max_length=160)
    vulnerability_class: str = Field(min_length=3, max_length=120)
    weakness: str = Field(min_length=3, max_length=500)
    supporting_condition: str = Field(min_length=3, max_length=500)
    privilege_boundary: str = Field(min_length=3, max_length=500)
    business_impact: str = Field(min_length=3, max_length=500)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=40)
    reasoning: str = Field(min_length=3, max_length=700)
    confidence: float = Field(ge=0.0, le=1.0)
    validation_requirement: str = Field(min_length=3, max_length=700)
    status: Literal["hypothesis", "blocked"] = "hypothesis"
    advisory_only: bool = True

    @field_validator(
        "chain_id",
        "vulnerability_class",
        "weakness",
        "supporting_condition",
        "privilege_boundary",
        "business_impact",
        "reasoning",
        "validation_requirement",
        "status",
        mode="before",
    )
    @classmethod
    def _redact_text(cls, value: Any) -> str:
        return _clean(value)

    @field_validator("source_refs", mode="before")
    @classmethod
    def _redact_refs(cls, value: Any) -> tuple[str, ...]:
        return _refs(value or ())

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.model_dump(mode="json"))
        return clean


class AdvancedAttackChainReasoner:
    """Compose explicit hypothesis and relationship context into chains."""

    def reason(
        self,
        hypotheses: Iterable[DiscoveryHypothesis],
        *,
        relationship_graph: EvidenceRelationshipGraph | None = None,
    ) -> tuple[AttackChainHypothesis, ...]:
        graph = relationship_graph
        relationships = tuple(graph.relationships) if graph is not None else ()
        result: list[AttackChainHypothesis] = []
        for hypothesis in tuple(hypotheses):
            if not isinstance(hypothesis, DiscoveryHypothesis):
                raise TypeError("hypotheses must be DiscoveryHypothesis instances")
            matching = tuple(
                relation
                for relation in relationships
                if set(relation.source_observation_ids) & set(hypothesis.source_refs)
            )
            relation = matching[0] if matching else None
            source_refs = _refs(
                (
                    *hypothesis.source_refs,
                    *(relation.source_observation_ids if relation else ()),
                )
            )
            if not source_refs:
                continue
            boundary = (
                relation.relationship_type.replace("_", " ")
                if relation is not None
                else "authorization or ownership boundary requires explicit evidence"
            )
            supporting = (
                relation.reasoning
                if relation is not None
                else (
                    "The hypothesis has supporting observations but no correlated relationship yet."
                )
            )
            impact = (
                "Potential security impact requires an approved causal oracle and an independent "
                "negative control."
            )
            requirement = (
                relation.validation_requirement
                if relation is not None
                else "Require candidate/control contrast, causal oracle, central verification, "
                "and replayable redacted evidence."
            )
            payload = {
                "vulnerability_class": hypothesis.vulnerability_class,
                "hypothesis_id": hypothesis.hypothesis_id,
                "source_refs": sorted(source_refs),
                "relationship_id": relation.relationship_id if relation else "none",
            }
            chain_id = "chain:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:24]
            result.append(
                AttackChainHypothesis(
                    chain_id=chain_id,
                    vulnerability_class=hypothesis.vulnerability_class,
                    weakness=hypothesis.security_assumption,
                    supporting_condition=supporting,
                    privilege_boundary=boundary,
                    business_impact=impact,
                    source_refs=source_refs,
                    reasoning=(
                        f"{hypothesis.reasoning_chain} A chain is retained as a hypothesis "
                        "until causal validation eliminates alternatives."
                    ),
                    confidence=min(
                        hypothesis.confidence,
                        relation.confidence if relation is not None else hypothesis.confidence,
                    ),
                    validation_requirement=requirement,
                    status="hypothesis" if relation is not None else "blocked",
                )
            )
        return tuple(sorted(result, key=lambda item: item.chain_id))


__all__ = ["AdvancedAttackChainReasoner", "AttackChainHypothesis"]
