"""Discovery-oriented hypothesis generation for the bounded AVDE layer.

This module deliberately produces hypotheses, not findings.  It consumes a
redacted world-model projection and optional attack-graph metadata, and never
performs I/O, grants authority, or changes canonical promotion policy.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.asros.world_model import SecurityWorldModel
from webpent.models.evidence import redact_sensitive


class DiscoveryHypothesisStatus(str, Enum):
    GENERATED = "generated"
    INVESTIGATING = "investigating"
    BLOCKED = "blocked"
    VALIDATED = "validated"
    REJECTED = "rejected"


class DiscoveryHypothesis(BaseModel):
    """A falsifiable, target-scoped research proposal."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=16, max_length=128)
    engagement_id: str = Field(min_length=1, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    vulnerability_class: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    identity_boundary: str = Field(min_length=3, max_length=300)
    affected_asset: str = Field(min_length=1, max_length=240)
    security_assumption: str = Field(min_length=8, max_length=700)
    reasoning_chain: tuple[str, ...] = Field(min_length=1, max_length=12)
    failure_condition: str = Field(min_length=8, max_length=700)
    validation_strategy: tuple[str, ...] = Field(min_length=1, max_length=8)
    expected_evidence: tuple[str, ...] = Field(min_length=1, max_length=8)
    source_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    required_capabilities: tuple[str, ...] = Field(default=(), max_length=16)
    novelty_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    status: DiscoveryHypothesisStatus = DiscoveryHypothesisStatus.GENERATED
    expected_impact: float = Field(default=0.0, ge=0.0, le=1.0)
    validation_cost: int = Field(default=0, ge=0, le=1000)
    supporting_evidence: tuple[str, ...] = Field(default=(), max_length=32)
    contradicting_evidence: tuple[str, ...] = Field(default=(), max_length=32)
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)

    @field_validator(
        "reasoning_chain",
        "validation_strategy",
        "expected_evidence",
        "source_refs",
        "required_capabilities",
        "supporting_evidence",
        "contradicting_evidence",
    )
    @classmethod
    def _clean_items(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned: list[str] = []
        for value in values:
            redacted, _ = redact_sensitive(str(value))
            if redacted.strip():
                cleaned.append(redacted.strip()[:320])
        return tuple(dict.fromkeys(cleaned))

    @classmethod
    def stable_id(cls, *, target_id: str, asset: str, condition: str) -> str:
        payload = json.dumps(
            {"asset": asset.strip(), "condition": condition.strip(), "target": target_id.strip()},
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class DiscoveryHypothesisEngine:
    """Generate novel hypotheses from invariants, deviations, and graph hints."""

    def generate(
        self,
        world_model: SecurityWorldModel,
        *,
        observations: Iterable[Mapping[str, Any]] = (),
        attack_graph: Iterable[Mapping[str, Any]] = (),
        prior_hypotheses: Iterable[DiscoveryHypothesis] = (),
        historical_evidence: Iterable[Mapping[str, Any]] = (),
        previous_failures: Iterable[Mapping[str, Any]] = (),
    ) -> tuple[DiscoveryHypothesis, ...]:
        if not isinstance(world_model, SecurityWorldModel):
            raise TypeError("security_world_model_required")
        prior_ids = {item.hypothesis_id for item in prior_hypotheses}
        graph = tuple(self._redacted_mapping(item) for item in attack_graph)
        observed = tuple(self._redacted_mapping(item) for item in observations)
        history = tuple(self._redacted_mapping(item) for item in historical_evidence)
        failures = tuple(self._redacted_mapping(item) for item in previous_failures)
        generated: list[DiscoveryHypothesis] = []
        for invariant in world_model.invariants:
            related_deviation = any(
                str(item.get("asset", item.get("protected_resource", "")))
                == invariant.protected_resource
                and str(item.get("status", "")) in {"deviation", "unexpected"}
                for item in observed
            ) or any(
                behaviour.subject == invariant.protected_resource
                and behaviour.status.value == "deviation"
                for behaviour in world_model.behaviours
            )
            condition = (
                f"{invariant.statement} is false for a subject outside the allowed "
                "condition under a controlled candidate/control comparison."
            )
            hypothesis_id = DiscoveryHypothesis.stable_id(
                target_id=world_model.target_id,
                asset=invariant.protected_resource,
                condition=condition,
            )
            supporting = self._evidence_for_asset(
                history, invariant.protected_resource, positive=True
            )
            contradicting = self._evidence_for_asset(
                history, invariant.protected_resource, positive=False
            )
            failed_paths = sum(
                1
                for item in failures
                if str(item.get("hypothesis_id", "")) == hypothesis_id
                or str(item.get("asset", item.get("protected_resource", "")))
                == invariant.protected_resource
            )
            graph_hint = next(
                (
                    item
                    for item in graph
                    if str(item.get("asset", item.get("resource", "")))
                    == invariant.protected_resource
                ),
                {},
            )
            if hypothesis_id in prior_ids:
                continue
            capability = str(graph_hint.get("required_capability", "analysis"))
            vulnerability_class = self._vulnerability_class(invariant.kind.value)
            reasoning_chain = (
                f"world_model invariant {invariant.invariant_id} defines the boundary",
                f"security kind {invariant.kind.value} maps to {vulnerability_class}",
                f"attack_graph_hint_present={bool(graph_hint)}",
                f"behavioral_deviation_present={related_deviation}",
                "candidate/control comparison and causal validation are required",
            )
            confidence = min(
                0.95,
                invariant.lineage.confidence
                + (0.15 if related_deviation else 0.0)
                + min(0.1, 0.02 * len(supporting)),
            )
            novelty = max(0.0, min(1.0, (0.85 if related_deviation else 0.7) - 0.08 * failed_paths))
            expected_impact = self._impact_for_kind(invariant.kind.value)
            validation_cost = max(1, int(graph_hint.get("validation_cost", 3)))
            priority_score = max(
                0.0,
                min(
                    1.0,
                    0.35 * novelty
                    + 0.3 * confidence
                    + 0.25 * expected_impact
                    + 0.1 * (1.0 / (1.0 + validation_cost))
                    - min(0.25, 0.04 * failed_paths),
                ),
            )
            generated.append(
                DiscoveryHypothesis(
                    hypothesis_id=hypothesis_id,
                    engagement_id=world_model.engagement_id,
                    target_id=world_model.target_id,
                    vulnerability_class=vulnerability_class,
                    identity_boundary=invariant.subject,
                    affected_asset=invariant.protected_resource,
                    security_assumption=invariant.statement,
                    reasoning_chain=reasoning_chain,
                    failure_condition=condition,
                    validation_strategy=(
                        "establish safe precondition",
                        "run authorized candidate/control comparison",
                        "require causal oracle and central proof references",
                    ),
                    expected_evidence=(
                        "redacted candidate observation",
                        "independent negative-control observation",
                        "central verifier result",
                    ),
                    source_refs=invariant.lineage.evidence_refs,
                    required_capabilities=(capability,),
                    novelty_score=novelty,
                    confidence=confidence,
                    expected_impact=expected_impact,
                    validation_cost=validation_cost,
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    priority_score=priority_score,
                )
            )
        return tuple(
            sorted(
                generated,
                key=lambda item: (
                    -item.priority_score,
                    -item.novelty_score,
                    item.hypothesis_id,
                ),
            )
        )

    @staticmethod
    def _evidence_for_asset(
        evidence: tuple[dict[str, Any], ...], asset: str, *, positive: bool
    ) -> tuple[str, ...]:
        refs: list[str] = []
        for item in evidence:
            item_asset = str(item.get("asset", item.get("protected_resource", "")))
            if item_asset != asset:
                continue
            outcome = str(item.get("outcome", item.get("status", ""))).lower()
            is_positive = outcome in {"evidence", "supported", "confirmed", "success"}
            if is_positive == positive:
                ref = str(item.get("evidence_ref", item.get("source_ref", ""))).strip()
                if ref:
                    refs.append(ref[:240])
        return tuple(dict.fromkeys(refs))[:32]

    @staticmethod
    def _impact_for_kind(kind: str) -> float:
        return {
            "transaction": 0.95,
            "ownership": 0.9,
            "role_boundary": 0.85,
            "workflow": 0.8,
            "data_flow": 0.75,
        }.get(kind, 0.5)

    @staticmethod
    def _vulnerability_class(kind: str) -> str:
        return {
            "ownership": "broken_access_control",
            "role_boundary": "privilege_escalation",
            "transaction": "business_logic_abuse",
            "data_flow": "data_exposure",
            "workflow": "business_logic_abuse",
        }.get(kind, "security_boundary_issue")

    @staticmethod
    def _redacted_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise TypeError("mapping_required")
        return {
            str(key)[:80]: re.sub(
                r"(?i)(token|secret|password|cookie|authorization)\s*[:=]\s*[^\s,;]+",
                "[REDACTED]",
                redact_sensitive(str(item))[0],
            )[:320]
            for key, item in value.items()
            if str(key).lower() not in {"body", "raw", "token", "cookie", "secret"}
        }


__all__ = [
    "DiscoveryHypothesis",
    "DiscoveryHypothesisEngine",
    "DiscoveryHypothesisStatus",
]
