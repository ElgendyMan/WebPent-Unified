"""Additive intelligence contracts for WebPent.

The existing graph/state models remain the source of truth for execution and
persistence.  This module provides a small, deterministic projection for the
roadmap's Target Brain and hypothesis terminology without introducing a second
execution authority or treating inference as proof.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.knowledge.target_knowledge import TargetKnowledgeModel
from webpent.models.findings import Severity, VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin


class IntelligenceRisk(str, Enum):
    """Risk labels used only for deterministic prioritisation."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EndpointIntelligence(BaseModel):
    """Bounded endpoint projection consumed by planners, never by executors."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    path: str = Field(..., min_length=1, max_length=2048)
    method: str = Field(default="GET", min_length=3, max_length=10)
    auth_required: bool = False
    role: str | None = Field(default=None, max_length=120)
    object_name: str | None = Field(default=None, alias="object", max_length=120)
    risk: IntelligenceRisk = IntelligenceRisk.LOW
    hypotheses: list[str] = Field(default_factory=list, max_length=8)
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("method", mode="before")
    @classmethod
    def _normalise_method(cls, value: str) -> str:
        return str(value).strip().upper()

    @field_validator("hypotheses", "evidence_refs")
    @classmethod
    def _unique_bounded_strings(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


class ApplicationKnowledgeGraph(BaseModel):
    """Safe application model joining existing knowledge with endpoint views."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: int = 1
    engagement_id: str = Field(..., min_length=1, max_length=200)
    endpoints: dict[str, EndpointIntelligence] = Field(default_factory=dict)
    knowledge: TargetKnowledgeModel | None = None

    def add_endpoint(self, endpoint: EndpointIntelligence) -> None:
        """Merge endpoint intelligence without weakening stronger observations."""
        key = f"{endpoint.method}:{endpoint.path}"
        current = self.endpoints.get(key)
        if current is None:
            self.endpoints[key] = endpoint
            return
        merged = endpoint.model_copy(
            update={
                "auth_required": current.auth_required or endpoint.auth_required,
                "role": endpoint.role or current.role,
                "object_name": endpoint.object_name or current.object_name,
                "risk": _max_risk(current.risk, endpoint.risk),
                "hypotheses": list(dict.fromkeys(current.hypotheses + endpoint.hypotheses)),
                "evidence_refs": list(
                    dict.fromkeys(current.evidence_refs + endpoint.evidence_refs)
                ),
            }
        )
        self.endpoints[key] = merged

    def as_dict(self) -> dict[str, Any]:
        """Return a checkpoint/report-safe projection."""
        return self.model_dump(mode="json", by_alias=True)


def _max_risk(left: IntelligenceRisk | str, right: IntelligenceRisk | str) -> IntelligenceRisk:
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    left_value = left.value if isinstance(left, IntelligenceRisk) else str(left)
    right_value = right.value if isinstance(right, IntelligenceRisk) else str(right)
    return IntelligenceRisk(left_value if order[left_value] >= order[right_value] else right_value)


class ResearchHypothesis(BaseModel):
    """Roadmap-shaped hypothesis that can be adapted to the legacy Kernel model."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: UUID = Field(default_factory=uuid4)
    target_url: str = Field(..., min_length=1, max_length=2048)
    reason: str = Field(..., min_length=3, max_length=1000)
    evidence_needed: list[str] = Field(default_factory=list, max_length=16)
    attack_plan: list[str] = Field(default_factory=list, max_length=16)
    risk: Severity = Severity.MEDIUM
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    vuln_class: VulnClass = VulnClass.UNKNOWN
    evidence_refs: list[str] = Field(default_factory=list, max_length=32)
    affected_asset: str = Field(default="", max_length=320)
    reasoning_chain: list[str] = Field(default_factory=list, max_length=16)
    required_capability: str = Field(default="http_read", max_length=120)
    origin: HypothesisOrigin = HypothesisOrigin.HEURISTIC

    @field_validator(
        "evidence_needed",
        "attack_plan",
        "evidence_refs",
        "reasoning_chain",
    )
    @classmethod
    def _unique_bounded_strings(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))

    def to_kernel_hypothesis(self) -> Hypothesis:
        """Convert to the existing hypothesis model without implying validation."""
        return Hypothesis(
            id=self.id,
            target_url=self.target_url,
            statement=self.reason,
            vuln_class=self.vuln_class,
            confidence_score=self.confidence,
            evidence_refs=self.evidence_refs,
            origin=self.origin,
            origin_detail="; ".join(self.evidence_needed[:4]),
            evidence_contract={
                "evidence_needed": self.evidence_needed,
                "attack_plan": self.attack_plan,
                "risk": self.risk.value if isinstance(self.risk, Severity) else self.risk,
                "affected_asset": self.affected_asset,
                "reasoning_chain": self.reasoning_chain,
                "required_capability": self.required_capability,
            },
        )


def build_endpoint_hypotheses(
    endpoint: EndpointIntelligence,
    *,
    target_url: str,
    observed_signals: Iterable[str] = (),
) -> list[ResearchHypothesis]:
    """Generate bounded, explainable hypotheses from endpoint metadata only.

    This function deliberately does not issue requests, select payloads, or
    promote findings.  Any resulting hypothesis remains subject to the normal
    scope, authority, validation, and proof gates.
    """

    path = endpoint.path.lower()
    signals = {
        str(signal).strip().lower()
        for signal in observed_signals
        if str(signal).strip()
    }
    hypotheses: list[ResearchHypothesis] = []
    object_like = endpoint.object_name or any(
        token in path for token in ("{id}", "/user", "/account", "/invoice", "/payment")
    )
    if endpoint.auth_required and object_like:
        confidence = 0.55 + (0.15 if "ownership_check_missing" in signals else 0.0)
        hypotheses.append(
            ResearchHypothesis(
                target_url=target_url,
                reason=(
                    "An authenticated caller may access an object outside its "
                    "ownership boundary."
                ),
                evidence_needed=[
                    "two authorized identities",
                    "same object requested under each identity",
                    "independent negative control",
                ],
                attack_plan=[
                    "compare owner and non-owner responses",
                    "verify object identity is stable",
                    "replay without changing scope",
                ],
                risk=Severity.HIGH,
                confidence=min(confidence, 1.0),
                vuln_class=VulnClass.IDOR,
            )
        )
    if endpoint.method in {"POST", "PUT", "PATCH", "DELETE"}:
        hypotheses.append(
            ResearchHypothesis(
                target_url=target_url,
                reason=(
                    "A state-changing endpoint may expose workflow or "
                    "business-logic invariants."
                ),
                evidence_needed=[
                    "before-state",
                    "single valid transition",
                    "replayed transition result",
                ],
                attack_plan=[
                    "map accepted state transitions",
                    "check duplicate or out-of-order transition",
                    "require target-backed causal signal",
                ],
                risk=Severity.MEDIUM,
                confidence=0.4,
                vuln_class=VulnClass.UNKNOWN,
            )
        )
    return hypotheses


__all__ = [
    "ApplicationKnowledgeGraph",
    "EndpointIntelligence",
    "IntelligenceRisk",
    "ResearchHypothesis",
    "build_endpoint_hypotheses",
]
