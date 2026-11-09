"""Data shapes for smarter hypothesis prioritization (additive, not frozen).

Pure dataclasses only — no LLM, no network, no authority. These are the
contract between the frozen planner/hypothesis-generator outputs and the new
enrichment/priority layer. Advisory only: a priority score never confirms,
seals, or promotes a finding.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PriorityLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class EndpointProfile:
    """Structural facts about one endpoint (no secrets, no verdict)."""

    route: str
    method: str = "GET"
    has_form: bool = False
    has_parameters: bool = False
    is_admin: bool = False
    is_debug: bool = False
    is_api: bool = False
    returns_user_data: bool = False
    is_static_asset: bool = False
    requires_session: bool = False
    auth_type: str = "none"
    content_type: str = ""  # e.g. "application/json", "application/x-www-form-urlencoded"
    waf_detected: bool = False
    uses_jwt: bool = False
    tech_stack: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": str(self.route)[:512],
            "method": str(self.method).upper()[:16],
            "has_form": bool(self.has_form),
            "has_parameters": bool(self.has_parameters),
            "is_admin": bool(self.is_admin),
            "is_debug": bool(self.is_debug),
            "is_api": bool(self.is_api),
            "returns_user_data": bool(self.returns_user_data),
            "is_static_asset": bool(self.is_static_asset),
            "requires_session": bool(self.requires_session),
            "auth_type": str(self.auth_type)[:32],
            "content_type": str(self.content_type)[:128],
            "waf_detected": bool(self.waf_detected),
            "uses_jwt": bool(self.uses_jwt),
            "tech_stack": list(self.tech_stack)[:32],
        }


@dataclass(frozen=True)
class PrioritizedHypothesis:
    hypothesis_id: str
    endpoint: EndpointProfile
    priority: PriorityLevel
    score: float
    rationale: str = ""
    payload_subtype: str = ""
    family: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": str(self.hypothesis_id)[:128],
            "endpoint": self.endpoint.as_dict(),
            "priority": self.priority.value,
            "score": round(float(self.score), 4),
            "rationale": str(self.rationale)[:240],
            "payload_subtype": str(self.payload_subtype)[:64],
            "family": str(self.family)[:64],
        }


@dataclass(frozen=True)
class EnrichedContext:
    """Context assembled for the planner (advisory data only)."""

    target_url: str
    tech_stack: tuple[str, ...] = ()
    auth_type: str = "none"
    prior_finding_patterns: tuple[str, ...] = ()
    payload_suggestions: tuple[str, ...] = ()
    lesson_priorities: Mapping[str, Any] = field(default_factory=dict)
    endpoints: tuple[EndpointProfile, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_url": str(self.target_url)[:512],
            "tech_stack": list(self.tech_stack)[:32],
            "auth_type": str(self.auth_type)[:32],
            "prior_finding_patterns": [str(p)[:128] for p in self.prior_finding_patterns][:64],
            "payload_suggestions": [str(p)[:128] for p in self.payload_suggestions][:64],
            "lesson_priorities": dict(self.lesson_priorities),
            "endpoints": [e.as_dict() for e in self.endpoints][:256],
        }


__all__ = ["PriorityLevel", "EndpointProfile", "PrioritizedHypothesis", "EnrichedContext"]
