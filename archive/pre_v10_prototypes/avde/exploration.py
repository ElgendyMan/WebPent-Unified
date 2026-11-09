"""Bounded attack-path exploration and validation selection."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from webpent.avde.discovery import DiscoveryHypothesis
from webpent.models.evidence import redact_sensitive


class PathKind(str, Enum):
    PRIVILEGE_TRANSITION = "privilege_transition"
    TRUST_BOUNDARY = "trust_boundary"
    OWNERSHIP = "ownership"
    WORKFLOW_ABUSE = "workflow_abuse"


class AttackPath(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path_id: str = Field(min_length=16, max_length=128)
    kind: PathKind
    steps: tuple[str, ...] = Field(min_length=1, max_length=16)
    impact_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    validation_cost: int = Field(ge=1, le=1000)
    required_capability: str = Field(min_length=1, max_length=120)
    expected_security_value: float = Field(ge=0.0, le=1.0)
    blocked_reason: str | None = Field(default=None, max_length=240)

    @field_validator("steps")
    @classmethod
    def _safe_steps(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(dict.fromkeys(redact_sensitive(str(item))[0][:320] for item in values))


class AttackPathExplorer:
    """Rank graph proposals; it has no transport or authority capability."""

    def explore(
        self,
        graph_edges: Iterable[Mapping[str, object]],
        *,
        target_id: str,
        available_capabilities: Iterable[str] = (),
    ) -> tuple[AttackPath, ...]:
        capabilities = {str(item) for item in available_capabilities}
        paths: list[AttackPath] = []
        for raw in graph_edges:
            if not isinstance(raw, Mapping):
                raise TypeError("mapping_required")
            kind = PathKind(str(raw.get("kind", PathKind.TRUST_BOUNDARY.value)))
            steps = tuple(str(item) for item in raw.get("steps", ()))
            if not steps:
                raise ValueError("path_steps_required")
            impact = self._score(raw.get("impact", raw.get("impact_score", 0.4)))
            confidence = self._score(raw.get("confidence", 0.5))
            cost = max(1, min(1000, int(raw.get("validation_cost", len(steps)))))
            capability = str(raw.get("required_capability", "analysis"))
            value = max(0.0, min(1.0, impact * confidence / (1.0 + cost / 10.0) * 10.0))
            blocked_reason = (
                None if capability in capabilities or not capabilities else "capability_unavailable"
            )
            payload = json.dumps(
                {"kind": kind.value, "steps": steps, "target": target_id},
                sort_keys=True,
                separators=(",", ":"),
            )
            paths.append(
                AttackPath(
                    path_id=hashlib.sha256(payload.encode()).hexdigest(),
                    kind=kind,
                    steps=steps,
                    impact_score=impact,
                    confidence=confidence,
                    validation_cost=cost,
                    required_capability=capability,
                    expected_security_value=value,
                    blocked_reason=blocked_reason,
                )
            )
        return tuple(sorted(paths, key=lambda item: (-item.expected_security_value, item.path_id)))

    @staticmethod
    def _score(value: object) -> float:
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError) as exc:
            raise ValueError("score_must_be_numeric") from exc


class ValidationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    hypothesis_id: str = Field(min_length=16, max_length=128)
    selected_path_id: str | None = Field(default=None, max_length=128)
    steps: tuple[str, ...] = Field(default=(), max_length=12)
    evidence_strength: float = Field(ge=0.0, le=1.0)
    estimated_cost: int = Field(ge=0, le=1000)
    risk: str = Field(pattern="^(low|medium|high|blocked)$")
    decision: str = Field(pattern="^(selected|deferred|blocked)$")
    rationale: str = Field(min_length=3, max_length=500)


class AutonomousValidationStrategy:
    """Choose a cheapest valid proof path, never a transport action."""

    def choose(
        self,
        hypothesis: DiscoveryHypothesis,
        paths: Iterable[AttackPath],
        *,
        available_capabilities: Iterable[str] = (),
        max_cost: int = 100,
    ) -> ValidationPlan:
        capabilities = {str(item) for item in available_capabilities}
        path_items = tuple(paths)
        candidates = [
            path
            for path in path_items
            if path.validation_cost <= max_cost
            and path.blocked_reason is None
            and (not capabilities or path.required_capability in capabilities)
        ]
        if not candidates:
            blocked = path_items[0] if path_items else None
            return ValidationPlan(
                hypothesis_id=hypothesis.hypothesis_id,
                selected_path_id=blocked.path_id if blocked else None,
                steps=(),
                evidence_strength=0.0,
                estimated_cost=blocked.validation_cost if blocked else 0,
                risk="blocked",
                decision="blocked",
                rationale="No available capability provides a bounded valid proof path.",
            )
        selected = sorted(
            candidates,
            key=lambda item: (item.validation_cost, -item.expected_security_value, item.path_id),
        )[0]
        strength = min(1.0, selected.confidence * selected.impact_score)
        return ValidationPlan(
            hypothesis_id=hypothesis.hypothesis_id,
            selected_path_id=selected.path_id,
            steps=selected.steps,
            evidence_strength=strength,
            estimated_cost=selected.validation_cost,
            risk="low" if selected.validation_cost <= 10 else "medium",
            decision="selected",
            rationale="Selected the lowest-cost available path with a bounded evidence strategy.",
        )


__all__ = [
    "AttackPath",
    "AttackPathExplorer",
    "AutonomousValidationStrategy",
    "PathKind",
    "ValidationPlan",
]
