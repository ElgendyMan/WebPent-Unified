"""Typed contracts for the bounded three-agent hunter loop.

The contracts are advisory/orchestration data only. Execution authority remains in
ScopeLaw, ToolBoundary, M4, AVI, deterministic validators, ProofBundle, replay,
and PromotionPipeline.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping

_MAX_TEXT = 800
_MAX_LIST = 64
_SECRET_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._~+/=-]{12,}|(?:api[_-]?key|token|password|secret)\s*[:=]\s*[^\s,;]+)"
)


class HunterStatus(str, Enum):
    PLANNED = "PLANNED"
    EXPLOITING = "EXPLOITING"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"
    HALTED = "HALTED"
    COMPLETED = "COMPLETED"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"


def digest(value: Any) -> str:
    """Return a stable digest of bounded JSON-safe advisory data."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest()


def sanitize_text(value: Any, limit: int = _MAX_TEXT) -> str:
    text = _SECRET_RE.sub("[REDACTED_SECRET]", str(value or ""))
    return text[:limit]


def sanitize_mapping(value: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in list((value or {}).items())[:_MAX_LIST]:
        name = sanitize_text(key, 80)
        if isinstance(item, Mapping):
            result[name] = sanitize_mapping(item)
        elif isinstance(item, (list, tuple)):
            result[name] = [sanitize_text(part, 240) for part in list(item)[:_MAX_LIST]]
        elif isinstance(item, (int, float, bool)) or item is None:
            result[name] = item
        else:
            result[name] = sanitize_text(item, 400)
    return result


@dataclass(frozen=True)
class BudgetState:
    max_llm_calls: int = 20
    llm_calls: int = 0
    max_cost_usd: float = 5.0
    cost_usd: float = 0.0
    max_iterations_per_hypothesis: int = 5
    max_replans_per_hypothesis: int = 3
    max_hypotheses: int = 30
    max_wall_seconds: float = 900.0
    halted: bool = False

    def can_continue(self) -> bool:
        return (
            not self.halted
            and self.llm_calls < self.max_llm_calls
            and self.cost_usd < self.max_cost_usd
        )

    def consume(self, *, calls: int = 0, cost_usd: float = 0.0) -> "BudgetState":
        return BudgetState(
            max_llm_calls=self.max_llm_calls,
            llm_calls=self.llm_calls + max(0, int(calls)),
            max_cost_usd=self.max_cost_usd,
            cost_usd=round(self.cost_usd + max(0.0, float(cost_usd)), 8),
            max_iterations_per_hypothesis=self.max_iterations_per_hypothesis,
            max_replans_per_hypothesis=self.max_replans_per_hypothesis,
            max_hypotheses=self.max_hypotheses,
            max_wall_seconds=self.max_wall_seconds,
            halted=self.halted,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CuriosityFlag:
    anomaly_type: str
    description: str
    target: str
    confidence: float
    suggested_investigation: str
    evidence_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["description"] = sanitize_text(data["description"])
        data["target"] = sanitize_text(data["target"], 240)
        data["suggested_investigation"] = sanitize_text(data["suggested_investigation"])
        return data


@dataclass(frozen=True)
class PlannerHypothesis:
    hypothesis_id: str
    hypothesis: str
    target_endpoint: str
    attack_type: str
    priority: int
    reasoning: str
    expected_behavior: str
    persona: str = "stok"
    wstg_reference: str | None = None
    payload_id: str | None = None
    attempt: int = 0
    method: str = "GET"
    parameter_to_change: str | None = None
    owner_value: str | None = None
    foreign_value: str | None = None
    expected_success: str = ""
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for key in ("hypothesis", "reasoning", "expected_behavior"):
            data[key] = sanitize_text(data[key])
        data["target_endpoint"] = sanitize_text(data["target_endpoint"], 300)
        data["method"] = str(data.get("method") or "GET").upper()[:12]
        data["parameter_to_change"] = sanitize_text(data.get("parameter_to_change"), 120) if data.get("parameter_to_change") else None
        data["owner_value"] = sanitize_text(data.get("owner_value"), 160) if data.get("owner_value") else None
        data["foreign_value"] = sanitize_text(data.get("foreign_value"), 160) if data.get("foreign_value") else None
        data["expected_success"] = sanitize_text(data.get("expected_success"), 300)
        data["requests"] = sanitize_mapping(data.get("requests"))
        return data


@dataclass(frozen=True)
class ExploitationResult:
    hypothesis_id: str
    status: HunterStatus
    request_executed: bool
    response_received: bool
    evidence: dict[str, Any] = field(default_factory=dict)
    authority_trace: tuple[str, ...] = ()
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["evidence"] = sanitize_mapping(self.evidence)
        data["authority_trace"] = list(self.authority_trace[:_MAX_LIST])
        data["error"] = sanitize_text(self.error) if self.error else None
        return data


@dataclass(frozen=True)
class ValidationVerdict:
    hypothesis_id: str
    verdict: Verdict
    confidence: float
    evidence_chain: tuple[str, ...] = ()
    proof_bundle_ref: str | None = None
    replay_verified: bool = False
    reason: str = ""
    next_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["verdict"] = self.verdict.value
        data["evidence_chain"] = list(self.evidence_chain[:_MAX_LIST])
        data["reason"] = sanitize_text(self.reason)
        data["next_action"] = sanitize_text(self.next_action) if self.next_action else None
        return data


@dataclass
class HunterState:
    surface_data: dict[str, Any] = field(default_factory=dict)
    tech_stack: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    hypotheses: list[PlannerHypothesis] = field(default_factory=list)
    exploitation_results: list[ExploitationResult] = field(default_factory=list)
    validation_verdicts: list[ValidationVerdict] = field(default_factory=list)
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)
    curiosity_flags: list[CuriosityFlag] = field(default_factory=list)
    session_state: dict[str, Any] = field(default_factory=dict)
    budget: BudgetState = field(default_factory=BudgetState)
    persona: str = "stok"
    status: HunterStatus = HunterStatus.PLANNED
    current_hypothesis_index: int = 0
    graph_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "surface_data": sanitize_mapping(self.surface_data),
            "tech_stack": sanitize_mapping(self.tech_stack),
            "notes": [sanitize_text(item) for item in self.notes[-_MAX_LIST:]],
            "hypotheses": [item.to_dict() for item in self.hypotheses[-_MAX_LIST:]],
            "exploitation_results": [item.to_dict() for item in self.exploitation_results[-_MAX_LIST:]],
            "validation_verdicts": [item.to_dict() for item in self.validation_verdicts[-_MAX_LIST:]],
            "confirmed_findings": [sanitize_mapping(item) for item in self.confirmed_findings[-_MAX_LIST:]],
            "curiosity_flags": [item.to_dict() for item in self.curiosity_flags[-_MAX_LIST:]],
            "session_state": sanitize_mapping(self.session_state),
            "budget": self.budget.to_dict(),
            "persona": sanitize_text(self.persona, 40),
            "status": self.status.value,
            "current_hypothesis_index": self.current_hypothesis_index,
            "graph_events": [sanitize_mapping(item) for item in self.graph_events[-_MAX_LIST:]],
        }

    def state_digest(self) -> str:
        return digest(self.to_dict())


__all__ = [
    "BudgetState", "CuriosityFlag", "ExploitationResult", "HunterState",
    "HunterStatus", "PlannerHypothesis", "ValidationVerdict", "Verdict",
    "digest", "sanitize_mapping", "sanitize_text",
]
