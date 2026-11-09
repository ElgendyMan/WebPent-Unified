"""Campaign schemas — the data spine of the strategist/executor.

Plain dataclasses, deliberately boring: deterministic construction, no
LLM output in any field, enums for every vocabulary the operator reads.

Versioning note (TargetThesis.create): refined theses chain through
``supersedes`` and a module-level version registry. The registry is
in-process state by design — thesis versions are a campaign-session
concept, not a durable store concept (ThesisStore owns durability).
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ConfidenceLevel(str, Enum):
    """The thesis's declared confidence vocabulary (operator-facing)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class Decision(str, Enum):
    """The operator's sovereign decision on a campaign brief."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    MODIFIED = "modified"


class PivotAction(str, Enum):
    """What to do when a boundary is hit (L-6: pivot at boundaries)."""

    PROCEED = "proceed"
    NEXT_PHASE = "next_phase"
    REGENERATE = "regenerate"
    ABORT = "abort"
    PROCEED_CAUTION = "proceed_caution"


class PhaseStatus(str, Enum):
    """Phase lifecycle status. The machine reports; it never grades."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    EXHAUSTED = "exhausted"
    PIVOTED = "pivoted"
    SKIPPED = "skipped"


class Family(str, Enum):
    """Vulnerability families the strategist reasons over."""

    BOLA = "bola"
    IDOR = "idor"
    SQLI = "sqli"
    SSRF = "ssrf"
    XSS = "xss"
    AUTH_BYPASS = "auth_bypass"
    SSTI = "ssti"
    INFO_DISCLOSURE = "info_disclosure"


# ---------------------------------------------------------------------------
# Thesis-side schemas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ThesisEvidence:
    """One claim the thesis stands on, traced to its source."""

    evidence_id: str
    source: str  # "oracle" | "prism" | "economist" | ...
    source_ref: str
    claim: str
    weight: float  # 0..1 — how strong this piece of evidence is


_THESIS_VERSION_REGISTRY: dict[str, int] = {}


@dataclass(frozen=True)
class TargetThesis:
    """L-1: the thesis is the ONLY entry point to a campaign.

    Frozen: a thesis is a claim about the target at a point in time.
    New evidence does not edit it — it supersedes it (version + 1).
    """

    thesis_id: str
    target_id: str
    statement: str
    confidence: float  # 0..1
    likely_vuln_families: list[tuple[Family, float]]
    unlikely_vuln_families: list[tuple[Family, float]]
    crown_jewels: list[str]
    likely_entry_points: list[str]
    evidence: list[ThesisEvidence]
    reasoning: str
    created_at: datetime
    version: int = 1
    supersedes: str | None = None

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        statement: str,
        confidence: float,
        likely_vuln_families: list[tuple[Family, float]],
        unlikely_vuln_families: list[tuple[Family, float]],
        crown_jewels: list[str],
        likely_entry_points: list[str],
        evidence: list[ThesisEvidence],
        reasoning: str,
        supersedes: str | None = None,
    ) -> "TargetThesis":
        if supersedes is None:
            version = 1
        else:
            version = _THESIS_VERSION_REGISTRY.get(supersedes, 1) + 1
        thesis = cls(
            thesis_id=f"thesis-{uuid.uuid4().hex[:12]}",
            target_id=target_id,
            statement=statement,
            confidence=confidence,
            likely_vuln_families=list(likely_vuln_families),
            unlikely_vuln_families=list(unlikely_vuln_families),
            crown_jewels=list(crown_jewels),
            likely_entry_points=list(likely_entry_points),
            evidence=list(evidence),
            reasoning=reasoning,
            created_at=datetime.now(timezone.utc),
            version=version,
            supersedes=supersedes,
        )
        _THESIS_VERSION_REGISTRY[thesis.thesis_id] = version
        return thesis


# ---------------------------------------------------------------------------
# Plan-side schemas
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hypothesis:
    """A disposable, falsifiable probe claim inside a phase.

    Phases are the plan; hypotheses are disposable ammunition. Killing
    one costs its estimate, not the campaign.
    """

    hypothesis_id: str
    family: Family
    statement: str
    success_indicator: str
    failure_indicator: str
    probe_strategy: str
    estimated_requests: int
    estimated_llm_calls: int
    estimated_duration_seconds: int
    order: int


@dataclass(frozen=True)
class PhaseBudget:
    """The phase's hard spend caps (L-3: budget is law)."""

    max_requests: int
    max_time_minutes: int
    max_llm_calls: int


@dataclass
class PivotTrigger:
    """A boundary declared UP FRONT, before any traffic (L-6).

    Triggers are part of the plan the operator approves — pivoting at
    frustration is forbidden; pivoting at a declared boundary is the
    machine's mechanical duty.
    """

    trigger_id: str
    condition: str
    condition_type: str  # "consecutive_failures" | ... (extensible)
    threshold: int
    action: PivotAction
    reason: str


@dataclass
class Phase:
    """One phase of the campaign plan: goal, hypotheses, budget, exits."""

    phase_id: str
    order: int
    goal: str
    thesis_alignment: str
    hypotheses: list[Hypothesis]
    budget: PhaseBudget
    exit_criteria: list[str]
    success_indicators: list[str]
    failure_indicators: list[str]
    pivot_triggers: list[PivotTrigger] = field(default_factory=list)
    entry_criteria: list[str] = field(default_factory=list)
    target_id: str | None = None


@dataclass
class CampaignBudget:
    """The campaign's total spend caps and accumulated usage (L-3).

    Mutable on purpose: the usage counters accumulate as the executor
    reports spends. The caps themselves are operator-set and never
    mutated by the machine.
    """

    max_requests: int
    max_time_minutes: int
    max_llm_calls: int
    requests_used: int = 0
    time_seconds_used: float = 0.0
    llm_calls_used: int = 0

    def would_exceed(self, requests: int, time_seconds: float,
                     llm_calls: int) -> bool:
        return (
            self.requests_used + requests > self.max_requests
            or self.time_seconds_used + time_seconds > self.max_time_minutes * 60
            or self.llm_calls_used + llm_calls > self.max_llm_calls
        )


@dataclass(frozen=True)
class CampaignBrief:
    """What the operator reads and rules on (L-2)."""

    campaign_id: str
    created_at: datetime
    thesis: TargetThesis | None
    phases: list[Phase]
    total_budget: CampaignBudget
    decision: Decision = Decision.PENDING
