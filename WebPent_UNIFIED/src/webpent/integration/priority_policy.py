# src/webpent/integration/priority_policy.py
"""Deterministic research-priority policy (integration layer).

This module is part of the Shannon→GOED protected integration
(docs/integration/). Architectural reference: Shannon's queue gating
discipline (apps/worker/src/services/exploitation-checker.ts, AGPL-3.0)
— **pattern only, no code copied**; Shannon itself has no dynamic
prioritization, so the actual policy below is original GOED work
(protocol §12).

Security contract (protocol §8, §12):

* LLM may *suggest* priority only, via :class:`PriorityProposal`.
  The proposal influence is hard-clamped and fully recorded.
* The effective priority is computed **deterministically** from
  auditable factors. Same inputs → byte-identical decision.
* Decisions are bounded, auditable, and reproducible (protocol §12).
* This module is planning-only: it performs no I/O, never executes
  anything, and has **no verdict authority** (CausalGuard remains the
  sole CONFIRMED authority — see webpent.cqa_v2.causal_guard).
* No ground-truth access, ever (Evaluator ≠ Executor, protocol §22).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

POLICY_VERSION = "integration-priority-policy-1.0"

# Proposal influence is hard-clamped: an LLM can never buy more than
# PROPOSAL_MAX_BOOST points of priority, and its suggestion is always
# recorded next to the deterministic result.
PROPOSAL_MAX_BOOST = 10

PRIORITY_MIN = 0
PRIORITY_MAX = 100


class PriorityFactor(str, Enum):
    """Auditable factor names used by the deterministic policy."""

    SEVERITY_POTENTIAL = "severity_potential"
    EVIDENCE_STRENGTH = "evidence_strength"
    EXPLOITABILITY = "exploitability"
    ASSET_CRITICALITY = "asset_criticality"
    CONFIDENCE = "confidence"
    NOVELTY = "novelty"
    DEPENDENCY_DEPTH_PENALTY = "dependency_depth_penalty"
    EXPLORATION_COST_PENALTY = "exploration_cost_penalty"


# Integer weights: deterministic, versioned, auditable (protocol §12).
DEFAULT_WEIGHTS: dict[PriorityFactor, int] = {
    PriorityFactor.SEVERITY_POTENTIAL: 30,
    PriorityFactor.EVIDENCE_STRENGTH: 25,
    PriorityFactor.EXPLOITABILITY: 15,
    PriorityFactor.ASSET_CRITICALITY: 10,
    PriorityFactor.CONFIDENCE: 10,
    PriorityFactor.NOVELTY: 5,
    PriorityFactor.DEPENDENCY_DEPTH_PENALTY: 5,
    PriorityFactor.EXPLORATION_COST_PENALTY: 10,
}

# Factor inputs are normalized to these bounded scales.
SEVERITY_SCALE_MAX = 10  # severity_potential input is 0..10
DEPTH_PENALTY_SCALE_MAX = 5  # depth beyond this saturates the penalty
COST_SCALE_MAX = 10  # cost input is 0..10


class PriorityProposal(BaseModel):
    """An LLM *suggestion* for priority — advisory, clamped, recorded.

    The LLM never decides execution priority (protocol §12). It may only
    propose a bounded boost/decrease plus a reason. The deterministic
    policy applies at most ``PROPOSAL_MAX_BOOST`` points of influence.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    suggested_delta: int = Field(ge=-PROPOSAL_MAX_BOOST, le=PROPOSAL_MAX_BOOST)
    reason: str = Field(min_length=1, max_length=240)
    proposer: str = Field(min_length=1, max_length=80)  # e.g. "llm_researcher"

    @model_validator(mode="after")
    def _non_empty_reason(self) -> PriorityProposal:
        if not self.reason.strip():
            raise ValueError("proposal_reason_required")
        return self


class PriorityInput(BaseModel):
    """Deterministic inputs for one priority decision.

    All numeric inputs are bounded; validation is fail-closed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    severity_potential: int = Field(ge=0, le=SEVERITY_SCALE_MAX)  # 0..10
    evidence_strength: float = Field(ge=0.0, le=1.0)  # 0.0..1.0
    exploitability: float = Field(ge=0.0, le=1.0)  # 0.0..1.0
    asset_criticality: float = Field(ge=0.0, le=1.0)  # 0.0..1.0
    confidence: float = Field(ge=0.0, le=1.0)  # 0.0..1.0
    novelty: float = Field(ge=0.0, le=1.0)  # 0.0..1.0
    dependency_depth: int = Field(ge=0, le=32)  # branch depth of the item
    exploration_cost: int = Field(ge=0, le=COST_SCALE_MAX)  # 0..10


class PriorityDecision(BaseModel):
    """Auditable, reproducible result of the deterministic policy."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    priority: int = Field(ge=PRIORITY_MIN, le=PRIORITY_MAX)
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    contributions: dict[str, float]
    proposal_applied: int = Field(ge=-PROPOSAL_MAX_BOOST, le=PROPOSAL_MAX_BOOST)
    proposal_reason: str = Field(default="", max_length=240)
    proposal_proposer: str = Field(default="", max_length=80)

    def to_audit_dict(self) -> dict[str, Any]:
        """Flat, JSON-serializable audit view (protocol §12: auditable)."""
        return {
            "policy_version": self.policy_version,
            "priority": self.priority,
            "contributions": dict(sorted(self.contributions.items())),
            "proposal_applied": self.proposal_applied,
            "proposal_reason": self.proposal_reason,
            "proposal_proposer": self.proposal_proposer,
        }


def _clamp(value: float, low: int, high: int) -> int:
    """Deterministic clamp to [low, high]."""
    if value <= low:
        return low
    if value >= high:
        return high
    return int(value)


def compute_priority(
    inputs: PriorityInput,
    weights: dict[PriorityFactor, int] | None = None,
    proposal: PriorityProposal | None = None,
) -> PriorityDecision:
    """Compute the deterministic priority for one research item.

    Pure function: no I/O, no clock, no randomness. Same inputs (and
    weights/proposal) always produce the identical decision — this is
    what makes priority changes auditable and reproducible (§12).
    """
    w = dict(DEFAULT_WEIGHTS if weights is None else weights)
    contributions: dict[str, float] = {}
    total = 0.0
    max_total = 0.0

    # Positive factors (normalized 0..1 times weight).
    positive: list[tuple[PriorityFactor, float]] = [
        (PriorityFactor.SEVERITY_POTENTIAL, inputs.severity_potential / SEVERITY_SCALE_MAX),
        (PriorityFactor.EVIDENCE_STRENGTH, inputs.evidence_strength),
        (PriorityFactor.EXPLOITABILITY, inputs.exploitability),
        (PriorityFactor.ASSET_CRITICALITY, inputs.asset_criticality),
        (PriorityFactor.CONFIDENCE, inputs.confidence),
        (PriorityFactor.NOVELTY, inputs.novelty),
    ]
    for factor, normalized in positive:
        contribution = round(normalized * w[factor], 4)
        contributions[factor.value] = contribution
        total += contribution
        max_total += w[factor]

    # Penalty factors: deeper branches and costlier explorations score lower.
    depth_norm = min(1.0, inputs.dependency_depth / DEPTH_PENALTY_SCALE_MAX)
    depth_contribution = -round(depth_norm * w[PriorityFactor.DEPENDENCY_DEPTH_PENALTY], 4)
    contributions[PriorityFactor.DEPENDENCY_DEPTH_PENALTY.value] = depth_contribution
    total += depth_contribution

    cost_norm = min(1.0, inputs.exploration_cost / COST_SCALE_MAX)
    cost_contribution = -round(cost_norm * w[PriorityFactor.EXPLORATION_COST_PENALTY], 4)
    contributions[PriorityFactor.EXPLORATION_COST_PENALTY.value] = cost_contribution
    total += cost_contribution

    base = 100.0 * (total / max_total) if max_total > 0 else 0.0
    base = max(0.0, min(100.0, base))

    # Clamp the LLM proposal influence (protocol §12: bounded).
    proposal_applied = 0
    proposal_reason = ""
    proposal_proposer = ""
    if proposal is not None:
        proposal_applied = max(
            -PROPOSAL_MAX_BOOST, min(PROPOSAL_MAX_BOOST, proposal.suggested_delta)
        )
        proposal_reason = proposal.reason
        proposal_proposer = proposal.proposer

    priority = _clamp(base + proposal_applied, PRIORITY_MIN, PRIORITY_MAX)
    return PriorityDecision(
        priority=priority,
        contributions=contributions,
        proposal_applied=proposal_applied,
        proposal_reason=proposal_reason,
        proposal_proposer=proposal_proposer,
    )


__all__ = [
    "DEFAULT_WEIGHTS",
    "POLICY_VERSION",
    "PRIORITY_MAX",
    "PRIORITY_MIN",
    "PROPOSAL_MAX_BOOST",
    "PriorityDecision",
    "PriorityFactor",
    "PriorityInput",
    "PriorityProposal",
    "compute_priority",
]
