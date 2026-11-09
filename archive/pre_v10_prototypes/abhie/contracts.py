"""Typed, bounded contracts for ABHIE v4.

This module deliberately contains decision-support data only.  It has no network,
filesystem, executor, finding, or governance authority.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Lifecycle(str, Enum):
    PROPOSED = "proposed"
    PRIORITIZED = "prioritized"
    VALIDATION_READY = "validation_ready"
    OBSERVED = "observed"
    INCONCLUSIVE = "inconclusive"
    REJECTED = "rejected"
    BLOCKED = "blocked"


class Disposition(str, Enum):
    ADVISORY = "advisory"
    INSUFFICIENT = "insufficient"
    BLOCKED = "blocked"
    OBSERVATION_ONLY = "observation_only"


class EvidenceState(str, Enum):
    PRESENT = "present"
    MISSING = "missing"
    CONTRADICTED = "contradicted"
    UNVERIFIED = "unverified"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    kind: str
    state: EvidenceState = EvidenceState.UNVERIFIED
    source: str = "recorded"
    digest: str | None = None
    redacted: bool = True

    def canonical(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class BrainObservation:
    observation_id: str
    target_ref: str
    asset: str
    domain: str
    statement: str
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0
    source_kind: str = "recorded"

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class SecurityAssumption:
    assumption_id: str
    statement: str
    domain: str
    affected_assets: tuple[str, ...]
    risk: float
    source_refs: tuple[str, ...] = ()
    falsifiers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not 0.0 <= self.risk <= 1.0:
            raise ValueError("risk must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class ResearchBrainState:
    target_ref: str
    engagement_ref: str
    known: tuple[BrainObservation, ...] = ()
    unknowns: tuple[str, ...] = ()
    risky_assumptions: tuple[SecurityAssumption, ...] = ()
    research_history: tuple[str, ...] = ()
    evidence: tuple[EvidenceRef, ...] = ()
    version: str = "abhie-v4"

    def snapshot(self) -> str:
        payload = asdict(self)
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)

    @classmethod
    def restore(cls, snapshot: str) -> ResearchBrainState:
        raw = json.loads(snapshot)
        if raw.get("version") != "abhie-v4":
            raise ValueError("unsupported brain state version")
        known = tuple(
            BrainObservation(
                **{**item, "evidence_refs": tuple(item.get("evidence_refs", ()))}
            )
            for item in raw.get("known", ())
        )
        assumptions = tuple(
            SecurityAssumption(
                **{
                    **item,
                    "affected_assets": tuple(item.get("affected_assets", ())),
                    "source_refs": tuple(item.get("source_refs", ())),
                    "falsifiers": tuple(item.get("falsifiers", ())),
                }
            )
            for item in raw.get("risky_assumptions", ())
        )
        evidence = tuple(
            EvidenceRef(**{**item, "state": EvidenceState(item["state"])})
            for item in raw.get("evidence", ())
        )
        return cls(
            target_ref=raw["target_ref"],
            engagement_ref=raw["engagement_ref"],
            known=known,
            unknowns=tuple(raw.get("unknowns", ())),
            risky_assumptions=assumptions,
            research_history=tuple(raw.get("research_history", ())),
            evidence=evidence,
            version=raw["version"],
        )

    def digest(self) -> str:
        return hashlib.sha256(self.snapshot().encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class BoundaryNode:
    node_id: str
    kind: str
    label: str
    trust_level: str = "unknown"


@dataclass(frozen=True, slots=True)
class BoundaryCrossing:
    crossing_id: str
    source_node: str
    destination_node: str
    condition: str
    opportunity: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SecurityBoundaryGraph:
    target_ref: str
    nodes: tuple[BoundaryNode, ...]
    crossings: tuple[BoundaryCrossing, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class Hypothesis:
    hypothesis_id: str
    statement: str
    why_it_matters: str
    supporting_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    validation_plan: tuple[str, ...]
    affected_assets: tuple[str, ...]
    assumption_id: str | None = None
    lifecycle: Lifecycle = Lifecycle.PROPOSED
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class HypothesisCompetition:
    observation_id: str
    candidates: tuple[Hypothesis, ...]
    winner_id: str | None
    rationale: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class StrategyCandidate:
    strategy_id: str
    description: str
    information_gain: float
    evidence_value: float
    cost: float
    risk: float
    capabilities: tuple[str, ...] = ()
    blocked_reasons: tuple[str, ...] = ()

    @property
    def eligible(self) -> bool:
        return not self.blocked_reasons and self.risk <= 0.25


@dataclass(frozen=True, slots=True)
class ResearchStrategyDecision:
    selected_strategy_id: str | None
    rationale: tuple[str, ...]
    candidates: tuple[StrategyCandidate, ...]
    delegated_only: bool = True


@dataclass(frozen=True, slots=True)
class ReflectionLesson:
    lesson_id: str
    target_ref: str
    engagement_ref: str
    worked: tuple[str, ...]
    failed: tuple[str, ...]
    wrong_assumptions: tuple[str, ...]
    patterns: tuple[str, ...]
    next_changes: tuple[str, ...]
    version: str = "1"


@dataclass(frozen=True, slots=True)
class AttackChainHypothesis:
    chain_id: str
    steps: tuple[str, ...]
    reasoning: tuple[str, ...]
    confidence: float
    validation_requirements: tuple[str, ...]
    evidence_dependencies: tuple[str, ...]
    disposition: Disposition = Disposition.ADVISORY

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True, slots=True)
class EvidenceAssessment:
    causal: EvidenceState
    negative_control: EvidenceState
    proof_bundle: EvidenceState
    replay: EvidenceState
    completeness: float
    contradictions: tuple[str, ...] = ()

    @property
    def strong_enough_for_confirmation(self) -> bool:
        return (
            self.causal == EvidenceState.PRESENT
            and self.negative_control == EvidenceState.PRESENT
            and self.proof_bundle == EvidenceState.PRESENT
            and self.replay == EvidenceState.PRESENT
            and self.completeness >= 1.0
            and not self.contradictions
        )


@dataclass(frozen=True, slots=True)
class ResearchQualityScore:
    discovery_quality: float | None
    reasoning_quality: float | None
    evidence_quality: float | None
    efficiency: float | None
    coverage_improvement: float | None
    production_detection_rate: None = None


@dataclass(frozen=True, slots=True)
class SeniorSecurityReview:
    target_ref: str
    hypothesis_id: str
    real_boundary: bool
    failed_assumption: bool
    impact_demonstrated: bool
    evidence_complete: bool
    alternative_explanation_exists: bool
    disposition: Disposition
    challenges: tuple[str, ...]
    no_finding_created: bool = True
    no_governance_override: bool = True


def stable_digest(value: Mapping[str, Any] | Sequence[Any] | str) -> str:
    if isinstance(value, str):
        data = value.encode("utf-8")
    else:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(data).hexdigest()
