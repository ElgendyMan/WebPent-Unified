"""Bounded, target-neutral contracts for the ABHC v3 research core.

These contracts describe advisory research decisions only.  They deliberately
contain no transport, credential, mutation, finding-promotion, or qualification
authority.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from typing import Any


class HypothesisStatus(StrEnum):
    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    SUPPORTED = "SUPPORTED"
    VALIDATING = "VALIDATING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


class AdvisoryDisposition(StrEnum):
    BLOCKED = "BLOCKED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    ADVISORY_CANDIDATE = "ADVISORY_CANDIDATE"


def _clean_refs(values: Iterable[str], limit: int = 32) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))[
        :limit
    ]


@dataclass(frozen=True, slots=True)
class ResearchMission:
    mission_id: str
    objective: str
    reasoning: str
    target_area: str
    expected_security_value: float
    required_capabilities: tuple[str, ...] = ()
    validation_criteria: tuple[str, ...] = ()
    priority: float = 0.0
    budget_cost: float = 1.0
    status: str = "PROPOSED"
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.mission_id.strip() or not self.objective.strip():
            raise ValueError("mission_identity_required")
        if not self.target_area.strip():
            raise ValueError("mission_target_area_required")
        if not 0.0 <= self.expected_security_value <= 1.0:
            raise ValueError("mission_value_out_of_range")
        if not 0.0 <= self.priority <= 1.0:
            raise ValueError("mission_priority_out_of_range")
        if self.budget_cost < 0.0:
            raise ValueError("mission_budget_invalid")
        if not self.advisory_only:
            raise ValueError("mission_must_be_advisory")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SurfaceCandidate:
    surface_id: str
    category: str
    label: str
    priority: float
    confidence: float
    potential: float
    explored: bool
    evidence_refs: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.surface_id.strip() or not self.label.strip():
            raise ValueError("surface_identity_required")
        for value in (self.priority, self.confidence, self.potential):
            if not 0.0 <= value <= 1.0:
                raise ValueError("surface_score_out_of_range")
        object.__setattr__(self, "evidence_refs", _clean_refs(self.evidence_refs))


@dataclass(frozen=True, slots=True)
class CoverageState:
    explored: tuple[str, ...] = ()
    unexplored: tuple[str, ...] = ()
    low_confidence: tuple[str, ...] = ()
    high_potential: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("explored", "unexplored", "low_confidence", "high_potential"):
            object.__setattr__(self, name, _clean_refs(getattr(self, name), limit=128))


@dataclass(frozen=True, slots=True)
class SurfaceExplorationReport:
    surfaces: tuple[SurfaceCandidate, ...]
    coverage: CoverageState
    knowledge_gaps: tuple[str, ...] = ()
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.advisory_only:
            raise ValueError("surface_report_must_be_advisory")
        object.__setattr__(self, "knowledge_gaps", _clean_refs(self.knowledge_gaps, 128))


@dataclass(frozen=True, slots=True)
class OracleEvidence:
    causal_signal: bool = False
    independent_negative_control: bool = False
    proof_bundle_complete: bool = False
    replay_verified: bool = False
    actual_observation_refs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "actual_observation_refs", _clean_refs(self.actual_observation_refs)
        )

    @property
    def sufficient(self) -> bool:
        return (
            self.causal_signal
            and self.independent_negative_control
            and self.proof_bundle_complete
            and self.replay_verified
            and bool(self.actual_observation_refs)
        )


@dataclass(frozen=True, slots=True)
class EvolvingHypothesis:
    hypothesis_id: str
    statement: str
    security_assumption: str
    target_area: str
    status: HypothesisStatus = HypothesisStatus.NEW
    confidence: float = 0.0
    evidence_refs: tuple[str, ...] = ()
    required_validation: tuple[str, ...] = ()
    history: tuple[str, ...] = ()
    oracle_evidence: OracleEvidence | None = None

    def __post_init__(self) -> None:
        if not self.hypothesis_id.strip() or not self.statement.strip():
            raise ValueError("hypothesis_identity_required")
        if not self.security_assumption.strip() or not self.target_area.strip():
            raise ValueError("hypothesis_context_required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("hypothesis_confidence_out_of_range")
        object.__setattr__(self, "evidence_refs", _clean_refs(self.evidence_refs))
        object.__setattr__(self, "required_validation", _clean_refs(self.required_validation, 64))
        object.__setattr__(self, "history", _clean_refs(self.history, 64))
        if self.status is HypothesisStatus.CONFIRMED and not (
            self.oracle_evidence and self.oracle_evidence.sufficient
        ):
            raise ValueError("confirmation_requires_complete_oracle_evidence")

    def _transition(
        self, status: HypothesisStatus, event: str, **changes: Any
    ) -> EvolvingHypothesis:
        return replace(self, status=status, history=(*self.history, event), **changes)

    def start_investigation(self) -> EvolvingHypothesis:
        if self.status not in {HypothesisStatus.NEW, HypothesisStatus.INVESTIGATING}:
            raise ValueError("invalid_investigation_transition")
        return self._transition(HypothesisStatus.INVESTIGATING, "investigation_started")

    def expand(self, statement: str, required_validation: Iterable[str] = ()) -> EvolvingHypothesis:
        if not statement.strip():
            raise ValueError("expanded_statement_required")
        return self._transition(
            self.status,
            "hypothesis_expanded",
            statement=statement.strip(),
            required_validation=_clean_refs((*self.required_validation, *required_validation), 64),
        )

    def attach_evidence(
        self, refs: Iterable[str], confidence: float | None = None
    ) -> EvolvingHypothesis:
        next_confidence = self.confidence if confidence is None else confidence
        if not 0.0 <= next_confidence <= 1.0:
            raise ValueError("hypothesis_confidence_out_of_range")
        return replace(
            self,
            evidence_refs=_clean_refs((*self.evidence_refs, *refs)),
            confidence=next_confidence,
            status=HypothesisStatus.SUPPORTED if refs else self.status,
            history=(*self.history, "evidence_attached") if refs else self.history,
        )

    def begin_validation(self) -> EvolvingHypothesis:
        if self.status not in {HypothesisStatus.SUPPORTED, HypothesisStatus.INVESTIGATING}:
            raise ValueError("validation_requires_investigation")
        return self._transition(HypothesisStatus.VALIDATING, "validation_started")

    def reject(self, reason: str) -> EvolvingHypothesis:
        if not reason.strip():
            raise ValueError("rejection_reason_required")
        return self._transition(HypothesisStatus.REJECTED, f"rejected:{reason.strip()}")

    def apply_oracle(self, oracle: OracleEvidence) -> EvolvingHypothesis:
        if not oracle.sufficient:
            raise ValueError("incomplete_oracle_cannot_confirm")
        if self.status not in {HypothesisStatus.SUPPORTED, HypothesisStatus.VALIDATING}:
            raise ValueError("oracle_requires_supported_hypothesis")
        return self._transition(
            HypothesisStatus.CONFIRMED,
            "oracle_complete",
            oracle_evidence=oracle,
            confidence=max(self.confidence, 0.95),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(frozen=True, slots=True)
class BoundaryCandidate:
    boundary_id: str
    boundary_type: str
    source_node: str
    target_node: str
    security_question: str
    evidence_refs: tuple[str, ...] = ()
    confidence: float = 0.0

    def __post_init__(self) -> None:
        if not self.boundary_id.strip() or not self.security_question.strip():
            raise ValueError("boundary_identity_required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("boundary_confidence_out_of_range")
        object.__setattr__(self, "evidence_refs", _clean_refs(self.evidence_refs))


@dataclass(frozen=True, slots=True)
class SecurityBoundaryMap:
    boundaries: tuple[BoundaryCandidate, ...]
    unresolved_questions: tuple[str, ...] = ()
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.advisory_only:
            raise ValueError("boundary_map_must_be_advisory")
        object.__setattr__(
            self, "unresolved_questions", _clean_refs(self.unresolved_questions, 128)
        )


@dataclass(frozen=True, slots=True)
class ExperimentPlan:
    experiment_id: str
    hypothesis_id: str
    purpose: str
    expected_result: str
    success_criteria: tuple[str, ...]
    failure_criteria: tuple[str, ...]
    information_gain: float
    evidence_value: float
    cost: float
    risk: float
    required_capabilities: tuple[str, ...] = ()
    selected: bool = False
    blocked_reason: str = ""

    def __post_init__(self) -> None:
        if not self.experiment_id.strip() or not self.hypothesis_id.strip():
            raise ValueError("experiment_identity_required")
        for value in (self.information_gain, self.evidence_value, self.cost, self.risk):
            if not 0.0 <= value <= 1.0:
                raise ValueError("experiment_score_out_of_range")
        if not self.purpose.strip() or not self.expected_result.strip():
            raise ValueError("experiment_purpose_required")
        if not self.success_criteria or not self.failure_criteria:
            raise ValueError("experiment_criteria_required")
        if self.selected and self.blocked_reason:
            raise ValueError("selected_experiment_cannot_be_blocked")

    @property
    def utility(self) -> float:
        return round(
            0.35 * self.information_gain
            + 0.35 * self.evidence_value
            - 0.20 * self.cost
            - 0.10 * self.risk,
            6,
        )


@dataclass(frozen=True, slots=True)
class FindingConfidenceReport:
    hypothesis_id: str
    vulnerability_exists: bool | None
    impact_demonstrated: bool | None
    alternative_explanations_considered: bool
    evidence_reproducible: bool
    confidence_justified: bool
    disposition: AdvisoryDisposition
    rationale: tuple[str, ...]
    promotion_allowed: bool = False

    def __post_init__(self) -> None:
        if self.promotion_allowed:
            raise ValueError("quality_report_cannot_promote")
        object.__setattr__(self, "rationale", _clean_refs(self.rationale, 32))


@dataclass(frozen=True, slots=True)
class WeakSignal:
    signal_id: str
    description: str
    evidence_refs: tuple[str, ...] = ()
    strength: float = 0.0

    def __post_init__(self) -> None:
        if not self.signal_id.strip() or not self.description.strip():
            raise ValueError("weak_signal_required")
        if not 0.0 <= self.strength <= 1.0:
            raise ValueError("signal_strength_out_of_range")
        object.__setattr__(self, "evidence_refs", _clean_refs(self.evidence_refs))


@dataclass(frozen=True, slots=True)
class PotentialAttackChain:
    chain_id: str
    reasoning_path: tuple[str, ...]
    weak_signal_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    required_validation: tuple[str, ...]
    confidence: float
    status: str = "HYPOTHESIS"
    advisory_only: bool = True

    def __post_init__(self) -> None:
        if not self.chain_id.strip() or len(self.reasoning_path) < 2:
            raise ValueError("attack_chain_path_required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("chain_confidence_out_of_range")
        if self.status != "HYPOTHESIS" or not self.advisory_only:
            raise ValueError("attack_chain_must_remain_hypothesis")
        object.__setattr__(self, "weak_signal_refs", _clean_refs(self.weak_signal_refs))
        object.__setattr__(self, "evidence_refs", _clean_refs(self.evidence_refs))
        object.__setattr__(self, "required_validation", _clean_refs(self.required_validation, 64))


@dataclass(frozen=True, slots=True)
class AutonomousResearchReviewReport:
    review_id: str
    hypothesis_count: int
    boundary_count: int
    chain_count: int
    evidence_complete_count: int
    challenged_count: int
    disposition: AdvisoryDisposition
    challenges: tuple[str, ...]
    qualification_allowed: bool = False
    confirmed_finding_created: bool = False

    def __post_init__(self) -> None:
        if self.qualification_allowed or self.confirmed_finding_created:
            raise ValueError("senior_review_has_no_promotion_authority")
        object.__setattr__(self, "challenges", _clean_refs(self.challenges, 64))


@dataclass(frozen=True, slots=True)
class ABHCOutput:
    missions: tuple[ResearchMission, ...]
    surfaces: SurfaceExplorationReport
    hypotheses: tuple[EvolvingHypothesis, ...]
    boundaries: SecurityBoundaryMap
    experiments: tuple[ExperimentPlan, ...]
    chains: tuple[PotentialAttackChain, ...]
    quality_reports: tuple[FindingConfidenceReport, ...]
    review: AutonomousResearchReviewReport
    requests_sent: int = 0
    mutation_performed: bool = False

    def __post_init__(self) -> None:
        if self.requests_sent != 0 or self.mutation_performed:
            raise ValueError("abhc_core_must_be_offline_advisory")


__all__ = [
    "ABHCOutput",
    "AdvisoryDisposition",
    "AutonomousResearchReviewReport",
    "BoundaryCandidate",
    "CoverageState",
    "EvolvingHypothesis",
    "ExperimentPlan",
    "FindingConfidenceReport",
    "HypothesisStatus",
    "OracleEvidence",
    "PotentialAttackChain",
    "ResearchMission",
    "SecurityBoundaryMap",
    "SurfaceCandidate",
    "SurfaceExplorationReport",
    "WeakSignal",
]
