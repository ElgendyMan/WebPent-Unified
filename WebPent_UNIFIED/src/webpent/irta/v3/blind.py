"""Blind-evaluation contracts for IRTA v3.

The owner registry and detector view are separate objects. The detector view
contains only an opaque target reference and safe campaign metadata; it never
returns routes, labels, expected answers, or source content.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256


class CaseOutcome(StrEnum):
    BLOCKED = "BLOCKED"
    OBSERVATION_ONLY = "OBSERVATION_ONLY"
    CONFIRMED = "CONFIRMED"
    CLEAN = "CLEAN"


@dataclass(frozen=True)
class GroundTruthCase:
    """Owner-only case record; never returned by detector-facing methods."""

    case_id: str
    vulnerability_class: str
    route_ref: str
    expected_outcome: CaseOutcome
    oracle_id: str


@dataclass(frozen=True)
class DetectorView:
    """The complete target view permitted to a detector."""

    target_id: str
    runtime_digest: str
    campaign_id: str
    network_scope: str = "loopback-only"


@dataclass(frozen=True)
class BlindObservation:
    """Redacted observation accepted from a detector without truth labels."""

    observation_id: str
    target_id: str
    case_ref: str
    status_code: int
    response_shape: str
    evidence_digest: str


class BlindEvaluationBoundary:
    """Owner-controlled registry with a deliberately narrow detector surface."""

    def __init__(self, target_id: str, runtime_digest: str, campaign_id: str) -> None:
        self._target_id = target_id
        self._runtime_digest = runtime_digest
        self._campaign_id = campaign_id
        self._truth: dict[str, GroundTruthCase] = {}
        self._observations: list[BlindObservation] = []

    def register_owner_case(self, case: GroundTruthCase) -> None:
        if case.case_id in self._truth:
            raise ValueError("duplicate owner case")
        if case.route_ref.startswith("http") or "password" in case.route_ref.lower():
            raise ValueError("unsafe or sensitive route reference")
        self._truth[case.case_id] = case

    def detector_view(self) -> DetectorView:
        return DetectorView(
            target_id=self._target_id,
            runtime_digest=self._runtime_digest,
            campaign_id=self._campaign_id,
        )

    def accept_observation(
        self,
        case_ref: str,
        status_code: int,
        response_shape: str,
        redacted_evidence: str,
    ) -> BlindObservation:
        if not case_ref or case_ref not in self._truth:
            raise ValueError("unknown case reference")
        evidence_digest = sha256(redacted_evidence.encode("utf-8")).hexdigest()
        observation = BlindObservation(
            observation_id=f"obs-{len(self._observations) + 1}",
            target_id=self._target_id,
            case_ref=case_ref,
            status_code=status_code,
            response_shape=response_shape,
            evidence_digest=evidence_digest,
        )
        self._observations.append(observation)
        return observation

    def owner_evaluate(
        self, observations: tuple[BlindObservation, ...]
    ) -> Mapping[str, CaseOutcome]:
        """Evaluate only on the owner side; detector code has no reference to this method."""
        results: dict[str, CaseOutcome] = {}
        for observation in observations:
            truth = self._truth.get(observation.case_ref)
            if truth is None:
                results[observation.case_ref] = CaseOutcome.BLOCKED
            elif truth.expected_outcome is CaseOutcome.CONFIRMED:
                results[observation.case_ref] = CaseOutcome.CONFIRMED
            else:
                results[observation.case_ref] = CaseOutcome.CLEAN
        return results
