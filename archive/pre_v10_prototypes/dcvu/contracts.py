"""Contracts for Detection Capability Validation Upgrade v1.

The DCVU layer is deliberately target-I/O free.  It evaluates recorded observations
from disposable local fixtures and never creates findings, opens qualification gates,
or performs network/state-changing actions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CaseDisposition(StrEnum):
    ACCEPTED = "accepted"
    BLOCKED = "blocked"
    OBSERVATION_ONLY = "observation_only"
    OUT_OF_SCOPE = "out_of_scope"


class ObservationKind(StrEnum):
    BASELINE = "baseline"
    CANDIDATE = "candidate"
    NEGATIVE_CONTROL = "negative_control"


class Verdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    TRUE_NEGATIVE = "true_negative"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class TargetProfile:
    target_id: str
    version: str
    source_digest: str
    semantic_family: str
    local_only: bool = True
    disposable: bool = True
    mutation_enabled: bool = False
    credentials_enabled: bool = False

    def validate(self) -> None:
        if not self.target_id or not self.version or not self.source_digest:
            raise ValueError("target profile requires immutable identity fields")
        if not self.local_only or not self.disposable:
            raise ValueError("DCVU targets must be local-only and disposable")
        if self.mutation_enabled or self.credentials_enabled:
            raise ValueError("credentials and mutation are disabled in DCVU v1")


@dataclass(frozen=True)
class VulnerabilityCase:
    case_id: str
    target_id: str
    vulnerability_class: str
    title: str
    disposition: CaseDisposition = CaseDisposition.ACCEPTED
    requires_credentials: bool = False
    requires_login: bool = False
    requires_mutation: bool = False
    oracle_id: str = ""
    negative_control_id: str = ""

    def validate(self) -> None:
        if not self.case_id or not self.target_id or not self.vulnerability_class:
            raise ValueError("case identity and class are required")
        if self.disposition == CaseDisposition.ACCEPTED and not self.oracle_id:
            raise ValueError("accepted case requires a causal oracle")
        if self.disposition == CaseDisposition.ACCEPTED and not self.negative_control_id:
            raise ValueError("accepted case requires an independent negative control")
        if self.requires_credentials or self.requires_login or self.requires_mutation:
            raise ValueError("DCVU v1 excludes credentials, login, and mutation cases")


@dataclass(frozen=True)
class GroundTruthRecord:
    case: VulnerabilityCase
    exists: bool
    location_fingerprint: str
    expected_impact: str
    source_evidence_digest: str
    independent_review_id: str

    def validate(self) -> None:
        self.case.validate()
        if not self.location_fingerprint or not self.expected_impact:
            raise ValueError("ground truth requires location and impact")
        if not self.source_evidence_digest or not self.independent_review_id:
            raise ValueError("ground truth must have source digest and independent review")


@dataclass(frozen=True)
class Observation:
    case_id: str
    target_id: str
    kind: ObservationKind
    semantic_signal: str
    subject_fingerprint: str
    object_fingerprint: str
    evidence_digest: str
    oracle_passed: bool
    independent_control_passed: bool
    redacted: bool = True

    def validate(self) -> None:
        if not all((self.case_id, self.target_id, self.semantic_signal, self.evidence_digest)):
            raise ValueError("observation is missing required evidence fields")
        if not self.redacted:
            raise ValueError("DCVU observations must be redacted")
        if self.kind == ObservationKind.NEGATIVE_CONTROL and self.oracle_passed:
            raise ValueError("negative control cannot pass the vulnerable oracle")


@dataclass(frozen=True)
class DetectorDecision:
    case_id: str
    target_id: str
    detected: bool
    confidence: float
    reason: str
    evidence_refs: tuple[str, ...] = ()
    execution_allowed: bool = False
    qualification_effect: bool = False

    def validate(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be bounded")
        if self.execution_allowed or self.qualification_effect:
            raise ValueError("DCVU detector decisions cannot authorize execution or qualification")


@dataclass(frozen=True)
class CaseEvaluation:
    ground_truth: GroundTruthRecord
    decision: DetectorDecision
    observations: tuple[Observation, ...]
    verdict: Verdict
    proof_complete: bool
    replay_verified: bool
    notes: tuple[str, ...] = ()

    def validate(self) -> None:
        self.ground_truth.validate()
        self.decision.validate()
        for observation in self.observations:
            observation.validate()
        if self.verdict == Verdict.TRUE_POSITIVE and not (
            self.proof_complete and self.replay_verified
        ):
            raise ValueError("true positive requires complete proof and replay")


@dataclass(frozen=True)
class MetricResult:
    target_id: str
    attempted_cases: int
    scored_cases: int
    true_positive: int
    false_positive: int
    false_negative: int
    true_negative: int
    precision: float | None
    recall: float | None
    f1: float | None
    class_coverage: float | None
    proof_completeness: float | None
    scoring_eligible: bool
    notes: tuple[str, ...] = ()


@dataclass
class DcvRun:
    run_id: str
    targets: list[TargetProfile] = field(default_factory=list)
    cases: list[VulnerabilityCase] = field(default_factory=list)
    evaluations: list[CaseEvaluation] = field(default_factory=list)
    metrics: list[MetricResult] = field(default_factory=list)
    governance: dict[str, Any] = field(
        default_factory=lambda: {
            "official_isolated_p10_runs_authorized": False,
            "qualification_effect": False,
            "external_scope": False,
            "credentials_used": False,
            "state_mutation": False,
        }
    )

    def validate(self) -> None:
        for target in self.targets:
            target.validate()
        for case in self.cases:
            case.validate()
        for evaluation in self.evaluations:
            evaluation.validate()
        if any(self.governance.values()):
            raise ValueError("DCVU governance invariants require all effect flags to remain false")
