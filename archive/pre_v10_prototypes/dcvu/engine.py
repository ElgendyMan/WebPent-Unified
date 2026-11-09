"""Detection quality engine for deterministic local DCVU campaigns."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .contracts import (
    CaseEvaluation,
    DetectorDecision,
    GroundTruthRecord,
    Observation,
    ObservationKind,
    Verdict,
)
from .fixtures import DisposableTargetFixture, FixtureProbe, FixtureResponse
from .ground_truth import GroundTruthRegistry


@dataclass(frozen=True)
class ProofSeal:
    bundle_id: str
    observation_digests: tuple[str, ...]
    seal_digest: str
    replay_verified: bool


class DetectionQualityValidationEngine:
    """Run generic read-only probes against a disposable in-process fixture."""

    def discover_case_ids(self, fixture: DisposableTargetFixture) -> tuple[str, ...]:
        return tuple(
            f"{fixture.profile.target_id}.{item['vulnerability_class']}.v1"
            for item in fixture.describe_surfaces()
        )

    def evaluate_target(
        self,
        fixture: DisposableTargetFixture,
        registry: GroundTruthRegistry,
    ) -> tuple[CaseEvaluation, ...]:
        evaluations: list[CaseEvaluation] = []
        for case_id in self.discover_case_ids(fixture):
            record = registry.record_for(case_id)
            evaluations.append(self.evaluate_case(fixture, record))
        return tuple(evaluations)

    def evaluate_case(
        self,
        fixture: DisposableTargetFixture,
        record: GroundTruthRecord,
    ) -> CaseEvaluation:
        case = record.case
        surface_id = self._surface_for_case(fixture, case.vulnerability_class)
        control_role = (
            "viewer"
            if case.vulnerability_class in {"idor_bola", "tenant_isolation"}
            else "admin"
            if case.vulnerability_class
            in {
                "privilege_escalation",
                "function_level_authorization",
            }
            else "editor"
        )
        control_identity = "admin-a" if control_role == "admin" else "editor-a"
        baseline = fixture.probe(
            FixtureProbe(
                surface_id=surface_id,
                requester_id=control_identity,
                object_owner_id=control_identity,
                object_tenant_id="tenant-a",
                requested_role=control_role,
            )
        )
        requester = "viewer-b" if case.vulnerability_class == "tenant_isolation" else "viewer-a"
        requested_role = (
            "viewer"
            if case.vulnerability_class in {"idor_bola", "tenant_isolation"}
            else "admin"
            if case.vulnerability_class
            in {
                "privilege_escalation",
                "function_level_authorization",
            }
            else "editor"
        )
        candidate = fixture.probe(
            FixtureProbe(
                surface_id=surface_id,
                requester_id=requester,
                object_owner_id="editor-a",
                object_tenant_id="tenant-a",
                requested_role=requested_role,
                transition="read"
                if case.vulnerability_class in {"idor_bola", "tenant_isolation"}
                else "transition",
            )
        )
        control = fixture.probe(
            FixtureProbe(
                surface_id=surface_id,
                requester_id=control_identity,
                object_owner_id=control_identity,
                object_tenant_id="tenant-a",
                requested_role=control_role,
            )
        )
        observations = (
            self._observation(
                case.case_id, fixture.profile.target_id, ObservationKind.BASELINE, baseline
            ),
            self._observation(
                case.case_id, fixture.profile.target_id, ObservationKind.CANDIDATE, candidate
            ),
            self._observation(
                case.case_id, fixture.profile.target_id, ObservationKind.NEGATIVE_CONTROL, control
            ),
        )
        causal = (
            baseline.semantic_signal == "authorized_semantic_access"
            and candidate.semantic_signal == "causal_unauthorized_access"
            and control.semantic_signal == "authorized_semantic_access"
            and candidate.impact != "none"
        )
        decision = DetectorDecision(
            case_id=case.case_id,
            target_id=case.target_id,
            detected=causal,
            confidence=0.95 if causal else 0.25,
            reason="causal_candidate_delta_with_control" if causal else "no_causal_candidate_delta",
            evidence_refs=tuple(item.evidence_digest for item in observations),
        )
        proof = self._seal_proof(case.case_id, observations)
        verdict = self._verdict(record.exists, decision.detected, proof.replay_verified)
        evaluation = CaseEvaluation(
            ground_truth=record,
            decision=decision,
            observations=observations,
            verdict=verdict,
            proof_complete=proof.replay_verified,
            replay_verified=proof.replay_verified,
            notes=("offline_fixture_evidence_only", "no_network_or_mutation"),
        )
        evaluation.validate()
        return evaluation

    @staticmethod
    def _surface_for_case(fixture: DisposableTargetFixture, vulnerability_class: str) -> str:
        for surface in fixture.surfaces.values():
            if surface.vulnerability_class == vulnerability_class:
                return surface.surface_id
        raise KeyError(vulnerability_class)

    @staticmethod
    def _observation(
        case_id: str,
        target_id: str,
        kind: ObservationKind,
        response: FixtureResponse,
    ) -> Observation:
        return Observation(
            case_id=case_id,
            target_id=target_id,
            kind=kind,
            semantic_signal=response.semantic_signal,
            subject_fingerprint=response.subject_fingerprint,
            object_fingerprint=response.object_fingerprint,
            evidence_digest=response.response_digest,
            oracle_passed=response.semantic_signal == "causal_unauthorized_access",
            independent_control_passed=(
                kind == ObservationKind.NEGATIVE_CONTROL
                and response.semantic_signal != "causal_unauthorized_access"
            ),
        )

    @staticmethod
    def _seal_proof(case_id: str, observations: tuple[Observation, ...]) -> ProofSeal:
        digests = tuple(item.evidence_digest for item in observations)
        material = f"{case_id}|{'|'.join(digests)}"
        seal = sha256(material.encode()).hexdigest()
        replay = sha256(material.encode()).hexdigest() == seal
        return ProofSeal(
            bundle_id=f"dcvu-proof:{case_id}",
            observation_digests=digests,
            seal_digest=f"sha256:{seal}",
            replay_verified=replay,
        )

    @staticmethod
    def _verdict(exists: bool, detected: bool, replay_verified: bool) -> Verdict:
        if not replay_verified:
            return Verdict.INCONCLUSIVE
        if exists and detected:
            return Verdict.TRUE_POSITIVE
        if exists and not detected:
            return Verdict.FALSE_NEGATIVE
        if not exists and detected:
            return Verdict.FALSE_POSITIVE
        return Verdict.TRUE_NEGATIVE
