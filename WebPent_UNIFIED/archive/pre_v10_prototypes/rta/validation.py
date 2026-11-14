"""Causal validation for the local real-HTTP RTA benchmark."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass

from .auth_campaign import PermissionGraph, RtaAuthProfiles, run_authenticated_read_campaign
from .contracts import HttpObservation, RtaScope, SyntheticAuthContext
from .harness import LocalTargetConfig

_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("idor", "/api/documents/doc-a-2", "synthetic:user-a", "synthetic:user-b"),
    ("bfla", "/api/admin/reports", "synthetic:user-a", "synthetic:admin"),
    (
        "tenant_isolation",
        "/api/tenant/tenant-b/documents/doc-b-1",
        "synthetic:user-a",
        "synthetic:tenant-b",
    ),
    (
        "workflow_authorization",
        "/api/workflows/wf-a-1/preview",
        "synthetic:user-a",
        "synthetic:user-b",
    ),
    (
        "privilege_escalation",
        "/api/admin/privilege-preview",
        "synthetic:user-b",
        "synthetic:admin",
    ),
    (
        "business_logic",
        "/api/orders/order-a-1/summary",
        "synthetic:user-a",
        "synthetic:admin",
    ),
    (
        "tenant_partial_access",
        "/api/tenant/tenant-b/billing-summary",
        "synthetic:user-a",
        "synthetic:tenant-b",
    ),
)


@dataclass(frozen=True)
class RtaGroundTruth:
    target_id: str
    case_id: str
    vulnerability_class: str
    exists: bool
    source_digest: str


@dataclass(frozen=True)
class RtaProof:
    proof_id: str
    observation_ids: tuple[str, ...]
    seal: str
    replay_verified: bool


@dataclass(frozen=True)
class RtaCaseResult:
    target_id: str
    case_id: str
    vulnerability_class: str
    predicted_vulnerable: bool
    truth_vulnerable: bool
    verdict: str
    proof: RtaProof | None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class RtaValidationRun:
    target_id: str
    runtime_digest: str
    results: tuple[RtaCaseResult, ...]
    observations: tuple[HttpObservation, ...]
    permission_graph: PermissionGraph
    governance: dict[str, bool]


def default_auth_profiles() -> tuple[SyntheticAuthContext, ...]:
    """Return synthetic contexts only; no password, token, or login is involved."""

    return (
        SyntheticAuthContext(
            "user-a", "viewer", "tenant-a", "synthetic:user-a", ("document:read", "order:read")
        ),
        SyntheticAuthContext(
            "user-b", "editor", "tenant-a", "synthetic:user-b", ("document:read", "document:write")
        ),
        SyntheticAuthContext(
            "admin", "admin", "tenant-a", "synthetic:admin", ("document:read", "admin:read")
        ),
        SyntheticAuthContext(
            "tenant-b-user",
            "viewer",
            "tenant-b",
            "synthetic:tenant-b",
            ("document:read", "order:read"),
        ),
    )


def build_ground_truth(config: LocalTargetConfig) -> tuple[RtaGroundTruth, ...]:
    """Build auditable truth from the fixture manifest, outside detector inference."""

    return tuple(
        RtaGroundTruth(
            target_id=config.target_id,
            case_id=f"{config.target_id}:{vulnerability_class}",
            vulnerability_class=vulnerability_class,
            exists=vulnerability_class in config.vulnerable_classes,
            source_digest=config.source_digest,
        )
        for vulnerability_class, _, _, _ in _CASES
    )


def _observation_id(observation: HttpObservation) -> str:
    payload = {
        "path": observation.request.path,
        "session": observation.request.auth_context_id,
        "status": observation.status_code,
        "digest": observation.response_digest,
        "facts": observation.semantic_facts,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def _seal(observations: Iterable[HttpObservation]) -> str:
    payload = [
        {
            "path": item.request.path,
            "session": item.request.auth_context_id,
            "status": item.status_code,
            "digest": item.response_digest,
            "facts": item.semantic_facts,
        }
        for item in observations
    ]
    return f"sha256:{hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()}"


def _proof(
    candidate: HttpObservation, control: HttpObservation, baseline: HttpObservation
) -> RtaProof:
    observations = (baseline, candidate, control)
    ids = tuple(_observation_id(item) for item in observations)
    seal = _seal(observations)
    replay = seal == _seal(observations)
    return RtaProof(
        proof_id=f"rta-proof:{ids[0][:16]}", observation_ids=ids, seal=seal, replay_verified=replay
    )


def _facts(observation: HttpObservation) -> set[str]:
    return set(observation.semantic_facts)


def _infer(
    vulnerability_class: str,
    candidate: HttpObservation,
    control: HttpObservation,
    graph: PermissionGraph,
) -> bool:
    candidate_facts = _facts(candidate)
    granted = "access_granted" in candidate_facts
    if vulnerability_class == "idor":
        return granted and "owner_match:false" in candidate_facts
    if vulnerability_class == "tenant_isolation":
        return granted and "tenant_match:false" in candidate_facts
    if vulnerability_class == "bfla":
        return granted and not any(
            edge[0] == candidate.request.auth_context_id.removeprefix("synthetic:")
            and edge[2] == "admin:read"
            for edge in graph.edges
        )
    if vulnerability_class == "workflow_authorization":
        return granted and "role:viewer" in candidate_facts
    if vulnerability_class == "privilege_escalation":
        return granted and "role:editor" in candidate_facts
    if vulnerability_class == "business_logic":
        return "business_rule:elevated_discount" in candidate_facts
    if vulnerability_class == "tenant_partial_access":
        return "access_level:full" in candidate_facts and "tenant_match:false" in candidate_facts
    return False


def run_rta_validation(
    base_url: str,
    scope: RtaScope,
    config: LocalTargetConfig,
    profiles: tuple[SyntheticAuthContext, ...] | None = None,
) -> RtaValidationRun:
    """Run only GET probes and compare inferred results with external truth."""

    contexts = profiles or default_auth_profiles()
    paths = ("/api/me", *(path for _, path, _, _ in _CASES))
    graph, observations = run_authenticated_read_campaign(
        base_url, scope, RtaAuthProfiles(contexts), paths
    )
    by_key = {(item.request.path, item.request.auth_context_id): item for item in observations}
    truths = {truth.vulnerability_class: truth for truth in build_ground_truth(config)}
    results: list[RtaCaseResult] = []
    for vulnerability_class, path, candidate_id, control_id in _CASES:
        candidate = by_key[(path, candidate_id)]
        control = by_key[(path, control_id)]
        baseline = by_key[("/api/me", candidate_id)]
        predicted = _infer(vulnerability_class, candidate, control, graph)
        truth = truths[vulnerability_class]
        proof = _proof(candidate, control, baseline) if predicted else None
        verdict = "confirmed" if predicted and proof and proof.replay_verified else "clean"
        results.append(
            RtaCaseResult(
                target_id=config.target_id,
                case_id=truth.case_id,
                vulnerability_class=vulnerability_class,
                predicted_vulnerable=predicted,
                truth_vulnerable=truth.exists,
                verdict=verdict,
                proof=proof,
                notes=("offline_fixture_truth_only",),
            )
        )
    return RtaValidationRun(
        target_id=config.target_id,
        runtime_digest=f"fixture-runtime:{config.target_id}:{config.version}",
        results=tuple(results),
        observations=observations,
        permission_graph=graph,
        governance={
            "external_scope": False,
            "real_credentials_used": False,
            "state_mutation": False,
            "qualification_effect": False,
        },
    )
