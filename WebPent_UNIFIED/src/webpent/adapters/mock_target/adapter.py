"""Minimal mock target for adapter-swap and safety-contract tests.

This adapter is intentionally non-networking. Its blocked precondition and
unsupported capability methods are target-local facts consumed only by tests;
the generic core remains unaware of them. A ready-state instance is an explicit
opt-in fixture for proof-pipeline tests and is never the default registration.
"""
from __future__ import annotations

import hashlib
from urllib.parse import urlsplit, urlunparse

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CapabilityRecord,
    CaseDefinition,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.verifier import verify_replay_evidence
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION

MOCK_TARGET_ORIGIN = "http://127.0.0.1:4200"
MOCK_TARGET_CASE_ID = "mock.public_observation.v1"
MOCK_TARGET_ORACLE_ID = "mock.read_only.public_observation"
MOCK_READY_TARGET_ID = "mock_target_ready_fixture"


class MockTargetAdapter:
    """Non-networking adapter with explicit safe and blocked capabilities."""

    lifecycle_contract_version = LIFECYCLE_CONTRACT_VERSION
    semantic_profiles = SemanticProfileRegistry({})

    def __init__(self, *, ready: bool = False) -> None:
        self.ready = bool(ready)
        self.target_id = MOCK_READY_TARGET_ID if self.ready else "mock_target"
        self.target_origin = MOCK_TARGET_ORIGIN
        self._last_verification = None

    def describe_target(self) -> dict[str, str]:
        return {
            "target_id": self.target_id,
            "target_origin": self.target_origin,
            "fixture_only": "True",
            "network_io": "False",
            "ready_state": "True" if self.ready else "False",
        }

    def capabilities(self) -> tuple[CapabilityRecord, ...]:
        records = [
            CapabilityRecord("read_only_navigation", "available", "fixture_navigation_declared")
        ]
        if self.ready:
            records.append(
                CapabilityRecord(
                    "independent_negative_control",
                    "available",
                    "ready_fixture_control_declared",
                )
            )
        return tuple(records)

    def prepare(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization, run_context
        if case.case_id != MOCK_TARGET_CASE_ID:
            return LifecycleStageResult("prepare", "unsupported", "case_not_owned_by_fixture")
        if not self.ready:
            return LifecycleStageResult(
                "prepare",
                "blocked",
                "mock_target_not_started_and_precondition_not_ready",
            )
        return LifecycleStageResult(
            "prepare",
            "ready",
            "mock_ready_fixture_precondition_satisfied",
            metadata={"target_classification": "mock_fixture"},
        )

    def baseline(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if not self.ready or case.case_id != MOCK_TARGET_CASE_ID:
            return LifecycleStageResult("baseline", "blocked", "mock_target_precondition_not_ready")
        return LifecycleStageResult(
            "baseline",
            "completed",
            "mock_ready_baseline_observation",
            observation_refs=(f"mock:{run_context.run_id}:baseline",),
            metadata={"target_backed": "True"},
        )

    def execute_safe_action(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if not self.ready or case.case_id != MOCK_TARGET_CASE_ID:
            return LifecycleStageResult(
                "execute_safe_action", "unsupported", "fixture_has_no_action"
            )
        return LifecycleStageResult(
            "execute_safe_action",
            "completed",
            "mock_ready_candidate_observation",
            observation_refs=(f"mock:{run_context.run_id}:candidate",),
            metadata={"target_backed": "True"},
        )

    def observe(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if not self.ready or case.case_id != MOCK_TARGET_CASE_ID:
            return LifecycleStageResult(
                "observe", "inconclusive", "fixture_observation_not_started"
            )
        return LifecycleStageResult(
            "observe",
            "completed",
            "mock_ready_observation_collected",
            observation_refs=(f"mock:{run_context.run_id}:observation",),
            metadata={"target_backed": "True"},
        )

    def execute_negative_control(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if not self.ready or case.case_id != MOCK_TARGET_CASE_ID:
            return LifecycleStageResult(
                "execute_negative_control", "unsupported", "fixture_has_no_control"
            )
        target_fingerprint = _target_fingerprint(f"{self.target_origin}/status")
        baseline = _target_observation(
            role="baseline",
            target_fingerprint=target_fingerprint,
            request_digest="1" * 64,
            response_digest="2" * 64,
            status_code=200,
            body_sha256="3" * 64,
            body_length=32,
            semantic_bucket="stable_baseline",
        )
        candidate = _target_observation(
            role="candidate",
            target_fingerprint=target_fingerprint,
            request_digest="4" * 64,
            response_digest="5" * 64,
            status_code=200,
            body_sha256="6" * 64,
            body_length=48,
            semantic_bucket="controlled_candidate",
        )
        negative_control = _target_observation(
            role="negative_control",
            target_fingerprint=target_fingerprint,
            request_digest="7" * 64,
            response_digest="8" * 64,
            status_code=200,
            body_sha256="9" * 64,
            body_length=32,
            semantic_bucket="stable_baseline",
        )
        verification = verify_replay_evidence(
            Finding(
                title="controlled mock differential",
                severity=Severity.MEDIUM,
                description="deterministic mock fixture proof",
                tool_name="mock-fixture-verifier",
                url=f"{self.target_origin}/status",
                vuln_class=VulnClass.INFO_DISCLOSURE,
                target_param="fixture_state",
                request_data={"fixture_state": "ready"},
            ),
            baseline=baseline,
            candidate=candidate,
            negative_control=negative_control,
            target_fingerprint=target_fingerprint,
            causal_signal=True,
            negative_control_complete=True,
            validator_id="mock-fixture-verifier",
            validator_version="1.0",
            causal_basis="deterministic_ready_fixture_differential",
            engagement_id=run_context.engagement_id,
            hypothesis_id=f"{MOCK_TARGET_CASE_ID}:ready",
            scope_context={
                "target_origin": self.target_origin,
                "scope_bound": True,
                "fixture_only": True,
            },
            identity_context={"mode": "fixture", "cookie_count": 0},
            require_target_backed=True,
        )
        self._last_verification = verification
        return LifecycleStageResult(
            "execute_negative_control",
            "completed",
            "mock_ready_negative_control_verified",
            observation_refs=(f"mock:{run_context.run_id}:negative_control",),
            verification=verification,
            metadata={
                "target_backed": "True",
                "negative_control_independent": "True",
                "validator_id": "mock-fixture-verifier",
                "validator_version": "1.0",
            },
        )

    def cleanup(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del case, authorization, run_context
        return LifecycleStageResult("cleanup", "completed", "fixture_has_no_state_to_cleanup")

    def workflow_ids(self) -> tuple[str, ...]:
        return (READ_ONLY_NAVIGATION,)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return (MOCK_TARGET_CASE_ID,)

    def case_definition(self) -> CaseDefinition:
        return CaseDefinition(
            case_id=MOCK_TARGET_CASE_ID,
            workflow_id=READ_ONLY_NAVIGATION,
            required_capabilities=("read_only_navigation",),
            requires_negative_control=self.ready,
        )

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if str(case_id or "").strip() != MOCK_TARGET_CASE_ID:
            return None
        return TargetCaseBinding(
            case_id=MOCK_TARGET_CASE_ID,
            operation="navigate",
            path="/status",
            oracle_id=MOCK_TARGET_ORACLE_ID,
            workflow_id=READ_ONLY_NAVIGATION,
            semantic_profile=None,
            scoring_status="fixture_only_not_benchmark_scored",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        if str(case_id or "").strip() == MOCK_TARGET_CASE_ID:
            return None
        return None

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == MOCK_TARGET_ORIGIN

    def preconditions_ready(self, case_id: str) -> bool:
        """Return readiness only for the explicit opt-in fixture instance."""
        return self.ready and str(case_id or "").strip() == MOCK_TARGET_CASE_ID

    def supports_operation(self, operation: str) -> bool:
        """Expose the intentionally unsupported typed-search capability."""
        return str(operation or "").strip() == "navigate"


def build_mock_target_registration(
    adapter: MockTargetAdapter | None = None,
) -> RegisteredTargetAdapter:
    selected = adapter or MOCK_TARGET_ADAPTER
    capabilities = {"read_only_navigation"}
    if selected.ready:
        capabilities.add("independent_negative_control")
    return RegisteredTargetAdapter(
        adapter=selected,
        source="webpent.adapters.mock_target.adapter",
        version="1",
        policy_ref="non-networking-mock-fixture",
        proof_contract="central-causal-negative-sealed-replay-v1",
        manifest=TargetManifest(
            target_id=selected.target_id,
            adapter_version="1",
            supported_capabilities=frozenset(capabilities),
            supported_case_types=frozenset({"navigate"}),
            authorization_requirements=("explicit_fixture_authorization", "loopback_origin"),
            allowed_scope=(MOCK_TARGET_ORIGIN,),
            redaction_policy="metadata_only_no_raw_bodies_or_credentials",
            cleanup_policy="fixture_context_dispose_without_target_mutation",
        ),
        metadata={
            "target_family": "mock_target",
            "fixture_only": True,
            "network_io": False,
            "ready_state": selected.ready,
        },
    )


MOCK_TARGET_ADAPTER = MockTargetAdapter()
MOCK_TARGET_REGISTRATION = build_mock_target_registration(MOCK_TARGET_ADAPTER)
READY_MOCK_TARGET_ADAPTER = MockTargetAdapter(ready=True)
READY_MOCK_TARGET_REGISTRATION = build_mock_target_registration(READY_MOCK_TARGET_ADAPTER)


def _target_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url))
    shape = urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", "", "")
    )
    return f"sha256:{hashlib.sha256(shape.encode('utf-8')).hexdigest()}"


def _target_observation(
    *,
    role: str,
    target_fingerprint: str,
    request_digest: str,
    response_digest: str,
    status_code: int,
    body_sha256: str,
    body_length: int,
    semantic_bucket: str,
) -> dict[str, object]:
    return {
        "target_backed": True,
        "observation_role": role,
        "target_fingerprint": target_fingerprint,
        "request_digest": f"sha256:{request_digest}",
        "response_digest": f"sha256:{response_digest}",
        "status_code": status_code,
        "body_sha256": f"sha256:{body_sha256}",
        "body_length": body_length,
        "semantic_bucket": semantic_bucket,
    }


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}" + (
        "" if default else f":{port}"
    )


__all__ = [
    "MOCK_TARGET_ADAPTER",
    "MOCK_TARGET_CASE_ID",
    "MOCK_TARGET_ORIGIN",
    "MOCK_TARGET_REGISTRATION",
    "MockTargetAdapter",
    "READY_MOCK_TARGET_ADAPTER",
    "READY_MOCK_TARGET_REGISTRATION",
    "build_mock_target_registration",
]
