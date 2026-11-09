"""Fail-closed, target-neutral case lifecycle orchestration.

The runner owns policy and sequencing only. Target adapters own transport and
case semantics. No lifecycle callback is serialized and no stage status is a
finding; promotion is delegated to the existing strict replay verifier.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from webpent.shared.generic_case_lifecycle import case_result_from_verification
from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CaseDefinition,
    CaseResult,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
)
from webpent.shared.target_adapters import (
    CaseLifecycleAdapter,
    RegisteredTargetAdapter,
    lifecycle_adapter_for_registration,
)

_SAFE_RESULT_METADATA = frozenset(
    {
        "target_classification",
        "target_backed",
        "negative_control_independent",
        "validator_id",
        "validator_version",
        "cleanup_status",
        "lifecycle_contract_version",
    }
)
_TERMINAL_STATUS_MAP = {
    "ready": "inconclusive",
    "completed": "inconclusive",
    "blocked": "blocked",
    "unsupported": "unsupported",
    "needs_profile": "needs_profile",
    "observation_only": "observation_only",
    "inconclusive": "inconclusive",
}


class GenericCaseRunner:
    """Execute a registered adapter lifecycle under a strict read-only policy."""

    @classmethod
    def execute_case(
        cls,
        registration: RegisteredTargetAdapter,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> CaseResult:
        """Run one case, returning a structured result for every safe outcome."""
        if not isinstance(registration, RegisteredTargetAdapter):
            return cls._result(case, "blocked", "target_registration_required")
        if not isinstance(case, CaseDefinition):
            raise TypeError("case_definition_required")
        if not isinstance(authorization, LifecycleAuthorization):
            raise TypeError("lifecycle_authorization_required")
        if not isinstance(run_context, LifecycleRunContext):
            raise TypeError("lifecycle_run_context_required")
        if run_context.target_id != registration.target_id or run_context.case_id != case.case_id:
            return cls._result(case, "blocked", "lifecycle_context_identity_mismatch")
        if authorization.contract_version != LIFECYCLE_CONTRACT_VERSION:
            return cls._result(case, "blocked", "lifecycle_authorization_contract_invalid")
        if run_context.contract_version != LIFECYCLE_CONTRACT_VERSION:
            return cls._result(case, "blocked", "lifecycle_run_contract_invalid")
        if run_context.engagement_id != authorization.engagement_id:
            return cls._result(case, "blocked", "engagement_identity_mismatch")
        registration_errors = registration.validate()
        if registration_errors:
            return cls._result(case, "blocked", "target_registration_invalid")
        if not authorization.authorized:
            return cls._result(case, "blocked", "explicit_authorization_required")
        if not authorization.allowed_origin.strip():
            return cls._result(case, "blocked", "authorized_origin_required")
        try:
            origin_accepted = registration.adapter.accepts_origin(authorization.allowed_origin)
        except Exception:
            origin_accepted = False
        if origin_accepted is not True:
            return cls._result(case, "blocked", "authorized_origin_outside_registration")
        manifest = registration.effective_manifest
        if manifest is None or not manifest.explicit:
            return cls._result(case, "blocked", "explicit_target_manifest_required")
        missing_requirements = set(manifest.authorization_requirements) - set(
            authorization.satisfied_requirements
        )
        if missing_requirements:
            return cls._result(case, "blocked", "authorization_requirements_not_satisfied")
        if case.mutates_state:
            return cls._result(
                case,
                "unsupported",
                "state_changing_case_not_allowed_by_generic_runner",
            )
        if case.case_id not in tuple(registration.adapter.case_ids()):
            return cls._result(case, "unsupported", "case_not_registered_for_target")
        binding = registration.adapter.case(case.case_id)
        if binding is None or binding.workflow_id != case.workflow_id:
            return cls._result(case, "unsupported", "case_workflow_binding_mismatch")
        if binding.operation not in manifest.supported_case_types:
            return cls._result(case, "unsupported", "case_operation_not_manifested")

        try:
            adapter = lifecycle_adapter_for_registration(registration)
        except ValueError as exc:
            return cls._result(case, "unsupported", str(exc))
        if not isinstance(adapter, CaseLifecycleAdapter):
            return cls._result(case, "unsupported", "target_lifecycle_provider_invalid")

        capability_failure = cls._capability_failure(adapter, case)
        if capability_failure is not None:
            return cls._result(case, "unsupported", capability_failure)

        stages: list[LifecycleStageResult] = []
        result: CaseResult | None = None
        cleanup_result: LifecycleStageResult | None = None
        try:
            prepare = cls._invoke(adapter, "prepare", case, authorization, run_context)
            stages.append(prepare)
            if prepare.status != "ready":
                return cls._from_stage(case, prepare)

            baseline = cls._invoke(adapter, "baseline", case, authorization, run_context)
            stages.append(baseline)
            if baseline.status != "completed":
                return cls._from_stage(case, baseline, refs=cls._refs(stages))

            action = cls._invoke(adapter, "execute_safe_action", case, authorization, run_context)
            stages.append(action)
            if action.status not in {"completed", "observation_only"}:
                return cls._from_stage(case, action, refs=cls._refs(stages))

            observation = cls._invoke(adapter, "observe", case, authorization, run_context)
            stages.append(observation)
            if observation.status not in {"completed", "observation_only"}:
                return cls._from_stage(case, observation, refs=cls._refs(stages))

            if case.requires_negative_control:
                control = cls._invoke(
                    adapter,
                    "execute_negative_control",
                    case,
                    authorization,
                    run_context,
                )
                stages.append(control)
                if control.status != "completed":
                    return cls._from_stage(case, control, refs=cls._refs(stages))

            verification = next(
                (
                    stage.verification
                    for stage in reversed(stages)
                    if stage.verification is not None
                ),
                None,
            )
            refs = cls._refs(stages)
            if verification is not None:
                result = case_result_from_verification(
                    case.case_id,
                    verification,
                    observation_refs=refs,
                    metadata=cls._metadata(stages),
                )
            else:
                result = cls._result(
                    case,
                    "observation_only" if refs else "inconclusive",
                    "lifecycle_completed_without_strict_verification",
                    refs=refs,
                    metadata=cls._metadata(stages),
                )
        except Exception as exc:
            result = cls._result(
                case,
                "blocked",
                f"lifecycle_stage_failed:{type(exc).__name__}",
                refs=cls._refs(stages),
            )
        finally:
            try:
                cleanup_result = cls._invoke(adapter, "cleanup", case, authorization, run_context)
            except Exception:
                cleanup_result = LifecycleStageResult(
                    stage="cleanup",
                    status="blocked",
                    reason="cleanup_failed",
                )
        if result is None:
            result = cls._result(case, "inconclusive", "lifecycle_result_missing")
        if cleanup_result is not None and cleanup_result.status != "completed":
            return cls._result(
                case,
                "blocked",
                "cleanup_not_completed",
                refs=result.observation_refs,
                metadata={"cleanup_status": cleanup_result.status},
            )
        return result

    @staticmethod
    def _invoke(
        adapter: CaseLifecycleAdapter,
        method_name: str,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        value = getattr(adapter, method_name)(case, authorization, run_context)
        if not isinstance(value, LifecycleStageResult):
            raise TypeError(f"lifecycle_{method_name}_result_invalid")
        return value

    @staticmethod
    def _capability_failure(adapter: CaseLifecycleAdapter, case: CaseDefinition) -> str | None:
        try:
            records = tuple(adapter.capabilities())
        except Exception:
            return "capability_map_unavailable"
        by_id: dict[str, Any] = {}
        for record in records:
            if not hasattr(record, "capability_id") or not hasattr(record, "status"):
                return "capability_record_invalid"
            by_id[str(record.capability_id)] = record
        for required in case.required_capabilities:
            record = by_id.get(required)
            if record is None:
                return f"required_capability_missing:{required}"
            if record.status != "available":
                return f"required_capability_unavailable:{required}"
        return None

    @staticmethod
    def _refs(stages: Sequence[LifecycleStageResult]) -> tuple[str, ...]:
        refs: list[str] = []
        for stage in stages:
            for ref in stage.observation_refs:
                if ref not in refs and len(refs) < 20:
                    refs.append(ref)
        return tuple(refs)

    @staticmethod
    def _metadata(stages: Sequence[LifecycleStageResult]) -> dict[str, str]:
        metadata: dict[str, str] = {"lifecycle_contract_version": LIFECYCLE_CONTRACT_VERSION}
        for stage in stages:
            for key, value in stage.metadata.items():
                if key in _SAFE_RESULT_METADATA and len(metadata) < 20:
                    metadata[key] = str(value)[:240]
        return metadata

    @staticmethod
    def _from_stage(
        case: CaseDefinition,
        stage: LifecycleStageResult,
        *,
        refs: Sequence[str] = (),
    ) -> CaseResult:
        status = _TERMINAL_STATUS_MAP[stage.status]
        return GenericCaseRunner._result(
            case,
            status,
            stage.reason,
            refs=tuple(refs) or stage.observation_refs,
            metadata=stage.metadata,
        )

    @staticmethod
    def _result(
        case: CaseDefinition,
        status: str,
        reason: str,
        *,
        refs: Sequence[str] = (),
        metadata: Mapping[str, Any] | None = None,
    ) -> CaseResult:
        safe_metadata = {
            str(key): str(value)[:240]
            for key, value in (metadata or {}).items()
            if str(key) in _SAFE_RESULT_METADATA and not isinstance(value, (dict, list, tuple, set))
        }
        if len(safe_metadata) < 20:
            safe_metadata.setdefault("lifecycle_contract_version", LIFECYCLE_CONTRACT_VERSION)
        return CaseResult(
            case_id=case.case_id,
            status=status,
            reason=str(reason)[:240],
            observation_refs=tuple(str(ref)[:240] for ref in refs if str(ref).strip())[:20],
            metadata=safe_metadata,
        )


execute_case = GenericCaseRunner.execute_case

__all__ = ["GenericCaseRunner", "execute_case"]
