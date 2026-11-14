"""Fail-closed validation for target-adapter review packets.

The validator checks governance metadata only.  It never performs target I/O,
creates evidence, or promotes a finding.  Target-specific selectors and
executors remain outside this module.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

_PACKET_STATUSES = {
    "draft",
    "pending",
    "mapping_approved",
    "qualified_for_runs",
    "approved",
    "rejected",
}
_DECISIONS = {"pending", "approved", "rejected"}
_CASE_STATUSES = {"pending", "approved", "out_of_scope", "rejected"}
_OPERATIONS = {"navigate", "typed_search"}
_REQUIRED_FORBIDDEN_OPERATIONS = {
    "credential_creation",
    "credential_recovery",
    "otp_or_mfa_bypass",
    "captcha_bypass",
    "ssrf_or_oast",
    "raw_request_or_response_retention",
    "raw_cookie_or_token_retention",
}
_HEX_HASH_LENGTH = 64
_TARGET_REQUIRED_FIELDS = (
    "target_id",
    "target_origin",
    "source_ref",
    "adapter_module",
    "adapter_version",
    "scope_digest",
    "authorization_ref",
)
_PROOF_REQUIREMENTS = (
    "three_isolated_runs",
    "sealed_proof_bundle",
    "replay_required",
    "verify_seal_required",
)


def _mapping(value: Any, name: str, errors: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        errors.append(f"{name}:mapping_required")
        return {}
    return value


def _sequence(value: Any, name: str, errors: list[str]) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        errors.append(f"{name}:list_required")
        return ()
    return value


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _sha256(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return len(normalized) == _HEX_HASH_LENGTH and all(
        character in "0123456789abcdef" for character in normalized
    )


def validate_target_adapter_review_packet(packet: Mapping[str, Any]) -> tuple[str, ...]:
    """Return deterministic validation errors for one review packet.

    ``draft`` packets may contain the empty placeholder rows from the checked-in
    template.  Every later lifecycle state must contain concrete identities,
    workflow mappings, case dispositions, and the reviewer material required by
    its state.  No lifecycle state can assert a qualification claim or carry
    live metrics through this contract.
    """
    errors: list[str] = []
    root = _mapping(packet, "packet", errors)
    if root.get("schema") != "webpent.target_adapter_review_packet.v1":
        errors.append("packet:schema_invalid")
    status = root.get("packet_status")
    if status not in _PACKET_STATUSES:
        errors.append("packet:status_invalid")
    if root.get("qualification_claim") is not False:
        errors.append("packet:qualification_claim_must_be_false")

    target = _mapping(root.get("target"), "target", errors)
    if status != "draft":
        for field in _TARGET_REQUIRED_FIELDS:
            if not _nonempty(target.get(field)):
                errors.append(f"target:{field}_required")
    policy = _mapping(root.get("policy"), "policy", errors)
    workflows_raw = _sequence(root.get("workflows"), "workflows", errors)
    cases_raw = _sequence(root.get("cases"), "cases", errors)
    review = _mapping(root.get("review"), "review", errors)
    live_runs = _mapping(root.get("live_runs"), "live_runs", errors)

    if policy.get("raw_evidence_retained") is not False:
        errors.append("policy:raw_evidence_retained_must_be_false")
    allowed = policy.get("allowed_operations")
    if not isinstance(allowed, (list, tuple)):
        errors.append("policy:allowed_operations_list_required")
    elif any(operation not in _OPERATIONS for operation in allowed):
        errors.append("policy:allowed_operation_invalid")
    forbidden = policy.get("forbidden_operations")
    if not isinstance(forbidden, (list, tuple)):
        errors.append("policy:forbidden_operations_list_required")
    elif not _REQUIRED_FORBIDDEN_OPERATIONS.issubset(set(forbidden)):
        errors.append("policy:required_forbidden_operation_missing")

    workflow_ids: list[str] = []
    workflow_operations: dict[str, str] = {}
    for index, raw_workflow in enumerate(workflows_raw):
        workflow = _mapping(raw_workflow, f"workflows[{index}]", errors)
        workflow_id = str(workflow.get("workflow_id") or "").strip()
        operation = str(workflow.get("operation") or "").strip()
        if not workflow_id:
            if status != "draft":
                errors.append(f"workflows[{index}]:workflow_id_required")
            continue
        if workflow_id in workflow_ids:
            errors.append(f"workflows[{index}]:duplicate_workflow_id")
        workflow_ids.append(workflow_id)
        if operation not in _OPERATIONS:
            errors.append(f"workflows[{index}]:operation_invalid")
        else:
            workflow_operations[workflow_id] = operation
        if status != "draft":
            if workflow.get("reviewed") is not True:
                errors.append(f"workflows[{index}]:review_required")
            if workflow.get("allowlisted") is not True:
                errors.append(f"workflows[{index}]:allowlist_required")
            if workflow.get("executor_is_target_local") is not True:
                errors.append(f"workflows[{index}]:target_local_executor_required")
            if operation == "typed_search":
                if workflow.get("executor_required") is not True:
                    errors.append(f"workflows[{index}]:typed_executor_required")
                if workflow.get("executor_callable") is not True:
                    errors.append(f"workflows[{index}]:typed_executor_callable_required")

    case_ids: list[str] = []
    for index, raw_case in enumerate(cases_raw):
        case = _mapping(raw_case, f"cases[{index}]", errors)
        case_id = str(case.get("case_id") or "").strip()
        if not case_id:
            if status != "draft":
                errors.append(f"cases[{index}]:case_id_required")
            continue
        if case_id in case_ids:
            errors.append(f"cases[{index}]:duplicate_case_id")
        case_ids.append(case_id)
        operation = str(case.get("operation") or "").strip()
        workflow_id = str(case.get("workflow_id") or "").strip()
        if operation not in _OPERATIONS:
            errors.append(f"cases[{index}]:operation_invalid")
        if workflow_id not in workflow_ids:
            errors.append(f"cases[{index}]:workflow_not_declared")
        elif workflow_operations.get(workflow_id) != operation:
            errors.append(f"cases[{index}]:workflow_operation_mismatch")
        for field in ("path", "oracle_id"):
            if not _nonempty(case.get(field)):
                errors.append(f"cases[{index}]:{field}_required")
        if operation == "typed_search" and not _nonempty(case.get("semantic_profile")):
            errors.append(f"cases[{index}]:semantic_profile_required")
        case_status = case.get("mapping_status")
        if case_status not in _CASE_STATUSES:
            errors.append(f"cases[{index}]:mapping_status_invalid")
        if status != "draft":
            expected_disposition = case.get("expected_disposition")
            if expected_disposition not in _CASE_STATUSES - {"pending"}:
                errors.append(f"cases[{index}]:expected_disposition_invalid")
            if case_status == "pending":
                errors.append(f"cases[{index}]:pending_mapping_in_closed_packet")
            if expected_disposition != case_status:
                errors.append(f"cases[{index}]:disposition_mismatch")
        causal = _mapping(
            case.get("causal_signal_contract"),
            f"cases[{index}].causal_signal_contract",
            errors,
        )
        negative = _mapping(
            case.get("negative_control_contract"),
            f"cases[{index}].negative_control_contract",
            errors,
        )
        if status != "draft":
            if causal.get("defined") is not True or causal.get("target_backed") is not True:
                errors.append(f"cases[{index}]:target_backed_causal_contract_required")
            if causal.get("observation_only") is True:
                errors.append(f"cases[{index}]:causal_contract_observation_only")
            if not _nonempty(causal.get("description")):
                errors.append(f"cases[{index}]:causal_description_required")
            if negative.get("defined") is not True or negative.get("independent") is not True:
                errors.append(f"cases[{index}]:independent_negative_control_required")
            if not _nonempty(negative.get("description")):
                errors.append(f"cases[{index}]:negative_description_required")
            proof_requirements = _mapping(
                case.get("proof_requirements"),
                f"cases[{index}].proof_requirements",
                errors,
            )
            for field in _PROOF_REQUIREMENTS:
                if proof_requirements.get(field) is not True:
                    errors.append(f"cases[{index}]:{field}_required")

    decision = review.get("approval_decision")
    if decision not in _DECISIONS:
        errors.append("review:approval_decision_invalid")
    if status in {"draft", "pending"} and decision != "pending":
        errors.append("review:decision_must_be_pending_for_open_status")
    if status in {"mapping_approved", "qualified_for_runs"} and decision != "approved":
        errors.append("review:mapping_status_requires_approved_decision")
    if status == "approved" and decision != "approved":
        errors.append("review:approved_status_requires_approved_decision")
    if status == "rejected" and decision != "rejected":
        errors.append("review:rejected_status_requires_rejected_decision")
    if status in {"mapping_approved", "qualified_for_runs", "approved"}:
        if decision == "pending":
            errors.append("review:decision_pending_for_closed_status")
        for field in (
            "reviewer_id",
            "reviewed_at_utc",
            "reviewed_mapping_sha256",
            "reviewed_oracle_contract_sha256",
        ):
            if not _nonempty(review.get(field)):
                errors.append(f"review:{field}_required")
        for field in ("reviewed_mapping_sha256", "reviewed_oracle_contract_sha256"):
            if review.get(field) and not _sha256(review.get(field)):
                errors.append(f"review:{field}_invalid")
    if decision == "approved":
        results_seen = review.get("results_seen_by_reviewer")
        if status == "approved" and results_seen is not True:
            errors.append("review:results_must_be_seen_for_final_approval")
        if status in {"mapping_approved", "qualified_for_runs"} and results_seen is not False:
            errors.append("review:results_must_not_be_seen_for_pre_run_approval")
    elif review.get("results_seen_by_reviewer") is not False:
        errors.append("review:results_seen_must_be_false_without_approval")

    disposition_sets: dict[str, set[str]] = {}
    for field in ("approved_case_ids", "out_of_scope_case_ids", "rejected_case_ids"):
        values = review.get(field)
        if not isinstance(values, (list, tuple)):
            errors.append(f"review:{field}_list_required")
            disposition_sets[field] = set()
        else:
            disposition_sets[field] = {str(value).strip() for value in values if str(value).strip()}
    if len(set().union(*disposition_sets.values())) != sum(
        len(values) for values in disposition_sets.values()
    ):
        errors.append("review:case_dispositions_overlap")
    if status in {"mapping_approved", "qualified_for_runs", "approved", "rejected"}:
        assigned = set().union(*disposition_sets.values())
        if assigned != set(case_ids):
            errors.append("review:case_dispositions_must_cover_all_cases")
        disposition_by_case = dict.fromkeys(
            disposition_sets["approved_case_ids"], "approved"
        )
        disposition_by_case.update(
            dict.fromkeys(
                disposition_sets["out_of_scope_case_ids"], "out_of_scope"
            )
        )
        disposition_by_case.update(
            dict.fromkeys(disposition_sets["rejected_case_ids"], "rejected")
        )
        for index, raw_case in enumerate(cases_raw):
            case = _mapping(raw_case, f"cases[{index}]", errors)
            case_id = str(case.get("case_id") or "").strip()
            expected = disposition_by_case.get(case_id)
            if expected and case.get("mapping_status") != expected:
                errors.append(f"cases[{index}]:review_disposition_mismatch")

    if live_runs.get("qualification_status") != "not_qualified":
        errors.append("live_runs:qualification_status_must_remain_not_qualified")
    if live_runs.get("metrics") is not None:
        errors.append("live_runs:metrics_must_remain_null")
    authorized = live_runs.get("authorized")
    if status in {"qualified_for_runs", "approved"} and authorized is not True:
        errors.append("live_runs:authorization_required_for_run_lifecycle")
    if status in {"draft", "pending", "mapping_approved", "rejected"} and authorized is not False:
        errors.append("live_runs:authorization_must_remain_false_before_runs")
    run_ids = live_runs.get("run_ids")
    executed_case_ids = live_runs.get("executed_case_ids")
    proof_bundle_ids = live_runs.get("proof_bundle_ids")
    run_case_matrix = live_runs.get("run_case_matrix")
    replay_statuses = live_runs.get("replay_statuses")
    verify_seal_results = live_runs.get("verify_seal_results")
    for field, value in (
        ("run_ids", run_ids),
        ("executed_case_ids", executed_case_ids),
        ("proof_bundle_ids", proof_bundle_ids),
    ):
        if not isinstance(value, (list, tuple)):
            errors.append(f"live_runs:{field}_list_required")
    for field, value in (
        ("run_case_matrix", run_case_matrix),
        ("replay_statuses", replay_statuses),
        ("verify_seal_results", verify_seal_results),
    ):
        if not isinstance(value, Mapping):
            errors.append(f"live_runs:{field}_mapping_required")
    if status == "approved":
        normalized_run_ids: list[str] = []
        if isinstance(run_ids, (list, tuple)):
            normalized_run_ids = [str(value).strip() for value in run_ids if str(value).strip()]
            if (
                len(normalized_run_ids) < 3
                or len(set(normalized_run_ids)) != len(normalized_run_ids)
            ):
                errors.append("live_runs:three_distinct_run_ids_required")
        if isinstance(proof_bundle_ids, (list, tuple)) and not any(
            str(value).strip() for value in proof_bundle_ids
        ):
            errors.append("live_runs:proof_bundle_ids_required")
        if isinstance(executed_case_ids, (list, tuple)):
            normalized_executed = {
                str(value).strip() for value in executed_case_ids if str(value).strip()
            }
            if normalized_executed != disposition_sets.get("approved_case_ids", set()):
                errors.append("live_runs:executed_cases_must_match_approved_cases")
        approved_case_ids = disposition_sets.get("approved_case_ids", set())
        if isinstance(run_case_matrix, Mapping):
            normalized_matrix: dict[str, set[str]] = {}
            matrix_values_valid = True
            for run_id, case_ids in run_case_matrix.items():
                normalized_run_id = str(run_id).strip()
                if not normalized_run_id:
                    continue
                if not isinstance(case_ids, (list, tuple)):
                    matrix_values_valid = False
                    continue
                normalized_matrix[normalized_run_id] = {
                    str(case_id).strip()
                    for case_id in case_ids
                    if str(case_id).strip()
                }
            if (
                not matrix_values_valid
                or normalized_matrix.keys() != set(normalized_run_ids)
            ):
                errors.append("live_runs:run_case_matrix_must_cover_all_runs")
            elif any(case_ids != approved_case_ids for case_ids in normalized_matrix.values()):
                errors.append("live_runs:run_case_matrix_must_cover_all_approved_cases")
        if isinstance(replay_statuses, Mapping):
            normalized_replay = {
                str(run_id).strip(): str(result).strip().lower()
                for run_id, result in replay_statuses.items()
                if str(run_id).strip()
            }
            if normalized_replay.keys() != set(normalized_run_ids) or any(
                result != "passed" for result in normalized_replay.values()
            ):
                errors.append("live_runs:replay_statuses_must_be_passed")
        if isinstance(verify_seal_results, Mapping):
            normalized_seal = {
                str(run_id).strip(): result
                for run_id, result in verify_seal_results.items()
                if str(run_id).strip()
            }
            if normalized_seal.keys() != set(normalized_run_ids) or any(
                result is not True for result in normalized_seal.values()
            ):
                errors.append("live_runs:verify_seal_results_must_be_true")

    return tuple(sorted(set(errors)))
