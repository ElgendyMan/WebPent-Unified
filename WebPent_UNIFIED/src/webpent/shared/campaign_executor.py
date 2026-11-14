"""Bounded campaign execution and next-best-action planning.

The executor is deliberately transport-agnostic. It accepts a caller-supplied
handler only after :class:`ActionAuthority` authorizes the task. Campaign
contracts, coverage records, and decision traces are redaction-safe metadata;
they never promote a hypothesis to a finding.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.models.proof_bundle import build_proof_bundle, proof_bundle_promotion_ready
from webpent.research.experiment_manager import ExperimentManager
from webpent.shared.action_authority import (
    ActionAuthority,
    ActionRequest,
    ActionResult,
    ActionRisk,
    ActionStatus,
)
from webpent.shared.control_plane_runtime import project_browser_observation
from webpent.shared.proof_bundle_store import ProofBundleStore
from webpent.shared.target_context import (
    ContextCoordinator,
    ContextRequest,
    ContextStatus,
    ExecutionContext,
)


class CampaignTaskStatus(str, Enum):
    READY = "ready"
    BLOCKED_BY_PRECONDITION = "blocked_by_precondition"
    POLICY_DENIED = "policy_denied"
    EXECUTED = "executed"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    STOPPED = "stopped"
    CONTEXT_BLOCKED = "context_blocked"


@dataclass(frozen=True)
class CampaignTask:
    """The bounded task contract used by the planner and executor."""

    task_id: str
    engagement_id: str
    asset_id: str
    source_evidence_ids: tuple[str, ...]
    vulnerability_class: str
    hypothesis_id: str
    preconditions: tuple[str, ...] = ()
    identity_context: str = "anonymous"
    workflow_state: str = "unknown"
    probe_family: str = "read_only_compare"
    negative_control: str = "required"
    oracle: str = "deterministic_response_compare"
    risk_tier: ActionRisk = ActionRisk.READ_ONLY
    budget: float = 1.0
    expected_information_gain: float = 0.0
    idempotency_key: str = ""
    parent_task_id: str = ""
    cleanup_plan: tuple[str, ...] = ()
    rollback_plan: tuple[str, ...] = ()
    stop_condition: str = "proof_or_blocker"
    method: str = "GET"
    capability: str = "http_read"
    action_family: str = "http_read"
    target_url: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    body_schema: str = "none"
    content_type: str = ""
    tenant_context: str = "unknown"
    validator_id: str = ""

    def normalized_idempotency_key(self) -> str:
        if self.idempotency_key.strip():
            return self.idempotency_key.strip()[:160]
        payload = {
            "engagement_id": self.engagement_id,
            "asset_id": self.asset_id,
            "vulnerability_class": self.vulnerability_class,
            "hypothesis_id": self.hypothesis_id,
            "probe_family": self.probe_family,
            "identity_context": self.identity_context,
            "workflow_state": self.workflow_state,
        }
        return "task:" + hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:32]

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "task_id": self.task_id,
                "engagement_id": self.engagement_id,
                "asset_id": self.asset_id,
                "source_evidence_ids": list(self.source_evidence_ids),
                "vulnerability_class": self.vulnerability_class,
                "hypothesis_id": self.hypothesis_id,
                "preconditions": list(self.preconditions),
                "identity_context": self.identity_context,
                "workflow_state": self.workflow_state,
                "probe_family": self.probe_family,
                "negative_control": self.negative_control,
                "oracle": self.oracle,
                "risk_tier": self.risk_tier.value,
                "budget": self.budget,
                "expected_information_gain": self.expected_information_gain,
                "idempotency_key": self.normalized_idempotency_key(),
                "parent_task_id": self.parent_task_id,
                "cleanup_plan": list(self.cleanup_plan),
                "rollback_plan": list(self.rollback_plan),
                "stop_condition": self.stop_condition,
                "method": self.method,
                "capability": self.capability,
                "action_family": self.action_family,
                "target_url": self.target_url,
                "metadata": dict(self.metadata),
                "body_schema": self.body_schema,
                "content_type": self.content_type,
                "tenant_context": self.tenant_context,
                "validator_id": self.validator_id,
            }
        )
        return clean


@dataclass(frozen=True)
class PlannedAction:
    task: CampaignTask
    score: float
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {"task": self.task.as_dict(), "score": self.score, "reasons": list(self.reasons)}


def _normalize_precondition(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def resolve_preconditions(
    task: CampaignTask,
    *,
    observed_preconditions: Iterable[str] = (),
    blocked_preconditions: Iterable[str] = (),
    require_observations: bool = False,
) -> tuple[bool, tuple[str, ...]]:
    """Resolve readiness from explicit evidence without guessing missing state."""
    observed = {
        _normalize_precondition(item)
        for item in observed_preconditions
        if str(item).strip()
    }
    metadata_observed = task.metadata.get("observed_preconditions", ())
    if isinstance(metadata_observed, str):
        metadata_observed = (metadata_observed,)
    observed.update(
        _normalize_precondition(item)
        for item in metadata_observed
        if str(item).strip()
    )
    blocked = {_normalize_precondition(item) for item in blocked_preconditions if str(item).strip()}
    missing = tuple(
        precondition
        for precondition in task.preconditions
        if _normalize_precondition(precondition) in blocked
        or (
            (observed or require_observations)
            and _normalize_precondition(precondition) not in observed
        )
    )
    return not missing, missing


class NextBestActionEngine:
    """Score ready tasks while enforcing hard constraints before ranking."""

    def __init__(self, *, duplicate_penalty: float = 0.7) -> None:
        self.duplicate_penalty = max(0.0, min(1.0, duplicate_penalty))

    def score(
        self,
        task: CampaignTask,
        *,
        observed_evidence: Iterable[str] = (),
        covered_classes: Iterable[str] = (),
        attempted_keys: Iterable[str] = (),
        blocked_preconditions: Iterable[str] = (),
        observed_preconditions: Iterable[str] = (),
        causal_relevance: float = 0.0,
        coverage_attempts: Mapping[str, int] | None = None,
    ) -> PlannedAction:
        evidence = set(observed_evidence)
        covered = {str(item) for item in covered_classes}
        attempted = set(attempted_keys)
        reasons: list[str] = []
        _, hard_block = resolve_preconditions(
            task,
            observed_preconditions=observed_preconditions,
            blocked_preconditions=blocked_preconditions,
        )
        if hard_block:
            return PlannedAction(
                task=task,
                score=-1.0,
                reasons=("blocked_precondition:" + ",".join(hard_block),),
            )

        score = max(0.0, min(1.0, task.expected_information_gain))
        if any(item in evidence for item in task.source_evidence_ids):
            score += 0.25
            reasons.append("evidence_relevance")
        if task.vulnerability_class not in covered:
            score += 0.2
            reasons.append("coverage_value")
        if coverage_attempts is not None:
            coverage_key = task.vulnerability_class.strip().lower()[:120]
            try:
                attempts = max(0, min(1000, int(coverage_attempts.get(coverage_key, 0) or 0)))
            except (TypeError, ValueError):
                attempts = 0
            if attempts == 0:
                score += 0.2
                reasons.append("low_coverage_unattempted")
            elif attempts < 2:
                score += 0.1
                reasons.append("low_coverage_path")
        if task.normalized_idempotency_key() in attempted:
            score -= self.duplicate_penalty
            reasons.append("duplication_penalty")
        causal_value = max(0.0, min(0.35, float(causal_relevance)))
        if causal_value:
            score += causal_value
            reasons.append("causal_graph_relevance")
        if task.budget <= 1.0:
            score += 0.1
            reasons.append("low_cost")
        if task.risk_tier == ActionRisk.ACTIVE:
            score -= 0.05
            reasons.append("active_risk_discount")
        return PlannedAction(task=task, score=round(score, 6), reasons=tuple(reasons))

    def choose(self, tasks: Iterable[CampaignTask], **kwargs: Any) -> PlannedAction | None:
        planned = [self.score(task, **kwargs) for task in tasks]
        ready = [item for item in planned if item.score >= 0]
        return max(ready, key=lambda item: (item.score, item.task.task_id)) if ready else None


class CampaignExecutor:
    """Run at most one authorized task per call and retain an explainable trace."""

    def __init__(
        self,
        authority: ActionAuthority,
        *,
        action_engine: NextBestActionEngine | None = None,
        proof_bundle_store: ProofBundleStore | None = None,
        experiment_manager: ExperimentManager | None = None,
        context_coordinator: ContextCoordinator | None = None,
    ) -> None:
        self.authority = authority
        self.action_engine = action_engine or NextBestActionEngine()
        self.proof_bundle_store = proof_bundle_store
        self.experiment_manager = experiment_manager
        self.context_coordinator = context_coordinator
        self.coverage: dict[str, dict[str, Any]] = {}
        self.decision_trace: list[dict[str, Any]] = []
        self.lifecycle_events: list[dict[str, Any]] = []
        self._executed_keys: set[str] = set()
        self._inflight_keys: set[str] = set()
        self._bookkeeping_lock = threading.Lock()

    def _emit_lifecycle(self, task: CampaignTask, stage: str, reason: str = "") -> None:
        event = {
            "task_id": task.task_id,
            "engagement_id": task.engagement_id,
            "stage": stage,
            "status": "recorded",
            "reason": reason[:240],
            "action_family": task.action_family,
            "method": task.method,
            "vulnerability_class": task.vulnerability_class,
        }
        with self._bookkeeping_lock:
            self.lifecycle_events.append(event)

    def _request(self, task: CampaignTask) -> ActionRequest:
        continuity = task.metadata.get("target_package_continuity", {})
        if not isinstance(continuity, Mapping):
            continuity = {}
        metadata: dict[str, Any] = {
            "vulnerability_class": task.vulnerability_class,
            "probe_family": task.probe_family,
            "body_schema": task.body_schema,
            "content_type": task.content_type,
            "tenant_context": task.tenant_context,
            "validator_id": task.validator_id,
            "adapter_name": str(task.metadata.get("adapter_name") or "")[:160],
            "g02_inventory_ref": str(task.metadata.get("g02_inventory_ref") or "")[:240],
            "g02_proof_contract": str(task.metadata.get("g02_proof_contract") or "")[:240],
        }
        continuity_keys = {
            "package_id": "target_package_id",
            "package_sha256": "target_package_sha256",
            "scope_digest": "scope_digest",
            "policy_digest": "policy_digest",
        }
        for source_key, metadata_key in continuity_keys.items():
            value = str(continuity.get(source_key) or "").strip()
            if value:
                metadata[metadata_key] = value[:240]
        redirect_chain = task.metadata.get("redirect_chain")
        if isinstance(redirect_chain, (list, tuple)):
            metadata["redirect_chain"] = [str(item)[:2000] for item in redirect_chain[:8]]
        return ActionRequest(
            task_id=task.task_id,
            engagement_id=task.engagement_id,
            target_url=task.target_url,
            method=task.method,
            action_family=task.action_family,
            capability=task.capability,
            risk=task.risk_tier,
            identity_ref=task.identity_context,
            idempotency_key=task.normalized_idempotency_key(),
            estimated_cost=task.budget,
            human_approved=bool(task.metadata.get("human_approved", False)),
            metadata=metadata,
        )

    def execute(
        self,
        task: CampaignTask,
        handler: Callable[[CampaignTask], Any],
        *,
        preconditions_met: bool = True,
        context_request: ContextRequest | None = None,
        context_handler: Callable[[CampaignTask, ExecutionContext], Any] | None = None,
    ) -> dict[str, Any]:
        key = task.normalized_idempotency_key()
        self._emit_lifecycle(task, "planned")
        execution_context: ExecutionContext | None = None
        state_snapshot = None
        if self.context_coordinator is not None:
            if context_request is None:
                self._emit_lifecycle(task, "blocked", "target_context_request_required")
                return self._record(
                    task,
                    CampaignTaskStatus.CONTEXT_BLOCKED,
                    "target_context_request_required",
                )
            context_status, context_reason, execution_context = self.context_coordinator.acquire(
                context_request
            )
            self._emit_lifecycle(task, "context_acquired", context_status.value)
            if context_status != ContextStatus.READY or execution_context is None:
                self._emit_lifecycle(task, "blocked", context_reason)
                return self._record(
                    task,
                    CampaignTaskStatus.CONTEXT_BLOCKED,
                    f"context_{context_status.value}:{context_reason}",
                )
            state_snapshot = self.context_coordinator.snapshot(execution_context)
            self._emit_lifecycle(task, "snapshot", state_snapshot.snapshot_ref)
        if not preconditions_met:
            if execution_context is not None and state_snapshot is not None:
                self.context_coordinator.restore(execution_context, state_snapshot)
                self.context_coordinator.dispose(execution_context)
            self._emit_lifecycle(task, "blocked", "precondition_failed")
            return self._record(
                task,
                CampaignTaskStatus.BLOCKED_BY_PRECONDITION,
                "precondition_failed",
            )
        with self._bookkeeping_lock:
            duplicate = key in self._executed_keys or key in self._inflight_keys
            if not duplicate:
                self._inflight_keys.add(key)
        if duplicate:
            if execution_context is not None and state_snapshot is not None:
                restore_result = self.context_coordinator.restore(execution_context, state_snapshot)
                self._emit_lifecycle(task, "restored", restore_result.status.value)
                disposal_result = self.context_coordinator.dispose(execution_context)
                self._emit_lifecycle(task, "disposed", disposal_result.status.value)
            self._emit_lifecycle(task, "deduplicated", "duplicate_idempotency_key")
            return self._record(task, CampaignTaskStatus.STOPPED, "duplicate_idempotency_key")

        request = self._request(task)
        try:
            def run_handler(_request: ActionRequest) -> Any:
                if context_handler is not None and execution_context is not None:
                    return context_handler(task, execution_context)
                return handler(task)

            result: ActionResult = self.authority.execute(request, run_handler)
        finally:
            if execution_context is not None and state_snapshot is not None:
                restore_result = self.context_coordinator.restore(execution_context, state_snapshot)
                self._emit_lifecycle(task, "restored", restore_result.status.value)
                disposal_result = self.context_coordinator.dispose(execution_context)
                self._emit_lifecycle(task, "disposed", disposal_result.status.value)
            with self._bookkeeping_lock:
                self._inflight_keys.discard(key)
        if result.status in {ActionStatus.AUTHORIZED, ActionStatus.EXECUTED}:
            self._emit_lifecycle(task, "authorized")
        elif result.status == ActionStatus.POLICY_DENIED:
            self._emit_lifecycle(task, "denied", ",".join(result.decision.reasons))
        else:
            self._emit_lifecycle(task, "failed", result.status.value)
        status = self._status_from_action(result.status)
        if result.status == ActionStatus.EXECUTED:
            with self._bookkeeping_lock:
                self._executed_keys.add(key)
            self._emit_lifecycle(task, "completed")
        record = self._record(
            task,
            status,
            ",".join(result.decision.reasons) or result.status.value,
            output=result.output,
            audit_event=result.decision.audit_event,
        )
        return record

    def _status_from_action(self, status: ActionStatus) -> CampaignTaskStatus:
        return {
            ActionStatus.EXECUTED: CampaignTaskStatus.EXECUTED,
            ActionStatus.INFRASTRUCTURE_FAILURE: CampaignTaskStatus.INFRASTRUCTURE_FAILURE,
            ActionStatus.POLICY_DENIED: CampaignTaskStatus.POLICY_DENIED,
            ActionStatus.AUTHORIZED: CampaignTaskStatus.READY,
        }[status]

    def _record(
        self,
        task: CampaignTask,
        status: CampaignTaskStatus,
        reason: str,
        *,
        output: Any = None,
        audit_event: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = {
            "task_id": task.task_id,
            "engagement_id": task.engagement_id,
            "vulnerability_class": task.vulnerability_class,
            "hypothesis_id": task.hypothesis_id,
            "status": status.value,
            "reason": reason[:240],
            "idempotency_key": task.normalized_idempotency_key(),
            "output_available": output is not None,
            "audit_event": dict(audit_event or {}),
            "g02_execution": {
                "adapter_name": str(task.metadata.get("adapter_name") or "")[:160],
                "inventory_ref": str(
                    task.metadata.get("g02_inventory_ref") or ""
                )[:240],
                "proof_contract": str(
                    task.metadata.get("g02_proof_contract") or ""
                )[:240],
                "proof_required": True,
                "confirmation_requires": [
                    "causal_signal",
                    "negative_control",
                    "sealed_proof_bundle",
                ],
            },
            "proof_bundle": None,
            "proof_bundle_sealed": False,
        }
        if status == CampaignTaskStatus.EXECUTED and isinstance(output, Mapping):
            handler_status = str(output.get("handler_status") or "")[:80]
            handler_reason = str(output.get("handler_reason") or "")[:300]
            if handler_status:
                record["handler_status"] = handler_status
            if handler_reason:
                record["handler_reason"] = handler_reason
            observation = project_browser_observation(output.get("observation"))
            if observation:
                record["observation"] = observation
            observation_refs = output.get("observation_refs", ())
            if isinstance(observation_refs, str):
                observation_refs = (observation_refs,)
            if isinstance(observation_refs, (list, tuple)):
                record["observation_refs"] = tuple(str(ref)[:240] for ref in observation_refs[:32])
            for field_name, max_length in (
                ("causal_next_action_ids", 20),
                ("causal_next_hypothesis_ids", 20),
                ("causal_next_vulnerability_classes", 20),
            ):
                value = output.get(field_name)
                if isinstance(value, str):
                    value = (value,)
                if isinstance(value, (list, tuple)):
                    record[field_name] = [str(item)[:200] for item in value[:max_length]]
            evidence = output.get("proof_evidence")
            if isinstance(evidence, (list, tuple)) and evidence:
                record["negative_control_present"] = output.get("negative_control") is not None
                if output.get("proof_verified") is not True:
                    record["proof_bundle_rejection_reason"] = "verifier_attestation_required"
                    record["proof_bundle_store_status"] = "not_verified"
                else:
                    evidence_refs = output.get("evidence_refs", ())
                    if isinstance(evidence_refs, str):
                        evidence_refs = (evidence_refs,)
                    if not isinstance(evidence_refs, (list, tuple)):
                        evidence_refs = ()
                    continuity = task.metadata.get("target_package_continuity", {})
                    if not isinstance(continuity, Mapping):
                        continuity = {}
                    bundle = build_proof_bundle(
                        engagement_id=task.engagement_id,
                        finding_id=str(output.get("finding_id") or task.hypothesis_id),
                        evidence=list(evidence),
                        evidence_refs=list(evidence_refs),
                        negative_control=output.get("negative_control"),
                        hypothesis_id=str(output.get("hypothesis_id") or task.hypothesis_id),
                        target_fingerprint=str(output.get("target_fingerprint") or "") or None,
                        target_package_id=str(continuity.get("package_id") or "") or None,
                        target_package_sha256=str(continuity.get("package_sha256") or "") or None,
                        target_package_scope_digest=(
                            str(continuity.get("scope_digest") or "") or None
                        ),
                        target_package_policy_digest=(
                            str(continuity.get("policy_digest") or "") or None
                        ),
                        scope_context=output.get("scope_context"),
                        identity_context=output.get("identity_context"),
                        baseline=output.get("baseline"),
                        request_evidence=output.get("request_evidence") or (),
                        response_evidence=output.get("response_evidence") or (),
                        causal_oracle=output.get("causal_oracle"),
                        target_backed=bool(output.get("target_backed")),
                        negative_control_independent=bool(
                            output.get("negative_control_independent")
                        ),
                        validator_id=str(output.get("validator_id") or task.validator_id) or None,
                        validator_version=str(output.get("validator_version") or "") or None,
                        replay_metadata=output.get("replay_metadata"),
                        cleanup_status=str(output.get("cleanup_status") or "not_recorded")[:80],
                    ).seal(actor="action_executor")
                    supplied_replay_context = output.get("replay_context")
                    replay_context = (
                        dict(supplied_replay_context)
                        if isinstance(supplied_replay_context, Mapping)
                        else {}
                    )
                    # The executor owns the canonical bundle inputs. Complete
                    # omitted binding metadata from the same output, but never
                    # overwrite caller-supplied values so cross-context replay
                    # remains fail-closed.
                    for field_name in (
                        "engagement_id",
                        "finding_id",
                        "hypothesis_id",
                        "target_fingerprint",
                        "scope_context",
                        "identity_context",
                    ):
                        if field_name not in replay_context:
                            value = output.get(field_name)
                            if value is None:
                                value = getattr(bundle, field_name, None)
                            if value is not None:
                                replay_context[field_name] = value
                    bundle_ready = bool(
                        proof_bundle_promotion_ready(bundle)
                        and bundle.verify_seal()
                        and (
                            not output.get("target_backed")
                            or isinstance(replay_context, Mapping)
                        )
                        and bundle.replay(
                            list(evidence),
                            output.get("negative_control"),
                            replay_context=replay_context or None,
                        )
                    )
                    if not bundle_ready:
                        record["proof_bundle"] = None
                        record["proof_bundle_sealed"] = False
                        record["proof_bundle_rejection_reason"] = (
                            "bundle_replay_or_promotion_failed"
                        )
                        record["proof_bundle_store_status"] = "rejected"
                    elif self.proof_bundle_store is None:
                        record["proof_bundle"] = bundle.model_dump(mode="json")
                        record["proof_bundle_sealed"] = True
                    else:
                        try:
                            self.proof_bundle_store.put(bundle)
                        except Exception as exc:
                            record["proof_bundle_store_status"] = "failed"
                            record["proof_bundle_store_error"] = type(exc).__name__
                            record["proof_bundle"] = None
                            record["proof_bundle_sealed"] = False
                        else:
                            record["proof_bundle_store_status"] = "stored"
                            record["proof_bundle"] = bundle.model_dump(mode="json")
                            record["proof_bundle_sealed"] = True
            if self.experiment_manager is not None:
                experiment_observation = dict(output)
                bundle_value = record.get("proof_bundle")
                if isinstance(bundle_value, Mapping):
                    experiment_observation["proof_bundle_id"] = bundle_value.get("bundle_id")
                    experiment_observation["proof_bundle_sealed"] = (
                        bundle_value.get("sealed") is True
                    )
                experiment_observation["engagement_id"] = task.engagement_id
                experiment_observation.setdefault(
                    "template_id", task.metadata.get("experiment_template")
                )
                experiment_observation.setdefault("outcome", record.get("status"))
                experiment_record = self.experiment_manager.record(
                    task.hypothesis_id,
                    experiment_observation,
                )
                record["experiment_record"] = experiment_record
        with self._bookkeeping_lock:
            self.coverage[task.task_id] = record
            self.decision_trace.append({"selected_task": task.task_id, "outcome": record})
        return record


class ActionExecutor(CampaignExecutor):
    """Named central execution facade retained for graph and integration callers."""


__all__ = [
    "ActionExecutor",
    "CampaignExecutor",
    "CampaignTask",
    "CampaignTaskStatus",
    "NextBestActionEngine",
    "PlannedAction",
    "resolve_preconditions",
]
