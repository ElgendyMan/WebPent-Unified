"""Bounded controller loop for Smart Autonomous Bug Hunter.

The controller is orchestration only. It never creates transport clients and never
executes an action without an explicitly injected handler and ActionExecutor.
Legacy graph callers can keep using ``smart_campaigns_node`` unchanged.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from webpent.agents.smart_campaigns.agent import (
    build_smart_campaign_handler,
    build_smart_campaign_tasks,
    smart_campaigns_node,
)
from webpent.models.proof_bundle import proof_bundle_promotion_ready
from webpent.shared.attack_graph import build_attack_graph
from webpent.shared.autonomy_contracts import (
    ActionBudgetState,
    AutonomousCycle,
    StopDecision,
)
from webpent.shared.campaign_executor import (
    ActionExecutor,
    CampaignTask,
    resolve_preconditions,
)
from webpent.shared.capability_manifest import CapabilityRegistry
from webpent.shared.g02_contract import (
    G02_HTTP_APPROVAL_EXPIRY,
    G02_HTTP_CANONICAL_WRAPPER,
    G02_HTTP_INVENTORY_REF,
    G02_HTTP_PROOF_CONTRACT,
    G02_HTTP_SCOPE_POLICY,
)
from webpent.shared.runtime import RegisteredAdapter

TaskHandler = Callable[[CampaignTask], Any]


class AutonomousController:
    """Run bounded plan -> gate -> execute -> observe iterations.

    A missing handler or executor is a configuration error, not an implicit
    transport fallback. Every actual action must pass through the supplied
    ActionExecutor.
    """

    def __init__(
        self,
        *,
        capability_registry: CapabilityRegistry | None = None,
        action_executor: ActionExecutor | None = None,
        max_iterations: int = 3,
    ) -> None:
        self.capability_registry = capability_registry or CapabilityRegistry()
        self.action_executor = action_executor
        self.max_iterations = max(1, min(10, int(max_iterations)))

    def _planning_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        manifest = self.capability_registry.ensure_discovered()
        return {**dict(state), "capability_manifest": manifest}

    @staticmethod
    def _state_fingerprint(state: Mapping[str, Any]) -> str:
        """Hash only redaction-safe state relevant to research convergence."""
        relevant = {
            "target_knowledge": state.get("target_knowledge", {}),
            "positive_evidence": state.get("positive_evidence_ledger", []),
            "negative_evidence": state.get("negative_evidence_ledger", []),
            "knowledge_gaps": state.get("knowledge_gaps", []),
            "findings": state.get("findings", []),
            # Coverage attempts are bookkeeping, not new knowledge. Including
            # them here lets an execution with no output/evidence look like
            # progress and delays the fail-closed no-progress stop by one
            # controller round. The ledger remains persisted for reporting.
            "causal_attack_edges": state.get(
                "causal_attack_edges", state.get("causal_edges", [])
            ),
        }
        encoded = json.dumps(relevant, sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _action_signature(task: CampaignTask) -> str:
        return task.normalized_idempotency_key() or task.task_id

    @staticmethod
    def _causal_edge_from_record(
        task: CampaignTask, record: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Create a graph edge only from a sealed, target-backed causal proof."""
        if record.get("status") != "executed" or record.get("proof_bundle_sealed") is not True:
            return None
        bundle = record.get("proof_bundle")
        if not isinstance(bundle, Mapping):
            return None
        oracle = bundle.get("causal_oracle")
        if not isinstance(oracle, Mapping):
            return None
        if not proof_bundle_promotion_ready(bundle):
            return None
        if (
            bundle.get("target_backed") is not True
            or bundle.get("negative_control_independent") is not True
            or oracle.get("causal_signal") is not True
            or oracle.get("negative_control_complete") is not True
        ):
            return None
        evidence_refs = bundle.get("evidence_refs")
        if not isinstance(evidence_refs, (list, tuple)) or not evidence_refs:
            return None
        finding_id = str(bundle.get("finding_id") or task.hypothesis_id).strip()[:160]
        if not finding_id:
            return None
        target_action_ids = record.get("causal_next_action_ids") or ()
        if isinstance(target_action_ids, str):
            target_action_ids = (target_action_ids,)
        if not isinstance(target_action_ids, (list, tuple)):
            target_action_ids = ()
        target_hypothesis_ids = record.get("causal_next_hypothesis_ids") or ()
        if isinstance(target_hypothesis_ids, str):
            target_hypothesis_ids = (target_hypothesis_ids,)
        if not isinstance(target_hypothesis_ids, (list, tuple)):
            target_hypothesis_ids = ()
        vulnerability_classes = record.get("causal_next_vulnerability_classes") or ()
        if isinstance(vulnerability_classes, str):
            vulnerability_classes = (vulnerability_classes,)
        if not isinstance(vulnerability_classes, (list, tuple)):
            vulnerability_classes = ()
        edge_id = hashlib.sha256(
            f"{task.engagement_id}|{finding_id}|{task.hypothesis_id}".encode()
        ).hexdigest()[:32]
        return {
            "id": f"causal:{edge_id}",
            "engagement_id": task.engagement_id,
            "kind": "confirmed_finding_leads_to_next_action",
            "source_id": f"finding:{finding_id}",
            "target_id": f"hypothesis:{task.hypothesis_id}",
            "confidence": "target_backed_causal_proof",
            "evidence_refs": [str(ref)[:200] for ref in evidence_refs[:20]],
            "causal_signal": True,
            "negative_control_complete": True,
            "control_complete": True,
            "target_backed": True,
            "proof_bundle_sealed": True,
            "metadata": {
                "proof_bundle_id": str(bundle.get("bundle_id") or "")[:160],
                "target_action_ids": [str(value)[:200] for value in target_action_ids[:20]],
                "target_hypothesis_ids": [
                    str(value)[:200] for value in target_hypothesis_ids[:20]
                ],
                "target_vulnerability_classes": [
                    str(value)[:120] for value in vulnerability_classes[:20]
                ],
            },
        }

    @staticmethod
    def _update_coverage_ledger(
        current: Any,
        tasks: list[CampaignTask],
        records: list[Mapping[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        ledger = {
            str(key): dict(value)
            for key, value in (current.items() if isinstance(current, Mapping) else ())
            if isinstance(value, Mapping)
        }
        for task, record in zip(tasks, records, strict=True):
            key = str(task.vulnerability_class)[:120]
            item = ledger.setdefault(
                key,
                {
                    "attempts": 0,
                    "proof_confirmed": False,
                    "last_status": "unknown",
                    "evidence_refs": [],
                    "proof_bundle_ids": [],
                },
            )
            item["attempts"] = min(1000, int(item.get("attempts", 0) or 0) + 1)
            item["last_status"] = str(record.get("status") or "unknown")[:80]
            bundle = record.get("proof_bundle")
            if (
                isinstance(bundle, Mapping)
                and record.get("proof_bundle_sealed") is True
                and proof_bundle_promotion_ready(bundle)
            ):
                item["proof_confirmed"] = True
                bundle_id = str(bundle.get("bundle_id") or "")[:160]
                if bundle_id and bundle_id not in item["proof_bundle_ids"]:
                    item["proof_bundle_ids"] = [*item["proof_bundle_ids"], bundle_id][-20:]
            refs = record.get("evidence_refs")
            if isinstance(refs, (list, tuple)):
                merged = [*item.get("evidence_refs", []), *(str(ref)[:200] for ref in refs)]
                item["evidence_refs"] = list(dict.fromkeys(merged))[-20:]
        return dict(list(ledger.items())[:100])

    @classmethod
    def _merge_causal_edges(
        cls,
        current: Any,
        tasks: list[CampaignTask],
        records: list[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        edges = (
            [dict(item) for item in current if isinstance(item, Mapping)]
            if isinstance(current, (list, tuple))
            else []
        )
        by_id = {str(item.get("id")): item for item in edges if item.get("id")}
        for task, record in zip(tasks, records, strict=True):
            edge = cls._causal_edge_from_record(task, record)
            if edge is not None:
                by_id[edge["id"]] = edge
        return list(by_id.values())[-100:]

    @staticmethod
    def _capability_state(
        manifest: Mapping[str, Any], capability: str
    ) -> dict[str, Any]:
        capabilities = manifest.get("capabilities", {}) if isinstance(manifest, Mapping) else {}
        value = capabilities.get(capability, {}) if isinstance(capabilities, Mapping) else {}
        if not isinstance(value, Mapping):
            return {"status": "unsupported", "capability": capability}
        return {
            "capability": capability,
            "status": str(
                value.get("status") or ("available" if value.get("available") else "unknown")
            ),
            "fallback": bool(value.get("fallback") or value.get("safe_fallback")),
        }

    @staticmethod
    def _record_has_new_evidence(record: Mapping[str, Any]) -> bool:
        return bool(
            record.get("proof_bundle_sealed")
            or record.get("output_available")
            or record.get("negative_control_present")
            or record.get("evidence_refs")
        )

    @staticmethod
    def _parallel_settings(state: Mapping[str, Any]) -> tuple[bool, int]:
        """Read an explicit, bounded parallel policy; default remains serial."""
        raw = state.get("parallel_execution")
        if not isinstance(raw, Mapping) or raw.get("enabled") is not True:
            return False, 1
        try:
            workers = int(raw.get("max_workers", 2))
        except (TypeError, ValueError):
            workers = 2
        return True, max(1, min(8, workers))

    @staticmethod
    def _select_independent_tasks(
        tasks: list[CampaignTask], max_workers: int
    ) -> list[CampaignTask]:
        """Select only read-only tasks without explicit dependency conflicts."""
        selected: list[CampaignTask] = []
        selected_keys: set[str] = set()
        selected_preconditions: set[str] = set()
        for task in tasks:
            if len(selected) >= max_workers:
                break
            if task.risk_tier.value != "read_only" or task.parent_task_id:
                continue
            key = task.normalized_idempotency_key()
            if not key or key in selected_keys:
                continue
            preconditions = {
                str(item).strip().lower()
                for item in task.preconditions
                if str(item).strip()
            }
            if selected_preconditions.intersection(preconditions):
                continue
            selected.append(task)
            selected_keys.add(key)
            selected_preconditions.update(preconditions)
        return selected

    def _execute_batch(
        self,
        tasks: list[CampaignTask],
        state: Mapping[str, Any],
        handler: TaskHandler,
    ) -> list[dict[str, Any]]:
        """Execute a preselected batch and return records in task order."""
        prepared: list[tuple[CampaignTask, bool]] = []
        observed_preconditions = state.get("observed_preconditions", ())
        blocked_preconditions = state.get("blocked_preconditions", ())
        if isinstance(observed_preconditions, str):
            observed_preconditions = (observed_preconditions,)
        if isinstance(blocked_preconditions, str):
            blocked_preconditions = (blocked_preconditions,)
        for task in tasks:
            ready, _ = resolve_preconditions(
                task,
                observed_preconditions=observed_preconditions,
                blocked_preconditions=blocked_preconditions,
                require_observations=True,
            )
            prepared.append((task, ready))

        def execute_one(item: tuple[CampaignTask, bool]) -> dict[str, Any]:
            task, ready = item
            try:
                return self.action_executor.execute(
                    task, handler, preconditions_met=ready
                )
            except Exception as exc:  # noqa: BLE001 - convert transport faults to safe records
                return {
                    "task_id": task.task_id,
                    "engagement_id": task.engagement_id,
                    "vulnerability_class": task.vulnerability_class,
                    "hypothesis_id": task.hypothesis_id,
                    "status": "infrastructure_failure",
                    "reason": "handler_exception",
                    "error_type": type(exc).__name__[:80],
                    "idempotency_key": task.normalized_idempotency_key(),
                    "output_available": False,
                    "proof_bundle_sealed": False,
                }

        enabled, workers = self._parallel_settings(state)
        if not enabled or len(prepared) <= 1:
            return [execute_one(item) for item in prepared]
        with ThreadPoolExecutor(max_workers=min(workers, len(prepared))) as pool:
            futures = [pool.submit(execute_one, item) for item in prepared]
            return [future.result() for future in futures]

    @staticmethod
    def _planned_tasks(
        state: Mapping[str, Any], planning: Mapping[str, Any]
    ) -> list[CampaignTask]:
        tasks, _ = build_smart_campaign_tasks(
            {**dict(state), "campaign_plan": planning.get("campaign_plan", {})},
            max_tasks=10,
        )
        tasks_by_id = {task.task_id: task for task in tasks}
        ordered_tasks: list[CampaignTask] = []
        for item in planning.get("smart_next_actions", []):
            if not isinstance(item, Mapping) or not isinstance(item.get("task"), Mapping):
                continue
            task_id = str(item["task"].get("task_id") or "")
            task = tasks_by_id.get(task_id)
            if task is not None and task not in ordered_tasks:
                ordered_tasks.append(task)
        return ordered_tasks

    def run(
        self,
        state: Mapping[str, Any],
        *,
        handler: TaskHandler | None = None,
        iterations: int = 1,
    ) -> dict[str, Any]:
        """Return an additive state update for bounded controller iterations."""
        limit = max(1, min(self.max_iterations, int(iterations)))
        working: dict[str, Any] = dict(state)
        all_outcomes: list[dict[str, Any]] = []
        all_lifecycle: list[dict[str, Any]] = []
        trace: list[dict[str, Any]] = []
        last_planning: dict[str, Any] = {}
        executed = 0
        completed_action_signatures = {
            str(item).strip()[:160]
            for item in (state.get("completed_action_signatures") or ())
            if str(item).strip()
        }
        completed_action_signatures = set(
            sorted(completed_action_signatures)[:500]
        )
        seen_actions: set[str] = set(completed_action_signatures)
        stop_reason = "iteration_limit_reached"
        minimum_information_gain = 0.05
        recovery_events: list[dict[str, Any]] = list(
            state.get("recovery_events") or []
        )
        recovery_state = dict(state.get("recovery_state") or {})
        recovery_attempts = max(0, int(recovery_state.get("attempts", 0) or 0))
        max_recovery_attempts = max(
            0, min(3, int(recovery_state.get("max_attempts", 2) or 0))
        )
        budget = ActionBudgetState.from_state(
            state.get("action_budget"), default_iterations=limit
        )
        budget.iterations_limit = min(budget.iterations_limit, limit)
        cycle_records: list[dict[str, Any]] = []

        for round_number in range(limit):
            if not budget.can_start_iteration():
                stop_reason = budget.stop_reason or "action_budget_exhausted"
                break
            budget.start_iteration()
            state_before = self._state_fingerprint(working)
            planning = smart_campaigns_node(self._planning_state(working))
            last_planning = dict(planning)
            tasks = self._planned_tasks(working, planning)
            if handler is None or self.action_executor is None:
                raise RuntimeError(
                    "autonomous_controller_runtime_dependencies_required: "
                    "inject both action_executor and handler"
                )

            parallel_enabled, parallel_workers = self._parallel_settings(working)
            selected = self._select_independent_tasks(
                tasks,
                parallel_workers if parallel_enabled else 1,
            )
            if not selected:
                stop_reason = "no_new_ready_task"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": None,
                        "hypothesis_id": None,
                        "action_id": None,
                        "precondition_state": "not_evaluated",
                        "capability_state": {"status": "not_selected"},
                        "status": "complete",
                        "result": "no_new_ready_task",
                        "reason": stop_reason,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            unseen = [
                candidate
                for candidate in selected
                if self._action_signature(candidate) not in seen_actions
            ]
            if not unseen:
                task = selected[0]
                stop_reason = "same_action_repeated"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": task.task_id,
                        "hypothesis_id": task.hypothesis_id,
                        "action_id": self._action_signature(task),
                        "precondition_state": "not_evaluated",
                        "capability_state": self._capability_state(
                            planning.get("capability_manifest", {}), task.capability
                        ),
                        "status": "stopped",
                        "result": stop_reason,
                        "reason": stop_reason,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            selected = [
                candidate
                for candidate in unseen
                if candidate.expected_information_gain >= minimum_information_gain
            ]
            if not selected:
                task = unseen[0]
                action_signature = self._action_signature(task)
                stop_reason = "expected_information_gain_below_threshold"
                trace.append(
                    {
                        "correlation_id": str(
                            working.get("correlation_id")
                            or working.get("engagement_id")
                            or "controller"
                        ),
                        "controller_round": round_number,
                        "task_id": task.task_id,
                        "hypothesis_id": task.hypothesis_id,
                        "action_id": action_signature,
                        "precondition_state": "not_evaluated",
                        "capability_state": self._capability_state(
                            planning.get("capability_manifest", {}), task.capability
                        ),
                        "status": "stopped",
                        "result": stop_reason,
                        "reason": stop_reason,
                        "expected_information_gain": task.expected_information_gain,
                        "redacted_evidence_refs": [],
                    }
                )
                break
            estimated_cost = sum(
                max(0.0, min(100.0, float(candidate.budget)))
                for candidate in selected
            )
            if not budget.reserve(estimated_cost):
                stop_reason = budget.stop_reason or "action_budget_exhausted"
                break
            for candidate in selected:
                seen_actions.add(self._action_signature(candidate))
            task = selected[0]
            action_signature = self._action_signature(task)
            lifecycle_start = len(self.action_executor.lifecycle_events)
            records = self._execute_batch(selected, working, handler)
            all_outcomes.extend(records)
            all_lifecycle.extend(self.action_executor.lifecycle_events[lifecycle_start:])
            batch_failed = False
            failed_signatures: list[str] = []
            recoverable_failures: list[tuple[CampaignTask, dict[str, Any]]] = []
            for batch_task, record in zip(selected, records, strict=True):

                batch_signature = self._action_signature(batch_task)
                capability_state = self._capability_state(
                    planning.get("capability_manifest", {}), batch_task.capability
                )
                status = str(record.get("status", "unknown"))
                trace_entry = {
                    "correlation_id": str(
                        working.get("correlation_id")
                        or working.get("engagement_id")
                        or "controller"
                    ),
                    "controller_round": round_number,
                    "task_id": batch_task.task_id,
                    "hypothesis_id": batch_task.hypothesis_id,
                    "action_id": batch_signature,
                    "precondition_state": (
                        "met" if status != "blocked_by_precondition" else "blocked"
                    ),
                    "capability_state": capability_state,
                    "status": status,
                    "result": str(record.get("reason") or status),
                    "proof_bundle_sealed": bool(record.get("proof_bundle_sealed")),
                    "parallel_batch": len(selected) > 1,
                    "parallel_workers": len(selected),
                    "redacted_evidence_refs": list(record.get("evidence_refs", ()))[:20]
                    if isinstance(record.get("evidence_refs", ()), (list, tuple))
                    else [],
                }
                trace.append(trace_entry)
                if status == "executed":
                    completed_action_signatures.add(batch_signature)
                    executed += 1
                    continue
                batch_failed = True
                failed_signatures.append(batch_signature)
                if status == "infrastructure_failure":
                    recoverable_failures.append((batch_task, record))
                stop_reason = {
                    "blocked_by_precondition": "blocked_by_precondition",
                    "policy_denied": "capability_or_authority_blocked",
                    "infrastructure_failure": "infrastructure_failure",
                    "stopped": "action_stopped",
                }.get(status, "action_not_executed")
                trace_entry["result"] = stop_reason
            working = {
                **working,
                **planning,
                "campaign_task_outcomes": all_outcomes,
                "coverage_ledger": self._update_coverage_ledger(
                    working.get("coverage_ledger"), selected, records
                ),
            }
            working["causal_attack_edges"] = self._merge_causal_edges(
                working.get("causal_attack_edges") or working.get("causal_edges"),
                selected,
                records,
            )
            working["causal_edges"] = list(working["causal_attack_edges"])
            try:
                working["attack_graph"] = build_attack_graph(
                    working.get("mental_model") or {},
                    relational_evidence=working.get("relational_evidence") or (),
                    findings=working.get("findings") or (),
                    hypotheses=working.get("hypotheses") or (),
                    causal_edges=working["causal_attack_edges"],
                    coverage_gaps=working.get("knowledge_gaps") or (),
                    target_knowledge=working.get("target_knowledge") or {},
                )
            except Exception:
                working["attack_graph"] = working.get("attack_graph") or {}
            state_after_batch = self._state_fingerprint(working)
            cycle_records.append(
                AutonomousCycle(
                    cycle_id=f"{working.get('engagement_id', 'controller')}:{round_number}",
                    phase="execute",
                    status="blocked" if batch_failed else "completed",
                    selected_tasks=len(selected),
                    executed_tasks=sum(
                        1 for record in records if record.get("status") == "executed"
                    ),
                    evidence_added=any(
                        self._record_has_new_evidence(record) for record in records
                    ),
                    knowledge_updated=state_before != state_after_batch,
                ).as_dict()
            )
            if batch_failed:
                if (
                    recoverable_failures
                    and recovery_attempts < max_recovery_attempts
                    and budget.record_replan()
                ):
                    recovery_attempts = budget.replans
                    seen_actions.difference_update(failed_signatures)
                    for failed_task, failed_record in recoverable_failures:
                        recovery_events.append(
                            {
                                "event_id": (
                                    f"{failed_task.task_id}:recovery:{recovery_attempts}"
                                ),
                                "engagement_id": failed_task.engagement_id,
                                "task_id": failed_task.task_id,
                                "hypothesis_id": failed_task.hypothesis_id,
                                "failure_class": "infrastructure_failure",
                                "attempt": recovery_attempts,
                                "max_attempts": max_recovery_attempts,
                                "status": "replan_requested",
                                "reason": str(
                                    failed_record.get("reason") or "infrastructure_failure"
                                )[:120],
                                "error_type": str(failed_record.get("error_type") or "")[:80],
                                "retry_allowed": True,
                            }
                        )
                    recovery_state = {
                        **recovery_state,
                        "status": "replanning",
                        "attempts": recovery_attempts,
                        "max_attempts": max_recovery_attempts,
                        "last_failure_class": "infrastructure_failure",
                    }
                    stop_reason = "recovery_replan_requested"
                    continue
                if recoverable_failures:
                    recovery_state = {
                        **recovery_state,
                        "status": "exhausted",
                        "attempts": recovery_attempts,
                        "max_attempts": max_recovery_attempts,
                        "last_failure_class": "infrastructure_failure",
                    }
                    stop_reason = "recovery_budget_exhausted"
                break
            if any(bool(record.get("negative_control_contradicts")) for record in records):
                stop_reason = "negative_control_contradicts_theory"
                for entry in trace[-len(records) :]:
                    entry["result"] = stop_reason
                break
            if budget.spent >= budget.limit:
                budget.stop("action_budget_exhausted")
                stop_reason = budget.stop_reason
                trace_entry["result"] = stop_reason
                break
            state_after = self._state_fingerprint(working)
            if state_before == state_after and not any(
                self._record_has_new_evidence(record) for record in records
            ):
                stop_reason = "no_new_evidence_or_state_delta"
                trace_entry["result"] = stop_reason
                break

        replanning = dict(last_planning.get("smart_replanning") or {})
        replanning.update(
            {
                "status": "controller_completed",
                "controller_iterations": len(trace),
                "controller_executed": executed,
                "controller_trace": trace,
                "execution_required": (
                    executed == 0 and bool(last_planning.get("smart_next_actions"))
                ),
                "stop_reason": stop_reason,
            }
        )
        update = dict(last_planning)
        if all_outcomes:
            update["campaign_task_outcomes"] = all_outcomes
        if all_lifecycle:
            update["lifecycle_events"] = all_lifecycle
        if recovery_events:
            update["recovery_events"] = recovery_events
        for state_key in (
            "coverage_ledger",
            "causal_attack_edges",
            "causal_edges",
            "attack_graph",
        ):
            if state_key in working:
                update[state_key] = working[state_key]
        recovery_state = {
            **recovery_state,
            "status": (
                "completed"
                if recovery_state.get("status") == "replanning"
                and stop_reason != "recovery_budget_exhausted"
                else recovery_state.get("status", "not_started")
            ),
            "attempts": recovery_attempts,
            "max_attempts": max_recovery_attempts,
        }
        update["recovery_state"] = recovery_state
        update["action_budget"] = budget.as_dict()
        update["completed_action_signatures"] = sorted(
            completed_action_signatures
        )[:500]
        update["autonomous_cycle_records"] = cycle_records
        update["stop_decision"] = StopDecision(
            True,
            stop_reason,
            category=(
                "budget" if "budget" in stop_reason else
                "recovery" if "recovery" in stop_reason else
                "evidence" if (
                    "evidence" in stop_reason
                    or "negative_control" in stop_reason
                ) else
                "normal"
            ),
            safe_to_resume=stop_reason in {
                "iteration_limit_reached",
                "action_budget_exhausted",
                "no_new_evidence_or_state_delta",
            },
        ).as_dict()
        update["smart_replanning"] = replanning
        update["current_phase"] = "smart_autonomous_controller"
        return update


def autonomous_controller_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Graph-safe controller node using the single injected runtime spine."""
    from webpent.shared.runtime import RuntimeContext, RuntimeFactory

    runtime = state.get("runtime_context")
    if not isinstance(runtime, RuntimeContext):
        return RuntimeFactory.blocked_result(
            node="autonomous_controller",
            reason="runtime_context_required",
        )
    if not runtime.valid:
        return runtime.blocked_result(node="autonomous_controller")
    observations: list[dict[str, Any]] = []
    direct_findings: list[Any] = []
    handler = build_smart_campaign_handler(
        state,
        root=runtime.target_origin,
        observations=observations,
        direct_findings=direct_findings,
    )
    adapter = runtime.adapters.get("smart_http")
    if adapter is None:
        runtime.adapters.register(
            RegisteredAdapter(
                name="smart_http",
                capability="smart_http_execution",
                transport="http",
                handler=handler,
                source="smart_campaigns",
                version="1",
                policy_checked=True,
                canonical_wrapper=G02_HTTP_CANONICAL_WRAPPER,
                scope_policy=G02_HTTP_SCOPE_POLICY,
                static_inventory_ref=G02_HTTP_INVENTORY_REF,
                proof_contract=G02_HTTP_PROOF_CONTRACT,
                expires_at=G02_HTTP_APPROVAL_EXPIRY,
            )
        )
    else:
        handler = adapter.handler
    result = AutonomousController(action_executor=runtime.action_executor).run(
        state, handler=handler
    )
    result["autonomous_controller_runs"] = int(
        state.get("autonomous_controller_runs", 0) or 0
    ) + 1
    if observations:
        result["smart_http_observations"] = observations
    if direct_findings:
        result["findings"] = [
            *list(state.get("findings") or []),
            *[finding.model_dump(mode="json") for finding in direct_findings],
        ]
        try:
            result["attack_graph"] = build_attack_graph(
                result.get("mental_model") or {},
                relational_evidence=result.get("relational_evidence") or (),
                findings=result.get("findings") or (),
                hypotheses=result.get("hypotheses") or (),
                causal_edges=result.get("causal_attack_edges")
                or result.get("causal_edges")
                or (),
                coverage_gaps=result.get("knowledge_gaps") or (),
                target_knowledge=result.get("target_knowledge") or {},
            )
        except Exception:
            result["attack_graph"] = result.get("attack_graph") or {}
    result["runtime_diagnostics"] = runtime.diagnostics()
    result["runtime_capability_gaps"] = [
        gap.as_dict() for gap in runtime.current_capability_gaps()
    ]
    return result


__all__ = ["AutonomousController", "autonomous_controller_node"]
