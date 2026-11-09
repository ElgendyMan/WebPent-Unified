"""Governed agent harness for WebPent.

The harness is a control-plane boundary, not a transport.  It validates typed
agent proposals, checks engagement-scoped capability grants, and delegates all
execution to the existing :class:`ActionExecutor`.  No handler is invoked by
this module unless the executor has first passed ActionAuthority and its
idempotency/budget gates.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from webpent.models.evidence import redact_sensitive
from webpent.shared.action_authority import ActionRisk
from webpent.shared.campaign_executor import ActionExecutor, CampaignTask

_SENSITIVE_TEXT = re.compile(
    r"(?i)\b(?:password|passwd|authorization|cookie|token|secret|api[_-]?key|credential)\s*[:=]\s*[^\s,;]+"
)


def _scrub_untrusted(value: Any) -> Any:
    if isinstance(value, str):
        return _SENSITIVE_TEXT.sub("<redacted-sensitive-text>", value)[:4000]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(
                marker in key_text
                for marker in (
                    "password",
                    "authorization",
                    "cookie",
                    "token",
                    "secret",
                    "api_key",
                    "credential",
                )
            ):
                result[str(key)[:120]] = "<redacted>"
            else:
                result[str(key)[:120]] = _scrub_untrusted(item)
        return result
    if isinstance(value, (list, tuple)):
        return [_scrub_untrusted(item) for item in value[:64]]
    return value


class HarnessStatus(str, Enum):
    READY = "ready"
    DENIED = "denied"
    BLOCKED = "blocked"
    EXECUTED = "executed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class BudgetReservation:
    """Bounded reservation carried in a run context."""

    max_actions: int
    max_cost: float
    used_actions: int = 0
    used_cost: float = 0.0

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if self.max_actions < 0:
            errors.append("budget:max_actions_invalid")
        if self.max_cost < 0:
            errors.append("budget:max_cost_invalid")
        if self.used_actions < 0 or self.used_actions > self.max_actions:
            errors.append("budget:used_actions_invalid")
        if self.used_cost < 0 or self.used_cost > self.max_cost:
            errors.append("budget:used_cost_invalid")
        return tuple(errors)


@dataclass(frozen=True)
class AgentRunContext:
    """Immutable context required before an agent can submit a proposal."""

    run_id: str
    engagement_id: str
    package_digest: str
    authorization_context: Mapping[str, Any]
    target_model_version: str
    agent_identity: str
    capabilities: tuple[str, ...]
    budget: BudgetReservation
    deadline: str
    stop_token: str
    trace_id: str
    redaction_policy: str = "default"
    stop_requested: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        for field_name in (
            "run_id",
            "engagement_id",
            "package_digest",
            "target_model_version",
            "agent_identity",
            "deadline",
            "stop_token",
            "trace_id",
        ):
            if not str(getattr(self, field_name) or "").strip():
                errors.append(f"context:{field_name}:required")
        if not isinstance(self.authorization_context, Mapping):
            errors.append("context:authorization_context:invalid")
        if not self.capabilities:
            errors.append("context:capabilities:required")
        errors.extend(self.budget.validate())
        try:
            deadline = datetime.fromisoformat(self.deadline.replace("Z", "+00:00"))
            if deadline.tzinfo is None:
                errors.append("context:deadline:timezone_required")
            elif deadline.astimezone(UTC) <= datetime.now(UTC):
                errors.append("context:deadline:expired")
        except (TypeError, ValueError):
            errors.append("context:deadline:invalid")
        return tuple(errors)

    def descriptor(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "run_id": self.run_id,
                "engagement_id": self.engagement_id,
                "package_digest": self.package_digest,
                "authorization_context": dict(self.authorization_context),
                "target_model_version": self.target_model_version,
                "agent_identity": self.agent_identity,
                "capabilities": list(self.capabilities),
                "budget": {
                    "max_actions": self.budget.max_actions,
                    "max_cost": self.budget.max_cost,
                    "used_actions": self.budget.used_actions,
                    "used_cost": self.budget.used_cost,
                },
                "deadline": self.deadline,
                "stop_token": self.stop_token,
                "trace_id": self.trace_id,
                "redaction_policy": self.redaction_policy,
                "stop_requested": self.stop_requested,
            }
        )
        return clean


@dataclass(frozen=True)
class ToolCapability:
    """Allowlisted tool metadata; registration does not grant access."""

    name: str
    input_schema: Mapping[str, Any]
    allowed_side_effects: tuple[str, ...]
    required_authorization: str
    budget_class: str
    evidence_output: str
    safe_fallback: str
    direct_io: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.name.strip():
            errors.append("capability:name:required")
        if not isinstance(self.input_schema, Mapping):
            errors.append("capability:input_schema:invalid")
        if not self.required_authorization.strip():
            errors.append(f"capability:{self.name}:authorization_required")
        if not self.budget_class.strip():
            errors.append(f"capability:{self.name}:budget_class_required")
        if not self.evidence_output.strip():
            errors.append(f"capability:{self.name}:evidence_output_required")
        if not self.safe_fallback.strip():
            errors.append(f"capability:{self.name}:safe_fallback_required")
        return tuple(errors)


@dataclass(frozen=True)
class CapabilityGrant:
    capability_name: str
    engagement_id: str
    lease_id: str
    expires_at: str
    approved_by: str

    def active(self, *, now: datetime | None = None) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
            if expiry.tzinfo is None:
                return False
            return expiry.astimezone(UTC) > (now or datetime.now(UTC)).astimezone(UTC)
        except (TypeError, ValueError):
            return False


class ToolCapabilityRegistry:
    """Deny-by-default capability registry with engagement-scoped grants."""

    def __init__(self) -> None:
        self._capabilities: dict[str, ToolCapability] = {}
        self._grants: dict[tuple[str, str], CapabilityGrant] = {}

    def register(self, capability: ToolCapability) -> None:
        errors = capability.validate()
        if errors:
            raise ValueError(";".join(errors))
        key = capability.name.strip()
        if key in self._capabilities:
            raise ValueError(f"capability:{key}:duplicate")
        self._capabilities[key] = capability

    def grant(self, grant: CapabilityGrant) -> None:
        capability = self._capabilities.get(grant.capability_name.strip())
        if capability is None:
            raise ValueError(f"capability:{grant.capability_name}:unregistered")
        if not grant.engagement_id.strip() or not grant.lease_id.strip():
            raise ValueError("capability:grant_identity_required")
        if not grant.approved_by.strip() or not grant.active():
            raise ValueError("capability:grant_not_active_or_approved")
        key = (grant.engagement_id.strip(), grant.capability_name.strip())
        if key in self._grants:
            raise ValueError(f"capability:{grant.capability_name}:duplicate_grant")
        self._grants[key] = grant

    def check(
        self, *, capability_name: str, engagement_id: str, declared: tuple[str, ...]
    ) -> tuple[bool, tuple[str, ...]]:
        name = capability_name.strip()
        reasons: list[str] = []
        capability = self._capabilities.get(name)
        if capability is None:
            reasons.append(f"capability:{name}:not_registered")
            return False, tuple(reasons)
        if name not in {item.strip() for item in declared}:
            reasons.append(f"capability:{name}:not_declared_in_context")
        grant = self._grants.get((engagement_id.strip(), name))
        if grant is None:
            reasons.append(f"capability:{name}:not_granted")
        elif not grant.active():
            reasons.append(f"capability:{name}:lease_expired")
        if capability.direct_io and grant is None:
            reasons.append(f"capability:{name}:direct_io_requires_grant")
        return not reasons, tuple(reasons)

    def descriptor(self) -> dict[str, Any]:
        return {
            "capabilities": [
                {
                    "name": item.name,
                    "allowed_side_effects": list(item.allowed_side_effects),
                    "required_authorization": item.required_authorization,
                    "budget_class": item.budget_class,
                    "evidence_output": item.evidence_output,
                    "safe_fallback": item.safe_fallback,
                    "direct_io": item.direct_io,
                }
                for item in sorted(self._capabilities.values(), key=lambda value: value.name)
            ],
            "active_grants": [
                {
                    "capability_name": grant.capability_name,
                    "engagement_id": grant.engagement_id,
                    "lease_id": grant.lease_id,
                    "expires_at": grant.expires_at,
                    "approved_by": grant.approved_by,
                }
                for grant in sorted(
                    self._grants.values(),
                    key=lambda value: (value.engagement_id, value.capability_name),
                )
                if grant.active()
            ],
            "deny_by_default": True,
        }


@dataclass(frozen=True)
class ProposedAction:
    """Transport-neutral action intent delegated to CampaignTask."""

    action_id: str
    target_url: str
    capability: str
    method: str = "GET"
    action_family: str = "http_read"
    risk: ActionRisk = ActionRisk.READ_ONLY
    cost: float = 1.0
    identity_ref: str = "anonymous"
    idempotency_key: str = ""
    vulnerability_class: str = "unknown"
    hypothesis_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        for field_name in ("action_id", "target_url", "capability", "vulnerability_class"):
            if not str(getattr(self, field_name) or "").strip():
                errors.append(f"action:{field_name}:required")
        if self.cost <= 0:
            errors.append(f"action:{self.action_id}:cost_invalid")
        return tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "action_id": self.action_id,
                "target_url": self.target_url,
                "capability": self.capability,
                "method": self.method,
                "action_family": self.action_family,
                "risk": self.risk.value,
                "cost": self.cost,
                "identity_ref": self.identity_ref,
                "idempotency_key": self.idempotency_key,
                "vulnerability_class": self.vulnerability_class,
                "hypothesis_id": self.hypothesis_id,
                "metadata": dict(self.metadata),
            }
        )
        return clean


@dataclass(frozen=True)
class AgentProposal:
    """Structured proposal; it is advisory and never an authorization."""

    objective: str
    assumptions: tuple[str, ...]
    prerequisites: tuple[str, ...]
    proposed_actions: tuple[ProposedAction, ...]
    expected_observations: tuple[str, ...]
    risk: ActionRisk
    cost: float
    confidence: float
    fallback: str
    stop_conditions: tuple[str, ...]
    proposal_id: str = ""

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.objective.strip():
            errors.append("proposal:objective:required")
        if not self.proposal_id.strip():
            errors.append("proposal:proposal_id:required")
        if not self.proposed_actions:
            errors.append("proposal:actions:required")
        if not self.stop_conditions:
            errors.append("proposal:stop_conditions:required")
        if not self.fallback.strip():
            errors.append("proposal:fallback:required")
        if not 0.0 <= self.confidence <= 1.0:
            errors.append("proposal:confidence:out_of_range")
        if self.cost <= 0:
            errors.append("proposal:cost_invalid")
        for action in self.proposed_actions:
            errors.extend(action.validate())
        return tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "proposal_id": self.proposal_id,
                "objective": self.objective,
                "assumptions": list(self.assumptions),
                "prerequisites": list(self.prerequisites),
                "proposed_actions": [item.as_dict() for item in self.proposed_actions],
                "expected_observations": list(self.expected_observations),
                "risk": self.risk.value,
                "cost": self.cost,
                "confidence": self.confidence,
                "fallback": self.fallback,
                "stop_conditions": list(self.stop_conditions),
            }
        )
        return clean


@dataclass(frozen=True)
class HarnessOutcome:
    status: HarnessStatus
    run_id: str
    proposal_id: str
    action_results: tuple[Mapping[str, Any], ...]
    observations: tuple[Mapping[str, Any], ...]
    blocked_reasons: tuple[str, ...]
    confirmation_status: str = "not_confirmed"
    trace_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "status": self.status.value,
                "run_id": self.run_id,
                "proposal_id": self.proposal_id,
                "action_results": [dict(item) for item in self.action_results],
                "observations": [dict(item) for item in self.observations],
                "blocked_reasons": list(self.blocked_reasons),
                "confirmation_status": self.confirmation_status,
                "trace_id": self.trace_id,
            }
        )
        return clean


class _LocalEventSink:
    """Minimal event sink used only when the runtime did not inject one."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, event_type: str, **kwargs: Any) -> dict[str, Any]:
        event = {"event_type": str(event_type)[:80], **kwargs}
        self.events.append(event)
        return event


class HarnessRunner:
    """Validate proposals and delegate each action to the central executor."""

    def __init__(
        self,
        action_executor: ActionExecutor,
        capability_registry: ToolCapabilityRegistry,
        *,
        event_sink: Any | None = None,
    ) -> None:
        self.action_executor = action_executor
        self.capability_registry = capability_registry
        self.event_sink = event_sink
        if self.event_sink is None:
            self.event_sink = _LocalEventSink()
        self.trajectory: list[dict[str, Any]] = []

    @staticmethod
    def prompt_context(
        *,
        control_metadata: Mapping[str, Any],
        untrusted_observations: Any,
    ) -> dict[str, Any]:
        """Keep control metadata separate from target-controlled observations."""
        clean_control, _ = redact_sensitive(dict(control_metadata))
        clean_observations, _ = redact_sensitive(_scrub_untrusted(untrusted_observations))
        clean_observations = _scrub_untrusted(clean_observations)
        return {
            "control_metadata": clean_control,
            "untrusted_observations": clean_observations,
            "untrusted_observations_are_instructions": False,
        }

    def run(
        self,
        context: AgentRunContext,
        proposal: AgentProposal,
        handlers: Mapping[str, Callable[[Any], Any]],
        *,
        observed_preconditions: tuple[str, ...] = (),
    ) -> HarnessOutcome:
        errors = list(context.validate())
        errors.extend(proposal.validate())
        if context.stop_requested:
            errors.append("stop:requested_before_execution")
        if errors:
            return self._outcome(context, proposal, HarnessStatus.BLOCKED, errors)

        observed = {" ".join(item.lower().split()) for item in observed_preconditions}
        if any(" ".join(item.lower().split()) not in observed for item in proposal.prerequisites):
            missing = [
                item
                for item in proposal.prerequisites
                if " ".join(item.lower().split()) not in observed
            ]
            return self._outcome(
                context,
                proposal,
                HarnessStatus.BLOCKED,
                ["precondition:missing:" + ",".join(missing)],
            )

        results: list[Mapping[str, Any]] = []
        observations: list[Mapping[str, Any]] = []
        blocked: list[str] = []
        executed_cost = 0.0
        for executed_count, action in enumerate(proposal.proposed_actions):
            if context.stop_requested:
                blocked.append("stop:requested")
                break
            if executed_count >= context.budget.max_actions:
                blocked.append("budget:max_actions_exhausted")
                break
            if executed_cost + action.cost > context.budget.max_cost:
                blocked.append("budget:max_cost_exhausted")
                break
            allowed, reasons = self.capability_registry.check(
                capability_name=action.capability,
                engagement_id=context.engagement_id,
                declared=context.capabilities,
            )
            if not allowed:
                blocked.extend(reasons)
                self._record(context, proposal, action, "capability_denied", reasons)
                break
            handler = handlers.get(action.action_id)
            if handler is None:
                blocked.append(f"action:{action.action_id}:handler_unavailable")
                self._record(context, proposal, action, "handler_unavailable", blocked[-1:])
                break
            metadata = dict(action.metadata)
            metadata.update(
                {
                    "harness_run_id": context.run_id,
                    "harness_trace_id": context.trace_id,
                    "target_package_continuity": {
                        "package_sha256": context.package_digest,
                    },
                    "harness_capability": action.capability,
                }
            )
            task = CampaignTask(
                task_id=f"{context.run_id}:{action.action_id}"[:160],
                engagement_id=context.engagement_id,
                asset_id=str(metadata.get("asset_id") or action.target_url)[:240],
                source_evidence_ids=tuple(
                    str(item) for item in metadata.get("source_evidence_ids", ())
                ),
                vulnerability_class=action.vulnerability_class,
                hypothesis_id=action.hypothesis_id or action.action_id,
                preconditions=proposal.prerequisites,
                identity_context=action.identity_ref,
                risk_tier=action.risk,
                method=action.method,
                negative_control="required",
                oracle="deterministic_response_compare",
                expected_information_gain=0.5,
                budget=action.cost,
                idempotency_key=action.idempotency_key,
                target_url=action.target_url,
                capability=action.capability,
                action_family=action.action_family,
                metadata=metadata,
            )
            result = self.action_executor.execute(task, handler, preconditions_met=True)
            safe_result, _ = redact_sensitive(result)
            if not isinstance(safe_result, Mapping):
                safe_result = {"status": "inconclusive", "result_type": type(result).__name__}
            results.append(dict(safe_result))
            executed_cost += action.cost
            output = safe_result.get("output") if isinstance(safe_result, Mapping) else None
            observations.append(
                {
                    "action_id": action.action_id,
                    "status": safe_result.get("status", "inconclusive"),
                    "output": output
                    if isinstance(output, (str, int, float, bool, type(None), Mapping, list, tuple))
                    else None,
                    "target_backed": bool(
                        isinstance(output, Mapping) and output.get("target_backed")
                    ),
                    "proof_bundle_sealed": bool(safe_result.get("proof_bundle_sealed")),
                }
            )
            self._record(
                context, proposal, action, str(safe_result.get("status", "inconclusive")), ()
            )
            if safe_result.get("status") in {
                "policy_denied",
                "infrastructure_failure",
                "blocked_by_precondition",
            }:
                blocked.append(str(safe_result.get("reason") or safe_result.get("status")))
                break

        if blocked:
            status = (
                HarnessStatus.BLOCKED
                if not results or all(item.get("status") != "executed" for item in results)
                else HarnessStatus.INCONCLUSIVE
            )
        elif results and all(item.get("status") == "executed" for item in results):
            status = HarnessStatus.EXECUTED
        else:
            status = HarnessStatus.INCONCLUSIVE
        return self._outcome(context, proposal, status, blocked, results, observations)

    def _record(
        self,
        context: AgentRunContext,
        proposal: AgentProposal,
        action: ProposedAction,
        status: str,
        reasons: Any,
    ) -> None:
        event = self.event_sink.emit(
            "agent_harness.action",
            engagement_id=context.engagement_id,
            campaign_id=context.run_id,
            task_id=f"{context.run_id}:{action.action_id}",
            action_id=action.action_id,
            correlation_id=context.trace_id,
            payload={
                "proposal_id": proposal.proposal_id,
                "status": status,
                "reasons": list(reasons) if isinstance(reasons, (list, tuple)) else [str(reasons)],
                "capability": action.capability,
            },
        )
        self.trajectory.append(
            {
                "event_id": str(
                    getattr(event, "event_id", "")
                    or (event.get("event_id", "") if isinstance(event, Mapping) else "")
                ),
                "run_id": context.run_id,
                "trace_id": context.trace_id,
                "proposal_id": proposal.proposal_id,
                "action_id": action.action_id,
                "status": status,
            }
        )

    @staticmethod
    def _outcome(
        context: AgentRunContext,
        proposal: AgentProposal,
        status: HarnessStatus,
        reasons: list[str],
        results: list[Mapping[str, Any]] | None = None,
        observations: list[Mapping[str, Any]] | None = None,
    ) -> HarnessOutcome:
        # Execution is never equivalent to confirmation. Proof requirements are
        # checked by the validator/ProofEngine, not by the harness.
        proof_complete = bool(observations) and all(
            bool(item.get("target_backed")) and bool(item.get("proof_bundle_sealed"))
            for item in observations or ()
        )
        return HarnessOutcome(
            status=status,
            run_id=context.run_id,
            proposal_id=proposal.proposal_id,
            action_results=tuple(results or ()),
            observations=tuple(observations or ()),
            blocked_reasons=tuple(str(item)[:240] for item in reasons),
            confirmation_status="candidate_only" if proof_complete else "not_confirmed",
            trace_id=context.trace_id,
        )


__all__ = [
    "AgentProposal",
    "AgentRunContext",
    "BudgetReservation",
    "CapabilityGrant",
    "HarnessOutcome",
    "HarnessRunner",
    "HarnessStatus",
    "ProposedAction",
    "ToolCapability",
    "ToolCapabilityRegistry",
]


def proposal_from_campaign_task(
    task: CampaignTask,
    *,
    proposal_id: str = "",
    objective: str = "",
    assumptions: tuple[str, ...] = (),
    expected_observations: tuple[str, ...] = (),
) -> AgentProposal:
    """Translate one bounded campaign task into an advisory proposal.

    This helper does not authorize, execute, or promote a finding.  It rejects
    targetless tasks and preserves the task's identity, negative-control,
    validator, and idempotency metadata for the central executor to review.
    """
    if not task.target_url.strip():
        raise ValueError("proposal:target_url:required")
    action = ProposedAction(
        action_id=task.task_id,
        target_url=task.target_url,
        capability=task.capability,
        method=task.method,
        action_family=task.action_family,
        risk=task.risk_tier,
        cost=task.budget,
        identity_ref=task.identity_context,
        idempotency_key=task.normalized_idempotency_key(),
        vulnerability_class=task.vulnerability_class,
        hypothesis_id=task.hypothesis_id,
        metadata={
            "asset_id": task.asset_id,
            "source_evidence_ids": list(task.source_evidence_ids),
            "preconditions": list(task.preconditions),
            "negative_control": task.negative_control,
            "oracle": task.oracle,
            "workflow_state": task.workflow_state,
            "probe_family": task.probe_family,
            "validator_id": task.validator_id,
            "tenant_context": task.tenant_context,
            "task_metadata": _scrub_untrusted(dict(task.metadata)),
        },
    )
    return AgentProposal(
        objective=objective.strip() or f"bounded_probe:{task.vulnerability_class}",
        assumptions=tuple(str(item)[:240] for item in assumptions),
        prerequisites=tuple(str(item)[:240] for item in task.preconditions),
        proposed_actions=(action,),
        expected_observations=tuple(str(item)[:240] for item in expected_observations)
        or (task.oracle,),
        risk=task.risk_tier,
        cost=task.budget,
        confidence=max(0.0, min(1.0, float(task.expected_information_gain))),
        fallback="blocked_by_policy_or_missing_proof",
        stop_conditions=(
            task.stop_condition,
            "negative_control_required",
            "scope_mismatch_is_terminal",
        ),
        proposal_id=proposal_id.strip() or f"proposal:{task.task_id}",
    )


__all__ = [
    "AgentProposal",
    "AgentRunContext",
    "BudgetReservation",
    "CapabilityGrant",
    "HarnessOutcome",
    "HarnessRunner",
    "HarnessStatus",
    "ProposedAction",
    "ToolCapability",
    "ToolCapabilityRegistry",
    "proposal_from_campaign_task",
]
