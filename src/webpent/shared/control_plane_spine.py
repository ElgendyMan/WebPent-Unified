"""Runtime control-plane spine for browser, identity, workflow, and proof flows.

This module contains no direct I/O. External browser and mailbox effects remain
injected handlers and must be called through the existing ActionExecutor.
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from webpent.shared.campaign_executor import ActionExecutor, CampaignTask
from webpent.shared.control_plane import (
    BrowserActionRequest,
    BrowserSessionRef,
    EngagementScope,
    IdentityProfileRef,
    ScopeDecisionType,
    WorkflowStep,
)
from webpent.shared.control_plane_runtime import (
    BrowserActionAdapter,
    BrowserSessionManager,
    WorkflowRecord,
    WorkflowStateMachine,
    project_browser_observation,
)
from webpent.shared.secret_vault import SecretVault


class IdentityBinding(BaseModel):
    """Checkpoint-safe identity-to-tenant binding; no credentials are stored."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    identity_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    tenant_ref: str = Field(default="", max_length=160)
    role: str = Field(default="unknown", max_length=120)
    status: str = Field(min_length=1, max_length=80)
    email_ref: str = Field(min_length=1, max_length=240)
    username_ref: str = Field(min_length=1, max_length=240)


class IdentityTenantObjectGraph:
    """Thread-safe, engagement-isolated graph of redacted identity bindings."""

    def __init__(self, *, engagement_id: str) -> None:
        if not str(engagement_id or "").strip():
            raise ValueError("identity_graph_engagement_required")
        self.engagement_id = str(engagement_id).strip()[:160]
        self._items: dict[str, IdentityBinding] = {}
        self._lock = RLock()

    def register(self, identity: IdentityProfileRef) -> IdentityBinding:
        if identity.engagement_id != self.engagement_id:
            raise ValueError("identity_graph_engagement_mismatch")
        binding = IdentityBinding(
            identity_id=identity.identity_id,
            engagement_id=identity.engagement_id,
            tenant_ref=identity.tenant_ref,
            role=identity.role,
            status=identity.status.value,
            email_ref=identity.email_ref,
            username_ref=identity.username_ref,
        )
        with self._lock:
            existing = self._items.get(binding.identity_id)
            if existing is not None and existing != binding:
                raise ValueError("identity_graph_rebinding_denied")
            self._items[binding.identity_id] = binding
        return binding

    def get(self, identity_id: str) -> IdentityBinding | None:
        with self._lock:
            return self._items.get(str(identity_id or "").strip())

    def authorize(self, *, identity_id: str, tenant_ref: str = "") -> bool:
        binding = self.get(identity_id)
        if binding is None or binding.status in {"revoked", "destroyed", "quarantined"}:
            return False
        requested_tenant = str(tenant_ref or "").strip()
        return not requested_tenant or binding.tenant_ref == requested_tenant

    def diagnostics(self) -> dict[str, Any]:
        with self._lock:
            values = tuple(self._items.values())
        return {
            "engagement_id": self.engagement_id,
            "identity_count": len(values),
            "identity_ids": sorted(item.identity_id for item in values),
            "tenant_refs": sorted({item.tenant_ref for item in values if item.tenant_ref}),
        }


class ReplayReceipt(BaseModel):
    """Redacted result of a centrally authorized replay."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task_id: str = Field(min_length=1, max_length=160)
    engagement_id: str = Field(min_length=1, max_length=160)
    status: str = Field(min_length=1, max_length=80)
    reason: str = Field(default="", max_length=300)
    observation_refs: tuple[str, ...] = ()
    observation: dict[str, Any] = Field(default_factory=dict)
    clean: bool = False


class ActionReplayEngine:
    """Build and execute replay tasks exclusively through ActionExecutor."""

    def __init__(self, *, executor: ActionExecutor, engagement_id: str) -> None:
        self.executor = executor
        self.engagement_id = str(engagement_id or "").strip()[:160]
        if not self.engagement_id:
            raise ValueError("replay_engagement_required")

    def replay_browser(
        self,
        request: BrowserActionRequest,
        session: BrowserSessionRef,
        adapter: BrowserActionAdapter,
        *,
        target_url: str,
        vulnerability_class: str = "workflow_observation",
        hypothesis_id: str = "control-plane-replay",
        validator_id: str = "control-plane-browser",
        g02_inventory_ref: str,
        g02_proof_contract: str,
        preconditions_met: bool = True,
    ) -> ReplayReceipt:
        if request.engagement_id != self.engagement_id:
            return ReplayReceipt(
                task_id=request.action_id,
                engagement_id=self.engagement_id,
                status="blocked_by_precondition",
                reason="replay_engagement_mismatch",
            )
        if request.scope_decision.decision != ScopeDecisionType.ALLOWED:
            return ReplayReceipt(
                task_id=request.action_id,
                engagement_id=self.engagement_id,
                status="blocked_by_precondition",
                reason="scope_decision_not_allowed",
            )
        task = CampaignTask(
            task_id=request.action_id,
            engagement_id=self.engagement_id,
            asset_id=request.url,
            source_evidence_ids=(),
            vulnerability_class=vulnerability_class,
            hypothesis_id=hypothesis_id,
            identity_context=session.session_id,
            workflow_state="browser_session_active",
            probe_family=f"browser_{request.operation}",
            negative_control="required",
            oracle="browser_observation_only",
            target_url=target_url,
            capability="browser_action",
            action_family="browser_action",
            validator_id=validator_id,
            idempotency_key=request.idempotency_key,
            metadata={
                "adapter_name": "control_plane_browser",
                "g02_inventory_ref": g02_inventory_ref,
                "g02_proof_contract": g02_proof_contract,
                "scope_decision": request.scope_decision.reason,
            },
        )
        def _run_browser_action(_task: CampaignTask) -> dict[str, Any]:
            outcome = adapter.execute(request, session)
            return {
                "handler_status": outcome.status,
                "handler_reason": outcome.reason,
                "observation_refs": list(outcome.observation_refs),
                "observation": project_browser_observation(outcome.observation),
                "clean": outcome.clean,
            }

        result = self.executor.execute(
            task,
            _run_browser_action,
            preconditions_met=preconditions_met,
        )
        handler_status = str(result.get("handler_status") or "")
        effective_status = (
            "blocked_by_precondition"
            if handler_status not in {"", "completed"}
            else str(
                getattr(
                    result.get("status"),
                    "value",
                    result.get("status", "infrastructure_failure"),
                )
            )
        )
        return ReplayReceipt(
            task_id=request.action_id,
            engagement_id=self.engagement_id,
            status=effective_status,
            reason=str(
                result.get("handler_reason") or result.get("reason", "")
            )[:300],
            observation_refs=tuple(result.get("observation_refs", ())),
            observation=project_browser_observation(result.get("observation")),
            clean=bool(result.get("clean", False)),
        )


@dataclass(frozen=True)
class ControlPlaneRuntime:
    """Live, non-serializable control-plane dependencies for one engagement."""

    engagement_id: str
    scope: EngagementScope
    identity_graph: IdentityTenantObjectGraph
    session_manager: BrowserSessionManager
    workflow_state_machine: WorkflowStateMachine
    replay_engine: ActionReplayEngine
    secret_vault: SecretVault

    def start_workflow(
        self,
        *,
        workflow_id: str,
        identity: IdentityProfileRef,
        session: BrowserSessionRef,
        intent_model: Any | None = None,
    ) -> WorkflowRecord:
        """Start a graph-bound workflow with an optional passive intent binding."""
        self.identity_graph.register(identity)
        if not self.identity_graph.authorize(
            identity_id=identity.identity_id,
            tenant_ref=identity.tenant_ref,
        ):
            raise ValueError("workflow_identity_not_authorized")
        return self.workflow_state_machine.start(
            workflow_id=workflow_id,
            engagement_id=self.engagement_id,
            identity=identity,
            session=session,
            intent_model=intent_model,
        )

    def apply_workflow_step(
        self,
        step: WorkflowStep,
        *,
        identity: IdentityProfileRef,
        session: BrowserSessionRef,
        idempotency_key: str,
        intent_model: Any | None = None,
    ) -> WorkflowRecord:
        """Apply a workflow step while preserving identity/session/intent binding."""
        if (
            identity.engagement_id != self.engagement_id
            or session.engagement_id != self.engagement_id
        ):
            raise ValueError("workflow_binding_mismatch")
        if not self.identity_graph.authorize(
            identity_id=identity.identity_id,
            tenant_ref=identity.tenant_ref,
        ):
            raise ValueError("workflow_identity_not_authorized")
        return self.workflow_state_machine.apply(
            step,
            engagement_id=self.engagement_id,
            identity_id=identity.identity_id,
            session_id=session.session_id,
            idempotency_key=idempotency_key,
            intent_model=intent_model,
        )

    def descriptor(self) -> dict[str, Any]:
        """Return metadata only; handlers, profiles, and secret values are omitted."""
        return {
            "engagement_id": self.engagement_id,
            "scope_engagement_id": self.scope.engagement_id,
            "identity_graph": self.identity_graph.diagnostics(),
            "control_plane": {
                "browser_sessions": "reference_only",
                "gmail": "read_only_injected",
                "secret_storage": "volatile_opaque_ref",
                "replay": "action_executor_only",
            },
        }


def build_control_plane_runtime(
    *,
    engagement_id: str,
    scope: EngagementScope,
    executor: ActionExecutor,
    profile_root: str,
    identity_graph: IdentityTenantObjectGraph | None = None,
    workflow_state_machine: WorkflowStateMachine | None = None,
    secret_vault: SecretVault | None = None,
) -> ControlPlaneRuntime:
    """Construct pure/injected control-plane components without performing I/O."""
    normalized = str(engagement_id or "").strip()[:160]
    if not normalized or scope.engagement_id != normalized:
        raise ValueError("control_plane_engagement_mismatch")
    return ControlPlaneRuntime(
        engagement_id=normalized,
        scope=scope,
        identity_graph=identity_graph or IdentityTenantObjectGraph(engagement_id=normalized),
        session_manager=BrowserSessionManager(profile_root),
        workflow_state_machine=workflow_state_machine or WorkflowStateMachine(),
        replay_engine=ActionReplayEngine(executor=executor, engagement_id=normalized),
        secret_vault=secret_vault or SecretVault(),
    )


__all__ = [
    "ActionReplayEngine",
    "ControlPlaneRuntime",
    "IdentityBinding",
    "IdentityTenantObjectGraph",
    "ReplayReceipt",
    "build_control_plane_runtime",
]
