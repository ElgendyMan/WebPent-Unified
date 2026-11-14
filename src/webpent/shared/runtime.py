"""Single dependency-injection spine for WebPent runtime actions.

The runtime module is intentionally transport-agnostic.  It constructs policy and
analysis components, but never performs network, browser, subprocess, or OOB I/O.
Those operations must be registered as audited adapters and invoked through the
central :class:`ActionExecutor`.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

from webpent.config.settings import Settings, get_settings
from webpent.models.evidence import redact_sensitive
from webpent.shared.action_authority import ActionAuthority
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.agent_harness import (
    AgentProposal,
    AgentRunContext,
    HarnessOutcome,
    HarnessRunner,
    HarnessStatus,
    ToolCapability,
    ToolCapabilityRegistry,
)
from webpent.shared.campaign_executor import ActionExecutor, NextBestActionEngine
from webpent.shared.capability_manifest import CapabilityRegistry
from webpent.shared.control_plane import EngagementScope
from webpent.shared.engagement_scope import OriginPolicy
from webpent.shared.generic_case_runner import GenericCaseRunner
from webpent.shared.generic_web_contracts import (
    CaseDefinition,
    CaseResult,
    LifecycleAuthorization,
    LifecycleRunContext,
)
from webpent.shared.package_scope import ScopeCompiler
from webpent.shared.proof_bundle_store import ProofBundleStore
from webpent.shared.proof_oracles import NegativeControlEngine, OracleEngine
from webpent.shared.research_intelligence import (
    KnowledgeGapEngine,
    SmartNextBestActionEngine,
)
from webpent.shared.safety_gate import EngagementSafetyGate
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetAdapterRegistry,
)
from webpent.shared.wildcard_scope import ScopeRuntimeHandle, compile_wildcard_scope


class RuntimeConfigurationError(ValueError):
    """Raised when a graph cannot obtain a valid runtime context."""


@dataclass(frozen=True)
class RuntimeCapabilityGap:
    """Typed, checkpoint-safe description of an unavailable runtime dependency."""

    code: str
    component: str
    required_for: str
    recovery_action: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "component": self.component,
            "required_for": self.required_for,
            "recovery_action": self.recovery_action,
        }


@dataclass(frozen=True)
class RuntimeEvent:
    """Redacted, correlation-aware event emitted by the runtime spine."""

    event_id: str
    event_type: str
    engagement_id: str
    campaign_id: str
    task_id: str = ""
    action_id: str = ""
    correlation_id: str = ""
    timestamp: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)


class RuntimeEventSink:
    """Small append-only event sink suitable for tests and worker injection."""

    def __init__(self, *, max_events: int = 5000) -> None:
        self.max_events = max(1, int(max_events))
        self._events: list[RuntimeEvent] = []
        self._lock = Lock()

    @staticmethod
    def _clean(value: Any) -> Any:
        clean, _ = redact_sensitive(value)
        return clean

    def emit(
        self,
        event_type: str,
        *,
        engagement_id: str,
        campaign_id: str,
        task_id: str = "",
        action_id: str = "",
        correlation_id: str = "",
        payload: Mapping[str, Any] | None = None,
    ) -> RuntimeEvent:
        event = RuntimeEvent(
            event_id=f"evt-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}",
            event_type=str(event_type or "unknown")[:80],
            engagement_id=str(engagement_id or "")[:160],
            campaign_id=str(campaign_id or "")[:160],
            task_id=str(task_id or "")[:160],
            action_id=str(action_id or "")[:160],
            correlation_id=str(correlation_id or "")[:160],
            timestamp=datetime.now(UTC).isoformat(),
            payload=self._clean(dict(payload or {})),
        )
        with self._lock:
            self._events.append(event)
            if len(self._events) > self.max_events:
                del self._events[: len(self._events) - self.max_events]
        return event

    def snapshot(self) -> tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(frozen=True)
class RegisteredAdapter:
    """Audited adapter registration; the handler itself is never serialized."""

    name: str
    capability: str
    transport: str
    handler: Callable[..., Any]
    source: str = "runtime"
    version: str = "unknown"
    policy_checked: bool = False
    canonical_wrapper: str = ""
    scope_policy: str = ""
    static_inventory_ref: str = ""
    proof_contract: str = ""
    expires_at: str = ""

    def g02_errors(self) -> tuple[str, ...]:
        """Return missing or malformed execution-plane metadata.

        Registration remains backward-compatible for legacy callers, while the
        central execution plane can require this contract before an adapter is
        actually invoked.
        """
        errors: list[str] = []
        required = {
            "canonical_wrapper": self.canonical_wrapper,
            "scope_policy": self.scope_policy,
            "static_inventory_ref": self.static_inventory_ref,
            "proof_contract": self.proof_contract,
            "expires_at": self.expires_at,
        }
        errors.extend(
            f"adapter:{self.name}:{field}:required"
            for field, value in required.items()
            if not str(value or "").strip()
        )
        expiry = str(self.expires_at or "").strip()
        if expiry:
            try:
                parsed = (
                    datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                    if "T" in expiry
                    else datetime.combine(
                        date.fromisoformat(expiry),
                        datetime.min.time(),
                        tzinfo=UTC,
                    )
                )
            except ValueError:
                errors.append(f"adapter:{self.name}:expires_at:invalid")
            else:
                now = datetime.now(UTC)
                if "T" in expiry:
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=UTC)
                    else:
                        parsed = parsed.astimezone(UTC)
                    expired = parsed <= now
                else:
                    # Date-only approvals are valid through the stated UTC date.
                    expired = parsed.date() < now.date()
                if expired:
                    errors.append(f"adapter:{self.name}:approval_expired")
        return tuple(errors)


CONTROL_PLANE_BROWSER_ADAPTER_NAME = "control_plane_browser"
CONTROL_PLANE_BROWSER_CANONICAL_WRAPPER = "control_plane.browser_action"
CONTROL_PLANE_BROWSER_SCOPE_POLICY = "engagement_scope_same_origin"
CONTROL_PLANE_BROWSER_INVENTORY_REF = "control_plane.browser_action.injected"
CONTROL_PLANE_BROWSER_PROOF_CONTRACT = "observation_only_no_confirmation"


class AdapterRegistry:
    """Allowlist of explicitly injected adapters.

    Missing adapters are represented as unavailable.  The registry never falls
    back to raw clients, subprocesses, sockets, or arbitrary callables.
    """

    def __init__(self) -> None:
        self._adapters: dict[str, RegisteredAdapter] = {}

    def register(self, adapter: RegisteredAdapter) -> None:
        key = str(adapter.name or "").strip()
        if not key or not adapter.capability.strip() or not adapter.transport.strip():
            raise RuntimeConfigurationError("adapter registration is incomplete")
        if not adapter.policy_checked:
            raise RuntimeConfigurationError(f"adapter:{key}:policy_checked_manifest_required")
        if key in self._adapters:
            raise RuntimeConfigurationError(f"adapter:{key}:duplicate_registration")
        self._adapters[key] = adapter

    def get(self, name: str) -> RegisteredAdapter | None:
        return self._adapters.get(str(name or "").strip())

    def available(self, name: str) -> bool:
        return self.get(name) is not None

    def validate_for_execution(self, name: str) -> tuple[bool, tuple[str, ...]]:
        """Validate one adapter immediately before central execution."""
        adapter = self.get(name)
        if adapter is None:
            return False, (f"adapter:{str(name or '').strip()}:not_registered",)
        if not adapter.policy_checked:
            return False, (f"adapter:{adapter.name}:policy_not_checked",)
        errors = adapter.g02_errors()
        return not errors, errors

    def manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "name": adapter.name,
                "capability": adapter.capability,
                "transport": adapter.transport,
                "source": adapter.source,
                "version": adapter.version,
                "policy_checked": adapter.policy_checked,
                "canonical_wrapper": adapter.canonical_wrapper,
                "scope_policy": adapter.scope_policy,
                "static_inventory_ref": adapter.static_inventory_ref,
                "proof_contract": adapter.proof_contract,
                "expires_at": adapter.expires_at,
            }
            for adapter in sorted(self._adapters.values(), key=lambda item: item.name)
        ]


@dataclass(frozen=True)
class RuntimeContext:
    """Explicit dependency-injection context consumed by graph nodes."""

    schema_version: str
    engagement_id: str
    campaign_id: str
    target_origin: str
    settings: Settings
    action_authority: ActionAuthority
    action_executor: ActionExecutor
    scope_matcher: OriginPolicy
    capabilities: CapabilityRegistry
    adapters: AdapterRegistry
    event_sink: RuntimeEventSink
    proof_bundle_store: ProofBundleStore
    oracle_engine: OracleEngine
    negative_control_engine: NegativeControlEngine
    coverage_ledger: dict[str, Any]
    identity_tenant_object_graph: Any | None
    workflow_state_machine: Any | None
    replay_engine: Any | None
    knowledge_gap_engine: KnowledgeGapEngine
    next_best_action_engine: SmartNextBestActionEngine
    configuration_errors: tuple[str, ...] = ()
    capability_gaps: tuple[RuntimeCapabilityGap, ...] = ()
    control_plane_runtime: Any | None = None
    # Live typed browser boundary only; never included in checkpoint-safe
    # descriptors or serialized state. Raw Playwright handlers are not exposed.
    control_plane_browser_adapter: Any | None = None
    campaign_next_best_action_engine: NextBestActionEngine | None = None
    safety_gate: EngagementSafetyGate | None = None
    # Optional transport-injected identity provisioning. It is deliberately
    # absent from descriptor/checkpoint payloads and remains default-off.
    identity_provisioning_agent: Any | None = None
    # The immutable control-plane scope used by optional identity workflows.
    engagement_scope: EngagementScope | None = None
    # Live wildcard scope handle; never placed directly in state/checkpoints.
    scope_runtime_handle: ScopeRuntimeHandle | None = None
    # Shared governed harness; live handlers and grants are never checkpointed.
    agent_harness: HarnessRunner | None = None
    # Optional target-specific proof registration. The live adapter is never
    # serialized; only its redacted identity is projected by ``descriptor``.
    target_adapter_registration: RegisteredTargetAdapter | None = None

    @property
    def valid(self) -> bool:
        return not self.configuration_errors and bool(
            self.engagement_id and self.campaign_id and self.target_origin
        )

    def require_valid(self) -> RuntimeContext:
        if not self.valid:
            reasons = ",".join(self.configuration_errors) or "identity:runtime_context_incomplete"
            raise RuntimeConfigurationError(reasons)
        return self

    def current_capability_gaps(self) -> tuple[RuntimeCapabilityGap, ...]:
        """Return capability gaps after all runtime DI registrations.

        ``AdapterRegistry`` is intentionally mutable so nodes can register an
        audited adapter at the point where its handler and proof contract are
        available.  The original ``capability_gaps`` field remains a
        checkpoint-safe creation snapshot for backward compatibility; runtime
        decisions and diagnostics must use this live projection instead.
        """
        return RuntimeFactory._capability_gaps(
            adapters=self.adapters,
            identity_tenant_object_graph=self.identity_tenant_object_graph,
            workflow_state_machine=self.workflow_state_machine,
            replay_engine=self.replay_engine,
        )

    def blocked_result(self, *, node: str, reason: str = "") -> dict[str, Any]:
        """Return the graph-safe result for an unavailable context."""
        detail = reason or ",".join(self.configuration_errors) or "runtime_context_invalid"
        gap_payload = [gap.as_dict() for gap in self.current_capability_gaps()]
        self.event_sink.emit(
            "runtime.blocked_by_configuration",
            engagement_id=self.engagement_id,
            campaign_id=self.campaign_id,
            payload={"node": str(node)[:120], "reason": detail[:300]},
        )
        return {
            "status": "blocked_by_configuration",
            "lifecycle_stage": "blocked_by_configuration",
            "node": str(node)[:120],
            "reason": detail[:300],
            "runtime_context_valid": False,
            "capability_gaps": gap_payload,
            "clean": False,
        }

    def require_capability(self, component: str, *, node: str) -> dict[str, Any]:
        """Return a typed blocked result when a named dependency is unavailable."""
        normalized = str(component or "").strip()
        gaps = [gap for gap in self.current_capability_gaps() if gap.component == normalized]
        if gaps:
            return self.blocked_result(
                node=node,
                reason=f"capability_gap:{normalized}",
            )
        return {
            "status": "capability_available",
            "node": str(node)[:120],
            "component": normalized[:120],
            "runtime_context_valid": self.valid,
            "clean": False,
        }

    def execute_registered_case(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        *,
        run_id: str,
    ) -> CaseResult:
        """Execute one declared target case through the versioned lifecycle runner.

        This is the runtime integration seam for case-level adapters. It never
        resolves a target from a URL, never falls back to a legacy executor, and
        returns a blocked result when the factory did not inject a registration.
        Adapter I/O remains owned by the registered lifecycle provider.
        """
        if not isinstance(case, CaseDefinition):
            raise TypeError("case_definition_required")
        if not isinstance(authorization, LifecycleAuthorization):
            raise TypeError("lifecycle_authorization_required")
        registration = self.target_adapter_registration
        if registration is None:
            return CaseResult(
                case_id=case.case_id,
                status="blocked",
                reason="target_adapter_registration_missing",
            )
        if not self.valid:
            return CaseResult(
                case_id=case.case_id,
                status="blocked",
                reason="runtime_context_invalid",
            )
        if authorization.engagement_id != self.engagement_id:
            return CaseResult(
                case_id=case.case_id,
                status="blocked",
                reason="engagement_identity_mismatch",
            )
        run_context = LifecycleRunContext(
            run_id=run_id,
            target_id=registration.target_id,
            case_id=case.case_id,
            engagement_id=self.engagement_id,
        )
        return GenericCaseRunner.execute_case(
            registration,
            case,
            authorization,
            run_context,
        )

    def run_agent_proposal(
        self,
        context: AgentRunContext,
        proposal: AgentProposal,
        handlers: Mapping[str, Callable[[Any], Any]],
        *,
        observed_preconditions: tuple[str, ...] = (),
        expected_package_digest: str | None = None,
    ) -> HarnessOutcome:
        """Run a governed proposal through the shared harness when explicitly available.

        This is an integration seam, not a second executor.  It fails closed when
        the runtime is invalid, the engagement differs, the package identity is
        not the expected one, or an action target is outside the compiled scope.
        """
        if self.agent_harness is None:
            return HarnessOutcome(
                status=HarnessStatus.BLOCKED,
                run_id=context.run_id,
                proposal_id=proposal.proposal_id,
                action_results=(),
                observations=(),
                blocked_reasons=("runtime:agent_harness_unavailable",),
                trace_id=context.trace_id,
            )
        if not self.valid:
            return HarnessOutcome(
                status=HarnessStatus.BLOCKED,
                run_id=context.run_id,
                proposal_id=proposal.proposal_id,
                action_results=(),
                observations=(),
                blocked_reasons=("runtime:context_invalid",),
                trace_id=context.trace_id,
            )
        if context.engagement_id != self.engagement_id:
            return HarnessOutcome(
                status=HarnessStatus.BLOCKED,
                run_id=context.run_id,
                proposal_id=proposal.proposal_id,
                action_results=(),
                observations=(),
                blocked_reasons=("runtime:engagement_mismatch",),
                trace_id=context.trace_id,
            )
        if (
            expected_package_digest is not None
            and context.package_digest != expected_package_digest
        ):
            return HarnessOutcome(
                status=HarnessStatus.BLOCKED,
                run_id=context.run_id,
                proposal_id=proposal.proposal_id,
                action_results=(),
                observations=(),
                blocked_reasons=("runtime:package_identity_mismatch",),
                trace_id=context.trace_id,
            )
        for action in proposal.proposed_actions:
            if not self.scope_matcher.allows(action.target_url, method=action.method):
                return HarnessOutcome(
                    status=HarnessStatus.BLOCKED,
                    run_id=context.run_id,
                    proposal_id=proposal.proposal_id,
                    action_results=(),
                    observations=(),
                    blocked_reasons=(f"runtime:target_scope_denied:{action.action_id}",),
                    trace_id=context.trace_id,
                )
        return self.agent_harness.run(
            context,
            proposal,
            handlers,
            observed_preconditions=observed_preconditions,
        )

    def diagnostics(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "campaign_id": self.campaign_id,
            "target_origin": self.target_origin,
            "valid": self.valid,
            "configuration_errors": list(self.configuration_errors),
            "capability_gaps": [gap.as_dict() for gap in self.current_capability_gaps()],
            "capabilities": self.capabilities.diagnostics(),
            "adapters": self.adapters.manifest(),
            "control_plane": (
                self.control_plane_runtime.descriptor()
                if self.control_plane_runtime is not None
                else None
            ),
            "event_count": len(self.event_sink.snapshot()),
            "agent_harness": (
                self.agent_harness.capability_registry.descriptor()
                if self.agent_harness is not None
                else None
            ),
        }


class RuntimeFactory:
    """Construct one explicit runtime spine for an engagement/campaign."""

    @staticmethod
    def _capability_gaps(
        *,
        adapters: AdapterRegistry,
        identity_tenant_object_graph: Any | None,
        workflow_state_machine: Any | None,
        replay_engine: Any | None,
    ) -> tuple[RuntimeCapabilityGap, ...]:
        gaps: list[RuntimeCapabilityGap] = []
        if identity_tenant_object_graph is None:
            gaps.append(
                RuntimeCapabilityGap(
                    code="identity_graph_unavailable",
                    component="identity_tenant_object_graph",
                    required_for="multi_identity_and_tenant_controls",
                    recovery_action="register an authorized identity graph provider",
                )
            )
        if workflow_state_machine is None:
            gaps.append(
                RuntimeCapabilityGap(
                    code="workflow_state_machine_unavailable",
                    component="workflow_state_machine",
                    required_for="stateful_auth_and_business_workflow_replay",
                    recovery_action="register a workflow state machine adapter",
                )
            )
        if replay_engine is None:
            gaps.append(
                RuntimeCapabilityGap(
                    code="replay_engine_unavailable",
                    component="replay_engine",
                    required_for="replayable_validation_and_proof",
                    recovery_action="register a policy-checked replay engine",
                )
            )
        if not adapters.manifest():
            gaps.append(
                RuntimeCapabilityGap(
                    code="tool_adapters_unavailable",
                    component="adapters",
                    required_for="network_browser_and_external_tool_actions",
                    recovery_action="register only policy-checked runtime adapters",
                )
            )
        return tuple(gaps)

    @staticmethod
    def _origin(value: str) -> str:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port
        default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
            parsed.scheme.lower() == "https" and port in {None, 443}
        )
        return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{'' if default else f':{port}'}"

    @classmethod
    def create(
        cls,
        *,
        engagement_id: str,
        campaign_id: str,
        target_origin: str,
        settings: Settings | None = None,
        manifest: dict[str, Any] | None = None,
        ledger: SQLiteActionLedger | None = None,
        use_default_ledger: bool = True,
        used_actions: int = 0,
        used_budget: float = 0.0,
        event_sink: RuntimeEventSink | None = None,
        adapters: AdapterRegistry | None = None,
        proof_bundle_store: Any | None = None,
        identity_tenant_object_graph: Any | None = None,
        workflow_state_machine: Any | None = None,
        replay_engine: Any | None = None,
        identity_provisioning_agent: Any | None = None,
        scope_runtime_handle: ScopeRuntimeHandle | None = None,
        raw_scope_entries: list[str] | tuple[str, ...] | None = None,
        enable_control_plane: bool = False,
        control_plane_profile_root: str | None = None,
        control_plane_browser_adapter: Any | None = None,
        target_package: Mapping[str, Any] | None = None,
        target_adapter_registry: TargetAdapterRegistry | None = None,
    ) -> RuntimeContext:
        settings = settings or get_settings()
        if scope_runtime_handle is None and raw_scope_entries:
            scope_runtime_handle = ScopeRuntimeHandle(
                compile_wildcard_scope([str(entry) for entry in raw_scope_entries])
            )
        normalized_engagement = str(engagement_id or "").strip()[:160]
        normalized_campaign = str(campaign_id or "").strip()[:160]
        normalized_origin = cls._origin(target_origin)
        errors: list[str] = []
        if not normalized_engagement:
            errors.append("identity:engagement_id_required")
        if not normalized_campaign:
            errors.append("identity:campaign_id_required")
        if not normalized_origin:
            errors.append("scope:valid_http_origin_required")

        try:
            scope_matcher = OriginPolicy.from_url(normalized_origin)
        except ValueError:
            errors.append("scope:origin_policy_invalid")
            scope_matcher = OriginPolicy.from_url("http://127.0.0.1")

        safety_gate = EngagementSafetyGate(
            engagement_id=normalized_engagement,
            allowed_origins=(normalized_origin,) if normalized_origin else (),
        )
        capability_registry = CapabilityRegistry(settings)
        if manifest is not None:
            capability_registry._manifest = dict(manifest)
        else:
            capability_registry.ensure_discovered()
        action_ledger = (
            ledger
            if ledger is not None
            else SQLiteActionLedger(settings.action_ledger_path)
            if use_default_ledger
            else None
        )
        sink = event_sink or RuntimeEventSink()
        registry = adapters or AdapterRegistry()
        package_scope_compiler = (
            ScopeCompiler.from_projection(dict(target_package))
            if target_package is not None
            else None
        )
        target_adapter_registration: RegisteredTargetAdapter | None = None
        if target_adapter_registry is not None:
            try:
                target_adapter_registration = target_adapter_registry.require_for_origin(
                    normalized_origin
                )
            except (TypeError, ValueError, RuntimeError) as exc:
                errors.append(
                    "target_adapter:registration_unavailable:"
                    f"{type(exc).__name__}"
                )
        authority = ActionAuthority(
            settings=settings,
            allowed_origin=normalized_origin,
            manifest=capability_registry.ensure_discovered(),
            used_actions=max(0, int(used_actions)),
            used_budget=max(0.0, float(used_budget)),
            ledger=action_ledger,
            adapter_registry=registry,
            require_g02=True,
            safety_gate=safety_gate,
            target_package=dict(target_package or {}),
            scope_compiler=package_scope_compiler,
        )
        bundle_store = proof_bundle_store if proof_bundle_store is not None else ProofBundleStore()
        executor = ActionExecutor(authority, proof_bundle_store=bundle_store)
        harness_capabilities = ToolCapabilityRegistry()
        for capability_name, side_effects, authorization, evidence, fallback, direct_io in (
            (
                "http_read",
                ("read_only",),
                "scope_and_action_authority",
                "observation",
                "blocked",
                True,
            ),
            (
                "browser_read",
                ("read_only",),
                "scope_and_action_authority",
                "observation",
                "blocked",
                True,
            ),
            (
                "browser_action",
                ("state_change",),
                "scope_and_human_approval",
                "observation",
                "awaiting_confirmation",
                True,
            ),
            ("recon", ("read_only",), "scope_and_action_authority", "observation", "blocked", True),
            (
                "validation",
                ("read_only",),
                "scope_and_proof_contract",
                "validation_observation",
                "inconclusive",
                True,
            ),
        ):
            try:
                harness_capabilities.register(
                    ToolCapability(
                        name=capability_name,
                        input_schema={"type": "object"},
                        allowed_side_effects=side_effects,
                        required_authorization=authorization,
                        budget_class="engagement_action_budget",
                        evidence_output=evidence,
                        safe_fallback=fallback,
                        direct_io=direct_io,
                    )
                )
            except ValueError:
                # A duplicate is impossible in the local tuple; keep runtime
                # creation fail-closed if a future extension is malformed.
                errors.append(f"harness:capability_registration_failed:{capability_name}")
        harness = HarnessRunner(executor, harness_capabilities, event_sink=sink)
        control_plane_runtime = None
        engagement_scope = None
        if enable_control_plane and normalized_origin and not errors:
            try:
                from datetime import timedelta

                from webpent.shared.control_plane import compile_scope
                from webpent.shared.control_plane_spine import (
                    build_control_plane_runtime,
                )

                parsed_origin = urlsplit(normalized_origin)
                origin_port = parsed_origin.port or (
                    443 if parsed_origin.scheme.lower() == "https" else 80
                )
                control_scope = compile_scope(
                    engagement_id=normalized_engagement,
                    root_domains=(normalized_origin,),
                    created_by="runtime-bootstrap",
                    approval_source="runtime-bootstrap",
                    expires_at=datetime.now(UTC) + timedelta(hours=1),
                    allowed_schemes=(parsed_origin.scheme.lower(),),
                    allowed_ports=(origin_port,),
                    path_rules=("/",),
                )
                engagement_scope = control_scope
                control_plane_runtime = build_control_plane_runtime(
                    engagement_id=normalized_engagement,
                    scope=control_scope,
                    executor=executor,
                    profile_root=control_plane_profile_root
                    or str(Path(settings.action_ledger_path).parent / "browser_profiles"),
                )
                identity_tenant_object_graph = control_plane_runtime.identity_graph
                workflow_state_machine = control_plane_runtime.workflow_state_machine
                replay_engine = control_plane_runtime.replay_engine
            except (ImportError, OSError, TypeError, ValueError) as exc:
                errors.append(f"control_plane:bootstrap_failed:{type(exc).__name__}")
        if control_plane_browser_adapter is not None:
            if control_plane_runtime is None:
                errors.append("control_plane:browser_adapter_requires_bootstrap")
            else:
                try:
                    register_control_plane_browser_adapter(
                        registry,
                        control_plane_browser_adapter,
                    )
                except RuntimeConfigurationError as exc:
                    errors.append(
                        f"control_plane:browser_adapter_registration_failed:{str(exc)[:160]}"
                    )
        capability_gaps = cls._capability_gaps(
            adapters=registry,
            identity_tenant_object_graph=identity_tenant_object_graph,
            workflow_state_machine=workflow_state_machine,
            replay_engine=replay_engine,
        )
        sink.emit(
            "runtime.created",
            engagement_id=normalized_engagement,
            campaign_id=normalized_campaign,
            payload={"target_origin": normalized_origin},
        )
        campaign_action_engine = NextBestActionEngine()
        return RuntimeContext(
            schema_version="runtime-context-v1",
            engagement_id=normalized_engagement,
            campaign_id=normalized_campaign,
            target_origin=normalized_origin,
            settings=settings,
            action_authority=authority,
            action_executor=executor,
            scope_matcher=scope_matcher,
            capabilities=capability_registry,
            adapters=registry,
            event_sink=sink,
            proof_bundle_store=bundle_store,
            oracle_engine=OracleEngine(),
            negative_control_engine=NegativeControlEngine(),
            coverage_ledger={},
            identity_tenant_object_graph=identity_tenant_object_graph,
            workflow_state_machine=workflow_state_machine,
            replay_engine=replay_engine,
            knowledge_gap_engine=KnowledgeGapEngine(),
            next_best_action_engine=SmartNextBestActionEngine(),
            configuration_errors=tuple(dict.fromkeys(errors)),
            capability_gaps=capability_gaps,
            control_plane_runtime=control_plane_runtime,
            control_plane_browser_adapter=(
                control_plane_browser_adapter
                if control_plane_runtime is not None
                else None
            ),
            campaign_next_best_action_engine=campaign_action_engine,
            safety_gate=safety_gate,
            identity_provisioning_agent=identity_provisioning_agent,
            engagement_scope=engagement_scope,
            scope_runtime_handle=scope_runtime_handle,
            agent_harness=harness,
            target_adapter_registration=target_adapter_registration,
        )

    @staticmethod
    def descriptor(context: RuntimeContext) -> dict[str, Any]:
        """Return a checkpoint-safe descriptor, never live handlers or transports."""
        settings = context.settings
        return {
            "schema_version": context.schema_version,
            "engagement_id": context.engagement_id,
            "campaign_id": context.campaign_id,
            "target_origin": context.target_origin,
            "target_package": dict(context.action_authority.target_package),
            "scan_mode": str(getattr(settings.scan_mode, "value", settings.scan_mode)),
            "action_ledger_path": str(settings.action_ledger_path),
            "smart_max_actions": int(settings.smart_max_actions),
            "smart_action_budget": float(settings.smart_action_budget),
            "used_actions": int(context.action_authority.used_actions),
            "used_budget": float(context.action_authority.used_budget),
            "capability_gaps": [gap.as_dict() for gap in context.current_capability_gaps()],
            "manifest": context.capabilities.ensure_discovered(),
            "control_plane_enabled": context.control_plane_runtime is not None,
            "safety_gate_enabled": context.safety_gate is not None,
            "scope_projection": (
                context.scope_runtime_handle.as_dict()
                if context.scope_runtime_handle is not None
                else None
            ),
            "kill_switch_tripped": bool(
                context.safety_gate is not None and context.safety_gate.kill_switch.tripped
            ),
            "agent_harness_enabled": context.agent_harness is not None,
            "target_adapter": (
                {
                    "target_id": context.target_adapter_registration.target_id,
                    "target_origin": str(
                        context.target_adapter_registration.adapter.target_origin
                    ).strip(),
                    "source": context.target_adapter_registration.source,
                    "version": context.target_adapter_registration.version,
                    "policy_ref": context.target_adapter_registration.policy_ref,
                    "proof_contract": context.target_adapter_registration.proof_contract,
                }
                if context.target_adapter_registration is not None
                else None
            ),
            "kill_switch_reason": (
                context.safety_gate.kill_switch.reason if context.safety_gate is not None else ""
            ),
        }

    @classmethod
    def from_descriptor(
        cls,
        descriptor: Mapping[str, Any],
        *,
        target_adapter_registry: TargetAdapterRegistry | None = None,
    ) -> RuntimeContext | None:
        """Rebuild a live context from a redacted checkpoint descriptor."""
        if not isinstance(descriptor, Mapping):
            return None
        try:
            settings = get_settings()
            updates: dict[str, Any] = {}
            for key in (
                "scan_mode",
                "action_ledger_path",
                "smart_max_actions",
                "smart_action_budget",
            ):
                if key in descriptor and descriptor[key] not in (None, ""):
                    updates[key] = descriptor[key]
            if updates:
                settings = settings.model_copy(update=updates)
            manifest = descriptor.get("manifest")
            target_adapter_descriptor = descriptor.get("target_adapter")
            if target_adapter_descriptor is not None and not isinstance(
                target_adapter_descriptor, Mapping
            ):
                return None
            if (
                isinstance(target_adapter_descriptor, Mapping)
                and target_adapter_registry is None
            ):
                # A target-aware checkpoint must not silently degrade into a
                # generic context with no proof workflows after restoration.
                return None
            scope_runtime_handle = None
            scope_projection = descriptor.get("scope_projection")
            if isinstance(scope_projection, Mapping):
                raw_entries = scope_projection.get("raw_entries")
                if isinstance(raw_entries, (list, tuple)) and raw_entries:
                    scope_runtime_handle = ScopeRuntimeHandle(
                        compile_wildcard_scope([str(entry) for entry in raw_entries])
                    )
            context = cls.create(
                engagement_id=str(descriptor.get("engagement_id") or ""),
                campaign_id=str(descriptor.get("campaign_id") or ""),
                target_origin=str(descriptor.get("target_origin") or ""),
                settings=settings,
                manifest=dict(manifest) if isinstance(manifest, Mapping) else None,
                used_actions=int(descriptor.get("used_actions") or 0),
                used_budget=float(descriptor.get("used_budget") or 0.0),
                scope_runtime_handle=scope_runtime_handle,
                enable_control_plane=bool(descriptor.get("control_plane_enabled", False)),
                target_package=(
                    dict(descriptor.get("target_package"))
                    if isinstance(descriptor.get("target_package"), Mapping)
                    else None
                ),
                target_adapter_registry=target_adapter_registry,
            )
            if isinstance(target_adapter_descriptor, Mapping):
                expected_target_id = str(
                    target_adapter_descriptor.get("target_id") or ""
                ).strip()
                registration = context.target_adapter_registration
                if (
                    not expected_target_id
                    or registration is None
                    or registration.target_id != expected_target_id
                ):
                    return None
            if context.safety_gate is not None and descriptor.get("kill_switch_tripped"):
                context.safety_gate.kill_switch.trip(
                    str(descriptor.get("kill_switch_reason") or "checkpoint_stop")
                )
            return context
        except (TypeError, ValueError, OSError):
            return None

    @staticmethod
    def blocked_result(*, node: str, reason: str) -> dict[str, Any]:
        return {
            "status": "blocked_by_configuration",
            "lifecycle_stage": "blocked_by_configuration",
            "node": str(node)[:120],
            "reason": str(reason or "runtime_context_unavailable")[:300],
            "runtime_context_valid": False,
            "clean": False,
        }


def register_control_plane_browser_adapter(
    registry: AdapterRegistry,
    adapter: Any,
    *,
    source: str = "control_plane_runtime",
    version: str = "1",
    expires_at: str | None = None,
) -> None:
    """Register one explicitly injected browser adapter, never a raw handler.

    The adapter is a typed policy boundary around a caller-owned handler. The
    handler remains in memory only; descriptors expose metadata, not the live
    callable. No adapter is created when the caller provides nothing.
    """
    from webpent.shared.control_plane_runtime import BrowserActionAdapter

    if not isinstance(adapter, BrowserActionAdapter):
        raise RuntimeConfigurationError("control_plane_browser:typed_adapter_required")
    approval_expiry = expires_at or (datetime.now(UTC) + timedelta(hours=1)).date().isoformat()
    registration = RegisteredAdapter(
        name=CONTROL_PLANE_BROWSER_ADAPTER_NAME,
        capability="browser_action",
        transport="injected_browser_handler",
        handler=adapter.execute,
        source=str(source or "control_plane_runtime")[:160],
        version=str(version or "1")[:80],
        policy_checked=True,
        canonical_wrapper=CONTROL_PLANE_BROWSER_CANONICAL_WRAPPER,
        scope_policy=CONTROL_PLANE_BROWSER_SCOPE_POLICY,
        static_inventory_ref=CONTROL_PLANE_BROWSER_INVENTORY_REF,
        proof_contract=CONTROL_PLANE_BROWSER_PROOF_CONTRACT,
        expires_at=approval_expiry,
    )
    errors = registration.g02_errors()
    if errors:
        raise RuntimeConfigurationError(";".join(errors))
    registry.register(registration)


__all__ = [
    "AdapterRegistry",
    "RegisteredAdapter",
    "CONTROL_PLANE_BROWSER_ADAPTER_NAME",
    "CONTROL_PLANE_BROWSER_CANONICAL_WRAPPER",
    "CONTROL_PLANE_BROWSER_SCOPE_POLICY",
    "CONTROL_PLANE_BROWSER_INVENTORY_REF",
    "CONTROL_PLANE_BROWSER_PROOF_CONTRACT",
    "register_control_plane_browser_adapter",
    "RuntimeCapabilityGap",
    "RuntimeConfigurationError",
    "RuntimeContext",
    "RuntimeEvent",
    "RuntimeEventSink",
    "RuntimeFactory",
]
