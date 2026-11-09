"""Shared initial-state construction for WebPent engagements.

The CLI and Celery worker are different entry points, but they must start an
engagement with the same state contract.  This module owns the common empty
containers and keeps entry-point-specific values (for example Playwright
availability and stealth mode) explicit.

The factory is intentionally deterministic and does not perform network I/O,
load credentials from disk, or print operator-supplied values.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from webpent.config.settings import (
    ScanMode,
    ScanProfile,
    deployment_requires_proof_bundle,
    get_settings,
    profile_requires_proof_bundle,
    resolve_scan_profile,
)
from webpent.shared.bbscout_bridge import (
    BbscoutPackageAdmission,
    enforce_bbscout_allowlist,
    load_bbscout_package,
)
from webpent.shared.campaign_planner import build_campaign_plan
from webpent.shared.campaigns import build_generic_campaign_ledger
from webpent.shared.capability_manifest import build_capability_manifest
from webpent.shared.runtime import RuntimeFactory
from webpent.shared.target_adapters import (
    CampaignProfileSpec,
    TargetAdapterRegistry,
    campaign_profile_for_registration,
)
from webpent.shared.target_package_context import (
    TargetPackageContext,
    admit_target_package,
)

if TYPE_CHECKING:
    from webpent.models.targets import Target


def _profile_enables_autonomous_controller(profile: ScanProfile) -> bool:
    """Enable the bounded controller for active Smart profiles only.

    Legacy and observe-only profiles retain their historical behavior.  The
    controller remains bounded by the persisted action/replan budgets and the
    runtime ActionExecutor authority checks; this resolver only removes the
    accidental caller-side opt-in requirement for Smart execution profiles.
    """
    return profile in {
        ScanProfile.SMART,
        ScanProfile.AUTHORIZED_ACTIVE,
        ScanProfile.VIP_QUALIFICATION,
    }


def _root_goal_nodes() -> dict[str, Any]:
    """Create the engagement root goal without making startup fatal.

    Goal-tree creation is additive.  A failure must not prevent a legacy scan
    from starting; the Rabbit Hole layer already has a bounded fallback for an
    empty goal tree.
    """
    try:
        from webpent.models.goal_tree import create_root_goal

        root = create_root_goal()
        return {root.id: root.model_dump(mode="json")}
    except Exception:
        return {}


def build_initial_state(
    target: Target,
    *,
    thread_id: str | None = None,
    additional_target_origins: list[str] | None = None,
    owner_username: str | None = None,
    client_id: str | None = None,
    engagement_id: str | None = None,
    campaign_id: str | None = None,
    credentials: dict[str, str] | None = None,
    session_cookies: dict[str, str] | None = None,
    session_headers: dict[str, str] | None = None,
    identity_profiles: dict[str, Any] | None = None,
    jwt_weak_secret_candidates: list[str] | None = None,
    jwt_public_key_available: bool = False,
    disclosed_report_corpus: list[Any] | None = None,
    llm_override: bool | None = None,
    custom_payloads: list[str] | None = None,
    report_formats: list[str] | None = None,
    playwright_enabled: bool = True,
    skip_recon: bool = False,
    stealth_mode: bool = False,
    auto_approve: bool = False,
    enable_autonomous_controller: bool | None = None,
    scan_mode: str | ScanMode | None = None,
    profile: str | ScanProfile | None = None,
    root_goal_nodes: dict[str, Any] | None = None,
    action_ledger_path: str | None = None,
    campaign_inventory: str = "auto",
    enable_control_plane: bool = True,
    control_plane_profile_root: str | None = None,
    raw_scope_entries: list[str] | None = None,
    scope_source: str = "inferred_from_url",
    scope_declaration: dict[str, Any] | None = None,
    target_package: dict[str, Any] | None = None,
    target_package_context: TargetPackageContext | None = None,
    target_package_binding: Mapping[str, Any] | None = None,
    target_adapter_registry: TargetAdapterRegistry | None = None,
    campaign_profile: CampaignProfileSpec | None = None,
) -> dict[str, Any]:
    """Build a complete, redaction-safe starting state for one engagement.

    All mutable inputs are copied so the CLI/API caller cannot accidentally
    mutate LangGraph state after invocation.  The function only initializes
    state; authentication, crawling, tools, LLM calls, and PoC execution stay
    in their dedicated graph nodes.
    """
    resolved_engagement_id = str(engagement_id or thread_id or "").strip() or None
    resolved_owner_username = str(owner_username or "").strip() or None
    resolved_client_id = str(client_id or "").strip() or None
    target_url = target.url if hasattr(target, "url") else str(target.get("url", ""))
    settings = get_settings()
    if action_ledger_path:
        settings = settings.model_copy(
            update={"action_ledger_path": Path(action_ledger_path).expanduser()}
        )
    bbscout_admission: BbscoutPackageAdmission | None = None
    if settings.bbscout_enabled:
        package_path = str(settings.bbscout_package_path or "").strip()
        if not package_path:
            raise ValueError("bbscout_package_path_required")
        bbscout_admission = enforce_bbscout_allowlist(
            load_bbscout_package(
                package_path,
                mode=settings.bbscout_mode,
            ),
            provider_ids=settings.bbscout_allowed_provider_ids,
            program_ids=settings.bbscout_allowed_program_ids,
        )
    if target_package is not None and target_package_context is not None:
        raise ValueError(
            "raw target_package and admitted target_package_context are mutually exclusive"
        )
    admitted_package_context = target_package_context or (
        admit_target_package(target_package) if target_package is not None else None
    )
    binding_projection = dict(target_package_binding or {})
    if admitted_package_context is None and binding_projection:
        raise ValueError("target_package_binding requires an admitted target package context")
    # A raw package remains supported for legacy projection-only callers. It is
    # not an executable package-backed engagement because no lease binding was
    # created. The executable entrypoints pass an already-admitted context and
    # therefore must provide the durable binding below.
    binding_required = target_package_context is not None
    if binding_required and admitted_package_context is not None:
        required_binding = {
            "engagement_id": str(resolved_engagement_id or ""),
            "package_id": admitted_package_context.package_id,
            "package_sha256": admitted_package_context.package_sha256,
            "scope_digest": admitted_package_context.scope_digest,
            "policy_digest": admitted_package_context.policy_digest,
        }
        for key, expected in required_binding.items():
            if str(binding_projection.get(key) or "") != expected:
                raise ValueError(f"target_package_binding_{key}_mismatch")
        if binding_required and not str(binding_projection.get("lease_id") or ""):
            raise ValueError("target_package_binding_lease_missing")
    requested_inventory = str(campaign_inventory or "auto").strip().lower() or "auto"
    if campaign_profile is not None and not isinstance(campaign_profile, CampaignProfileSpec):
        raise ValueError("campaign_profile_invalid")
    resolved_scan_mode = settings.scan_mode
    if profile is not None:
        resolved_profile, resolved_scan_mode = resolve_scan_profile(profile)
        settings = settings.model_copy(update={"scan_mode": resolved_scan_mode})
    else:
        if scan_mode is not None:
            resolved_scan_mode = ScanMode(str(getattr(scan_mode, "value", scan_mode)))
            settings = settings.model_copy(update={"scan_mode": resolved_scan_mode})
        resolved_profile = {
            ScanMode.LEGACY: ScanProfile.LEGACY,
            ScanMode.SAFE_SMART: ScanProfile.SMART_OBSERVE,
            ScanMode.AUTHORIZED_ACTIVE: ScanProfile.AUTHORIZED_ACTIVE,
        }[resolved_scan_mode]
    vip_proof_required = profile_requires_proof_bundle(resolved_profile)
    deployment_proof_required = deployment_requires_proof_bundle(settings.environment_profile)
    proof_required = vip_proof_required or deployment_proof_required
    capability_manifest = build_capability_manifest(settings)
    resolved_campaign_id = (
        str(campaign_id or f"{resolved_engagement_id or 'engagement'}:main").strip()
        or "engagement:main"
    )
    control_plane_browser_adapter = None
    target_adapter_registration = None
    target_adapter_workflow_configured = True
    if target_adapter_registry is not None:
        target_adapter_registration = target_adapter_registry.for_origin(target_url)
        if target_adapter_registration is not None:
            try:
                target_adapter_registry.require_live_for_origin(target_url)
            except ValueError:
                target_adapter_workflow_configured = False
    semantic_profile_registry = None
    workflow_allowlist: tuple[str, ...] = ()
    workflow_executors: Mapping[str, Any] = {}
    if target_adapter_registration is not None:
        try:
            semantic_profile_registry = target_adapter_registration.adapter.semantic_profiles
            workflow_allowlist = tuple(target_adapter_registration.adapter.workflow_ids())
            workflow_executors = dict(target_adapter_registration.adapter.workflow_executors())
        except Exception:
            # A registration was validated during lookup, but its injected
            # provider may still be mutable or fail at bootstrap. Keep the
            # browser adapter unavailable rather than letting a provider
            # exception escape or falling back to an unbound workflow.
            semantic_profile_registry = None
            workflow_allowlist = ()
            workflow_executors = {}
            target_adapter_workflow_configured = False
    browser_capability = (capability_manifest.get("capabilities") or {}).get("browser") or {}
    browser_preflight_ok = browser_capability.get("available") is True
    if (
        bool(enable_control_plane)
        and bool(playwright_enabled)
        and bool(settings.playwright_adapter_enabled)
        and browser_preflight_ok
        and target_adapter_workflow_configured
    ):
        try:
            from webpent.shared.control_plane_runtime import BrowserActionAdapter
            from webpent.shared.playwright_adapter import (
                EphemeralProbeStore,
                PlaywrightBrowserHandler,
            )

            probe_store = EphemeralProbeStore()
            control_plane_browser_adapter = BrowserActionAdapter(
                PlaywrightBrowserHandler(
                    target_origin=target_url,
                    engagement_id=resolved_engagement_id or "",
                    profile_root=(
                        control_plane_profile_root
                        or str(Path(settings.action_ledger_path).parent / "browser_profiles")
                    ),
                    browser_timeout_ms=settings.playwright_browser_timeout_ms,
                    probe_resolver=probe_store.resolve,
                    semantic_profile_registry=semantic_profile_registry,
                    workflow_allowlist=workflow_allowlist,
                    workflow_executors=workflow_executors,
                ),
                probe_registrar=probe_store.put,
                probe_cleaner=probe_store.clear,
            )
        except (ImportError, OSError, TypeError, ValueError):
            # Keep startup fail-closed: an explicitly requested adapter that
            # cannot be constructed remains unavailable and is visible through
            # the runtime capability gap rather than becoming a raw handler.
            control_plane_browser_adapter = None
    registration_profile = campaign_profile_for_registration(target_adapter_registration)
    if requested_inventory in {"auto", "generic"}:
        resolved_campaign_profile = campaign_profile
        resolved_inventory = (
            campaign_profile.profile_id if campaign_profile is not None else "generic"
        )
    else:
        resolved_campaign_profile = campaign_profile or registration_profile
        if resolved_campaign_profile is None:
            raise ValueError("campaign_inventory_requires_explicit_registered_profile")
        if resolved_campaign_profile.profile_id.strip().lower() != requested_inventory:
            raise ValueError("campaign_inventory_profile_mismatch")
        resolved_inventory = resolved_campaign_profile.profile_id

    runtime_context = RuntimeFactory.create(
        engagement_id=resolved_engagement_id or "",
        campaign_id=resolved_campaign_id,
        target_origin=target_url,
        settings=settings,
        manifest=capability_manifest,
        enable_control_plane=bool(enable_control_plane),
        control_plane_profile_root=control_plane_profile_root,
        control_plane_browser_adapter=control_plane_browser_adapter,
        raw_scope_entries=list(raw_scope_entries or []),
        target_package=(
            admitted_package_context.as_state() if admitted_package_context is not None else None
        ),
        target_adapter_registry=target_adapter_registry,
    )
    scan_mode_value = getattr(resolved_scan_mode, "value", resolved_scan_mode)
    profile_value = getattr(resolved_profile, "value", resolved_profile)
    governance_profile = profile_value if profile is not None else str(scan_mode_value)
    controller_enabled = (
        bool(enable_autonomous_controller)
        if enable_autonomous_controller is not None
        else _profile_enables_autonomous_controller(resolved_profile)
    )
    normalized_payloads = [
        str(item).strip() for item in list(custom_payloads or []) if str(item).strip()
    ]
    normalized_formats = [
        str(item).strip().lower() for item in list(report_formats or []) if str(item).strip()
    ]
    normalized_origins = [
        str(item).strip() for item in list(additional_target_origins or []) if str(item).strip()
    ]

    # POST-P0 Phase 3: lab-profile-only defaults for the authorization
    # matrix / bounded IDOR enumeration. Production defaults stay safe
    # (settings flags remain False; qualification/staging/production
    # never receive these keys). Only an explicit ACTIVE profile on a
    # dev/lab environment flips the STATE defaults; the access_control
    # state-key override and settings flags keep their precedence
    # semantics for every other case.
    lab_authz_defaults: dict[str, bool] = {}
    try:
        _env_value = getattr(
            settings.environment_profile, "value", settings.environment_profile
        )
        if (
            resolved_profile
            in (ScanProfile.AUTHORIZED_ACTIVE, ScanProfile.VIP_QUALIFICATION)
            and str(_env_value).strip().lower() in {"dev", "lab"}
        ):
            lab_authz_defaults = {
                "enable_authorization_matrix": True,
                "enable_idor_enumeration": True,
            }
    except Exception:
        lab_authz_defaults = {}

    return {
        **lab_authz_defaults,
        "target": target,
        "target_package": (
            admitted_package_context.as_state() if admitted_package_context is not None else {}
        ),
        "target_package_status": (
            "ready" if admitted_package_context is not None else "not_provided"
        ),
        "target_package_id": (
            admitted_package_context.package_id if admitted_package_context is not None else None
        ),
        "target_package_sha256": (
            admitted_package_context.package_sha256
            if admitted_package_context is not None
            else None
        ),
        "target_package_scope_digest": (
            admitted_package_context.scope_digest if admitted_package_context is not None else None
        ),
        "target_package_policy_digest": (
            admitted_package_context.policy_digest if admitted_package_context is not None else None
        ),
        "target_package_capability_digest": (
            admitted_package_context.capability_digest
            if admitted_package_context is not None
            else None
        ),
        "target_package_authorization": (
            {
                "expires_at": admitted_package_context.expires_at,
                "revocation_state": admitted_package_context.revocation_state,
                "user_confirmed": True,
            }
            if admitted_package_context is not None
            else {}
        ),
        "target_package_preflight_status": (
            "not_requested" if admitted_package_context is not None else "not_provided"
        ),
        "target_package_capability_matrix": {},
        "target_package_knowledge_gaps": [],
        "target_package_blocked_tasks": [],
        "target_package_binding": binding_projection,
        "bbscout_advisory": (
            bbscout_admission.as_state()["bbscout"] if bbscout_admission is not None else {}
        ),
        "additional_target_origins": normalized_origins,
        "messages": [],
        "findings": [],
        "current_phase": "init",
        "hypotheses": [],
        "lessons": [],
        "payloads_to_test": ({"custom": normalized_payloads} if normalized_payloads else {}),
        "custom_payloads": normalized_payloads,
        "crawled_data": {},
        "auth_state": {},
        "optimization_retries": {},
        "errors": [],
        "credentials": dict(credentials or {}),
        "session_cookies": dict(session_cookies or {}),
        "session_headers": dict(session_headers or {}),
        "identity_profiles": dict(identity_profiles or {}),
        "raw_scope_entries": list(raw_scope_entries or []),
        "compiled_scope": {},
        "scope_compile_status": "not_requested",
        "scope_compile_error": "",
        "scope_source": str(scope_source or "inferred_from_url"),
        "scope_declaration": dict(scope_declaration or {}),
        "pre_auth_snapshot": {},
        "auth_surface_diff": {},
        "authentication_status": "",
        "engagement_limitations": [],
        "signup_forms_detected": [],
        "signup_submissions": [],
        "verification_material_events": [],
        "identity_records": {},
        "identity_provisioning_status": "disabled",
        "secret_refs": {
            **(
                {"credentials": f"vault://{resolved_engagement_id}/credentials"}
                if credentials and resolved_engagement_id
                else {}
            ),
            **(
                {"session_cookies": f"vault://{resolved_engagement_id}/session_cookies"}
                if session_cookies and resolved_engagement_id
                else {}
            ),
            **(
                {"identity_profiles": f"vault://{resolved_engagement_id}/identity_profiles"}
                if identity_profiles and resolved_engagement_id
                else {}
            ),
        },
        "bac_observations": [],
        "bac_coverage_gaps": [],
        "relational_evidence": [],
        "authorization_matrix": {},
        "subdomain_takeover_observations": [],
        "subdomain_takeover_coverage_gaps": [],
        "cloud_storage_observations": [],
        "cloud_storage_coverage_gaps": [],
        "jwt_weak_secret_candidates": list(jwt_weak_secret_candidates or []),
        "jwt_public_key_available": bool(jwt_public_key_available),
        "jwt_deep_observations": [],
        "jwt_deep_coverage_gaps": [],
        "disclosed_report_corpus": list(disclosed_report_corpus or []),
        "disclosed_report_advisories": [],
        "advisory_coverage_gaps": [],
        "workflow_observations": [],
        "workflow_coverage_gaps": [],
        "javascript_intelligence": {},
        "js_targeted_tasks": [],
        "surface_security": {},
        "canonical_executions": [],
        "canonical_observations": [],
        "target_understanding": {},
        "target_knowledge": {},
        "security_reasoning_proposals": [],
        "attack_graph": {},
        "report_quality_gate": {},
        "memory_summary": {},
        "memory_feedback": [],
        "adaptive_revisit_tasks": {},
        "adaptive_revisit_ledger": {},
        "adaptive_hunt": {},
        "planner_decision": {},
        "planner_gate_audits": [],
        "execution_gate": {},
        "executive_summary": "",
        "risk_score": "",
        "playwright_enabled": bool(playwright_enabled),
        "playwright_adapter_requested": bool(settings.playwright_adapter_enabled),
        "playwright_adapter_active": bool(control_plane_browser_adapter is not None),
        "stealth_mode": bool(stealth_mode),
        "stealth_telemetry": {},
        "llm_enabled_override": llm_override,
        "llm_usage_trace": [],
        "report_formats": normalized_formats,
        "auto_approve": bool(auto_approve),
        "enable_autonomous_controller": controller_enabled,
        "autonomous_controller_runs": 0,
        "skip_recon": bool(skip_recon),
        "scan_mode": str(scan_mode_value),
        "profile": str(profile_value),
        "capability_manifest": capability_manifest,
        "smart_governance": {
            "profile": str(governance_profile),
            "public_profile": str(profile_value),
            "authority_mode": str(scan_mode_value),
            "fail_closed": True,
            "auto_approve_requested": bool(auto_approve),
            "smart_auto_approve": bool(settings.smart_auto_approve),
            "require_idempotency": bool(settings.smart_require_idempotency or proof_required),
            "require_proof_bundle": bool(settings.smart_require_proof_bundle or proof_required),
        },
        "action_ledger_path": action_ledger_path,
        "action_budget": {
            "limit": float(settings.smart_action_budget),
            "spent": 0.0,
            "remaining": float(settings.smart_action_budget),
            "iterations_limit": min(10, int(settings.smart_max_replan_rounds or 3)),
            "iterations": 0,
            "replans_limit": min(10, int(settings.smart_max_replan_rounds or 2)),
            "replans": 0,
            # Legacy aliases remain for existing nodes/readers.
            "max_actions": int(settings.smart_max_actions),
            "used_actions": 0,
            "max_cost": float(settings.smart_action_budget),
            "used_cost": 0.0,
            "status": "active",
            "stop_reason": "",
        },
        "autonomous_cycle_records": [],
        "stop_decision": {
            "should_stop": False,
            "reason": "",
            "category": "normal",
            "safe_to_resume": True,
        },
        "research_loop_contract": {
            "version": "1",
            "status": "not_started",
            "target_knowledge_fingerprint": "",
            "last_outcome_class": "",
            "llm_advisory_only": True,
            "proof_authority": "validator_only",
        },
        "mental_model": {"nodes": {}, "edges": []},
        # POST-P0 Phase 2: retrieved-only learned-strategy record
        # (advisory; never confirmation evidence). Empty until a
        # fail-closed scoped retrieval produces it.
        "learned_strategy": {},
        # POST-P0 Phase 3: session liveness record (redacted by
        # construction — statuses/counters only, never cookie values).
        "session_liveness": {
            "schema_version": "session-liveness-v1",
            "status": "unknown",
            "last_verified_at": None,
            "last_probe_reason": "",
            "reauth_attempts": 0,
            "max_reauth_attempts": 2,
            "downgrade_requested": False,
        },
        "goal_tree": {
            "nodes": dict(_root_goal_nodes() if root_goal_nodes is None else root_goal_nodes)
        },
        "decision_log": [],
        "decision_trace": [],
        "lifecycle_events": [],
        "rabbit_hole_ledger": {},
        "coverage_ledger": {},
        "campaign_inventory": resolved_inventory,
        "campaign_id": resolved_campaign_id,
        "runtime_context": runtime_context,
        "runtime_capability_gaps": [gap.as_dict() for gap in runtime_context.capability_gaps],
        "control_plane_descriptor": (
            runtime_context.control_plane_runtime.descriptor()
            if runtime_context.control_plane_runtime is not None
            else None
        ),
        "campaign_ledger": (
            resolved_campaign_profile.ledger_builder()
            if resolved_campaign_profile is not None
            else build_generic_campaign_ledger()
        ),
        "campaign_profile": (
            resolved_campaign_profile.descriptor()
            if resolved_campaign_profile is not None
            else None
        ),
        "campaign_plan": build_campaign_plan(
            target_url=target_url,
            campaign_inventory=resolved_inventory,
            campaign_profile=resolved_campaign_profile,
        ),
        "evidence_ledger": [],
        "positive_evidence_ledger": [],
        "negative_evidence_ledger": [],
        "proof_gap_assessments": [],
        "proof_plan": {},
        "proof_observability": {},
        "proof_outcomes": [],
        "proof_bundles": [],
        "campaign_task_outcomes": [],
        "smart_next_actions": [],
        "smart_http_observations": [],
        "research_round_artifacts": {},
        "recovery_events": [],
        "recovery_state": {
            "status": "not_started",
            "attempts": 0,
            "max_attempts": 2,
            "last_failure_class": "",
        },
        "smart_replanning": {
            "round": 0,
            # TEAM-1 Phase 5 (P0 state-contract repair): the graph router
            # (graph/builder.py route_after_smart_campaigns_execution) and the
            # smart-campaigns executor (agents/smart_campaigns/agent.py) both
            # read/write the budget under the key ``max_replan_rounds``. The
            # previous ``max_rounds`` key was a dead alias no reader ever
            # consumed, so the persisted budget was invisible to the router
            # before the first executor pass. Both keys are now written for
            # one release so older in-flight checkpoints resume correctly;
            # the canonical key is ``max_replan_rounds``.
            "max_replan_rounds": int(settings.smart_max_replan_rounds),
            "max_rounds": int(settings.smart_max_replan_rounds),
            "status": "not_started",
        },
        "rabbit_hole_loop_back_count": 0,
        # TEAM-1 Phase 6: bounded post-validation replan counters.
        "post_validation_replan_count": 0,
        "post_validation_replan_evidence_count": 0,
        **({"thread_id": thread_id} if thread_id is not None else {}),
        **({"owner_username": resolved_owner_username} if resolved_owner_username else {}),
        **({"client_id": resolved_client_id} if resolved_client_id else {}),
        **({"engagement_id": resolved_engagement_id} if resolved_engagement_id else {}),
    }
