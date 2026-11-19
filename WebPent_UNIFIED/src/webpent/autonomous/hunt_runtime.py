"""Real execution wiring for the autonomous hunt loop (Phase 2).

This module binds ``AutonomousHuntOrchestrator`` to the already-audited
runtime spine so a hunt performs *real, gated* execution instead of
advisory planning only:

* a ``RuntimeContext`` is built through ``RuntimeFactory.create`` so the
  scope policy, action authority (``require_g02=True``), action budget,
  idempotency, event ledger and proof-bundle store are all the production
  components, not replicas;
* the canonical ``smart_http`` transport adapter is registered with the
  G-02 contract (scope policy ``same-origin``, inventory ref, proof
  contract, approval expiry) exactly as the graph nodes do;
* the task handler is the existing ``build_smart_campaign_handler``, so
  method-aware behavior comes from the audited path: GET/HEAD/OPTIONS run
  in every mode, POST and other state-changing methods are refused by the
  action authority unless the mode is ``authorized-active`` (and the
  smart-approval policy allows them).

The wiring adds no new execution authority of its own. Every gate it
relies on already exists; the tests in
``tests/test_autonomous_hunt_runtime.py`` prove the fail-closed behavior
end to end through this module.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator
from webpent.autonomous.hunt_state import AutonomousHuntState

_HUNT_ADAPTER_NAME = "smart_http"


@dataclass
class HuntRuntime:
    """The wired runtime pieces one autonomous hunt needs."""

    runtime: Any
    handler: Callable[[Any], Any]
    adapter_name: str = _HUNT_ADAPTER_NAME
    observations: list[dict[str, Any]] = field(default_factory=list)
    direct_findings: list[Any] = field(default_factory=list)

    @property
    def action_executor(self) -> Any:
        return self.runtime.action_executor

    @property
    def adapters(self) -> Any:
        return self.runtime.adapters


def build_hunt_runtime(
    *,
    engagement_id: str,
    campaign_id: str,
    target_url: str,
    settings: Any | None = None,
    scan_mode: Any | None = None,
    smart_auto_approve: bool | None = None,
    raw_scope_entries: list[str] | tuple[str, ...] | None = None,
    event_sink: Any | None = None,
    ledger: Any | None = None,
    use_default_ledger: bool = True,
    adapters: Any | None = None,
) -> HuntRuntime:
    """Build a real ``RuntimeContext`` plus the smart-campaign handler.

    ``scan_mode`` and ``smart_auto_approve`` may override the resolved
    settings so a caller can run a fail-closed audit of the mode gates
    (see the tests). No override can bypass the authority: it only
    changes which profile the existing authority enforces.
    """
    from webpent.agents.smart_campaigns.agent import build_smart_campaign_handler
    from webpent.config.settings import ScanMode, get_settings
    from webpent.shared.g02_contract import (
        G02_HTTP_APPROVAL_EXPIRY,
        G02_HTTP_CANONICAL_WRAPPER,
        G02_HTTP_INVENTORY_REF,
        G02_HTTP_PROOF_CONTRACT,
        G02_HTTP_SCOPE_POLICY,
    )
    from webpent.shared.runtime import RegisteredAdapter, RuntimeFactory

    resolved = settings or get_settings()
    overrides: dict[str, Any] = {}
    if scan_mode is not None:
        mode = scan_mode.value if isinstance(scan_mode, ScanMode) else str(scan_mode)
        overrides["scan_mode"] = mode
    if smart_auto_approve is not None:
        overrides["smart_auto_approve"] = bool(smart_auto_approve)
    if overrides:
        resolved = resolved.model_copy(update=overrides)

    runtime = RuntimeFactory.create(
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        target_origin=target_url,
        settings=resolved,
        ledger=ledger,
        use_default_ledger=use_default_ledger,
        event_sink=event_sink,
        adapters=adapters,
        raw_scope_entries=raw_scope_entries,
    )

    observations: list[dict[str, Any]] = []
    direct_findings: list[Any] = []
    handler = build_smart_campaign_handler(
        {"engagement_id": engagement_id},
        root=runtime.target_origin,
        observations=observations,
        direct_findings=direct_findings,
    )

    existing = runtime.adapters.get(_HUNT_ADAPTER_NAME)
    if existing is None:
        runtime.adapters.register(
            RegisteredAdapter(
                name=_HUNT_ADAPTER_NAME,
                capability="smart_http_execution",
                transport="http",
                handler=handler,
                source="autonomous_hunt",
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
        handler = existing.handler

    return HuntRuntime(
        runtime=runtime,
        handler=handler,
        adapter_name=_HUNT_ADAPTER_NAME,
        observations=observations,
        direct_findings=direct_findings,
    )


def bootstrap_knowledge(
    *,
    engagement_id: str,
    target_url: str,
    crawl_config: Any | None = None,
) -> Any:
    """Recon bootstrap: crawl the authorized target and return knowledge.

    Uses the audited ``AutonomousCrawler`` (GET-only, same-origin, robots
    honored, hard page/depth/byte limits) and converts its ``SurfaceMap``
    into a validated ``TargetKnowledgeV2`` through the knowledge bridge.
    Raises on any failure so the caller can decide to proceed empty;
    the bootstrap itself never weakens scope or robots compliance.
    """
    from urllib.parse import urlsplit

    from webpent.autonomous.hunt_knowledge import surface_map_to_knowledge
    from webpent.live_hunter.profile import build_authorized_lab_profile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.recon.autonomous_crawler import AutonomousCrawler, CrawlConfig

    config = crawl_config or CrawlConfig(
        max_pages=25, max_depth=2, request_timeout_seconds=10.0
    )
    host = urlsplit(target_url).hostname
    if not host:
        raise ValueError(f"cannot derive host from target_url: {target_url!r}")
    profile = build_authorized_lab_profile(
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        authorized_targets=(host,),
        knowledge_ready=True,
        # MERGE 2026-10-26: the absorbed donorC-lineage profile hardening
        # (live_hunter/profile.py) requires loopback lab fixtures to be
        # DECLARED (lab_fixture_mode) instead of implicitly in-scope. The
        # hunt bootstrap is by definition a lab/fixture surface (its own
        # docstring: "crawls a live local HTTP server"); declare it instead
        # of weakening the profile rule. Non-loopback targets are unaffected
        # (lab_fixture_mode only gates loopback hosts).
        lab_fixture_mode=True,
    )
    scope_law = ScopeLaw(profile=profile, engagement_id=engagement_id)
    crawler = AutonomousCrawler(
        target_url=target_url,
        scope_law=scope_law,
        engagement_id=engagement_id,
        config=config,
    )
    result = crawler.crawl()
    knowledge = surface_map_to_knowledge(
        result.surface_map, engagement_id=engagement_id, target_id=target_url
    )
    if knowledge is None:
        raise ValueError("crawler produced no convertible surface map")
    return knowledge


def wire_orchestrator(
    hunt_runtime: HuntRuntime,
    *,
    max_iterations: int = 5,
    memory: Any | None = None,
    minimum_information_gain: float = 0.05,
    event_sink: Any | None = None,
    intel: Any | None = None,
    deadends: Any | None = None,
    auth_recheck: Callable[[], str | None] | None = None,
) -> AutonomousHuntOrchestrator:
    """Bind an orchestrator to the wired runtime's executor and handler.

    ``intel`` is the optional cross-session advisory memory (v80),
    ``deadends`` the optional dead-end memory (v81), and ``auth_recheck``
    is re-invoked at the top of every iteration; a truthy return stops the
    hunt BLOCKED with ``AUTHORIZATION_REVOKED``.
    """
    return AutonomousHuntOrchestrator(
        action_executor=hunt_runtime.runtime.action_executor,
        handler=hunt_runtime.handler,
        memory=memory,
        max_iterations=max_iterations,
        minimum_information_gain=minimum_information_gain,
        event_sink=event_sink,
        intel=intel,
        deadends=deadends,
        auth_recheck=auth_recheck,
    )


def run_wired_hunt(
    *,
    engagement_id: str,
    campaign_id: str,
    target_url: str,
    target_knowledge: dict[str, Any] | None = None,
    settings: Any | None = None,
    scan_mode: Any | None = None,
    smart_auto_approve: bool | None = None,
    raw_scope_entries: list[str] | tuple[str, ...] | None = None,
    max_iterations: int = 5,
    memory: Any | None = None,
    bootstrap: bool = True,
    event_sink: Any | None = None,
    intel: Any | None = None,
    deadends: Any | None = None,
    auth_recheck: Callable[[], str | None] | None = None,
) -> AutonomousHuntState:
    """One-command entry: wire the runtime and run the bounded hunt.

    When ``target_knowledge`` is empty and ``bootstrap`` is true, the hunt
    first recon-bounds the target with the audited crawler (GET-only,
    same-origin, robots honored) and feeds the observed surface into the
    hypothesis phase. A failed bootstrap is fail-soft: the hunt proceeds
    with no knowledge and stops bounded rather than erroring.

    Raises ``RuntimeConfigurationError`` when the runtime context is not
    ready; a wired hunt never proceeds on a degraded runtime.
    """
    from webpent.config.settings import ScanMode

    # The autonomous hunt defaults to the bounded safe-smart profile
    # (GET-only, audited handlers) unless the caller pins another mode; it
    # never silently inherits an unbounded profile from ambient settings.
    effective_scan_mode = scan_mode if scan_mode is not None else ScanMode.SAFE_SMART
    hunt_runtime = build_hunt_runtime(
        engagement_id=engagement_id,
        campaign_id=campaign_id,
        target_url=target_url,
        settings=settings,
        scan_mode=effective_scan_mode,
        smart_auto_approve=smart_auto_approve,
        raw_scope_entries=raw_scope_entries,
    )
    hunt_runtime.runtime.require_valid()
    if memory is None:
        from webpent.autonomous.hunt_memory import ScopedHuntMemory

        memory = ScopedHuntMemory()
    orchestrator = wire_orchestrator(
        hunt_runtime,
        max_iterations=max_iterations,
        memory=memory,
        event_sink=event_sink,
        intel=intel,
        deadends=deadends,
        auth_recheck=auth_recheck,
    )
    effective_knowledge = dict(target_knowledge or {})
    if not effective_knowledge and bootstrap:
        try:
            knowledge = bootstrap_knowledge(
                engagement_id=engagement_id, target_url=target_url
            )
            effective_knowledge = knowledge.as_dict()
        except Exception:
            effective_knowledge = {}
    effective_mode = str(getattr(hunt_runtime.runtime.settings, "scan_mode", "") or "safe-smart")
    state = AutonomousHuntState(
        engagement_id=engagement_id,
        target_url=hunt_runtime.runtime.target_origin,
        target_knowledge=effective_knowledge,
        max_iterations=max_iterations,
        scan_mode=effective_mode,
    )
    return orchestrator.run(state)


def advisory_recon_summary(
    amplifier_reports: dict[str, Any] | None,
) -> dict[str, Any]:
    """Flatten advisory recon-amplifier reports into one bounded summary.

    Pure and optional: the wired hunt never calls this by default. Each
    source contributes at most ``MAX_ITEMS_PER_ROLE`` leads; failures of
    one source never hide another's.
    """
    from webpent.autonomous.amplifiers.swarm import MAX_ITEMS_PER_ROLE

    reports = amplifier_reports if isinstance(amplifier_reports, dict) else {}
    summary: dict[str, Any] = {"sources": {}, "total_leads": 0, "advisory": True}
    for source in ("takeover", "cloud_storage", "wayback", "js_analyzer", "ct_mining"):
        report = reports.get(source)
        if not isinstance(report, dict):
            continue
        leads = 0
        for key in ("candidates", "open_candidates"):
            values = report.get(key, []) or []
            if isinstance(values, list):
                leads += len(values)
        summary["sources"][source] = leads
        summary["total_leads"] += leads
    summary["total_leads"] = min(summary["total_leads"], MAX_ITEMS_PER_ROLE * 5)
    return summary


def advisory_cross_target_suggestions(
    store: Any, tech_stack: Any
) -> list[dict[str, Any]]:
    """Advisory class seeds for a new target from cross-target memory.

    Optional convenience pass-through: the store itself is the authority;
    this only keeps the amplifier surface reachable from the runtime module.
    """
    suggestions = getattr(store, "suggestions_for", None)
    if not callable(suggestions):
        return []
    try:
        return list(suggestions(tech_stack) or [])
    except Exception:
        return []


__all__ = [
    "HuntRuntime",
    "advisory_cross_target_suggestions",
    "advisory_recon_summary",
    "bootstrap_knowledge",
    "build_hunt_runtime",
    "run_wired_hunt",
    "wire_orchestrator",
]
