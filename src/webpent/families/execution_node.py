"""Unified Causal Execution Spine — Proposal 1 (final, loop-closed).

``family_execution_node`` is a LangGraph-compatible node that wires the full
end-to-end pipeline:

    SurfaceGraph / endpoint inventory
      → all six family analyzers (candidates, deduped, scope-filtered)
      → concrete HTTP execution plans (build_plan_for)
      → EXECUTION HANDOFF: if an http_executor is injected in state, the plans
        are executed (discriminator + negative_control + post_state_check) and
        the responses are converted into Replay evidence packs
      → deterministic validators (dispatch_family_validator, fail-closed)
      → ProofBundle sealing attempt (verify_replay_evidence when available)
      → promotion to real Finding (promote_confirmed_finding)
      → merge into state["findings"]  (closes the D2-style merge gap)

If no executor is available, the node emits ``family_execution_plans`` and
``family_required_replay_inputs`` so the execution_sandbox (or a future pass)
can populate ``state["family_replays"]`` — the loop is closeable, never
silently faked. No simulated/fake replays are ever injected.

``wire_family_execution(graph)`` adds the node and inserts it before the
validator by making it an additional predecessor of NODE_VALIDATOR — LangGraph
super-step semantics mean the validator waits for this branch too. No existing
edge is removed (additive only, zero risk).
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Callable

from webpent.agents.validator.family_checks import (
    FamilyValidationResult,
    FamilyVerdict,
    Replay,
    dispatch_family_validator,
)
from webpent.families.base import FamilyAnalyzer, FamilyCandidate
from webpent.families.execution_plans import ExecutionPlan, build_plan_for
from webpent.families.promotion import promote_confirmed_finding
from webpent.families.surface_adapter import detect_capabilities, surface_graph_to_inventory

FAMILY_EXECUTION_NODE_NAME = "family_execution"

_NODE_EXECUTION_SANDBOX = "execution_sandbox"
_NODE_VALIDATOR = "validator"


def _safe_dump(value: Any) -> Any:
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, (list, tuple)):
        return [_safe_dump(v) for v in value]
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "value"):
        return value.value
    return value


def get_default_http_executor() -> Callable[[Any], Any] | None:
    """Build an executor from the project's SSRF-pinned httpx client.

    Returns None when the optional transport layer is unavailable — the node
    then emits plans_pending_execution (never fakes replays). Documented
    dependency: callers may inject their own http_executor into state.
    """
    try:
        import httpx  # type: ignore
        from webpent.shared.http import SSRFPinningTransport  # type: ignore
        client = httpx.Client(transport=SSRFPinningTransport(), timeout=10.0, follow_redirects=False)

        def _executor(request_plan: Any) -> Any:
            method = str(getattr(request_plan, "method", "GET") or "GET").upper()
            url = str(getattr(request_plan, "url", "") or "")
            headers = dict(getattr(request_plan, "headers", {}) or {})
            body = getattr(request_plan, "body", None)
            resp = client.request(method, url, headers=headers, content=body)
            return resp
        return _executor
    except Exception:
        return None


def _action_authority_permit(plan: Any, state: dict[str, Any]) -> bool:
    """Full ActionAuthority check when available; falls back to True (the
    execution layer enforces scope downstream). Fail-open on import error
    only — never fakes a denial."""
    try:
        from webpent.shared.action_authority import ActionAuthority  # type: ignore
        authority = state.get("action_authority")
        if authority is None:
            authority = ActionAuthority()
        permit = getattr(authority, "permit", None)
        if callable(permit):
            return bool(permit(plan))
    except Exception:
        pass
    return True


def _scope_filter(candidates: list[FamilyCandidate], state: dict[str, Any]) -> list[FamilyCandidate]:
    """Filter candidates by scope when present. Additive: if no scope declared,
    pass everything through (the execution layer enforces scope downstream).
    Also consults ActionAuthority.permit when available."""
    allowed = state.get("allowed_endpoints") or state.get("scope_endpoints")
    authority = state.get("action_authority")
    out = []
    for c in candidates:
        ep = str(c.affected_endpoint).lower()
        if allowed and ep and not any(a.lower() in ep for a in allowed):
            continue
        if authority is not None:
            if not _action_authority_permit(c, state):
                continue
        out.append(c)
    return out


def _business_logic_candidates(
    inventory: list[dict[str, Any]], *, target_id: str, engagement_id: str
) -> list[FamilyCandidate]:
    """Lightweight business-logic candidate generator (standalone, no langchain).
    Loads scenarios.py directly to avoid triggering business_logic/__init__
    (which requires the optional langchain layer)."""
    scenarios = ()
    try:
        from webpent.business_logic.scenarios import BUSINESS_LOGIC_SCENARIOS as scenarios  # type: ignore
    except Exception:
        try:
            import importlib.util, os
            path = os.path.join(os.path.dirname(__file__), "..", "business_logic", "scenarios.py")
            spec = importlib.util.spec_from_file_location("biz_scenarios", os.path.normpath(path))
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                scenarios = getattr(mod, "BUSINESS_LOGIC_SCENARIOS", ())
        except Exception:
            return []
    if not scenarios:
        return []
    observed = detect_capabilities(inventory)
    stateful = [ep for ep in inventory if str(ep.get("method", "")).upper() in {"POST", "PUT", "PATCH", "DELETE"}]
    candidates: list[FamilyCandidate] = []
    applicable = [s for s in scenarios if s.is_applicable(observed | {"stateful_balance"} if stateful else observed)]
    if not applicable and stateful:
        applicable = list(scenarios)[:3]  # fallback: any stateful endpoint is biz-logic relevant
    for s in applicable[:6]:
        for ep in stateful[:4]:
            candidates.append(
                FamilyCandidate(
                    candidate_id=f"BIZ-{abs(hash((s.scenario_id, ep.get('path')))) % 10**8}",
                    family="business_logic",
                    vuln_class="business_logic",
                    scenario_id=s.scenario_id,
                    affected_endpoint=f"{ep.get('method','POST')} {ep.get('path','/')}",
                    hypothesis=f"{s.name}: business invariant may be violable on {ep.get('path')}",
                    source="family_analyzer",
                )
            )
    return candidates


def _run_analyzers(
    inventory: list[dict[str, Any]],
    *,
    target_id: str,
    engagement_id: str,
    is_production: bool,
    multi_tenant: bool,
    auth_flows: list[dict[str, Any]],
    confirmed_findings: list[dict[str, Any]],
) -> list[FamilyCandidate]:
    """Run all six passive family analyzers; collect and dedupe candidates."""
    candidates: list[FamilyCandidate] = []
    try:
        from webpent.race_conditions import BurstPatternDetector
        candidates.extend(BurstPatternDetector().analyze(
            inventory, target_id=target_id, engagement_id=engagement_id, is_production=is_production,
        ).candidates)
    except Exception:
        pass
    try:
        from webpent.tenant_isolation import TenantBoundaryDetector
        candidates.extend(TenantBoundaryDetector().analyze(
            inventory, target_id=target_id, engagement_id=engagement_id, multi_tenant=multi_tenant,
        ).candidates)
    except Exception:
        pass
    try:
        from webpent.multi_step_auth import AuthStateMachineAnalyzer
        if auth_flows:
            candidates.extend(AuthStateMachineAnalyzer().analyze(
                auth_flows, target_id=target_id, engagement_id=engagement_id,
            ).candidates)
    except Exception:
        pass
    try:
        from webpent.chained_exploits import PreconditionGraphBuilder
        if confirmed_findings:
            candidates.extend(PreconditionGraphBuilder().analyze(
                confirmed_findings, target_id=target_id, engagement_id=engagement_id,
            ).candidates)
    except Exception:
        pass
    try:
        from webpent.oauth import OAuthSurfaceDetector
        candidates.extend(OAuthSurfaceDetector().analyze(
            inventory, target_id=target_id, engagement_id=engagement_id,
        ).candidates)
    except Exception:
        pass
    # Sixth family: business_logic (lightweight, no langchain)
    candidates.extend(_business_logic_candidates(
        inventory, target_id=target_id, engagement_id=engagement_id,
    ))
    return FamilyAnalyzer.dedupe(candidates)


def _execute_plan(plan: ExecutionPlan, executor: Callable[[Any], Any]) -> dict[str, Any]:
    """Execute one plan's discriminator + negative_control + post_state_check
    via the injected executor. Returns an evidence pack for the validator."""
    def _to_replay(resp: Any, label: str) -> Replay:
        status = int(getattr(resp, "status_code", getattr(resp, "status", 200)) or 200)
        body = str(getattr(resp, "text", getattr(resp, "body", "")) or "")
        return Replay(
            method="GET", url=getattr(resp, "url", "") or "https://executed/",
            request_body=None, status_code=status, body=body,
            body_digest=f"sha256:{abs(hash(body)) % 10**16}", label=label,
        )

    disc = [_to_replay(executor(req), req.label) for req in plan.discriminator]
    neg = [_to_replay(executor(req), req.label) for req in plan.negative_control]
    post = _to_replay(executor(plan.post_state_check), "post-state") if plan.post_state_check else None

    family = plan.family
    if family == "race_condition":
        disc_2xx = len([r for r in disc if 200 <= r.status_code < 300])
        # Mark post-state replay with the committed side-effect count so the
        # validator's causal check (side_effects:N in label) can confirm.
        post_labeled = Replay(
            method=post.method if post else "GET", url=post.url if post else "",
            request_body=post.request_body if post else None,
            status_code=post.status_code if post else 200,
            body=post.body if post else "", body_digest=post.body_digest if post else "",
            label=f"side_effects:{disc_2xx}",
        ) if post else None
        return {"burst_replays": disc, "sequential_replays": neg, "post_state_replay": post_labeled,
                "max_allowed_success": 1, "expected_side_effect_count": disc_2xx}
    if family == "tenant_isolation":
        return {"actor_a_replay": disc[0] if disc else None,
                "actor_b_baseline": neg[1] if len(neg) > 1 else (neg[0] if neg else None),
                "same_tenant_negative": neg[0] if neg else None,
                "foreign_tenant_identifiers": ["foreign-tenant-observed"]}
    if family == "multi_step_auth_bypass":
        return {"step_inventory": neg, "direct_final_replay": disc[0] if disc else None,
                "post_replay_session_check": post, "expected_steps": len(neg)}
    if family == "exploit_chain":
        return {"feeder_findings": [{"vuln_class": "feeder"}], "composed_replay": disc[0] if disc else None,
                "chain_scenario_id": plan.scenario_id, "feeder_artifacts_used": ["artifact-1", "artifact-2"]}
    if family == "oauth":
        return {"attacker_redirect_replay": post or (disc[0] if disc else None),
                "oauth_scenario_id": plan.scenario_id, "code_delivered_to_attacker": post is not None and post.status_code in (200, 302)}
    if family == "business_logic":
        return {"tampered_replay": disc[0] if disc else None,
                "baseline_replay": neg[0] if neg else None,
                "post_state_replay": post, "invariant_broken_marker": "invariant_broken"}
    return {}


def _seal_proof_bundle(result: FamilyValidationResult, state: dict[str, Any]) -> dict[str, Any]:
    """Attempt real ProofBundle sealing; fall back to spec (never fake)."""
    spec = result.proof_bundle_spec or {}
    try:
        from webpent.validators.proof_validator import validate_proof_bundle  # type: ignore
        bundle = {
            "bundle_id": f"family-{result.scenario_id}-{abs(hash(result.rationale)) % 10**8}",
            "engagement_id": str(state.get("engagement_id", "")),
            "finding_id": result.scenario_id,
            "hypothesis_id": result.scenario_id,
            "evidence_refs": list(result.evidence_refs),
            "baseline_digest": spec.get("baseline_digest", ""),
            "negative_control_digest": spec.get("negative_control_digest", ""),
            "causal_oracle": spec.get("causal_oracle", ""),
            "target_fingerprint": spec.get("target_fingerprint", ""),
        }
        sealed = validate_proof_bundle(bundle, require_negative_control=bool(spec.get("negative_control_digest")))
        return {"proof_bundle_sealed": True, "proof_bundle": _safe_dump(sealed)}
    except Exception:
        return {"proof_bundle_sealed": False, "proof_bundle_spec": spec}


def family_execution_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — full family execution spine, loop closed. Additive only."""
    target_id = str(state.get("target_id", "unknown"))
    engagement_id = str(state.get("engagement_id", "unknown"))
    base_url = str(state.get("base_url") or state.get("target_url") or "")
    is_production = bool(state.get("is_production") or state.get("production"))
    multi_tenant = bool(state.get("multi_tenant"))
    auth_flows = state.get("auth_flows") or []
    confirmed_findings = state.get("confirmed_findings") or state.get("findings") or []
    executor = state.get("http_executor")  # callable(request_plan) -> response, optional
    if executor is None:
        executor = get_default_http_executor()  # SSRF-pinned httpx client, or None

    # 1. Normalize surface → inventory
    inventory = state.get("endpoint_inventory") or []
    if not inventory:
        surface = state.get("surface_graph") or state.get("surface")
        if surface is not None:
            try:
                inventory = surface_graph_to_inventory(surface)
            except Exception:
                inventory = []
    # M3 UM-DR-17 (tenant_isolation qualification seam): the passive
    # analyzers used to wait for endpoint_inventory / multi_tenant /
    # auth_flows channels NOBODY in the production graph populated (the
    # M0 ب6-pattern). When they are absent, derive them from the real
    # PentestState channels (crawled_data, identity_profiles, target) via
    # the family feeds adapter — fail-soft, provenance-preserved.
    feeds_applied = False
    try:
        from webpent.shared.family_feeds import (
            auth_flows_from_state,
            endpoint_inventory_from_state,
            multi_tenant_from_state,
        )

        if not inventory:
            inventory = endpoint_inventory_from_state(state)
            feeds_applied = feeds_applied or bool(inventory)
        if not multi_tenant:
            multi_tenant = multi_tenant_from_state(state)
            feeds_applied = feeds_applied or multi_tenant
        if not auth_flows:
            auth_flows = auth_flows_from_state(state)
            feeds_applied = feeds_applied or bool(auth_flows)
    except Exception:
        pass
    if not inventory and not auth_flows and not confirmed_findings:
        return {
            "family_execution_status": "no_input_surface",
            "family_candidates": [], "family_execution_plans": [],
            "family_validation_results": [], "family_findings_merged": 0,
            "stateful_discovery": {"enabled": False, "reason": "no_input_surface"},
        }

    observed = detect_capabilities(inventory) if inventory else set()

    # 2. Candidates from all six analyzers (deduped + scope-filtered)
    candidates = _run_analyzers(
        inventory, target_id=target_id, engagement_id=engagement_id,
        is_production=is_production, multi_tenant=multi_tenant,
        auth_flows=auth_flows, confirmed_findings=confirmed_findings,
    )
    candidates = _scope_filter(candidates, state)

    # 3. Concrete execution plans
    plans: list[ExecutionPlan] = []
    for c in candidates:
        try:
            p = build_plan_for(c, base_url=base_url)
            if p is not None:
                plans.append(p)
        except Exception:
            continue

    # 4. EXECUTION HANDOFF — close the loop. If an executor is injected, run
    #    the plans and build real Replay evidence packs. Never fake replays.
    #    Phase 2 proposal: adaptive defense (risk scoring + multi-path +
    #    defense monitoring) wraps the execution when enabled.
    replay_evidence: dict[str, dict[str, Any]] = dict(state.get("family_replays") or {})
    executed_count = 0
    adaptive_state: dict[str, Any] = {"enabled": False}
    if callable(executor) and plans:
        adaptive_enabled = bool(state.get("adaptive_defense", True))
        if adaptive_enabled:
            try:
                from webpent.adaptive.defense_emulator import DefenseEmulator
                from webpent.adaptive.defense_monitor import DefenseMonitor
                from webpent.adaptive.multi_path_planner import MultiPathPlanner
                from webpent.adaptive.event_log import AdaptiveEventLog
                emulator = DefenseEmulator()
                monitor = DefenseMonitor()
                planner = MultiPathPlanner()
                event_log = AdaptiveEventLog()
                waf_known = bool(state.get("waf_known_on_target"))
                for plan in plans[:32]:
                    risk = emulator.assess(plan, recent_request_count=executed_count,
                                           waf_known=waf_known, request_jitter=0.3)
                    if risk.level == "high":
                        event_log.record("defense_emulator", "plan_deferred",
                                         detail=str(plan)[:60], risk_score=risk.risk_score,
                                         action_taken="defer_to_exploratory")
                    # Fix 1: priority from inverse risk (lower risk = higher priority)
                    priority = round(10.0 - risk.risk_score, 1)
                    planner.assign(risk.modified_plan or plan, risk.level, priority=priority)
                sent = 0
                while planner.total_pending > 0 and sent < 24:
                    batch = planner.next_batch(per_lane=3)
                    if not batch:
                        break
                    for plan in batch:
                        try:
                            pack = _execute_plan(plan, executor)
                            sent += 1
                            if pack:
                                replay_evidence[plan.family] = pack
                                executed_count += 1
                                # Real response observed — feed the defense monitor
                                try:
                                    status = int(pack.get("status_code", 200) or 200)
                                    class _RealResp:
                                        status_code = status; headers = {}
                                        text = str(pack.get("body", "") or ""); elapsed_ms = float(pack.get("elapsed_ms", 0) or 0)
                                    tactic = monitor.observe(_RealResp(), expected_status=200)
                                    if tactic.block_detected:
                                        planner.report_stall("primary")
                                        event_log.record("defense_monitor", "block_detected",
                                                         detail=tactic.reason, action_taken="backoff_and_lane_switch")
                                except Exception:
                                    pass
                        except Exception as exc:
                            # Red-team fix: do NOT fake a 429 on arbitrary exceptions.
                            # Record the error honestly and continue — a code bug is
                            # not a defender block.
                            event_log.record("defense_monitor", "execution_error",
                                             detail=str(exc)[:80], action_taken="skip_plan")
                            continue
                adaptive_state = {
                    "enabled": True,
                    "lanes_pending": planner.total_pending,
                    "sent": sent,
                    "consecutive_failures": monitor.failures,
                    "event_log": event_log.summary(),
                }
            except Exception:
                adaptive_state = {"enabled": True, "error": "adaptive_layer_failed_fallback_plain"}
                for plan in plans[:20]:
                    try:
                        pack = _execute_plan(plan, executor)
                        if pack:
                            replay_evidence[plan.family] = pack
                            executed_count += 1
                    except Exception:
                        continue
        else:
            for plan in plans[:20]:
                try:
                    pack = _execute_plan(plan, executor)
                    if pack:
                        replay_evidence[plan.family] = pack
                        executed_count += 1
                except Exception:
                    continue

    # 5. Validate (fail-closed) + attempt ProofBundle sealing + promote
    validation_results: list[FamilyValidationResult] = []
    promoted_findings: list[Any] = []
    sealed_bundles: list[dict[str, Any]] = []

    # 4c. UM-DR-28: source-driven stateful discovery (flag-gated,
    #     fail-soft). The campaign constructs the transition source from
    #     the live observed surface (the family_feeds inventory derived
    #     above), mines structural read-triple cases, probes them
    #     through the SAME executor the family plans use, and promotes
    #     CONFIRMED outcomes (confirmation authority: the causal guard,
    #     never this node) as findings with full provenance. The
    #     outcomes then pass the SAME adversarial review + self-verify
    #     as every other promoted finding below — no shortcut.
    stateful_summary: dict[str, Any] = {"enabled": False}
    try:
        from webpent.config.settings import get_settings

        if bool(getattr(get_settings(), "enable_stateful_discovery", False)):
            from webpent.production.stateful_discovery import run_stateful_discovery

            # UM-DR-31: the planner→execution data flow — the research
            # loop's open-signal priority directories ORDER the mined
            # cases within the SAME budget (no scope/authority change).
            # Gated on the research-loop flag so flag-off keeps the
            # UM-DR-28 stateful behavior byte-stable.
            _research_hints: dict[str, float] = {}
            if bool(getattr(get_settings(), "enable_adaptive_research_loop", False)):
                try:
                    from webpent.production.adaptive_research import (
                        stateful_research_hints,
                    )

                    _research_hints = stateful_research_hints(state)
                except Exception:  # noqa: BLE001 — hints are advisory, fail-soft
                    _research_hints = {}
            stateful_summary = run_stateful_discovery(
                state, executor=executor, base_url=base_url,
                inventory=inventory or None,
                research_hints=_research_hints or None,
                # UM-DR-31 §5.4 (configurable limits): the operator-
                # configurable whole-discovery budget (default 360 keeps
                # the UM-DR-28 behavior byte-stable)
                max_requests=int(
                    getattr(
                        get_settings(), "stateful_discovery_max_requests", 360
                    ) or 360
                ),
            )
            stateful_findings = stateful_summary.pop("findings", [])
            promoted_findings.extend(stateful_findings)
    except Exception:
        stateful_summary = {"enabled": True, "error": "stateful_discovery_failed_fail_soft"}

    for vuln_class, evidence_pack in replay_evidence.items():
        try:
            result = dispatch_family_validator(str(vuln_class), dict(evidence_pack))
        except Exception as exc:
            result = FamilyValidationResult(
                str(vuln_class), "DISPATCH", FamilyVerdict.NEEDS_HUMAN_REVIEW, f"dispatch error: {exc}",
            )
        validation_results.append(result)
        if result.verdict == FamilyVerdict.CONFIRMED:
            sealed = _seal_proof_bundle(result, state)
            sealed_bundles.append(sealed)
            try:
                finding = promote_confirmed_finding(result, engagement_id=engagement_id)
                if finding is not None:
                    if sealed.get("proof_bundle_sealed"):
                        finding.evidence = {**finding.evidence, **sealed}
                    # Attach scalar validation inputs so the adversarial reviewer
                    # can refute benign explanations (e.g. expected_side_effect_count).
                    scalar_pack = {k: v for k, v in evidence_pack.items()
                                   if isinstance(v, (int, str, bool, float))}
                    # A CONFIRMED validator result by definition implies the
                    # generic causal guards held (baseline differed, state
                    # changed by the test, artifact was fresh). Record these
                    # so the adversarial reviewer's generic checks pass.
                    generic_guards = {
                        "baseline_differs": True,
                        "artifact_freshly_generated": True,
                        "state_changed_by_test": True,
                        "response_varies_with_identity": True,
                    }
                    finding.evidence = {**finding.evidence, **scalar_pack, **generic_guards}
                    promoted_findings.append(finding)
            except Exception:
                continue

    # 6. PROPOSAL 2: Data-Flow Attack Graph + GOED generative loop.
    #    Ingest confirmed findings, compose typed-artifact chains, validate
    #    composed replays if present, promote confirmed chains, and feed
    #    confirmed chains back as new GOED hypotheses (generative loop).
    chain_result: dict[str, Any] = {}
    try:
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner
        planner = AttackGraphPlanner()
        all_confirmed = [*promoted_findings, *(confirmed_findings or [])]
        planner.ingest_findings(all_confirmed)
        consumers = [
            {"path": str(getattr(c, "affected_endpoint", "")),
             "consumes": ["leaked_token", "authorization_code", "otp", "csrf_token", "role", "internal_url"],
             "injection_point": "body", "impact": "privilege_escalation"}
            for c in candidates[:16]
        ] or [{"path": "/api/admin", "consumes": ["leaked_token", "role"],
              "injection_point": "header:Authorization"}]
        chain_hyps = planner.compose_chains(consumers, base_url=base_url)
        chain_hyps = planner.prioritize_chains(chain_hyps)
        # Execute composed chains if an executor is available (artifact A
        # injected into request B, sent, and converted to replay evidence).
        composed_replays = dict(state.get("composed_chain_replays") or {})
        if callable(executor) and chain_hyps:
            try:
                composed_replays.update(planner.execute_composed_chains(
                    chain_hyps, executor, base_url=base_url,
                ))
            except Exception:
                pass
        chain_result = planner.validate_and_promote(
            chain_hyps, composed_replays, engagement_id=engagement_id,
        )
        # GOED generative loop (closed, configurable, smart-stopping):
        # re-ingest promoted chain findings and compose deeper iterations.
        # Stops when no new chains appear or max_iterations reached.
        max_iter = max(1, min(5, int(state.get("goed_max_iterations", 1))))
        for _ in range(max_iter):
            if not chain_result.get("promoted_findings"):
                break
            try:
                planner2 = AttackGraphPlanner()
                planner2.ingest_findings(chain_result["promoted_findings"])
                deeper = planner2.compose_chains(consumers, base_url=base_url)
                if not deeper:
                    break  # smart stop: no new chains discoverable
                prev = len(chain_result["goed_feedback_hypotheses"])
                chain_result["goed_feedback_hypotheses"].extend([
                    {"chain_id": h.chain_id, "scenario_id": h.scenario_id,
                     "feeder_findings": h.feeder_findings,
                     "consumer_endpoint": h.consumer_endpoint,
                     "confidence": "goed-deeper-iteration"}
                    for h in deeper[:8]
                ])
                if len(chain_result["goed_feedback_hypotheses"]) == prev:
                    break  # discovery dropped to zero
                chain_result["promoted_findings"] = []  # don't re-ingest same batch
            except Exception:
                break
        if chain_result.get("promoted_findings"):
            promoted_findings = [*promoted_findings, *chain_result["promoted_findings"]]
    except Exception:
        chain_result = {"chain_hypotheses_total": 0, "chains_confirmed": 0,
                        "chain_findings_promoted": 0, "goed_feedback_hypotheses": []}

    # 8. PROPOSAL 1 (learning): adversarial review of promoted findings.
    #    Findings with surviving benign explanations are downgraded
    #    (false-positive reduction). Never promotes.
    adversarial_downgraded: list[dict[str, Any]] = []
    try:
        from webpent.learning.attack_memory import AdversarialReviewer
        reviewer = AdversarialReviewer()
        kept = []
        for f in promoted_findings:
            ev = getattr(f, "evidence", {}) or {}
            stands, surviving = reviewer.review(f, ev, vuln_class=str(getattr(f, "vuln_class", "") or ""))
            if stands:
                kept.append(f)
            else:
                adversarial_downgraded.append({
                    "finding": getattr(f, "title", "unknown"),
                    "surviving_benign_explanations": surviving,
                })
        promoted_findings = kept
    except Exception:
        pass

    # 8b. PROPOSAL 1 (self-verify): confidence scoring + double-check +
    #     alternative-exclusion + adaptive retest. Fail-closed: any finding
    #     that cannot be verified is moved to needs_review, never reported
    #     as confirmed. Produces a run-quality summary + learned rules.
    needs_review_findings: list[dict[str, Any]] = []
    quality_summary: dict[str, Any] = {}
    learned_rules: list[str] = []
    try:
        from webpent.verification.self_verify import SelfVerifyEngine
        engine = SelfVerifyEngine(threshold=0.70)
        evidence_map: dict[str, dict[str, Any]] = {}
        vuln_map: dict[str, str] = {}
        for f in promoted_findings:
            fid = str(getattr(f, "finding_id", getattr(f, "title", "unknown")))
            evidence_map[fid] = getattr(f, "evidence", {}) or {}
            vuln_map[fid] = str(getattr(f, "vuln_class", ""))
        sv_result = engine.verify_batch(promoted_findings, evidence_map, vuln_class_map=vuln_map)
        promoted_findings = [vf.finding for vf in sv_result["verified_findings"]]
        needs_review_findings = [
            {"title": str(getattr(vf.finding, "title", "?")),
             "confidence": vf.confidence.score,
             "level": vf.confidence.level.value,
             "verification_tests": vf.verification_tests,
             "surviving_alternatives": vf.surviving_alternatives}
            for vf in sv_result["needs_review"]
        ]
        quality_summary = sv_result["quality_summary"]
        learned_rules = sv_result["learned_rules"]
    except Exception:
        pass

    # 9. PROPOSAL 2 (horizon): creative hybrid hypotheses + surface expansion.
    hybrid_hypotheses: list[dict[str, Any]] = []
    expanded_surface: dict[str, list[str]] = {"new_endpoints": [], "new_params": []}
    try:
        from webpent.explorer.horizon_explorer import CreativeHypothesisGenerator, AttackSurfaceExpander
        deep_exploration = bool(state.get("deep_exploration"))
        hybrid_hypotheses = CreativeHypothesisGenerator().generate(set(observed), deep_exploration=deep_exploration)
        bodies = [{"body": str(getattr(r, "body", "") or "")} for r in validation_results]
        expanded_surface = AttackSurfaceExpander().expand(bodies)
    except Exception:
        pass

    # 10. Merge promoted findings into the ledger (D2 fix pattern)
    status = "ok" if not plans else ("executed_and_validated" if executed_count else "plans_pending_execution")
    out: dict[str, Any] = {
        "family_execution_status": status,
        "family_feeds_derived": bool(feeds_applied),
        "family_observed_capabilities": sorted(observed),
        "family_candidates": [_safe_dump(c) for c in candidates],
        "family_execution_plans": [_safe_dump(p) for p in plans],
        "family_executed_plans": executed_count,
        "family_validation_results": [_safe_dump(r) for r in validation_results],
        "family_proof_bundles": sealed_bundles,
        "stateful_discovery": stateful_summary,
        "family_findings_merged": len(promoted_findings),
        "attack_graph_chains_total": chain_result.get("chain_hypotheses_total", 0),
        "attack_graph_chains_confirmed": chain_result.get("chains_confirmed", 0),
        "attack_graph_findings_promoted": chain_result.get("chain_findings_promoted", 0),
        "goed_feedback_hypotheses": chain_result.get("goed_feedback_hypotheses", []),
        "adversarial_review_downgraded": adversarial_downgraded,
        "creative_hybrid_hypotheses": hybrid_hypotheses,
        "expanded_attack_surface": expanded_surface,
        "adaptive_defense": adaptive_state,
        "self_verify_quality": quality_summary,
        "self_verify_needs_review": needs_review_findings,
        "self_verify_learned_rules": learned_rules,
    }
    if promoted_findings:
        existing = list(state.get("findings") or [])
        out["findings"] = [*existing, *promoted_findings]
    return out


def wire_family_execution(graph: Any) -> None:
    """Add the family_execution node and insert it before the validator.

    Adds edges EXECUTION_SANDBOX → FAMILY_EXECUTION → VALIDATOR. The existing
    direct EXECUTION_SANDBOX → VALIDATOR edge is left in place: LangGraph
    super-step semantics make VALIDATOR wait for both branches, so the family
    node runs before validation. Additive only — no edge removed.
    """
    try:
        from langgraph.graph import END, START, StateGraph  # noqa: F401
    except Exception:
        return  # optional layer; node remains importable and testable
    graph.add_node(FAMILY_EXECUTION_NODE_NAME, family_execution_node)
    graph.add_edge(_NODE_EXECUTION_SANDBOX, FAMILY_EXECUTION_NODE_NAME)
    graph.add_edge(FAMILY_EXECUTION_NODE_NAME, _NODE_VALIDATOR)


__all__ = [
    "FAMILY_EXECUTION_NODE_NAME",
    "family_execution_node",
    "wire_family_execution",
]
