# src/webpent/graph/builder.py
"""LangGraph orchestration for WebPent.

The compiled graph contains **45 base nodes**. ``attack_graph`` is an
additional node when ``enable_attack_graph`` is enabled. ``START`` and
``END`` are pseudo-nodes and are not included in that count.
(IMPL P0-E: the previous docstring said 31 base nodes — stale count,
re-measured against ``build_graph()`` at 45 real nodes.)

The graph is intentionally divided into readable stages:

* **Engagement setup:** ``planner`` -> ``auth``.
* **Recon and understanding:** optional ``recon``/``crawler`` path, static
  JavaScript intelligence, infrastructure checks, optional target
  understanding, scope enforcement, and WAF detection.
* **Hypothesis and deep probes:** ``hypothesis`` -> access-control, API,
  business-logic, request-smuggling, disclosed-report intelligence, optional
  attack graph, and ``strategist``.
* **Evidence pipeline:** ``payload_generator`` -> HITL-gated
  ``execution_sandbox`` -> ``validator`` -> bounded optimizer retries or
  ``devils_advocate``.
* **Post-validation reasoning:** ``exploit_chainer`` and ``rabbit_hole``
  feed only bounded loops back into the evidence pipeline; scoring, impact,
  cross-reasoning, executive summary, reporting, and reflection finish the
  engagement.

Conditional paths are fail-closed and feature-flagged. ``skip_recon`` can
bypass network reconnaissance, but it does not bypass the strategist or
validator when open hypotheses or findings exist. The ``route_after_hypothesis``
name is the canonical name; ``route_after_recon`` remains a compatibility
alias for older callers.

All loops are bounded by ``_MAX_OPTIMIZATION_RETRIES``, the rabbit-hole policy,
and the existing evidence/approval contracts. ``interrupt_before`` is placed
before ``execution_sandbox`` unless ``auto_approve=True``.
"""


from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

from langgraph.graph import END, START, StateGraph

from webpent.agents.access_control.agent import access_control_node
from webpent.agents.api_testing.agent import api_testing_node
from webpent.agents.attack_graph.agent import attack_graph_node
from webpent.agents.authentication.agent import auth_node
from webpent.agents.business_impact.agent import business_impact_node
from webpent.agents.business_logic_fuzzer.agent import business_logic_fuzzer_node
from webpent.agents.cloud_storage.agent import cloud_storage_node
from webpent.agents.crawler.agent import crawler_node
from webpent.agents.cross_reasoning.agent import cross_reasoning_node
from webpent.agents.cvss_engine.agent import cvss_node
from webpent.agents.devils_advocate.agent import devils_advocate_node
from webpent.agents.disclosed_report_intel.agent import disclosed_report_intel_node
from webpent.agents.execution_sandbox.agent import execution_sandbox_node
from webpent.agents.executive_summary.agent import executive_summary_node
from webpent.agents.exploit_chainer.agent import exploit_chainer_node
from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.agents.javascript_intelligence.agent import javascript_intelligence_node
from webpent.agents.payload_generator.agent import payload_generator_node
from webpent.agents.payload_optimizer.agent import (
    optimization_attempt_fingerprint,
    payload_optimizer_node,
)
from webpent.agents.planner.agent import planner_node
from webpent.agents.post_exploit.agent import post_exploitation_node
from webpent.agents.rabbit_hole.agent import rabbit_hole_node
from webpent.agents.recon.agent import recon_node
from webpent.agents.reflection.agent import reflection_node
from webpent.agents.reporter.agent import reporter_node, reporter_node_bug_bounty
from webpent.agents.request_smuggling.agent import request_smuggling_node
from webpent.agents.scope_enforcer.agent import scope_enforcer_node
from webpent.agents.smart_campaigns.agent import (
    _execute_campaign_task,
    build_smart_campaign_handler,
    smart_campaigns_execution_node,
    smart_campaigns_node,
)
from webpent.graph import budget_governor

# Sprint I-1b, item 3.1: restored after ruff --fix (F401) wrongly removed
# it -- unused within this file's own code, but imported here so
# webpent.graph.builder.ModernOrchestrator stays a valid attribute path
# for other code/tests (test_fabric_critical_fixes.py asserts hasattr).
# See the sprint changelog for the regression this fixes.
from webpent.production.modern_spine import ModernOrchestrator  # noqa: F401

# TEAM-1: Modern autonomous spine — default production recon/research path.
# The modern spine (DeepReconEngine -> WorldModel -> ResearchControlLoop ->
# OutcomeTracker -> ScopeLaw/ToolBoundary -> CausalGuard -> ProofBundle) is
# the DEFAULT. Legacy recon_node remains as compatibility/advisory fallback.
from webpent.production.modern_spine_integration import (
    MODERN_SPINE_ENABLED,
    modern_spine_recon_node,
)
from webpent.shared.exceptions import UnsupportedLegacyOnlyModeError

# ---------------------------------------------------------------------------
# CQA v2 + VIP Smart — supplementary post-processing layer (WIRED)
# ---------------------------------------------------------------------------
# GOVERNANCE: This is an OPTIONAL supplementary layer only.
# - NEVER overrides existing findings or decisions
# - NEVER mutates original state
# - Adds causal metadata and ProofBundles as additional evidence only
# - Activated by --enable-cqa-v2 / --enable-smart CLI flags (opt-in)
# - Original findings remain the authoritative source of truth
# ---------------------------------------------------------------------------
# D-1 (RA-3): removed dead top-level import — actual import is local in _cqa_v2_reporter_node

# Verify VIP Smart is importable (wiring confirmation)
try:
    from webpent.smart import VIPSmartHunter as _VIPSmartHunter  # noqa: F401
    _VIP_SMART_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    _VIP_SMART_AVAILABLE = False
from webpent.agents.strategist.agent import strategist_node
from webpent.agents.subdomain_takeover.agent import subdomain_takeover_node
from webpent.agents.target_understanding.agent import target_understanding_node
from webpent.agents.validator.agent import validator_node
from webpent.agents.waf_detector.agent import waf_detector_node
from webpent.config.settings import get_settings
from webpent.models.findings import (
    EXPLOITABLE_CLASSES,
    Confidence,
    Finding,
    Severity,
)
from webpent.models.research import CandidateAction
from webpent.shared.autonomous_controller import autonomous_controller_node
from webpent.shared.campaign_executor import CampaignTask, resolve_preconditions
from webpent.shared.causal_research import build_causal_research_projection
from webpent.shared.g02_contract import (
    G02_HTTP_APPROVAL_EXPIRY,
    G02_HTTP_CANONICAL_WRAPPER,
    G02_HTTP_INVENTORY_REF,
    G02_HTTP_PROOF_CONTRACT,
    G02_HTTP_SCOPE_POLICY,
    g02_http_metadata,
)
from webpent.shared.identity_provisioning import identity_provisioning_node
from webpent.shared.package_preflight import target_package_preflight_node
from webpent.shared.research_contracts import active_research_node
from webpent.shared.research_nodes import (
    knowledge_gap_node,
    next_best_action_node,
    research_session_node,
)
from webpent.shared.runtime import RegisteredAdapter, RuntimeContext
from webpent.shared.wildcard_scope import (
    route_after_wildcard_scope,
    wildcard_scope_node,
)
from webpent.shared.vip_campaign_node import vip_campaign_node
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

NODE_PLANNER = "planner"
NODE_AUTH = "auth"
NODE_RECON = "recon"
NODE_RESEARCH_CAMPAIGN = "research_campaign"  # TEAM-1: automatic fabric dispatch on production path
NODE_CRAWLER = "crawler"
NODE_SCOPE_ENFORCER = "scope_enforcer"
NODE_SCOPE_REVIEW = "scope_review"
NODE_WAF_DETECTOR = "waf_detector"
NODE_HYPOTHESIS = "hypothesis"
NODE_PAYLOAD_GENERATOR = "payload_generator"
NODE_EXECUTION_SANDBOX = "execution_sandbox"
NODE_VALIDATOR = "validator"
NODE_DEVILS_ADVOCATE = "devils_advocate"
# V7 "Apex Predator" addition: chains confirmed findings into candidate
# combined-exploit scenarios. Sits after devils_advocate (only chains
# from findings that survived debunking) and before post_exploitation.
NODE_EXPLOIT_CHAINER = "exploit_chainer"
NODE_POST_EXPLOITATION = "post_exploitation"
# V7 Cognitive Upgrade Phase 7: Rabbit Hole — runs after post_exploitation
# (where artifacts realistically get noticed via safe read-only enumeration)
# and before cvss_engine. Emits new Hypotheses that re-enter the existing
# payload_generator -> execution_sandbox (HITL-gated) -> validator pipeline.
NODE_RABBIT_HOLE = "rabbit_hole"
# V7 Cognitive Upgrade Section 4: Strategist — promotion checkpoint.
# Runs after all discovery nodes, before payload_generator. Promotes
# high-scoring hypotheses to Findings so the existing pipeline can
# process them. Bounded: can only rank+recommend, cannot authorize
# execution or expand scope (per Section 4).
NODE_STRATEGIST = "strategist"
# UM-DR-31 (evidence-driven adaptive research loop): the bounded
# adaptive research node. Flag-gated (enable_adaptive_research_loop,
# fail-closed default False) and wired AHEAD of the strategist on the
# discovery-line, research-line and post-validation replan routes —
# every planner entry with fresh evidence is preceded by one bounded
# research iteration that turns coverage-gap / invariant /
# workflow-boundary signals into ordinary pool hypotheses. The
# rabbit_hole loop-back is deliberately NOT redirected: that strategist
# pass filters to RABBIT_HOLE-origin hypotheses only, so enrichment
# there would be unreachable by construction.
NODE_RESEARCH_LOOP = "research_loop"
NODE_PAYLOAD_OPTIMIZER = "payload_optimizer"
NODE_CVSS_ENGINE = "cvss_engine"
NODE_BUSINESS_IMPACT = "business_impact"
NODE_CROSS_REASONING = "cross_reasoning"
NODE_EXECUTIVE_SUMMARY = "executive_summary"
NODE_REPORTER = "reporter"
# Track 11 item 5 (2026-10-28): dedup-before-nomination gate node.
NODE_DEDUP_GATE = "dedup_gate"
NODE_REFLECTION = "reflection"

# V7 Sprint 2: New node names for the expanded vulnerability-coverage agents.
# These run as a "deep probing" phase between hypothesis and payload_generator.
NODE_ACCESS_CONTROL = "access_control"
NODE_ATTACK_GRAPH = "attack_graph"
NODE_API_TESTING = "api_testing"
NODE_BUSINESS_LOGIC_FUZZER = "business_logic_fuzzer"
NODE_REQUEST_SMUGGLING = "request_smuggling"
NODE_SUBDOMAIN_TAKEOVER = "subdomain_takeover"
NODE_CLOUD_STORAGE = "cloud_storage"
# Track 2 (VIP speed initiative, 2026-10-19): only wired into the graph
# when settings.enable_parallel_recon is True (see _parallel_recon_enabled
# below) — a no-op dispatch/join pair so NODE_SUBDOMAIN_TAKEOVER and
# NODE_CLOUD_STORAGE run in the same LangGraph superstep instead of
# sequentially. See UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md.
NODE_RECON_FANOUT = "recon_fanout"
NODE_RECON_JOIN = "recon_join"
NODE_DISCLOSED_REPORT_INTEL = "disclosed_report_intel"
NODE_TARGET_UNDERSTANDING = "target_understanding"
NODE_JAVASCRIPT_INTELLIGENCE = "javascript_intelligence"
NODE_SMART_CAMPAIGNS = "smart_campaigns"
NODE_SMART_CAMPAIGNS_EXECUTION = "smart_campaigns_execution"
NODE_AUTONOMOUS_CONTROLLER = "autonomous_controller"
# 2026-10-24 layer 2: one-shot VIP campaign-leader pass (flag-gated, advisory).
NODE_VIP_ORCHESTRATOR = "vip_orchestrator"
NODE_ACTIVE_RESEARCH = "active_research"
NODE_CAUSAL_RESEARCH = "causal_research"
NODE_KNOWLEDGE_GAP = "knowledge_gap"
NODE_NEXT_BEST_ACTION = "next_best_action"
NODE_RESEARCH_SESSION = "research_session"
NODE_RECOVERY = "recovery"
NODE_WILDCARD_SCOPE = "wildcard_scope"
NODE_IDENTITY_PROVISIONING = "identity_provisioning"
NODE_IDENTITY_PROVISIONING_PRE_AUTH = "identity_provisioning_pre_auth"
NODE_TARGET_PACKAGE_PREFLIGHT = "target_package_preflight"

# ---------------------------------------------------------------------------
# ULTIMATE PLAN 2026-10-27 (proposals 2/3/7). Seven additive nodes.
# Every one is a pass-through when its flag is off or the target has no
# relevant surface — the legacy path is byte-identical when all flags
# are off, and each node carries zero finding authority (advisory
# outputs only; promotion stays with the validator/strategist chain).
# ---------------------------------------------------------------------------
#: (proposal 3) Consult accumulated lessons right after planning; the
#: output is ADVISORY priority context for hypothesis/payload nodes.
NODE_LESSON_CONSULTATION = "lesson_consultation"
#: (proposal 3) Extract and store this campaign's lessons at the tail.
NODE_LESSON_EXTRACTION = "lesson_extraction"
#: (proposal 2) Measure the surface and derive the dynamic step budget
#: between the WAF detector and the hypothesis generator.
NODE_SURFACE_SIZING = "surface_sizing"
#: (proposal 7) The four deterministic detector nodes, chained after
#: request_smuggling inside the deep-probe phase. Pass-throughs unless
#: the surface/flag applies.
NODE_GRAPHQL_TESTING = "graphql_testing"
NODE_CACHE_POISONING = "cache_poisoning"
NODE_PROTOTYPE_POLLUTION = "prototype_pollution"
NODE_OAUTH_MISCONFIG = "oauth_misconfig"

# V3.5 Obsidian Master: Import from central location (models/findings.py).
_EXPLOITABLE_CLASSES = EXPLOITABLE_CLASSES

_MIN_SEVERITY_VALUE = Severity.MEDIUM.value
_SEVERITY_RANKS: dict[str, int] = {
    Severity.INFO.value: 0, Severity.LOW.value: 1, Severity.MEDIUM.value: 2,
    Severity.HIGH.value: 3, Severity.CRITICAL.value: 4,
}

_MAX_OPTIMIZATION_RETRIES = 3


def _trace_wrap(node_name: str, fn):
    """R-B: wrap a node so every execution appends one step-trace entry.

    The wrapper is pure passthrough for the node's own result: it only
    ADDS a ``node_step_trace`` entry (append-only channel via
    ``merge_lists``).  It never alters the node's decisions, findings,
    or authority.  Nodes returning ``None`` are treated as empty
    updates; any other return type is passed through untouched.
    """

    def _traced(state: PentestState, *args, **kwargs):
        result = fn(state, *args, **kwargs)
        try:
            entry = budget_governor.trace_entry(state, node_name)
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):  # tracing must never break a node
            entry = {"node": str(node_name), "governor": "trace_error"}
        if isinstance(result, dict):
            update = dict(result)
        elif result is None:
            update = {}
        else:  # unexpected non-dict return: preserve pre-governor behavior
            return result
        prev = update.get("node_step_trace")
        if isinstance(prev, list):
            update["node_step_trace"] = [*prev, entry]
        else:
            update["node_step_trace"] = [entry]
        return update

    _traced.__name__ = getattr(fn, "__name__", f"traced_{node_name}")
    _traced.__doc__ = getattr(fn, "__doc__", None)
    # R-B transparency contract: tests and introspection can recover the
    # wrapped node (e.g. feature-flag selection locks assert
    # ``traced.__wrapped__ is reporter_node``).
    _traced.__wrapped__ = fn
    return _traced


# R2-graph-01: append-only channels (merge_lists reducer) of PentestState.
# A node that folds other nodes' state into its own update must never
# re-send these keys: the reducer appends the already-stored entries a
# second time, duplicating node_step_trace/consulted_lessons on every run
# and inflating the budget governor's consumed count (its only measure is
# len(node_step_trace)).
_APPEND_ONLY_CHANNELS = frozenset(
    name
    for klass in PentestState.__mro__
    for name, ann in vars(klass).get("__annotations__", {}).items()
    if any(
        getattr(m, "__name__", "") == "merge_lists"
        for m in (getattr(ann, "__metadata__", ()) or ())
    )
)


def _strip_append_only_channels(update):
    """Drop append-only channel keys from a node update (R2-graph-01)."""
    if not isinstance(update, dict):
        return update
    return {k: v for k, v in update.items() if k not in _APPEND_ONLY_CHANNELS}


#: legacy recon output keys that may never clobber authoritative fields
#: (Sprint I-1 item 1.4 + TEAM-1 advisory-only invariants).
_RECON_LEGACY_LOCKED_KEYS = frozenset({
    "modern_spine_active", "_modern_orchestrator", "_modern_spine_trace",
    "modern_spine_version", "legacy_recon_advisory_only",
    "hypotheses", "candidate_hypotheses",
})


def _make_combined_recon_node(engagement_id):
    """Build the combined recon node (modern spine first, legacy advisory).

    TEAM-1: the modern spine is the DEFAULT recon path — authoritative —
    and the legacy recon_node runs second as advisory/compatibility (its
    output is marked advisory_only and cannot bypass authority or clobber
    modern hypotheses). If MODERN_SPINE_ENABLED is False (emergency
    rollback only), the legacy node runs alone.

    R2-graph-01: the node returns ONLY its own delta — never the input
    state — so append-only channels already stored by earlier nodes are
    not re-sent through merge_lists on the default production path.
    """

    def _combined_recon_node(state):
        update: dict = {}
        working = dict(state)
        if engagement_id and not working.get("engagement_id"):
            update["engagement_id"] = engagement_id
            working["engagement_id"] = engagement_id
        if MODERN_SPINE_ENABLED:
            # Modern spine runs FIRST — authoritative.
            modern_state = modern_spine_recon_node(dict(working))
            for k, v in modern_state.items():
                update[k] = v
                working[k] = v
            update["modern_spine_active"] = True
            update["legacy_recon_advisory_only"] = True  # BEFORE legacy runs
            working["modern_spine_active"] = True
            working["legacy_recon_advisory_only"] = True
        # Legacy recon runs SECOND — compatibility/advisory only.
        try:
            legacy_state = recon_node(dict(working))
            # Legacy output merged but explicitly marked advisory; cannot
            # overwrite modern authoritative fields.
            for k, v in legacy_state.items():
                if k not in _RECON_LEGACY_LOCKED_KEYS:
                    update[k] = v
                    working[k] = v
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError,
                TypeError, ValueError) as exc:
            logger.warning(
                "legacy recon_node advisory failure (modern spine authoritative): %s",
                exc,
            )
        if MODERN_SPINE_ENABLED:
            # Structural invariant: legacy output is ALWAYS advisory.
            update["legacy_recon_advisory_only"] = True
            update["legacy_recon_cannot_confirm"] = True
            update["legacy_recon_requires_modern_evidence_path"] = True
        return _strip_append_only_channels(update)

    return _combined_recon_node


def _is_exploitable(finding: Finding) -> bool:
    """Return True if ``finding.vuln_class`` is in the exploitable set.

    V3.5: Replaces fragile keyword matching on titles/descriptions with
    a deterministic check on the ``vuln_class`` enum field.

    V10 EXHAUSTIVE AUDIT (P0-1): uses :func:`model_get` so it works on
    both Finding instances and plain dicts (after checkpoint round-trip).
    """
    from webpent.state.reducers import model_get
    vc = model_get(finding, "vuln_class")
    return vc in _EXPLOITABLE_CLASSES


def _meets_severity_threshold(finding: Finding) -> bool:
    from webpent.state.reducers import model_get
    rank = _SEVERITY_RANKS.get(str(model_get(finding, "severity", "")), 0)
    return rank >= _SEVERITY_RANKS[_MIN_SEVERITY_VALUE]


def _attack_graph_enabled() -> bool:
    """Return the additive Attack Graph flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_attack_graph)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _family_execution_enabled() -> bool:
    """M3 UM-DR-17 (tenant_isolation qualification seam): the causal
    family execution spine flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_family_execution_spine)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _oast_enabled() -> bool:
    """M3 UM-DR-17 (OAST production wiring): the OAST correlation flag,
    fail-closed (declared in M1-C, UM-DR-12)."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_oast)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _umdr31_research_loop_enabled() -> bool:
    """UM-DR-31 (adaptive research loop): flag + mandatory limits both
    available, fail-closed (the coverage_gap_report double-gate
    precedent — the node itself re-checks at runtime)."""
    try:
        from webpent.config.settings import get_settings

        if not bool(get_settings().enable_adaptive_research_loop):
            return False
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False
    try:
        from webpent.production.adaptive_research import research_loop_enabled

        return research_loop_enabled()
    except (ImportError, AttributeError):
        return False


def _umdr31_routes(routes: dict[str, str]) -> dict[str, str]:
    """UM-DR-31: redirect strategist-bound conditional routes through the
    research_loop node when the adaptive research loop is enabled.

    Flag-off returns the mapping unchanged (byte-comparable graph
    shape). The research_loop node is registered only when the flag is
    on, so the redirected mapping always targets a registered node; the
    research_loop → strategist edge makes the planner the immediate
    consumer of the enriched pool (same-superstep-chain handoff)."""
    if not _umdr31_research_loop_enabled():
        return routes
    if NODE_STRATEGIST in routes:
        return {**routes, NODE_STRATEGIST: NODE_RESEARCH_LOOP}
    return routes


def _autonomous_controller_enabled(state: PentestState) -> bool:
    """Enable the bounded controller only through an explicit state flag."""
    return state.get("enable_autonomous_controller") is True


def _vip_orchestrator_enabled() -> bool:
    """Return the additive VIP campaign-leader flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_vip_orchestrator)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _vip_pass_pending(state: PentestState) -> bool:
    """The VIP node runs at most once per scan; every node return bumps
    ``vip_campaign_runs`` (including the fail-soft path), so this gate
    can never admit a second pass on a checkpoint replay."""
    return int(state.get("vip_campaign_runs", 0) or 0) < 1


def _smart_campaigns_enabled(state: PentestState) -> bool:
    """Enable Smart Hunter only for an explicit non-legacy scan profile."""
    governance = state.get("smart_governance", {})
    profile = governance.get("profile") if isinstance(governance, dict) else None
    return bool(
        state.get("smart_mode")
        or state.get("enable_smart_campaigns")
        or profile in {
            "smart",
            "smart-observe",
            "safe-smart",
            "authorized-active",
            "vip-qualification",
        }
    )


def route_after_disclosed_report_intel(state: PentestState) -> str:
    """Preserve Attack Graph routing; otherwise enter Smart Hunter when opted in."""
    # R-B completion cutoff: the attack-graph + smart-campaigns pre-tail
    # is optional forward work; under the cutoff the strategist line
    # (<= 16 supersteps to END) is the convergent route.
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_STRATEGIST
    if _attack_graph_enabled():
        return NODE_ATTACK_GRAPH
    if _vip_orchestrator_enabled() and _vip_pass_pending(state):
        return NODE_VIP_ORCHESTRATOR
    return NODE_SMART_CAMPAIGNS if _smart_campaigns_enabled(state) else NODE_STRATEGIST


def route_after_attack_graph(state: PentestState) -> str:
    """Continue from Attack Graph into Smart Hunter only when explicitly enabled."""
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_STRATEGIST
    if _vip_orchestrator_enabled() and _vip_pass_pending(state):
        return NODE_VIP_ORCHESTRATOR
    return NODE_SMART_CAMPAIGNS if _smart_campaigns_enabled(state) else NODE_STRATEGIST


def route_after_vip_orchestrator(state: PentestState) -> str:
    """Continue from the one-shot VIP pass into Smart Hunter when opted in.

    The VIP node is advisory-only (perceive/plan over already-crawled
    data, no executor), so its exit re-joins the exact routing the
    graph would have taken without it: budget cutoff, then Smart
    Hunter, then the strategist line."""
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_STRATEGIST
    return NODE_SMART_CAMPAIGNS if _smart_campaigns_enabled(state) else NODE_STRATEGIST


def _autonomous_max_runs(state: PentestState) -> int:
    """Return the persisted, bounded controller budget."""
    replanning = state.get("smart_replanning") or {}
    if not isinstance(replanning, dict):
        return 0
    try:
        return max(0, int(replanning.get("max_replan_rounds", 0)))
    except (TypeError, ValueError):
        return 0


def route_after_smart_campaigns_execution(state: PentestState) -> str:
    """Enter the controller only while its persisted budget remains."""
    # R-B research cutoff (tier-1): once the remaining budget touches the
    # research reserve, stop discovering more and spend what is left
    # validating what was already found.  Forward strategist line is
    # <= 16 supersteps, inside the reserve.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    if _autonomous_controller_enabled(state):
        runs = int(state.get("autonomous_controller_runs", 0) or 0)
        return (
            NODE_AUTONOMOUS_CONTROLLER
            if runs < _autonomous_max_runs(state)
            else NODE_STRATEGIST
        )
    replanning = state.get("smart_replanning") or {}
    if not isinstance(replanning, dict):
        return NODE_STRATEGIST
    if replanning.get("replan_requested") is not True:
        return NODE_STRATEGIST
    try:
        current_round = int(replanning.get("round", 0))
        max_rounds = int(replanning.get("max_replan_rounds", 0))
    except (TypeError, ValueError):
        return NODE_STRATEGIST
    if current_round >= max_rounds:
        return NODE_STRATEGIST
    # IMPL Phase 2-G: evidence-monotonic gate. Each additional
    # smart-campaigns replan round must have ADDED deterministic evidence
    # (Tool-Confirmed or Refuted) during the round that requested it —
    # recorded by the executor as ``replan_evidence_start``/``replan_evidence_end``
    # (see smart_campaigns_execution_node). Replanning on noise
    # (observations without sealed evidence) is refused, matching the
    # post-validation replan law. Missing markers (pre-fix in-flight
    # checkpoints) fail closed.
    try:
        evidence_start = int(replanning.get("replan_evidence_start", 0) or 0)
        evidence_end = int(replanning.get("replan_evidence_end", 0) or 0)
    except (TypeError, ValueError):
        return NODE_STRATEGIST
    if evidence_end <= evidence_start:
        return NODE_STRATEGIST
    return NODE_SMART_CAMPAIGNS


def _research_candidates_available(state: Mapping[str, Any]) -> bool:
    """Return True only when at least one valid, unattempted candidate exists."""
    candidates = state.get("research_candidate_actions") or []
    attempted = {
        str(item)
        for item in (state.get("research_context") or {}).get(
            "attempted_action_fingerprints", []
        )
        if str(item)
    }
    for raw in candidates[:100]:
        if not isinstance(raw, Mapping):
            continue
        try:
            payload = dict(raw)
            payload.pop("fingerprint", None)
            candidate = CandidateAction.model_validate(payload)
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
            continue
        if candidate.fingerprint() not in attempted:
            return True
    return False


def _recovery_pending(state: Mapping[str, Any]) -> bool:
    """Return True only for an explicit, retryable infrastructure failure."""
    recovery_state = state.get("recovery_state") or {}
    if not isinstance(recovery_state, Mapping):
        return False
    try:
        attempts = int(recovery_state.get("attempts", 0) or 0)
        maximum = max(0, min(3, int(recovery_state.get("max_attempts", 0) or 0)))
    except (TypeError, ValueError):
        return False
    if attempts >= maximum or recovery_state.get("status") not in {
        "replanning",
        "retry_ready",
    }:
        return False
    events = state.get("recovery_events") or []
    return any(
        isinstance(event, Mapping)
        and event.get("failure_class") == "infrastructure_failure"
        and event.get("retry_allowed") is True
        and event.get("status") in {"replan_requested", "retry_ready"}
        for event in events[-20:]
    )


def route_after_autonomous_controller(state: PentestState) -> str:
    """Return to recovery, smart execution, or bounded research after controller work."""
    # R-B research cutoff: cut the recovery/knowledge-gap/smart-campaigns
    # re-entries; the strategist line converges to END within reserve.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    if _recovery_pending(state):
        return NODE_RECOVERY
    runs = int(state.get("autonomous_controller_runs", 0) or 0)
    replanning = state.get("smart_replanning") or {}
    if not isinstance(replanning, dict):
        return NODE_STRATEGIST
    if replanning.get("controller_executed") is not True:
        return NODE_STRATEGIST
    if runs >= _autonomous_max_runs(state):
        return NODE_STRATEGIST
    if _research_candidates_available(state) or not state.get("smart_next_actions"):
        return NODE_KNOWLEDGE_GAP
    return NODE_SMART_CAMPAIGNS


def _active_research_task(candidate: CandidateAction, state: Mapping[str, Any]) -> CampaignTask:
    """Convert a validated research candidate into the central task contract."""
    metadata = g02_http_metadata(candidate.metadata)
    metadata.update(
        {
            "probe_kind": "active_research",
            "research_action_id": candidate.action_id,
            "research_action_fingerprint": candidate.fingerprint(),
            "objective": candidate.objective[:240],
            "human_approved": bool(state.get("auto_approve", False)),
        }
    )
    package_id = str(state.get("target_package_id") or "").strip()
    if package_id:
        metadata["target_package_continuity"] = {
            "package_id": package_id[:160],
            "package_sha256": str(state.get("target_package_sha256") or "")[:64],
            "scope_digest": str(state.get("target_package_scope_digest") or "")[:64],
            "policy_digest": str(state.get("target_package_policy_digest") or "")[:64],
        }
    observed = state.get("observed_preconditions", ())
    if isinstance(observed, str):
        observed = (observed,)
    metadata["observed_preconditions"] = tuple(str(item)[:160] for item in observed)[:20]
    return CampaignTask(
        task_id=f"active-research:{candidate.action_id}"[:160],
        engagement_id=str(state.get("engagement_id") or "engagement:unknown")[:160],
        asset_id=candidate.target_ref[:500],
        source_evidence_ids=tuple(
            str(item)[:160]
            for item in metadata.get("evidence_refs", ())
            if str(item)
        )[:20],
        vulnerability_class="research_information",
        hypothesis_id=candidate.hypothesis_id[:160] or f"research-gap:{candidate.action_id}"[:160],
        preconditions=tuple(candidate.prerequisites[:20]),
        identity_context=candidate.identity_context[:120],
        workflow_state=candidate.workflow_state[:120],
        probe_family="bounded_information_action",
        negative_control=(
            "required" if candidate.action_class == "negative_control" else "not_applicable"
        ),
        oracle="response_metadata_only",
        budget=max(0.1, min(100000.0, candidate.cost)),
        expected_information_gain=candidate.expected_information_gain,
        idempotency_key=candidate.idempotency_key or f"active-research:{candidate.fingerprint()}",
        method=candidate.method,
        capability=candidate.capability,
        action_family="http_read",
        target_url=candidate.target_ref,
        metadata=metadata,
        tenant_context=candidate.tenant_context[:120],
        validator_id="active_research_observation",
    )


def _active_research_runtime_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Run one graph-owned research step through an injected runtime adapter."""
    runtime = state.get("runtime_context")
    if not isinstance(runtime, RuntimeContext):
        return active_research_node(state)
    if not runtime.valid:
        return {
            **runtime.blocked_result(node=NODE_ACTIVE_RESEARCH),
            "research_active_observations": [
                {
                    "observation_id": "observation:runtime:blocked",
                    "action_id": "action:none",
                    "action_fingerprint": "0" * 32,
                    "status": "blocked",
                    "reason": "runtime_context_invalid",
                    "revisit_conditions": ["repair runtime context"],
                }
            ],
        }

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
                source="active_research",
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

    def injected_research_handler(candidate: CandidateAction) -> Mapping[str, Any]:
        target_allowed = runtime.scope_matcher.allows(candidate.target_ref, method=candidate.method)
        if not target_allowed:
            raise PermissionError("target_scope_denied")
        task = _active_research_task(candidate, state)
        observed = state.get("observed_preconditions", ())
        blocked = state.get("blocked_preconditions", ())
        ready, _ = resolve_preconditions(
            task,
            observed_preconditions=(observed if not isinstance(observed, str) else (observed,)),
            blocked_preconditions=(blocked if not isinstance(blocked, str) else (blocked,)),
            require_observations=bool(task.preconditions),
        )
        record = _execute_campaign_task(
            runtime,
            task,
            handler,
            state=state,
            root=runtime.target_origin,
            observed_preconditions=(
                observed
                if isinstance(observed, tuple)
                else tuple(observed)
                if isinstance(observed, (list, set))
                else (observed,)
                if isinstance(observed, str)
                else ()
            ),
            preconditions_met=ready,
        )
        status = str(record.get("status") or "inconclusive")
        proof_bundle = record.get("proof_bundle")
        evidence_refs = (
            proof_bundle.get("evidence_refs", [])
            if isinstance(proof_bundle, Mapping)
            else []
        )
        if status == "executed":
            observation_status = (
                "positive"
                if record.get("proof_bundle_sealed") is True
                else "inconclusive"
            )
        elif status == "infrastructure_failure":
            observation_status = "infrastructure_failure"
        else:
            observation_status = "blocked"
        return {
            "observation_id": f"observation:executor:{candidate.fingerprint()}",
            "action_id": candidate.action_id,
            "action_fingerprint": candidate.fingerprint(),
            "status": observation_status,
            "evidence_refs": [str(item)[:200] for item in evidence_refs[:20]],
            "reason": str(record.get("reason") or status)[:500],
            "control_complete": bool(record.get("negative_control_present")),
            "causal_signal": False,
            "proof_bundle_sealed": bool(record.get("proof_bundle_sealed")),
            "metadata": {
                "executor_status": status,
                "output_available": bool(record.get("output_available")),
                "runtime_adapter": "smart_http",
            },
            "revisit_conditions": ["fresh evidence or explicit policy change"]
            if observation_status != "positive"
            else [],
        }

    target_allowed = any(
        isinstance(raw, Mapping)
        and runtime.scope_matcher.allows(
            str(raw.get("target_ref") or ""),
            method=str(raw.get("method") or "GET"),
        )
        for raw in (state.get("research_candidate_actions") or [])[:100]
    )
    result = active_research_node(
        state,
        handler=injected_research_handler,
        target_allowed=target_allowed,
        approved=bool(state.get("auto_approve", False)),
    )
    if observations:
        result["smart_http_observations"] = observations[:20]
    if direct_findings:
        result["findings"] = [*list(state.get("findings") or []), *direct_findings]
    return result


def causal_research_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Project causal links and ledger decisions without executing any I/O."""
    try:
        return build_causal_research_projection(state)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        logger.exception("Causal research projection failed; preserving state")
        return {
            "causal_attack_graph": {
                "version": 1,
                "edges": [],
                "nodes": [],
                "next_best_action_links": [],
                "negative_evidence_consulted": False,
                "projection_status": "failed_closed",
            }
        }


def recovery_node(state: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a retry request without executing transport or changing scope."""
    recovery_state = dict(state.get("recovery_state") or {})
    pending = _recovery_pending(state)
    recovery_state["status"] = "retry_ready" if pending else "exhausted"
    if not pending:
        recovery_state["last_failure_class"] = str(
            recovery_state.get("last_failure_class") or ""
        )[:80]
    return {"recovery_state": recovery_state}


def route_after_recovery(state: PentestState) -> str:
    """Re-enter only the bounded controller; otherwise fail closed."""
    # R-B research cutoff: no infrastructure retry re-entry late in the run.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    if _recovery_pending(state) and _research_candidates_available(state):
        runs = int(state.get("autonomous_controller_runs", 0) or 0)
        if runs < _autonomous_max_runs(state):
            return NODE_AUTONOMOUS_CONTROLLER
    return NODE_STRATEGIST


def route_after_research_session(state: PentestState) -> str:
    """Enter active research only with a validated, unattempted candidate."""
    # R-B research cutoff: stop spawning new research actions late in the run.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    runs = int(state.get("autonomous_controller_runs", 0) or 0)
    if _research_candidates_available(state) and runs < _autonomous_max_runs(state):
        return NODE_ACTIVE_RESEARCH
    return NODE_STRATEGIST


def route_after_active_research(state: PentestState) -> str:
    """Send every active result through causal projection before replanning."""
    # R-B research cutoff: skip the causal projection hop; strategist line
    # is the convergent route and projection is advisory metadata.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    if state.get("research_active_observations"):
        return NODE_CAUSAL_RESEARCH
    return NODE_STRATEGIST


def route_after_causal_research(state: PentestState) -> str:
    """Re-enter the bounded controller only after causal context is attached."""
    # R-B research cutoff: no controller re-entry late in the run.
    if budget_governor.budget_pressure(state)["research_active"]:
        return NODE_STRATEGIST
    runs = int(state.get("autonomous_controller_runs", 0) or 0)
    if _research_candidates_available(state) and runs < _autonomous_max_runs(state):
        return NODE_AUTONOMOUS_CONTROLLER
    return NODE_STRATEGIST


def _target_understanding_enabled() -> bool:
    """Return the additive Target Understanding flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_target_understanding)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _js_intelligence_enabled() -> bool:
    """Return the optional static-JS intelligence flag, fail-closed."""
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_js_intelligence)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _parallel_recon_enabled() -> bool:
    """Return the Track 2 parallel-recon flag, fail-closed.

    Mirrors the established fail-closed pattern of
    ``_target_understanding_enabled``/``_js_intelligence_enabled`` above:
    any settings-resolution error is treated as "disabled" so a broken or
    unexpected config never silently turns ON a graph-topology change.
    """
    try:
        from webpent.config.settings import get_settings
        return bool(get_settings().enable_parallel_recon)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def _strip_current_phase(fn):
    """Wrap a node so its returned ``current_phase`` write is dropped.

    Track 2: ``current_phase`` is a plain (non-``Annotated``) state field —
    last-write-wins, with LangGraph raising ``InvalidUpdateError`` if two
    nodes in the SAME superstep both try to set it to different values
    (verified empirically against the pinned langgraph==1.2.10; see
    UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md). When
    NODE_SUBDOMAIN_TAKEOVER and NODE_CLOUD_STORAGE run concurrently under
    the parallel-recon flag, both would otherwise write conflicting
    ``current_phase`` values and crash the graph. This wrapper is applied
    ONLY to those two nodes ONLY when parallel-recon is enabled — it
    changes nothing else about either node's return value, and
    NODE_RECON_JOIN sets the merged ``current_phase`` once both branches
    have completed, so the field is never silently dropped from state,
    only deferred to the join point.
    """

    def _wrapped(state: PentestState, *args, **kwargs):
        result = fn(state, *args, **kwargs)
        if isinstance(result, dict) and "current_phase" in result:
            result = {k: v for k, v in result.items() if k != "current_phase"}
        return result

    return _wrapped


def _identity_provisioning_enabled() -> bool:
    """Return the opt-in identity flag; configuration errors fail closed."""
    try:
        return bool(get_settings().identity_provisioning_enabled)
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return False


def route_after_planner(state: PentestState) -> str:
    """Ultimate plan 2026-10-27: consult lessons before anything else.

    planner -> lesson_consultation (when the learning loop is enabled)
    -> identity pre-auth -> auth. The consultation is ADVISORY ONLY: it
    writes priority hints (consulted_lessons / adjustments), never
    instructions, and never gates the campaign. When the flag is off
    the route is the pre-plan planner->auth/identity chain unchanged.
    """
    del state
    if _lesson_consultation_enabled():
        return NODE_LESSON_CONSULTATION
    return NODE_IDENTITY_PROVISIONING_PRE_AUTH if _identity_provisioning_enabled() else NODE_AUTH


def route_after_lesson_consultation(state: PentestState) -> str:
    """Continue from the advisory consultation into the pre-plan chain."""
    del state
    return NODE_IDENTITY_PROVISIONING_PRE_AUTH if _identity_provisioning_enabled() else NODE_AUTH


def _lesson_consultation_enabled() -> bool:
    """Feature flag read for the learning-loop nodes (fail-open off)."""
    try:
        from webpent.config.settings import get_settings

        return bool(get_settings().enable_lesson_consultation)
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        return False


def route_after_pre_auth_identity(state: PentestState) -> str:
    """Always continue to auth after the bounded pre-auth identity seam."""
    del state
    return NODE_AUTH


def route_after_crawler(state: PentestState) -> str:
    """Run static JavaScript review only when explicitly enabled."""
    del state
    return NODE_JAVASCRIPT_INTELLIGENCE if _js_intelligence_enabled() else NODE_SUBDOMAIN_TAKEOVER


def route_after_crawler_with_identity(state: PentestState) -> str:
    """Insert optional identity provisioning without changing the legacy route."""
    if _identity_provisioning_enabled():
        return NODE_IDENTITY_PROVISIONING
    return route_after_crawler(state)


def route_after_infrastructure(state: PentestState) -> str:
    """Route through Target Understanding for configured or Smart scans."""
    smart_scan = _smart_campaigns_enabled(state)
    return (
        NODE_TARGET_UNDERSTANDING
        if _target_understanding_enabled() or smart_scan
        else NODE_SCOPE_ENFORCER
    )


def route_after_auth(state: PentestState) -> str:
    """V6.1: Conditional edge after AUTH — skip recon if requested.

    If ``skip_recon`` is True, bypass the recon/crawler/scope/waf
    pipeline and go straight to the hypothesis node (using the
    provided target URL as the sole endpoint).
    """
    if state.get("skip_recon"):
        logger.info("skip_recon=True — bypassing recon/crawler/scope/waf")
        if _target_understanding_enabled():
            return NODE_TARGET_UNDERSTANDING
        return NODE_HYPOTHESIS
    return NODE_RECON


def route_after_scope_enforcer(state: PentestState) -> str:
    """Stop on discovered scope drift until an operator approves it."""
    return NODE_SCOPE_REVIEW if state.get("scope_drift_detected") else NODE_WAF_DETECTOR


def scope_review_node(state: PentestState) -> dict[str, Any]:
    """Record the explicit scope-review checkpoint without authorizing it."""
    return {
        "scope_review_blocked": state.get("scope_drift_approved") is not True,
        "scope_review_required": True,
    }


def recon_fanout_node(state: PentestState) -> dict[str, Any]:
    """Track 2: no-op dispatch point for the parallel recon branches.

    Only wired into the graph (two outgoing edges, to NODE_SUBDOMAIN_TAKEOVER
    and NODE_CLOUD_STORAGE) when ``_parallel_recon_enabled()`` is True. A
    trivial pass-through — it does not read or write any finding/crawl
    state — whose sole purpose is to be the single predecessor both
    branches share, so LangGraph's Pregel engine schedules them in the
    same superstep (concurrently) rather than one after the other.
    """
    del state
    return {"current_phase": "recon_fanout"}


def recon_join_node(state: PentestState) -> dict[str, Any]:
    """Track 2: no-op join/barrier point for the parallel recon branches.

    Only wired into the graph when ``_parallel_recon_enabled()`` is True.
    LangGraph does not execute a node until every edge feeding it in the
    current superstep has fired, so this node is a correctness barrier,
    not just documentation: ``route_after_infrastructure`` (attached to
    this node instead of NODE_CLOUD_STORAGE when parallel-recon is on)
    only ever sees ``crawled_data``/``findings`` already merged from BOTH
    NODE_SUBDOMAIN_TAKEOVER and NODE_CLOUD_STORAGE — identical to what it
    would see in the sequential chain, just arrived at concurrently. Sets
    the ``current_phase`` that both parallel branches had stripped (see
    ``_strip_current_phase``) so the field is never missing from state.
    """
    del state
    return {"current_phase": "recon_join"}


def route_after_scope_review(state: PentestState) -> str:
    """Continue only after an explicit operator approval; otherwise stop."""
    return NODE_WAF_DETECTOR if state.get("scope_drift_approved") is True else END


def route_after_target_package_preflight(state: PentestState) -> str:
    """Route package preflight failures without ever labeling them clean."""
    status = str(state.get("target_package_preflight_status") or "not_provided")
    if status == "blocked":
        return NODE_REPORTER
    return NODE_WILDCARD_SCOPE


def route_after_hypothesis(state: PentestState) -> str:
    """Conditional edge after ``hypothesis``: exploit or report.

    V10 P1-3: renamed from ``route_after_recon`` — the old name was a
    leftover from V3.5 when this router sat after the recon node. It
    has sat after ``hypothesis`` since V6.1, but the name was never
    updated, making the graph construction code misleading to read.
    A backward-compat alias ``route_after_recon = route_after_hypothesis``
    is kept below so any external callers / tests that imported the
    old name continue to work.

    V10 P0-B FIX: the previous version gated on ``state["findings"]``
    emptiness under ``skip_recon=True``. But ``hypothesis_node`` emits
    ``Hypothesis`` objects (V7 Phase 1 migration), NOT ``Finding``
    objects — so under ``skip_recon=True`` with path-classified
    hypotheses (e.g. /vulnerabilities/sqli/), the router short-
    circuited to ``NODE_REPORTER`` before the Strategist could
    promote any hypothesis to a Finding. Live operator symptom:
    skip_recon=True + path hypotheses → immediate Report + Persisted 0,
    no strategist/payload_generator/validator run.

    Fix: gate on OPEN HYPOTHESES (``state["hypotheses"]`` non-empty
    with status ``UNEXPLORED``) instead of findings emptiness. Any
    open hypothesis means the Strategist (sitting downstream of
    NODE_ACCESS_CONTROL → NODE_API_TESTING → NODE_BUSINESS_LOGIC_FUZZER
    → NODE_REQUEST_SMUGGLING → NODE_STRATEGIST) still has work to do.
    The Strategist's ``deterministic_match=True`` bypass (set by
    ``hypothesis_node`` on every path-classified hypothesis) already
    allows promotion without nuclei evidence — no strategist change
    needed.

    V6.1: If ``skip_recon`` is True, bypass the recon/crawler nodes
    entirely and go straight to hypothesis. The hypothesis_node uses
    the target URL as the sole endpoint.

    V7 Sprint 2: The routing goes through the deep-probing agents
    (access_control, api_testing, business_logic_fuzzer,
    request_smuggling) before reaching payload_generator. These agents
    may discover additional findings that weren't in the hypothesis
    pass, so they run even when the hypothesis found nothing
    actionable — they might find something the hypothesis missed.
    """
    # V10 P0-B: check for open hypotheses (UNEXPLORED status). The
    # hypothesis_node emits Hypothesis objects with status=UNEXPLORED
    # by default (models/hypothesis.py). The Strategist promotes them
    # to Findings; the router must NOT short-circuit past the
    # Strategist when open hypotheses exist.
    try:
        from webpent.models.hypothesis import HypothesisStatus
        unexplored = (
            HypothesisStatus.UNEXPLORED.value
            if hasattr(HypothesisStatus, "UNEXPLORED")
            else "unexplored"
        )
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        unexplored = "unexplored"

    from webpent.state.reducers import model_get
    hypotheses = state.get("hypotheses") or []
    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get instead of getattr so
    # dict-shaped hypotheses (after checkpoint round-trip) are handled
    # correctly — getattr(dict, "status", None) returns None (silent
    # degradation); model_get(dict, "status") returns the actual value.
    has_open_hypotheses = any(
        model_get(h, "status") == unexplored for h in hypotheses
    )

    # V6.1: Phase skipping — bypass recon + crawler.
    if state.get("skip_recon"):
        findings: list[Finding] = list(state.get("findings") or [])
        # V10 P0-B: route to access_control (which leads to strategist)
        # when EITHER findings OR open hypotheses exist. The previous
        # ``if not findings: return NODE_REPORTER`` gate dropped the
        # entire exploit chain when only hypotheses existed.
        if not findings and not has_open_hypotheses:
            # Genuine no-op fast path: operator requested skip_recon
            # AND there are no findings AND no open hypotheses. This
            # is the only case we short-circuit to reporter.
            return NODE_REPORTER
        # Findings OR open hypotheses exist — run the deep probes +
        # strategist so hypotheses get promoted to findings.
        # R-B completion cutoff: the deep-probe chain (up to 5 nodes) +
        # optional attack-graph/smart-campaigns pre-tail can exceed the
        # remaining budget; the strategist line (<= 16 supersteps) is
        # the convergent route under the cutoff.
        if budget_governor.budget_pressure(state)["active"]:
            return NODE_STRATEGIST
        return NODE_ACCESS_CONTROL
    # Normal path: always run the deep-probing agents. They may find
    # vulnerabilities the hypothesis missed (IDOR, GraphQL, race
    # conditions, request smuggling).
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_STRATEGIST
    return NODE_ACCESS_CONTROL


# V10 P1-3: backward-compat alias. Any code (or test) that imported
# ``route_after_recon`` continues to work; new code should use the
# renamed ``route_after_hypothesis``.
route_after_recon = route_after_hypothesis

#: R2-graph-02: route_after_hypothesis can return NODE_STRATEGIST under
#: budget pressure; langgraph 1.2.10 resolves dict path maps strictly
#: (``ends[r]``), so every router return MUST be wired here or the whole
#: run dies with KeyError exactly in the over-budget scenario the R-B
#: governor exists to converge.
HYPOTHESIS_PATH_MAP: dict = {
    NODE_ACCESS_CONTROL: NODE_ACCESS_CONTROL,
    NODE_REPORTER: NODE_REPORTER,
    NODE_STRATEGIST: NODE_STRATEGIST,
}


def route_after_chainer(state: PentestState) -> str:
    """Conditional edge after ``exploit_chainer``: re-enter the exploit
    loop for new chained candidates, or proceed straight to
    post-exploitation if none were proposed.

    V7 "Apex Predator": exploit_chainer never executes anything itself
    (see its module docstring) — it only appends Pending findings
    tagged ``tool_name="exploit_chainer"``. If any exist, route back
    through NODE_PAYLOAD_GENERATOR so they get the exact same
    execution_sandbox (HITL-gated) -> validator -> devils_advocate
    treatment as every other finding — there is no shortcut path for
    chained candidates. If none were proposed this pass, proceed
    directly to post_exploitation as before this node existed.

    R-B completion cutoff: under the cutoff the payload_generator
    re-entry is cut (the generator->sandbox->validator cycle costs 4+
    supersteps); chained candidates keep their honest Pending status.
    """
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_POST_EXPLOITATION
    findings: list[Finding] = list(state.get("findings") or [])
    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get for dict-safety.
    from webpent.state.reducers import model_get
    has_new_chain_candidates = any(
        model_get(f, "tool_name") == "exploit_chainer"
        and model_get(f, "confidence_level") == "Pending"
        for f in findings
    )
    return NODE_PAYLOAD_GENERATOR if has_new_chain_candidates else NODE_POST_EXPLOITATION


def route_after_rabbit_hole(state: PentestState) -> str:
    """Conditional edge after ``rabbit_hole``: bounded loop-back to
    Strategist, or fall through to cvss_engine.

    V8 P0 A2: closes the loop that the V7 graph left one-directional.
    When Rabbit Hole emits NEW RABBIT_HOLE-origin hypotheses (status
    UNEXPLORED — i.e. not yet promoted/abandoned by a prior Strategist
    pass), and the loop-back counter has not exceeded
    ``RabbitHolePolicy.max_loop_back_iterations``, route back to the
    Strategist so it can promote/abandon them. Otherwise fall through
    to cvss_engine (the V7 default behaviour).

    Bounded by:
      1. ``RabbitHolePolicy.max_loop_back_iterations`` (default 1, max 3)
         — the policy-level cap.
      2. ``state["rabbit_hole_loop_back_count"]`` — the runtime counter
         the Strategist increments on every re-entry pass.
      3. The presence of NEW RABBIT_HOLE-origin UNEXPLORED hypotheses
         — if all of them have already been decided (PROMOTED /
         ABANDONED), there is nothing for the Strategist to do, so
         we fall through.

    Pure deterministic routing — no LLM. The router does NOT mutate
    state (LangGraph conditional-edge functions must be pure); the
    counter is incremented INSIDE the Strategist node itself.

    R-B completion cutoff: under the cutoff the loop-back to the
    Strategist is cut (cvss_engine is the forward route); the Rabbit
    Hole hypotheses keep their honest UNEXPLORED status.
    """
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_CVSS_ENGINE
    # Local imports to keep the module-import surface minimal.
    try:
        from webpent.config.policies import RabbitHolePolicy
        from webpent.models.hypothesis import HypothesisOrigin, HypothesisStatus
        from webpent.state.reducers import model_get
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        # If imports fail, fail-safe to the V7 default (no loop-back).
        return NODE_CVSS_ENGINE

    # Cap check.
    try:
        policy = RabbitHolePolicy()
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
        return NODE_CVSS_ENGINE
    max_iters = getattr(policy, "max_loop_back_iterations", 0)
    current_count = int(state.get("rabbit_hole_loop_back_count") or 0)
    # ULTIMATE PLAN 2026-10-27, proposal 2 phase 3: when the dynamic
    # step budget is active, the loop-back cap scales with the REMAINING
    # budget instead of the flat policy 1-3 — derived as remaining // 10
    # (10 supersteps = the empirical cost of one rabbit-hole cycle:
    # rabbit_hole -> strategist -> payload_generator -> execution_sandbox
    # -> validator -> devils_advocate -> chainer -> post_exploit ->
    # rabbit_hole), clamped to [policy cap, 6] so the derived value can
    # only ever RELAX the flat cap when the budget genuinely allows it.
    # The completion cutoff above still hard-cuts every loop-back under
    # pressure, so this can never outrun the governor.
    try:
        dynamic_budget = int(state.get("dynamic_step_budget") or 0)
    except (TypeError, ValueError):
        dynamic_budget = 0
    if dynamic_budget > 0:
        derived_cap = max(int(budget_governor.steps_remaining(state) // 10), int(max_iters))
        max_iters = min(max(int(max_iters), derived_cap), 6)
    if max_iters <= 0 or current_count >= max_iters:
        return NODE_CVSS_ENGINE

    # New-hypotheses check: are there any RABBIT_HOLE-origin hypotheses
    # still in the UNEXPLORED status? (INVESTIGATING would also count,
    # but Rabbit Hole always emits UNEXPLORED.)
    hypotheses = state.get("hypotheses") or []
    rabbit_hole_origin = (HypothesisOrigin.RABBIT_HOLE.value
                          if hasattr(HypothesisOrigin, "RABBIT_HOLE")
                          else "rabbit_hole")
    unexplored = (HypothesisStatus.UNEXPLORED.value
                  if hasattr(HypothesisStatus, "UNEXPLORED")
                  else "unexplored")
    has_new = any(
        model_get(h, "origin") == rabbit_hole_origin
        and model_get(h, "status") == unexplored
        for h in hypotheses
    )
    if has_new:
        logger.info(
            "Rabbit Hole -> Strategist loop-back: re-entry %d/%d "
            "(new RABBIT_HOLE-origin hypotheses present).",
            current_count + 1, max_iters,
        )
        return NODE_STRATEGIST
    return NODE_CVSS_ENGINE


def _post_validation_evidence_count(state: Mapping[str, Any]) -> int:
    """TEAM-1 Phase 6: count deterministic validation outcomes in state.

    Evidence = findings whose persisted-class outcome is deterministic:
    Tool-Confirmed or Refuted. Unconfirmed/AI-assessed/pending candidates
    are NOT evidence — replanning on them would re-rank on noise.

    IMPL Phase 2-G: delegates to the shared reducer helper so the
    smart-campaigns replan router and this gate measure evidence
    identically (single source of truth).
    """
    from webpent.state.reducers import deterministic_evidence_count

    return deterministic_evidence_count(state.get("findings") or [])


def _post_validation_replan_eligible(state: Mapping[str, Any]) -> bool:
    """TEAM-1 Phase 6: bounded, evidence-gated replan trigger.

    Constraints (spec):
      * maximum 2 replan entries per run,
      * require monotonic evidence-count increase since the last
        strategist ranking pass,
      * reuses the EXISTING strategist node (no second scheduler).
    """
    try:
        replans_used = int(state.get("post_validation_replan_count") or 0)
    except (TypeError, ValueError):
        replans_used = 0
    if replans_used >= 2:
        return False
    evidence_now = _post_validation_evidence_count(state)
    try:
        evidence_at_last_replan = int(
            state.get("post_validation_replan_evidence_count") or 0
        )
    except (TypeError, ValueError):
        evidence_at_last_replan = 0
    return evidence_now > evidence_at_last_replan


def strategist_node_with_replan_bookkeeping(state: PentestState) -> dict[str, Any]:
    """TEAM-1 Phase 6: existing strategist + bounded replan bookkeeping.

    Wraps — never replaces — the existing strategist ranking logic. On
    every pass it records the current deterministic-evidence count; when
    the pass was evidence-triggered (evidence grew since the recorded
    baseline) it consumes one of the 2 replan entries. The ranking,
    promotion, ToolBoundary, CausalGuard, and LLM candidate-selection
    behaviour are untouched.

    POST-P0 Phase 1: evidence-triggered passes now also append a
    ``replan`` entry to the operator-visible ``decision_log`` state key
    (reason = deterministic evidence growth, with the exact counters and
    remaining budget), so mid-run replans are auditable instead of
    living only in process logs. Purely additive bookkeeping — no
    routing or ranking behaviour changes.
    """
    update: dict[str, Any] = dict(strategist_node(state))
    evidence_now = _post_validation_evidence_count(state)
    try:
        recorded = int(state.get("post_validation_replan_evidence_count") or 0)
    except (TypeError, ValueError):
        recorded = 0
    try:
        replans_used = int(state.get("post_validation_replan_count") or 0)
    except (TypeError, ValueError):
        replans_used = 0
    if evidence_now > recorded:
        new_count = min(2, replans_used + 1)
        update["post_validation_replan_count"] = new_count
        # POST-P0 Phase 1: auditable replan decision (operator-visible).
        entries = list(update.get("decision_log") or [])
        entries.append(
            {
                "decision_type": "replan",
                "rule_fired": (
                    "post_validation_evidence_monotonic_growth "
                    f"({recorded} -> {evidence_now} deterministic outcomes)"
                ),
                "outcome": (
                    "strategist re-rank scheduled on new Tool-Confirmed/Refuted "
                    f"evidence; replan budget {new_count}/2 consumed"
                ),
                "entity_refs": [],
                "metadata": {
                    "evidence_before": recorded,
                    "evidence_after": evidence_now,
                    "replan_budget_used": new_count,
                    "replan_budget_max": 2,
                },
            }
        )
        update["decision_log"] = entries
    update["post_validation_replan_evidence_count"] = max(recorded, evidence_now)
    return update


def route_after_validator(state: PentestState) -> str:
    """Conditional edge after ``validator``: optimize or debunk.

    V5 Sprint 10: The validator's conditional edge now routes to either
    NODE_PAYLOAD_OPTIMIZER (retry unconfirmed findings) or
    NODE_DEVILS_ADVOCATE (proceed to the Devil's Advocate debunking
    pass). The Devil's Advocate node then feeds directly into
    NODE_CVSS_ENGINE.

    R-B budget governor (completion cutoff): while the remaining step
    budget is at or below the completion reserve, optimizer retries and
    the bounded strategist replan are skipped — each retry cycle costs
    2+ supersteps and the reporting tail needs the reserve to converge.
    ROUTING ONLY: no finding's confidence, status, or authority is
    touched here; un-retried candidates keep their honest Pending
    status and are labeled by the existing fail-safe chain.
    """
    if budget_governor.budget_pressure(state)["active"]:
        return NODE_DEVILS_ADVOCATE
    findings: list[Finding] = list(state.get("findings") or [])
    payloads_to_test: dict[str, list[str]] = dict(state.get("payloads_to_test") or {})
    retries: dict[str, int] = dict(state.get("optimization_retries") or {})
    attempt_fingerprints: dict[str, str] = dict(
        state.get("optimization_attempt_fingerprints") or {}
    )

    # V10 EXHAUSTIVE AUDIT (P0-1): use model_get for dict-safety so
    # findings loaded from a checkpoint (plain dicts after SqliteSaver
    # JSON round-trip) don't crash with AttributeError.
    from webpent.state.reducers import model_get
    for finding in findings:
        if not _meets_severity_threshold(finding):
            continue
        if not _is_exploitable(finding):
            continue
        if model_get(finding, "confidence") == Confidence.CONFIRMED.value:
            continue
        # A missing validator/tool is a terminal coverage limitation for this
        # bounded engagement. Retrying payloads cannot create evidence, so
        # fail closed and leave the candidate explicitly for human review.
        confidence_level = model_get(finding, "confidence_level", "")
        evidence = model_get(finding, "evidence") or {}
        if confidence_level == "Needs Human Review":
            continue
        if isinstance(evidence, dict) and (
            evidence.get("validation_unavailable")
            or evidence.get("tool_infra_failure")
        ):
            continue
        fid = str(model_get(finding, "id", ""))
        if not fid or fid not in payloads_to_test:
            continue
        # An empty payload set means no actionable retry exists (for example
        # offline mode, a browser-only validator without Playwright, or a
        # failed payload synthesis). Presence of the dict key alone must not
        # route the graph back into payload_optimizer forever.
        _queued_payloads = payloads_to_test.get(fid) or []
        if not _queued_payloads:
            continue
        # SQLi is confirmed by sqlmap's own payload engine. The synthetic
        # marker exists only to keep the execution-sandbox contract alive;
        # it is not an optimizer payload. Routing it through the optimizer
        # can never make progress and previously caused repeated sqlmap
        # invocations when a POST probe timed out or returned no marker.
        if (
            len(_queued_payloads) == 1
            and _queued_payloads[0] == "__SQLMAP_TOOL_DRIVEN__"
            and str(model_get(finding, "vuln_class", "")) == "sqli"
        ):
            continue
        current_retry = retries.get(fid, 0)
        if current_retry >= _MAX_OPTIMIZATION_RETRIES:
            continue
        current_fingerprint = optimization_attempt_fingerprint(
            finding, _queued_payloads
        )
        if attempt_fingerprints.get(fid) == current_fingerprint:
            logger.info(
                "Validator -> Devil's Advocate for %s: optimizer state made "
                "no progress; identical attempt fingerprint",
                fid,
            )
            continue
        return NODE_PAYLOAD_OPTIMIZER
    # TEAM-1 Phase 6 (post-validation replan): a validated finding or a
    # meaningful refutation is NEW deterministic evidence that materially
    # changes the research state — give the existing strategist a fresh
    # ranking pass. Bounded (max 2 entries/run) and monotonic (evidence
    # count must strictly exceed the last recorded baseline).
    if _post_validation_replan_eligible(state):
        logger.info(
            "Validator -> Strategist replan: deterministic evidence grew "
            "(confirmed+refuted=%d, used=%d/2) — re-ranking research state.",
            _post_validation_evidence_count(state),
            int(state.get("post_validation_replan_count") or 0),
        )
        return NODE_STRATEGIST
    # V5 Sprint 10: changed from NODE_CVSS_ENGINE to NODE_DEVILS_ADVOCATE
    return NODE_DEVILS_ADVOCATE


def route_after_devils_advocate(state: PentestState) -> str:
    """Route DA rejections through one bounded validator re-check.

    The Devil's Advocate is a hard gate for a fresh high-confidence
    rejection. The node marks those findings as Pending and records the
    revalidation trace; this router sends them back to the deterministic
    validator exactly once, then falls through to the normal chain.
    """
    revalidation_ids = state.get("devils_advocate_revalidation_ids") or []
    revalidation_count = int(state.get("devils_advocate_revalidation_count") or 0)
    gate_active = bool(state.get("devils_advocate_gate_active"))
    if gate_active and revalidation_ids and revalidation_count == 1:
        return NODE_VALIDATOR
    return NODE_EXPLOIT_CHAINER


def make_cqa_v2_reporter_wrapper(base_reporter):
    """TEAM-1 Phase 9: factory wrapping ANY selected reporter variant.

    Wires the previously import-only ``run_cqa_v2_postprocess`` seam so the
    intended supplementary architecture is REAL. Governance is enforced by
    construction: the post-process receives finding COPIES, its result is
    stored under a dedicated non-authoritative state key, and the original
    findings are never mutated. Off by default (Settings.enable_cqa_v2).
    """

    def _cqa_v2_reporter_node(state: PentestState) -> dict[str, Any]:
        update: dict[str, Any] = dict(base_reporter(state))
        try:
            settings = get_settings()
            if getattr(settings, "enable_cqa_v2", False):
                from webpent.cqa_v2.pipeline_integration import (
                    run_cqa_v2_postprocess,
                )

                findings_payload = [
                    f.model_dump(mode="json") if hasattr(f, "model_dump") else dict(f)
                    for f in (state.get("findings") or [])
                ]
                update["cqa_v2_postprocess"] = run_cqa_v2_postprocess(
                    findings_payload,
                    enable_smart=bool(getattr(settings, "enable_smart", False)),
                    asset_context=(state.get("smart_governance") or {}),
                )
                logger.info(
                    "CQA v2 supplementary post-process attached (%d finding(s), "
                    "smart=%s) — original findings unchanged.",
                    len(findings_payload),
                    bool(getattr(settings, "enable_smart", False)),
                )
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError):
            # Supplementary layer: never break the report path.
            logger.exception("CQA v2 post-process failed; report continues unchanged")
            update["cqa_v2_postprocess"] = {
                "status": "failed",
                "governance_note": "supplementary layer failure is non-authoritative",
            }
        return update

    return _cqa_v2_reporter_node


def build_graph(checkpointer: Any = None, auto_approve: bool = False,
                engagement_id: str | None = None):
    """Construct and compile the WebPent engagement graph.

    Args:
        checkpointer: Optional LangGraph checkpointer for state persistence.
        auto_approve: If ``True``, compile without ``interrupt_before``
            so the graph runs to completion without pausing for human
            approval. Used for automated scanning pipelines.
        engagement_id: Optional default engagement identity for graph state.

    Returns:
        A compiled :class:`CompiledStateGraph`.

    Raises:
        UnsupportedLegacyOnlyModeError: when the spine mode resolves
            disabled (the import-time constant ``MODERN_SPINE_ENABLED`` is
            False, i.e. ``WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY``).

    R3 E-2 (Ruling R3-002 §3.3 — BYP-05 builder-level fail-closed
    rejection): ``build_graph`` is the earliest composition point ALL
    entry surfaces traverse (cli / api-dispatched worker / worker /
    resume). When the spine mode resolves disabled, composition REJECTS
    here — loudly, operator-visibly, pointing at the SDD §8 rollback
    flags — instead of silently continuing legacy-only on any path. The
    node-level raise (modern_spine_integration.py) is retained as
    defense-in-depth. The rollback flags are INDEPENDENT: the
    ``WEBPENT_MODERN_SPINE=0`` downgrade (COMPATIBILITY_LEGACY) keeps
    ``MODERN_SPINE_ENABLED=True`` and does NOT trigger this rejection
    (asserted by tests/test_r3_e2_builder_rejection.py).
    """
    if not MODERN_SPINE_ENABLED:
        # R3 E-2: never re-route, only reject — at the composition point.
        raise UnsupportedLegacyOnlyModeError(
            "WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY refuses to "
            "compose the engagement graph: no legacy-only continuation on "
            "any entry surface (cli / api / worker / resume). The modern "
            "production spine is the only authoritative recon/research "
            "path. To restore graph composition, unset "
            "WEBPENT_MODERN_SPINE_MODE or set it to COMPATIBILITY_LEGACY "
            "(see SDD §8 — feature flags / rollback semantics; the "
            "authority rollback flag is deliberately independent of the "
            "composition rollback flags)."
        )
    graph = StateGraph(PentestState)

    # Track 2 (VIP speed initiative, 2026-10-19): resolved once per build
    # and threaded through both node registration (to strip the
    # conflicting current_phase write — see _strip_current_phase) and edge
    # wiring (to insert the recon_fanout/recon_join pair) below. Default
    # False ⇒ byte-for-byte the same topology and node behavior as before
    # this change.
    _parallel_recon = _parallel_recon_enabled()

    graph.add_node(NODE_PLANNER, _trace_wrap(NODE_PLANNER, planner_node))
    graph.add_node(NODE_AUTH, _trace_wrap(NODE_AUTH, auth_node))
    # TEAM-1: Modern spine is the DEFAULT recon path. The modern_spine_recon_node
    # runs DeepReconEngine -> WorldModel -> ResearchControlLoop (authoritative),
    # then the legacy recon_node runs as advisory/compatibility (its output is
    # marked advisory_only and cannot bypass authority). If MODERN_SPINE_ENABLED
    # is False (emergency rollback only), the legacy node runs alone.
    # R2-graph-01: the combined recon node is built by the module-level
    # factory above and returns ONLY the node's delta. The previous inline
    # version returned the full input state, so every pre-recon entry of
    # the append-only node_step_trace channel was appended a second time
    # (merge_lists has no dedup) and the budget governor's consumed count
    # was permanently inflated on the default production path.
    _combined_recon_node = _make_combined_recon_node(engagement_id)

    graph.add_node(NODE_RECON, _trace_wrap(NODE_RECON, _combined_recon_node))
    # TEAM-1 CRITICAL fix: run_research_campaign is now part of STANDARD production graph path.
    # Invokes automatic fabric dispatch (real HTTP execution, no fake observations).
    def _research_campaign_node(state):
        # M2-impl WP-B (R2 of Ruling M2-001): the campaign lane acquires its
        # orchestrator via FACTORY RE-DERIVATION from declared state keys.
        # State transport of the live orchestrator object is PROHIBITED
        # (Ruling 2a; checkpoint serialization fails loudly per RED-2 V13)
        # and its writer was removed from the seam. Fail-closed derivation
        # failures become a skip with a persistent marker (R7 adds the
        # operator-visible surface in WP-E) — never a silent continuation.
        from webpent.production.modern_spine_integration import (
            _derive_target_url,
            _load_or_create_campaign_state,
            resolve_spine_orchestrator,
        )
        from webpent.production.production_spine import ProductionSpineError
        try:
            orch, _spine_trace, _spine_cfg, _entrypoint = resolve_spine_orchestrator(state)
        except ProductionSpineError as exc:
            # M2-impl WP-E (R7 of Ruling M2-001): a campaign-lane skip MUST be
            # operator-visible. RED-2 P-1.4 proved the as-shipped skip was
            # FULLY SILENT end-to-end (zero log lines, normal-looking
            # completion) — an honesty defect. Every skip path below now
            # emits a loud, named warning carrying the reason.
            logger.warning(
                "RESEARCH CAMPAIGN SKIPPED (operator-visible, R7): "
                "factory re-derivation failed — %s", exc)
            return {"research_campaign_skipped": f"no_orchestrator: {exc}"[:200],
                    "research_campaign_executed": False}
        hyps = state.get("hypotheses", state.get("candidate_hypotheses", []))
        if not hyps:
            logger.warning(
                "RESEARCH CAMPAIGN SKIPPED (operator-visible, R7): no "
                "hypotheses in the declared channel "
                "(hypotheses/candidate_hypotheses both empty)")
            return {"research_campaign_skipped": "no_hypotheses"}
        target = _derive_target_url(state) or "https://lab.example.com"
        # M2-impl WP-C (R3 of Ruling M2-001): REHYDRATION IS MANDATORY. The
        # factory re-derivation above yields a FRESH orchestrator with an
        # EMPTY research loop — accepting that state would be the rejected
        # half-fix. The candidates registered at the seam are recovered from
        # the durable, versioned CampaignState and re-registered into the
        # fresh loop (the campaign worker's load -> factory -> re-register
        # reference pattern, executed in-process on the graph path).
        _rehydrated = 0
        _rehydrated_failed = 0
        try:
            _eng_inst = str(state.get("engagement_instance_id") or (
                str(state.get("engagement_id") or "eng_unknown") + "_inst"))
            _campaign_state, _cs_path = _load_or_create_campaign_state(
                _eng_inst, str(target))
            for _rec in _campaign_state.registered_candidates:
                try:
                    orch.research_loop.register_candidate(
                        candidate_id=str(_rec.get("candidate_id", "")),
                        hypothesis_ids=tuple(str(h) for h in (_rec.get("hypothesis_ids") or ())),
                        experiment_signature=str(_rec.get("experiment_signature", "")),
                    )
                    _rehydrated += 1
                except (AttributeError, KeyError, TypeError, ValueError):
                    _rehydrated_failed += 1
        except ProductionSpineError:
            # Corrupted durable state must not silently skip rehydration
            # (replay risk) — the refusal propagates as a campaign error.
            raise
        # TEAM-1 AVI V1: ensure every hypothesis carries a vulnerability_class so
        # the production dispatch routes through AutonomousValidationIntelligence
        # (run_research_campaign delegates to AVI for registry-covered classes).
        # M2-impl WP-D (R4): the dispatch receives CANONICAL forms only. Each
        # channel element is coerced through the canonicalizer - hostile or
        # malformed entries are REJECTED (counted, loud), never dispatched
        # raw through AVI (RED-2 P-4.1) and never crash the lane.
        # ORDER FIX (Dispatch #009-A window reopen, NF-009A-02): canonicalization
        # MUST run before the multi-principal flag gate - the pre-amendment
        # block gated before annotated_hyps was bound, so a flag-deny crashed
        # the lane with NameError instead of failing closed (found during
        # WP-J re-verification; the ALLOW path masked it in the 695 suite).
        from webpent.production.advisory_registration import (
            canonicalize_campaign_hypothesis,
        )
        default_vuln = str(state.get("default_vulnerability_class", "IDOR")).upper()
        annotated_hyps = []
        _hyps_rejected = 0
        for h in list(hyps)[:10]:
            hh, reject_reason = canonicalize_campaign_hypothesis(h, default_vuln)
            if hh is None:
                _hyps_rejected += 1
                logger.warning(
                    "research campaign rejected noncanonical hypothesis "
                    "(fail-closed, not dispatched): reason=%s repr=%.80s",
                    reject_reason, repr(h))
                continue
            annotated_hyps.append(hh)
        # M2-impl WP-F (R6): multi-principal experiment dispatch is gated
        # fail-closed by its spine flag (factory-bound snapshot, rebuilt
        # from THIS node's own factory re-derivation - never from state).
        # Runs AFTER canonicalization so the deny path filters
        # advisory_intake-sourced candidates out of the canonical channel
        # (canonical forms preserve source) instead of crashing.
        from webpent.production.spine_flag_gates import (
            SpineFlagSnapshot,
            gate_multi_principal_execution,
        )
        _mp_gate = gate_multi_principal_execution(
            SpineFlagSnapshot.from_config(_spine_cfg),
            engagement_instance_id=str(state.get("engagement_instance_id") or ""),
            target_fingerprint=str(state.get("target_fingerprint") or ""))
        _flag_gated_out = 0
        if _mp_gate.decision != "ALLOW":
            _pre_gate_count = len(annotated_hyps)
            annotated_hyps = [
                _ch for _ch in annotated_hyps
                if _ch.get("source") != "advisory_intake"
            ]
            _flag_gated_out = _pre_gate_count - len(annotated_hyps)
            if _flag_gated_out:
                logger.warning(
                    "M2 dispatch gated (fail-closed, R6): multi_principal_"
                    "execution=%s/%s - advisory candidates schedulable: NO "
                    "(gated out: %d)", _mp_gate.decision, _mp_gate.reason,
                    _flag_gated_out)
        if not annotated_hyps:
            _skip_reason = (
                "multi_principal_execution_flag_gated"
                if _flag_gated_out else "no_canonical_hypotheses")
            logger.warning(
                "RESEARCH CAMPAIGN SKIPPED (operator-visible, R7): no "
                "schedulable candidates after canonical normalization and "
                "flag gating (canonical_rejected=%d, flag_gated=%d)",
                _hyps_rejected, _flag_gated_out)
            return {"research_campaign_skipped": _skip_reason,
                    "research_campaign_hypotheses_rejected": _hyps_rejected}
        try:
            campaign_result = orch.run_research_campaign(
                target_url=target, hypotheses=annotated_hyps,
                max_steps=min(5, len(annotated_hyps)),
            )
            out = {"research_campaign_result": campaign_result,
                   "fabric_dispatch_trace": orch._fabric_dispatch_trace,
                   "research_campaign_executed": True,
                   "research_campaign_hypotheses_rejected": _hyps_rejected,
                   "research_loop_rehydrated": _rehydrated,
                   "research_loop_rehydrated_failed": _rehydrated_failed,
                   "research_loop_active_candidates": len(getattr(orch.research_loop, "_candidates", {}) or {}),
                   "avi_production_dispatch": campaign_result.get("legacy_run_research_campaign_delegated", False),
                   "manual_path_used": campaign_result.get("manual_path_used", False)}
            # Surface AVI artifacts on the graph state for downstream consumers.
            if "avi_version" in campaign_result:
                out["avi_version"] = campaign_result.get("avi_version")
                out["avi_trace_summary"] = campaign_result.get("trace", {})
                out["avi_security_report"] = campaign_result.get("security_report", {})
                out["avi_decisions_executed"] = campaign_result.get("decisions_executed")
                out["avi_promoted_count"] = campaign_result.get("promoted_count")
            # REMEDIATION (hostile-audit D2 / P1): AVI-promoted findings previously
            # lived only in the in-memory SecurityReport and were never merged into
            # state["findings"], so they never reached the persistent ledger. Merge
            # them now as first-class Finding objects, marked with their proof trace.
            # Fail-visible: any per-finding construction failure is counted and logged,
            # never silently dropped. The raw report remains in avi_security_report.
            _avi_promoted = []
            _avi_merge_failed = 0
            try:
                from webpent.models.findings import Finding
                _sec = campaign_result.get("security_report") or {}
                _promoted = (_sec.get("promoted_findings") if isinstance(_sec, dict) else []) or []
                for _pf in _promoted:
                    if not isinstance(_pf, dict):
                        _avi_merge_failed += 1
                        continue
                    _vc = str(_pf.get("vulnerability_class", "UNKNOWN")).upper()
                    try:
                        _f = Finding(
                            title=f"[AVI-promoted] {_vc} finding {_pf.get('finding_id') or _pf.get('hypothesis_id')}",
                            severity="high",
                            description=(
                                f"Autonomously validated by AutonomousValidationIntelligence. "
                                f"outcome={_pf.get('outcome')} evidence_quality={_pf.get('evidence_quality')} "
                                f"identity_bound={_pf.get('identity_bound')} actor={_pf.get('actor_id')} "
                                f"resource={_pf.get('resource_id')} causal_difference={_pf.get('causal_difference')}"
                            ),
                            tool_name="autonomous_validation_intelligence_v1",
                            url=str(target),
                            vuln_class=_vc.lower(),
                            confidence="confirmed",
                            confidence_level="Tool-Confirmed",
                            reasoning=f"AVI PromotionPipeline decision: {(_pf.get('promotion') or {}).get('reason')}",
                            evidence={
                                "avi_promoted": True,
                                "avi_finding_id": _pf.get("finding_id"),
                                "avi_hypothesis_id": _pf.get("hypothesis_id"),
                                "avi_experiment_id": _pf.get("experiment_id"),
                                "avi_bundle_id": _pf.get("bundle_id"),
                                "avi_seal_digest": _pf.get("seal_digest"),
                                "avi_replay_verified": _pf.get("replay_verified"),
                                "avi_proof_seal_verified": _pf.get("proof_seal_verified"),
                                "avi_identity_bound": _pf.get("identity_bound"),
                                "avi_actor_id": _pf.get("actor_id"),
                                "avi_resource_id": _pf.get("resource_id"),
                                "avi_causal_difference": _pf.get("causal_difference"),
                                "avi_discriminating_signal": _pf.get("discriminating_signal"),
                                "avi_proof_trace": _pf.get("proof_trace"),
                                "avi_promotion": _pf.get("promotion"),
                            },
                            references=[],
                        )
                        _avi_promoted.append(_f)
                    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as _mexc:
                        _avi_merge_failed += 1
                        logger.warning(
                            "AVI promoted finding merge failed (fail-visible, not dropped from report): %s",
                            _mexc,
                        )
            except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as _iexc:
                logger.warning("AVI promoted-findings merge block failed: %s", _iexc)
            if _avi_promoted:
                out["findings"] = [*list(state.get("findings") or []), *_avi_promoted]
                out["avi_promoted_merged"] = len(_avi_promoted)
            if _avi_merge_failed:
                out["avi_promoted_merge_failed"] = _avi_merge_failed
            return out
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError) as e:
            logger.warning(
                "RESEARCH CAMPAIGN ERROR (operator-visible, R7): %s", e)
            return {"research_campaign_error": str(e), "research_campaign_executed": False}
    graph.add_node(NODE_RESEARCH_CAMPAIGN, _trace_wrap(NODE_RESEARCH_CAMPAIGN, _research_campaign_node))
    graph.add_node(NODE_CRAWLER, _trace_wrap(NODE_CRAWLER, crawler_node))
    graph.add_node(NODE_JAVASCRIPT_INTELLIGENCE, _trace_wrap(NODE_JAVASCRIPT_INTELLIGENCE, javascript_intelligence_node))
    graph.add_node(
        NODE_SUBDOMAIN_TAKEOVER,
        _trace_wrap(
            NODE_SUBDOMAIN_TAKEOVER,
            _strip_current_phase(subdomain_takeover_node) if _parallel_recon else subdomain_takeover_node,
        ),
    )
    graph.add_node(
        NODE_CLOUD_STORAGE,
        _trace_wrap(
            NODE_CLOUD_STORAGE,
            _strip_current_phase(cloud_storage_node) if _parallel_recon else cloud_storage_node,
        ),
    )
    if _parallel_recon:
        graph.add_node(NODE_RECON_FANOUT, _trace_wrap(NODE_RECON_FANOUT, recon_fanout_node))
        graph.add_node(NODE_RECON_JOIN, _trace_wrap(NODE_RECON_JOIN, recon_join_node))
    graph.add_node(NODE_TARGET_UNDERSTANDING, _trace_wrap(NODE_TARGET_UNDERSTANDING, target_understanding_node))
    graph.add_node(NODE_SCOPE_ENFORCER, _trace_wrap(NODE_SCOPE_ENFORCER, scope_enforcer_node))
    graph.add_node(NODE_SCOPE_REVIEW, _trace_wrap(NODE_SCOPE_REVIEW, scope_review_node))
    graph.add_node(NODE_WAF_DETECTOR, _trace_wrap(NODE_WAF_DETECTOR, waf_detector_node))
    graph.add_node(NODE_HYPOTHESIS, _trace_wrap(NODE_HYPOTHESIS, hypothesis_node))
    graph.add_node(NODE_PAYLOAD_GENERATOR, _trace_wrap(NODE_PAYLOAD_GENERATOR, payload_generator_node))
    graph.add_node(NODE_EXECUTION_SANDBOX, _trace_wrap(NODE_EXECUTION_SANDBOX, execution_sandbox_node))
    graph.add_node(NODE_VALIDATOR, _trace_wrap(NODE_VALIDATOR, validator_node))
    graph.add_node(NODE_DEVILS_ADVOCATE, _trace_wrap(NODE_DEVILS_ADVOCATE, devils_advocate_node))
    graph.add_node(NODE_EXPLOIT_CHAINER, _trace_wrap(NODE_EXPLOIT_CHAINER, exploit_chainer_node))
    graph.add_node(NODE_POST_EXPLOITATION, _trace_wrap(NODE_POST_EXPLOITATION, post_exploitation_node))
    # V7 Cognitive Upgrade Phase 7: Rabbit Hole node — scans the Mental
    # Model for followable artifacts and emits new Hypotheses that
    # re-enter the existing payload_generator pipeline.
    graph.add_node(NODE_RABBIT_HOLE, _trace_wrap(NODE_RABBIT_HOLE, rabbit_hole_node))
    # V7 Cognitive Upgrade Section 4: Strategist — promotion checkpoint.
    graph.add_node(
        NODE_STRATEGIST,
        _trace_wrap(
            NODE_STRATEGIST,
            # TEAM-1 Phase 6: existing strategist + bounded replan bookkeeping.
            strategist_node_with_replan_bookkeeping,
        ),
    )
    # UM-DR-31 (evidence-driven adaptive research loop): the bounded
    # adaptive research node ahead of the strategist planner. Additive
    # and flag-gated fail-closed: with the flag off neither the node nor
    # the edge exists and every conditional mapping keeps its original
    # strategist target (byte-comparable graph shape). With the flag on,
    # strategist-bound routes on the discovery line, the research line
    # and the post-validation replan path are redirected through this
    # node (see the _umdr31_routes call sites), which injects
    # deduplicated evidence-backed hypotheses into the real pool for
    # the UNCHANGED strategist ranking/promotion gates — the closed
    # loop: execution outcomes → updated coverage/invariant state →
    # new research decisions. Non-promoting by construction (no
    # findings, no confirmations, no authority; the causal guard stays
    # the sole confirmation authority).
    if _umdr31_research_loop_enabled():
        from webpent.production.adaptive_research import research_loop_node

        graph.add_node(
            NODE_RESEARCH_LOOP,
            _trace_wrap(NODE_RESEARCH_LOOP, research_loop_node),
        )
        graph.add_edge(NODE_RESEARCH_LOOP, NODE_STRATEGIST)
        logger.info(
            "Adaptive research loop wired (enable_adaptive_research_loop=True)"
        )
    graph.add_node(NODE_PAYLOAD_OPTIMIZER, _trace_wrap(NODE_PAYLOAD_OPTIMIZER, payload_optimizer_node))
    graph.add_node(NODE_CVSS_ENGINE, _trace_wrap(NODE_CVSS_ENGINE, cvss_node))
    graph.add_node(NODE_BUSINESS_IMPACT, _trace_wrap(NODE_BUSINESS_IMPACT, business_impact_node))
    graph.add_node(NODE_CROSS_REASONING, _trace_wrap(NODE_CROSS_REASONING, cross_reasoning_node))
    graph.add_node(NODE_EXECUTIVE_SUMMARY, _trace_wrap(NODE_EXECUTIVE_SUMMARY, executive_summary_node))
    report_node = (
        reporter_node_bug_bounty
        if getattr(get_settings(), "enable_bug_bounty_reporter", False)
        else reporter_node
    )
    # TEAM-1 Phase 9: when the opt-in CQA v2 post-process is enabled the
    # selected reporter is wrapped (supplementary artifacts only, findings
    # untouched); with the flag off the raw selected reporter is registered
    # unchanged so feature-flag selection stays observable.
    if getattr(get_settings(), "enable_cqa_v2", False):
        graph.add_node(
            NODE_REPORTER,
            _trace_wrap(NODE_REPORTER, make_cqa_v2_reporter_wrapper(report_node)),
        )
    else:
        graph.add_node(NODE_REPORTER, _trace_wrap(NODE_REPORTER, report_node))
    graph.add_node(NODE_REFLECTION, _trace_wrap(NODE_REFLECTION, reflection_node))

    # V7 Sprint 2: Register the new vulnerability-coverage agents.
    # These run as a "deep probing" phase between hypothesis and
    # payload_generator. Each agent adds findings to the state, which
    # the rest of the pipeline (validator → devils_advocate → cvss →
    # reporter) processes alongside the hypothesis-generated findings.
    graph.add_node(NODE_ACCESS_CONTROL, _trace_wrap(NODE_ACCESS_CONTROL, access_control_node))
    graph.add_node(NODE_API_TESTING, _trace_wrap(NODE_API_TESTING, api_testing_node))
    graph.add_node(NODE_BUSINESS_LOGIC_FUZZER, _trace_wrap(NODE_BUSINESS_LOGIC_FUZZER, business_logic_fuzzer_node))
    graph.add_node(NODE_REQUEST_SMUGGLING, _trace_wrap(NODE_REQUEST_SMUGGLING, request_smuggling_node))
    graph.add_node(NODE_DISCLOSED_REPORT_INTEL, _trace_wrap(NODE_DISCLOSED_REPORT_INTEL, disclosed_report_intel_node))
    graph.add_node(NODE_SMART_CAMPAIGNS, _trace_wrap(NODE_SMART_CAMPAIGNS, smart_campaigns_node))
    graph.add_node(NODE_SMART_CAMPAIGNS_EXECUTION, _trace_wrap(NODE_SMART_CAMPAIGNS_EXECUTION, smart_campaigns_execution_node))
    graph.add_node(NODE_AUTONOMOUS_CONTROLLER, _trace_wrap(NODE_AUTONOMOUS_CONTROLLER, autonomous_controller_node))
    graph.add_node(NODE_RECOVERY, _trace_wrap(NODE_RECOVERY, recovery_node))
    graph.add_node(NODE_WILDCARD_SCOPE, _trace_wrap(NODE_WILDCARD_SCOPE, wildcard_scope_node))
    graph.add_node(NODE_TARGET_PACKAGE_PREFLIGHT, _trace_wrap(NODE_TARGET_PACKAGE_PREFLIGHT, target_package_preflight_node))
    graph.add_node(NODE_IDENTITY_PROVISIONING, _trace_wrap(NODE_IDENTITY_PROVISIONING, identity_provisioning_node))
    graph.add_node(NODE_IDENTITY_PROVISIONING_PRE_AUTH, _trace_wrap(NODE_IDENTITY_PROVISIONING_PRE_AUTH, identity_provisioning_node))
    graph.add_node(NODE_KNOWLEDGE_GAP, _trace_wrap(NODE_KNOWLEDGE_GAP, knowledge_gap_node))
    graph.add_node(NODE_NEXT_BEST_ACTION, _trace_wrap(NODE_NEXT_BEST_ACTION, next_best_action_node))
    graph.add_node(NODE_RESEARCH_SESSION, _trace_wrap(NODE_RESEARCH_SESSION, research_session_node))
    graph.add_node(NODE_ACTIVE_RESEARCH, _trace_wrap(NODE_ACTIVE_RESEARCH, _active_research_runtime_node))
    graph.add_node(NODE_CAUSAL_RESEARCH, _trace_wrap(NODE_CAUSAL_RESEARCH, causal_research_node))
    if _attack_graph_enabled():
        graph.add_node(NODE_ATTACK_GRAPH, _trace_wrap(NODE_ATTACK_GRAPH, attack_graph_node))
    if _vip_orchestrator_enabled():
        graph.add_node(
            NODE_VIP_ORCHESTRATOR,
            _trace_wrap(NODE_VIP_ORCHESTRATOR, vip_campaign_node),
        )

    # ULTIMATE PLAN 2026-10-27 (proposals 2/3/7): the seven additive
    # nodes. Each is a pass-through when its flag is off or the target
    # carries no relevant surface — zero side effects, zero requests,
    # zero finding authority. Registered unconditionally (same pattern
    # as the V7 deep-probe agents); the internal gating lives in the
    # node functions themselves (graph/lesson_nodes.py,
    # graph/surface_sizing.py, graph/detector_nodes.py) so the wiring
    # below stays unconditional and simple.
    from webpent.graph.detector_nodes import (
        cache_poisoning_node,
        graphql_testing_node,
        oauth_misconfig_node,
        prototype_pollution_node,
    )
    from webpent.graph.lesson_nodes import (
        lesson_consultation_node,
        lesson_extraction_node,
    )
    from webpent.graph.surface_sizing import surface_sizing_node

    graph.add_node(NODE_LESSON_CONSULTATION, _trace_wrap(NODE_LESSON_CONSULTATION, lesson_consultation_node))
    graph.add_node(NODE_LESSON_EXTRACTION, _trace_wrap(NODE_LESSON_EXTRACTION, lesson_extraction_node))
    graph.add_node(NODE_SURFACE_SIZING, _trace_wrap(NODE_SURFACE_SIZING, surface_sizing_node))
    graph.add_node(NODE_GRAPHQL_TESTING, _trace_wrap(NODE_GRAPHQL_TESTING, graphql_testing_node))
    graph.add_node(NODE_CACHE_POISONING, _trace_wrap(NODE_CACHE_POISONING, cache_poisoning_node))
    graph.add_node(NODE_PROTOTYPE_POLLUTION, _trace_wrap(NODE_PROTOTYPE_POLLUTION, prototype_pollution_node))
    graph.add_node(NODE_OAUTH_MISCONFIG, _trace_wrap(NODE_OAUTH_MISCONFIG, oauth_misconfig_node))

    # V3.5: CRAWLER -> SCOPE_ENFORCER -> WAF_DETECTOR
    # V6.1: Conditional edge from AUTH — if skip_recon, bypass to HYPOTHESIS.
    graph.add_edge(START, NODE_TARGET_PACKAGE_PREFLIGHT)
    graph.add_conditional_edges(
        NODE_TARGET_PACKAGE_PREFLIGHT,
        route_after_target_package_preflight,
        {NODE_WILDCARD_SCOPE: NODE_WILDCARD_SCOPE, NODE_REPORTER: NODE_REPORTER},
    )
    graph.add_conditional_edges(
        NODE_WILDCARD_SCOPE,
        route_after_wildcard_scope,
        {NODE_PLANNER: NODE_PLANNER, NODE_REPORTER: NODE_REPORTER},
    )
    graph.add_conditional_edges(
        NODE_PLANNER,
        route_after_planner,
        {
            NODE_AUTH: NODE_AUTH,
            NODE_IDENTITY_PROVISIONING_PRE_AUTH: NODE_IDENTITY_PROVISIONING_PRE_AUTH,
            # ULTIMATE PLAN 2026-10-27, proposal 3: the advisory lesson
            # consultation sits between the planner and the pre-auth
            # chain. Its own router continues into identity/auth.
            NODE_LESSON_CONSULTATION: NODE_LESSON_CONSULTATION,
        },
    )
    graph.add_conditional_edges(
        NODE_LESSON_CONSULTATION,
        route_after_lesson_consultation,
        {
            NODE_AUTH: NODE_AUTH,
            NODE_IDENTITY_PROVISIONING_PRE_AUTH: NODE_IDENTITY_PROVISIONING_PRE_AUTH,
        },
    )
    graph.add_edge(NODE_IDENTITY_PROVISIONING_PRE_AUTH, NODE_AUTH)

    # V6.1: Conditional routing after AUTH — skip recon if requested.
    graph.add_conditional_edges(
        NODE_AUTH, route_after_auth,
        {
            NODE_RECON: NODE_RECON,
            NODE_TARGET_UNDERSTANDING: NODE_TARGET_UNDERSTANDING,
            NODE_HYPOTHESIS: NODE_HYPOTHESIS,
        },
    )

    # TEAM-1 CRITICAL B fix: NODE_RESEARCH_CAMPAIGN is now REACHABLE from production path.
    # START → ... → NODE_RECON → NODE_RESEARCH_CAMPAIGN → NODE_CRAWLER → ...
    graph.add_edge(NODE_RECON, NODE_RESEARCH_CAMPAIGN)
    graph.add_edge(NODE_RESEARCH_CAMPAIGN, NODE_CRAWLER)
    # Track 2 (VIP speed initiative, 2026-10-19): when parallel-recon is
    # enabled, every router that used to hand off directly to
    # NODE_SUBDOMAIN_TAKEOVER instead hands off to NODE_RECON_FANOUT, which
    # fans out to NODE_SUBDOMAIN_TAKEOVER and NODE_CLOUD_STORAGE concurrently
    # (same superstep). The router FUNCTIONS themselves
    # (route_after_crawler_with_identity, route_after_crawler) are
    # UNCHANGED — they still decide and return the literal string
    # NODE_SUBDOMAIN_TAKEOVER; only what that returned key maps to in each
    # add_conditional_edges() destination dict changes. When disabled
    # (default), _subdomain_entry == NODE_SUBDOMAIN_TAKEOVER and every edge
    # below is byte-for-byte identical to the pre-Track-2 sequential chain.
    _subdomain_entry = NODE_RECON_FANOUT if _parallel_recon else NODE_SUBDOMAIN_TAKEOVER
    graph.add_conditional_edges(
        NODE_CRAWLER,
        route_after_crawler_with_identity,
        {
            NODE_JAVASCRIPT_INTELLIGENCE: NODE_JAVASCRIPT_INTELLIGENCE,
            NODE_SUBDOMAIN_TAKEOVER: _subdomain_entry,
            NODE_IDENTITY_PROVISIONING: NODE_IDENTITY_PROVISIONING,
        },
    )
    graph.add_conditional_edges(
        NODE_IDENTITY_PROVISIONING,
        route_after_crawler,
        {
            NODE_JAVASCRIPT_INTELLIGENCE: NODE_JAVASCRIPT_INTELLIGENCE,
            NODE_SUBDOMAIN_TAKEOVER: _subdomain_entry,
        },
    )
    graph.add_edge(NODE_JAVASCRIPT_INTELLIGENCE, _subdomain_entry)
    if _parallel_recon:
        # Fan-out: both edges share NODE_RECON_FANOUT as their sole
        # predecessor, so LangGraph schedules both in the same superstep.
        # Fan-in: both edges target NODE_RECON_JOIN, which LangGraph does
        # not execute until every edge feeding it this superstep has fired
        # (verified empirically — see UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md).
        graph.add_edge(NODE_RECON_FANOUT, NODE_SUBDOMAIN_TAKEOVER)
        graph.add_edge(NODE_RECON_FANOUT, NODE_CLOUD_STORAGE)
        graph.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_RECON_JOIN)
        graph.add_edge(NODE_CLOUD_STORAGE, NODE_RECON_JOIN)
        _infra_router_origin = NODE_RECON_JOIN
    else:
        graph.add_edge(NODE_SUBDOMAIN_TAKEOVER, NODE_CLOUD_STORAGE)
        _infra_router_origin = NODE_CLOUD_STORAGE
    # route_after_infrastructure reads only settings-derived flags
    # (_target_understanding_enabled()/_smart_campaigns_enabled()), never
    # subdomain_takeover's or cloud_storage's output — so attaching it to
    # NODE_RECON_JOIN instead of NODE_CLOUD_STORAGE changes nothing about
    # its decision, only ensures it fires after BOTH branches have merged
    # their findings/crawled_data into state.
    graph.add_conditional_edges(
        _infra_router_origin,
        route_after_infrastructure,
        {
            NODE_TARGET_UNDERSTANDING: NODE_TARGET_UNDERSTANDING,
            NODE_SCOPE_ENFORCER: NODE_SCOPE_ENFORCER,
        },
    )
    graph.add_edge(NODE_TARGET_UNDERSTANDING, NODE_SCOPE_ENFORCER)
    graph.add_conditional_edges(
        NODE_SCOPE_ENFORCER,
        route_after_scope_enforcer,
        {NODE_SCOPE_REVIEW: NODE_SCOPE_REVIEW, NODE_WAF_DETECTOR: NODE_WAF_DETECTOR},
    )
    graph.add_conditional_edges(
        NODE_SCOPE_REVIEW,
        route_after_scope_review,
        {NODE_WAF_DETECTOR: NODE_WAF_DETECTOR, END: END},
    )
    graph.add_edge(NODE_WAF_DETECTOR, NODE_SURFACE_SIZING)
    # ULTIMATE PLAN 2026-10-27, proposal 2: measure the surface right
    # after the WAF stage (crawl data is complete, the exploratory tail
    # has not started) and derive the per-run dynamic step budget. The
    # node is a pass-through when the flag is off — the edge chain is
    # then waf_detector -> surface_sizing -> hypothesis with the sizing
    # node adding two zero-cost supersteps, byte-identical routing.
    graph.add_edge(NODE_SURFACE_SIZING, NODE_HYPOTHESIS)

    graph.add_conditional_edges(
        # V10 P1-3: renamed route_after_recon -> route_after_hypothesis
        # (the router sits after NODE_HYPOTHESIS, not NODE_RECON). The
        # backward-compat alias is kept above for external callers.
        # R2-graph-02: the path map lives in HYPOTHESIS_PATH_MAP and now
        # also wires NODE_STRATEGIST (the budget-pressure return).
        NODE_HYPOTHESIS, route_after_hypothesis, dict(HYPOTHESIS_PATH_MAP),
    )

    # V7 Sprint 2: Deep-probing agent chain.
    # access_control -> api_testing -> business_logic_fuzzer -> request_smuggling
    # -> strategist -> payload_generator
    # Each agent adds findings to the state. After all 4 agents have
    # run, the Strategist (V7 Section 4) promotes high-scoring
    # hypotheses to Findings, then payload_generator picks up all
    # actionable findings (both from the hypothesis and from the deep
    # probes and from Strategist promotions).
    graph.add_edge(NODE_ACCESS_CONTROL, NODE_API_TESTING)
    graph.add_edge(NODE_API_TESTING, NODE_BUSINESS_LOGIC_FUZZER)
    graph.add_edge(NODE_BUSINESS_LOGIC_FUZZER, NODE_REQUEST_SMUGGLING)
    # V7 Cognitive Upgrade Section 4: Strategist promotion checkpoint.
    # Runs after all discovery nodes, before payload_generator. Promotes
    # high-scoring hypotheses to Findings (deterministic score >= threshold).
    # The promoted Findings enter state["findings"] with
    # confidence_level="Pending" — exactly what payload_generator expects.
    graph.add_edge(NODE_REQUEST_SMUGGLING, NODE_GRAPHQL_TESTING)
    # ULTIMATE PLAN 2026-10-27, proposal 7: the four deterministic
    # detector nodes extend the deep-probe chain. Each is a no-op
    # pass-through unless the target carries the relevant surface AND
    # its flag is on (REST-only targets pay four near-zero supersteps —
    # the "صفر أثر جانبي" contract is enforced inside each node).
    graph.add_edge(NODE_GRAPHQL_TESTING, NODE_CACHE_POISONING)
    graph.add_edge(NODE_CACHE_POISONING, NODE_PROTOTYPE_POLLUTION)
    graph.add_edge(NODE_PROTOTYPE_POLLUTION, NODE_OAUTH_MISCONFIG)
    graph.add_edge(NODE_OAUTH_MISCONFIG, NODE_DISCLOSED_REPORT_INTEL)
    if _attack_graph_enabled():
        _intel_routes = {
            NODE_ATTACK_GRAPH: NODE_ATTACK_GRAPH,
            NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
            NODE_STRATEGIST: NODE_STRATEGIST,
        }
        _post_attack_graph_routes = {
            NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
            NODE_STRATEGIST: NODE_STRATEGIST,
        }
        if _vip_orchestrator_enabled():
            _intel_routes[NODE_VIP_ORCHESTRATOR] = NODE_VIP_ORCHESTRATOR
            _post_attack_graph_routes[NODE_VIP_ORCHESTRATOR] = NODE_VIP_ORCHESTRATOR
        graph.add_conditional_edges(
            NODE_DISCLOSED_REPORT_INTEL,
            route_after_disclosed_report_intel,
            _umdr31_routes(_intel_routes),
        )
        graph.add_conditional_edges(
            NODE_ATTACK_GRAPH,
            route_after_attack_graph,
            _umdr31_routes(_post_attack_graph_routes),
        )
    else:
        _intel_routes = {
            NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
            NODE_STRATEGIST: NODE_STRATEGIST,
        }
        if _vip_orchestrator_enabled():
            _intel_routes[NODE_VIP_ORCHESTRATOR] = NODE_VIP_ORCHESTRATOR
        graph.add_conditional_edges(
            NODE_DISCLOSED_REPORT_INTEL,
            route_after_disclosed_report_intel,
            _umdr31_routes(_intel_routes),
        )
    if _vip_orchestrator_enabled():
        graph.add_conditional_edges(
            NODE_VIP_ORCHESTRATOR,
            route_after_vip_orchestrator,
            _umdr31_routes(
                {
                    NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
                    NODE_STRATEGIST: NODE_STRATEGIST,
                }
            ),
        )
    graph.add_edge(NODE_SMART_CAMPAIGNS, NODE_SMART_CAMPAIGNS_EXECUTION)
    graph.add_conditional_edges(
        NODE_SMART_CAMPAIGNS_EXECUTION,
        route_after_smart_campaigns_execution,
        _umdr31_routes(
            {
                NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
                NODE_AUTONOMOUS_CONTROLLER: NODE_AUTONOMOUS_CONTROLLER,
                NODE_STRATEGIST: NODE_STRATEGIST,
            }
        ),
    )
    graph.add_conditional_edges(
        NODE_AUTONOMOUS_CONTROLLER,
        route_after_autonomous_controller,
        {
            NODE_SMART_CAMPAIGNS: NODE_SMART_CAMPAIGNS,
            NODE_RECOVERY: NODE_RECOVERY,
            NODE_KNOWLEDGE_GAP: NODE_KNOWLEDGE_GAP,
            NODE_ACTIVE_RESEARCH: NODE_ACTIVE_RESEARCH,
            NODE_STRATEGIST: NODE_STRATEGIST,
        },
    )
    graph.add_conditional_edges(
        NODE_RECOVERY,
        route_after_recovery,
        {
            NODE_AUTONOMOUS_CONTROLLER: NODE_AUTONOMOUS_CONTROLLER,
            NODE_STRATEGIST: NODE_STRATEGIST,
        },
    )
    graph.add_edge(NODE_KNOWLEDGE_GAP, NODE_NEXT_BEST_ACTION)
    graph.add_edge(NODE_NEXT_BEST_ACTION, NODE_RESEARCH_SESSION)
    graph.add_conditional_edges(
        NODE_RESEARCH_SESSION,
        route_after_research_session,
        {
            NODE_ACTIVE_RESEARCH: NODE_ACTIVE_RESEARCH,
            NODE_STRATEGIST: NODE_STRATEGIST,
        },
    )
    graph.add_conditional_edges(
        NODE_ACTIVE_RESEARCH,
        route_after_active_research,
        {
            NODE_CAUSAL_RESEARCH: NODE_CAUSAL_RESEARCH,
            NODE_STRATEGIST: NODE_STRATEGIST,
        },
    )
    graph.add_conditional_edges(
        NODE_CAUSAL_RESEARCH,
        route_after_causal_research,
        _umdr31_routes(
            {
                NODE_AUTONOMOUS_CONTROLLER: NODE_AUTONOMOUS_CONTROLLER,
                NODE_STRATEGIST: NODE_STRATEGIST,
            }
        ),
    )
    graph.add_edge(NODE_STRATEGIST, NODE_PAYLOAD_GENERATOR)

    # TEAM-1 Phase 6: NODE_STRATEGIST is registered through the replan
    # bookkeeping wrapper (adds bounded replan counters to the strategist's
    # own update; ranking logic untouched).
    # (registration updated below where the node is added)

    graph.add_edge(NODE_PAYLOAD_GENERATOR, NODE_EXECUTION_SANDBOX)
    graph.add_edge(NODE_EXECUTION_SANDBOX, NODE_VALIDATOR)

    # V5 Sprint 10: Insert Devil's Advocate between validator and the
    # optimize/score conditional. The validator's conditional edge now
    # routes to either PAYLOAD_OPTIMIZER (retry) or DEVILS_ADVOCATE
    # (proceed to debunking). Devil's Advocate then feeds into CVSS.
    # TEAM-1 Phase 6: NODE_STRATEGIST added as the bounded
    # post-validation replan target (max 2 entries, monotonic evidence).
    graph.add_conditional_edges(
        NODE_VALIDATOR, route_after_validator,
        _umdr31_routes(
            {
                NODE_PAYLOAD_OPTIMIZER: NODE_PAYLOAD_OPTIMIZER,
                NODE_DEVILS_ADVOCATE: NODE_DEVILS_ADVOCATE,
                NODE_STRATEGIST: NODE_STRATEGIST,
            }
        ),
    )

    graph.add_edge(NODE_PAYLOAD_OPTIMIZER, NODE_EXECUTION_SANDBOX)

    # Phase 5.2: a fresh DA rejection is a hard gate and re-enters the
    # deterministic validator once; accepted/second-pass outcomes continue.
    graph.add_conditional_edges(
        NODE_DEVILS_ADVOCATE,
        route_after_devils_advocate,
        {
            NODE_VALIDATOR: NODE_VALIDATOR,
            NODE_EXPLOIT_CHAINER: NODE_EXPLOIT_CHAINER,
        },
    )
    graph.add_conditional_edges(
        NODE_EXPLOIT_CHAINER, route_after_chainer,
        {
            NODE_PAYLOAD_GENERATOR: NODE_PAYLOAD_GENERATOR,
            NODE_POST_EXPLOITATION: NODE_POST_EXPLOITATION,
        },
    )
    graph.add_edge(NODE_POST_EXPLOITATION, NODE_RABBIT_HOLE)
    # V7 Cognitive Upgrade Phase 7: Rabbit Hole emits new Hypotheses
    # (origin=RABBIT_HOLE) into the hypothesis pool.
    #
    # V8 P0 A2: BOUNDED LOOP-BACK to Strategist. Replaces the V7
    # one-directional edge `rabbit_hole -> cvss_engine` with a
    # conditional edge `rabbit_hole -> {strategist | cvss_engine}`.
    # When RABBIT_HOLE-origin hypotheses are present in state AND the
    # loop-back counter has not exceeded
    # RabbitHolePolicy.max_loop_back_iterations (default 1, max 3),
    # the graph routes back to the Strategist so it can promote the
    # new hypotheses to Findings. The Strategist on re-entry filters
    # to RABBIT_HOLE-origin hypotheses only — heuristic and cross-
    # reasons hypotheses already decided in the first pass are NOT
    # re-processed.
    #
    # The bounded loop-back is the closed loop the V7 plan called out
    # as "the Strategist's responsibility (Section 4), which is a
    # recurring decision function, not a single graph node." Phase A2
    # finally wires it: a Rabbit Hole hypothesis CAN now become a
    # Finding in the same engagement, traceable via hypothesis_id +
    # Decision Log (the Strategist's promotion entry sets branch_id
    # = str(hypothesis.id) on re-entry).
    #
    # HITL safety is inherited: any Finding promoted on re-entry
    # flows through NODE_PAYLOAD_GENERATOR -> NODE_EXECUTION_SANDBOX,
    # which is still gated by interrupt_before when auto_approve=False.
    # The loop-back does NOT add a new interrupt — it re-uses the
    # existing one.
    graph.add_conditional_edges(
        NODE_RABBIT_HOLE, route_after_rabbit_hole,
        {
            NODE_STRATEGIST: NODE_STRATEGIST,
            NODE_CVSS_ENGINE: NODE_CVSS_ENGINE,
        },
    )

    graph.add_edge(NODE_CVSS_ENGINE, NODE_BUSINESS_IMPACT)
    graph.add_edge(NODE_BUSINESS_IMPACT, NODE_CROSS_REASONING)
    # V5 Sprint 11: Executive Summary node runs after cross-reasoning
    # and before the reporter, so the reporter can embed the C-Suite
    # summary + risk score in the final report.
    graph.add_edge(NODE_CROSS_REASONING, NODE_EXECUTIVE_SUMMARY)
    # Track 11 item 5 (2026-10-28): dedup-before-nomination gate. When the
    # flag is ON, the prior-findings review runs between executive_summary
    # and reporter (condition for final-report nomination, fail-safe, zero
    # suppression inside the gate itself). Flag OFF keeps the exact
    # pre-0.17.0 edge so the graph shape stays byte-comparable.
    if getattr(get_settings(), "enable_dedup_gate", False):
        from webpent.vip.dedup_gate import dedup_gate_node

        graph.add_node(
            NODE_DEDUP_GATE,
            _trace_wrap(NODE_DEDUP_GATE, dedup_gate_node),
        )
        graph.add_edge(NODE_EXECUTIVE_SUMMARY, NODE_DEDUP_GATE)
        graph.add_edge(NODE_DEDUP_GATE, NODE_REPORTER)
    else:
        graph.add_edge(NODE_EXECUTIVE_SUMMARY, NODE_REPORTER)

    graph.add_edge(NODE_REPORTER, NODE_REFLECTION)
    # ULTIMATE PLAN 2026-10-27, proposal 3: the closed learning loop's
    # write side — extract and store this campaign's lessons after
    # reflection, then END. Pass-through when the flag is off.
    graph.add_edge(NODE_REFLECTION, NODE_LESSON_EXTRACTION)
    graph.add_edge(NODE_LESSON_EXTRACTION, END)

    # M3 UM-DR-17 (tenant_isolation qualification seam, M1b residual ②):
    # the causal family execution spine — six passive analyzers (incl.
    # tenant_isolation), deterministic validators, ProofBundle sealing,
    # promotion — inserted between execution_sandbox and validator.
    # Additive-only: the direct sandbox→validator edge stays; super-step
    # semantics make the validator wait for both branches. Fail-closed
    # behind the flag; the node itself degrades to plans_pending_execution
    # when no executor is available (replays are never faked).
    if _family_execution_enabled():
        from webpent.families.execution_node import wire_family_execution

        wire_family_execution(graph)
        logger.info("Family execution spine wired (enable_family_execution_spine=True)")

    # UM-DR-30 (Workstream F §8 — campaign-runtime coverage gap map):
    # the advisory coverage_gap_report node, flag-gated fail-closed and
    # wired between the reporter and reflection nodes (additive-only —
    # the existing reporter→reflection edge stays; super-step semantics
    # make reflection wait for both branches). The node projects the
    # final campaign state through the shared coverage ledger and emits
    # an explicit, bounded gap report on the declared channel. Advisory
    # only: no finding vocabulary, no promotion, no confirmation
    # authority (see production/coverage_gap_report.py).
    try:
        from webpent.config.settings import get_settings as _umdr30_settings

        if _umdr30_settings().enable_coverage_gap_report:
            from webpent.production.coverage_gap_report import (
                wire_coverage_gap_report,
            )

            wire_coverage_gap_report(graph)
            logger.info(
                "Coverage gap report node wired (enable_coverage_gap_report=True)"
            )
    except (ImportError, AttributeError, TypeError, ValueError) as _umdr30_exc:
        # builder.py is a p1-hygiene critical file: no broad handlers —
        # these four types cover the realistic wiring failures (optional
        # layer import, settings access, pydantic ValidationError is a
        # ValueError). Anything else SHOULD fail loudly here.
        logger.warning("Coverage gap report wiring skipped safely: %s", _umdr30_exc)

    # M3 UM-DR-17 (OAST production wiring): the out-of-band correlation
    # node — per-hypothesis nonce-bound sessions over the configured
    # provider, emitting CANDIDATE findings only (the bridge's
    # CandidateOnlyRule; promotion stays with the deterministic
    # validator). Additive-only: the direct post_exploitation→rabbit_hole
    # edge stays; fail-closed behind enable_oast; provider unavailable ⇒
    # honest status, interactions never fabricated.
    if _oast_enabled():
        from webpent.graph.oast_nodes import wire_oast_correlation

        wire_oast_correlation(graph)
        logger.info("OAST correlation node wired (enable_oast=True)")

    if auto_approve:
        compiled = graph.compile(checkpointer=checkpointer)
        logger.info("Graph compiled with auto_approve=True (no HITL interrupt)")
    else:
        compiled = graph.compile(
            checkpointer=checkpointer,
            interrupt_before=[NODE_SCOPE_REVIEW, NODE_EXECUTION_SANDBOX],
        )
        logger.info("Graph compiled with HITL interrupt before %s", NODE_EXECUTION_SANDBOX)

    return compiled
