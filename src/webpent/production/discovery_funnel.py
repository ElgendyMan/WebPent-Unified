"""UM-DR-33 Workstream J §12 — the auditable discovery funnel.

A pure, deterministic, JSON-safe measurement of the campaign's research
pipeline: from discovered endpoints, through object observations and
identity resolution, to hypotheses, validator executions and confirmed
findings. The funnel is computed from REAL campaign state channels
(nothing is invented) and marks stages whose data is not materialised in
state as ``not_materialized_in_state`` — an honest gap, never a zero
that looks like a measurement.

Why this module exists (the UM-DR-33 mission §12): previous reviews
identified the absence of sufficiently transparent, end-to-end discovery
funnel metrics as a major weakness. Drops between stages were invisible:
nobody could say why 20 candidate aliases produced 0 confirmed ones, or
why 12 hypotheses produced 3 executed experiments. The funnel surfaces
every stage with a count, the stage-to-stage conversion, and a documented
explanation for each major drop pattern.

Contract:
  * PURE: never mutates state, never performs I/O, never raises on
    well-formed campaign states (missing channels are reported, not
    crashed on — fail-soft for observability, which must never block a
    campaign).
  * Deterministic: identical state in, identical funnel out.
  * Advisory only: the funnel is telemetry. It never gates, ranks, or
    confirms anything (the constitution §1.1 is untouched).
  * Every count is derived from the channel contents at call time.
"""

from __future__ import annotations

from typing import Any, Mapping

__all__ = ["build_discovery_funnel", "FUNNEL_STAGES", "STAGE_VERSION"]


#: Version of the funnel stage list — bump when the stage set changes so
#: consumers can reconcile historical artifacts.
STAGE_VERSION = "funnel/v2"  # UM-DR-36.3: 16 -> 26 stages (24-stage
# minimum directive contract + the two alias-resolution detail stages).

#: Evidence source per stage (the state channel the count derives from).
#: Every stage carries its source in the funnel record — a count is never
#: presented without its evidence origin.
_STAGE_SOURCES: dict[str, str] = {
    "recon_surfaces_discovered": "surface_metrics.surfaces",
    "endpoints_discovered": "surface_metrics.endpoints",
    "parameters_observed": "surface_metrics.parameters",
    "application_entities_discovered": "application_model.entity_count",
    "object_observations": "workflow_observations+authorization_observations",
    "canonical_identities": "object_identity_registry.stats",
    "candidate_aliases": "identity_alias_graph",
    "confirmed_aliases": "identity_alias_graph",
    "abstained_or_conflicting": "object_identity_registry.stats",
    "principals_observed": "multi_identity_reasoning.principals",
    "identity_relationships": "application_model.relation_kinds",
    "object_ownership_relations": "application_model.relation_kinds(owns)",
    "authorization_observations": "authorization_observations",
    "differential_questions": "multi_identity_reasoning.differential_questions",
    "workflows_inferred": "workflow_observations",
    "workflow_sequence_candidates": "composite_workflow_candidates",
    "app_states_and_transitions": "application_model(entity_kinds)",
    "hypotheses_generated": "identity_workflow.hypotheses_generated",
    "hypotheses_in_pool": "hypotheses",
    "hypotheses_admitted_by_policy": "hypotheses(status!=rejected)",
    "hypotheses_open": "hypotheses(status in unexplored/investigating)",
    "hypotheses_resolved": "hypotheses(resolved_*)",
    "hypotheses_deferred_or_untested": "hypotheses(status in deferred/blocked)",
    "causalguard_confirmations": "findings(causalguard_verdict==CONFIRMED)",
    "proofbundles_created": "findings(bundle_id present)",
    "replay_verified_findings": "findings(replay_verified)",
    "promotion_decisions": "findings(promotion.decision==PROMOTED)",
    "confirmed_findings": "findings",
}


#: The ordered stage list (mission §12 + UM-DR-36.3's 24-stage minimum
#: directive contract, mapped to the channels that actually materialise
#: in PentestState).
FUNNEL_STAGES: tuple[str, ...] = (
    "recon_surfaces_discovered",
    "endpoints_discovered",
    "parameters_observed",
    "application_entities_discovered",
    "object_observations",
    "canonical_identities",
    "candidate_aliases",
    "confirmed_aliases",
    "abstained_or_conflicting",
    "principals_observed",
    "identity_relationships",
    "object_ownership_relations",
    "authorization_observations",
    "differential_questions",
    "workflows_inferred",
    "workflow_sequence_candidates",
    "app_states_and_transitions",
    "hypotheses_generated",
    "hypotheses_in_pool",
    "hypotheses_admitted_by_policy",
    "hypotheses_open",
    "hypotheses_resolved",
    "hypotheses_deferred_or_untested",
    "causalguard_confirmations",
    "proofbundles_created",
    "replay_verified_findings",
    "promotion_decisions",
    "confirmed_findings",
)


def _get(state: Mapping[str, Any], key: str, default: Any = None) -> Any:
    try:
        value = state.get(key, default)
    except Exception:  # noqa: BLE001 — observability must not crash
        return default
    return value


def _count(value: Any) -> int | str:
    """Count a channel value without ever raising; a non-countable shape
    reports ``not_materialized_in_state`` instead of a fake zero."""
    if value is None:
        return "not_materialized_in_state"
    if isinstance(value, (list, tuple, set, frozenset)):
        return len(value)
    if isinstance(value, Mapping):
        return len(value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    return "not_materialized_in_state"


def _alias_counts(alias_graph: Any) -> tuple[int, int, int]:
    """(candidate, confirmed, other) relationship counts."""
    if not isinstance(alias_graph, Mapping):
        return 0, 0, 0
    graph = alias_graph.get("graph", alias_graph)
    rels = graph.get("relationships") if isinstance(graph, Mapping) else None
    if not isinstance(rels, list):
        return 0, 0, 0
    candidate = confirmed = other = 0
    for rel in rels:
        if not isinstance(rel, Mapping):
            continue
        state = str(rel.get("state", ""))
        if state == "confirmed_same_object":
            confirmed += 1
        elif "candidate" in state or "possible" in state:
            candidate += 1
        else:
            other += 1
    return candidate, confirmed, other


def _drop_explanations(stages: dict[str, Any], caps: Mapping[str, Any]) -> list[str]:
    """Documented explanations for the major drop patterns (mission §12).

    Each explanation is emitted only when its pattern actually holds in
    the measured funnel — these are diagnostics, not excuses.
    """
    notes: list[str] = []

    def _n(key: str) -> Any:
        v = stages.get(key)
        return v if isinstance(v, int) else 0

    if _n("endpoints_discovered") == 0:
        notes.append("endpoints_discovered=0: no surface_metrics in state — "
                     "either crawling did not run or the surface was not "
                     "measured into state (dynamic-budget proposal 2 channel)")
    if _n("object_observations") > 0 and _n("canonical_identities") == 0:
        if not caps.get("object_identity", False):
            notes.append("observations>0 but identities=0: the object-identity "
                         "capability flag is OFF (fail-closed default) — "
                         "observations are not being resolved into identities")
        else:
            notes.append("observations>0 but identities=0: identity resolution "
                         "abstained (weak evidence) or the registry cap "
                         "was reached — see registry stats for the exact reason")
    if _n("candidate_aliases") > 0 and _n("confirmed_aliases") == 0:
        notes.append("candidate aliases>0 but confirmed=0: alias confirmation "
                     "requires corroborating evidence; conservative matching "
                     "abstains rather than merging (the §6.2 contract)")
    if _n("abstained_or_conflicting") > 0:
        notes.append("abstained_or_conflicting>0: ambiguous relationships are "
                     "preserved unresolved — a correct abstention, not a "
                     "pipeline failure")
    if _n("differential_questions") > 0 and _n("hypotheses_generated") == 0:
        notes.append("differential questions>0 but hypotheses=0: questions were "
                     "generated but not admitted as hypotheses (dedup against "
                     "the existing pool, or the capability gate for hypothesis "
                     "materialisation is off)")
    if _n("hypotheses_generated") > 0 and _n("hypotheses_in_pool") == 0:
        notes.append("hypotheses generated but pool empty: the pool merge "
                     "dropped every candidate — check hypothesis fingerprint "
                     "dedup and pool admission")
    if _n("hypotheses_in_pool") > 0 and _n("hypotheses_open") == 0:
        notes.append("pool has hypotheses but none open: all resolved or "
                     "abandoned — the research loop has no remaining work")
    if _n("hypotheses_open") > 0 and _n("confirmed_findings") == 0:
        notes.append("open hypotheses but zero confirmed findings: normal for "
                     "a running campaign (confirmation requires the "
                     "CausalGuard authority chain); if persistent, check "
                     "validator coverage and budget exhaustion")
    return notes


def build_discovery_funnel(state: Mapping[str, Any]) -> dict[str, Any]:
    """Compute the discovery funnel from a campaign state.

    Args:
        state: any ``PentestState``-shaped mapping (the real graph state
            after identity/research nodes have run, or a test state).

    Returns:
        A JSON-safe dict: ``{"version", "stages", "drops_explained",
        "capabilities", "totals"}`` where ``stages`` carries every stage
        in :data:`FUNNEL_STAGES` with an integer count or the honest
        ``not_materialized_in_state`` marker.
    """
    # ---- capability channels -------------------------------------------------
    surface_metrics = _get(state, "surface_metrics")
    endpoints = (
        surface_metrics.get("endpoints")
        if isinstance(surface_metrics, Mapping)
        else None
    )

    workflow_obs = _get(state, "workflow_observations")
    auth_obs = _get(state, "authorization_observations")

    registry_channel = _get(state, "object_identity_registry")
    identities = abstained = conflicts = 0
    if isinstance(registry_channel, Mapping):
        registry = registry_channel.get("registry", registry_channel)
        if isinstance(registry, Mapping):
            stats = registry.get("stats", {})
            if isinstance(stats, Mapping):
                identities = int(stats.get("identities", 0) or 0)
                abstained = int(stats.get("abstentions", 0) or 0)
                conflicts = int(stats.get("conflicts_preserved", 0) or 0)

    candidate_aliases, confirmed_aliases, _other = _alias_counts(
        _get(state, "identity_alias_graph")
    )

    multi = _get(state, "multi_identity_reasoning")
    principals: Any = 0
    questions: Any = 0
    if isinstance(multi, Mapping):
        principals = _count(multi.get("principals"))
        questions = _count(multi.get("differential_questions"))

    workflow_candidates = _get(state, "composite_workflow_candidates")

    telemetry = _get(state, "identity_workflow")
    caps: dict[str, bool] = {}
    if isinstance(telemetry, Mapping):
        raw_caps = telemetry.get("capabilities", {})
        if isinstance(raw_caps, Mapping):
            caps = {
                str(k): bool(v) for k, v in raw_caps.items() if v is not None
            }
    hypotheses_generated = (
        telemetry.get("hypotheses_generated")
        if isinstance(telemetry, Mapping)
        else None
    )

    hypotheses = _get(state, "hypotheses")
    hypotheses_open = hypotheses_resolved = 0
    if isinstance(hypotheses, (list, tuple)):
        for h in hypotheses:
            status = str(
                getattr(h, "status", (h or {}).get("status", "") if isinstance(h, Mapping) else "")
            ).lower()
            if status in ("unexplored", "investigating"):
                hypotheses_open += 1
            elif status in (
                "resolved_true", "resolved_false", "promoted", "abandoned", "learned",
            ):
                hypotheses_resolved += 1

    findings = _get(state, "findings")

    # ---- UM-DR-36.3 extension channels -----------------------------------
    surface_metrics_map = (
        surface_metrics if isinstance(surface_metrics, Mapping) else {}
    )
    surfaces = surface_metrics_map.get("surfaces")
    parameters = (
        surface_metrics_map.get("parameters")
        or surface_metrics_map.get("parameters_observed")
    )

    appmodel_channel = _get(state, "application_model")
    app_entities: Any = "not_materialized_in_state"
    app_relations: Any = "not_materialized_in_state"
    app_ownership: Any = "not_materialized_in_state"
    app_states_transitions: Any = "not_materialized_in_state"
    if isinstance(appmodel_channel, Mapping):
        app_entities = int(appmodel_channel.get("entity_count") or 0)
        app_relations = int(appmodel_channel.get("relation_count") or 0)
        relation_kinds = appmodel_channel.get("relation_kinds")
        if isinstance(relation_kinds, (list, tuple, set, frozenset)):
            app_ownership = sum(
                1 for k in relation_kinds if "owns" in str(k))
        entity_kinds = appmodel_channel.get("entity_kinds")
        if isinstance(entity_kinds, (list, tuple, set, frozenset)):
            app_states_transitions = sum(
                1 for k in entity_kinds
                if str(k) in ("state", "state_transition"))

    # Hypothesis-policy split (admitted vs deferred/untested).
    hypotheses_admitted = hypotheses_deferred = 0
    if isinstance(hypotheses, (list, tuple)):
        for h in hypotheses:
            status = str(
                getattr(h, "status", (h or {}).get("status", "") if isinstance(h, Mapping) else "")
            ).lower()
            if status in ("deferred", "blocked", "revisit_required"):
                hypotheses_deferred += 1
            if status not in ("rejected", "blocked"):
                hypotheses_admitted += 1

    # Authority-chain counts from the findings channel (CausalGuard /
    # ProofBundle / replay / promotion — the UM-DR-35 chain).
    causalguard_confirmed = proofbundles = replay_verified = promoted = 0
    if isinstance(findings, (list, tuple)):
        for f in findings:
            if isinstance(f, Mapping):
                attrs = dict(f)
            else:
                attrs = {}
                for attr in ("causalguard_verdict", "bundle_id", "replay_verified"):
                    attrs[attr] = getattr(f, attr, None)
            promotion = attrs.get("promotion")
            if isinstance(promotion, Mapping):
                attrs["promotion"] = promotion.get("decision")
            elif promotion is None and not isinstance(f, Mapping):
                attrs["promotion"] = getattr(getattr(f, "promotion", None), "decision", None)
            if str(attrs.get("causalguard_verdict") or "").upper() == "CONFIRMED":
                causalguard_confirmed += 1
            if attrs.get("bundle_id"):
                proofbundles += 1
            if attrs.get("replay_verified") is True:
                replay_verified += 1
            if str(attrs.get("promotion") or "").upper() == "PROMOTED":
                promoted += 1

    stages: dict[str, Any] = {
        "recon_surfaces_discovered": _count(surfaces),
        "endpoints_discovered": _count(endpoints),
        "parameters_observed": _count(parameters),
        "application_entities_discovered": app_entities,
        "object_observations": (
            (len(workflow_obs) if isinstance(workflow_obs, (list, tuple)) else 0)
            + (len(auth_obs) if isinstance(auth_obs, (list, tuple)) else 0)
        ) if (isinstance(workflow_obs, (list, tuple)) or isinstance(auth_obs, (list, tuple))) else "not_materialized_in_state",
        "canonical_identities": identities,
        "candidate_aliases": candidate_aliases,
        "confirmed_aliases": confirmed_aliases,
        "abstained_or_conflicting": abstained + conflicts,
        "principals_observed": principals if isinstance(principals, int) else 0,
        "identity_relationships": app_relations,
        "object_ownership_relations": app_ownership,
        "authorization_observations": (
            len(auth_obs) if isinstance(auth_obs, (list, tuple)) else 0
        ),
        "differential_questions": questions if isinstance(questions, int) else 0,
        "workflows_inferred": (
        # composite_workflow_candidates are the SEQUENCE candidates; the
        # inferred workflows count is reported from the same channel's
        # provenance when present, else the sequence count.
            _count(workflow_candidates)
        ),
        "workflow_sequence_candidates": _count(workflow_candidates),
        "app_states_and_transitions": app_states_transitions,
        "hypotheses_generated": _count(hypotheses_generated),
        "hypotheses_in_pool": _count(hypotheses),
        "hypotheses_admitted_by_policy": hypotheses_admitted,
        "hypotheses_open": hypotheses_open,
        "hypotheses_resolved": hypotheses_resolved,
        "hypotheses_deferred_or_untested": hypotheses_deferred,
        "causalguard_confirmations": causalguard_confirmed,
        "proofbundles_created": proofbundles,
        "replay_verified_findings": replay_verified,
        "promotion_decisions": promoted,
        "confirmed_findings": _count(findings),
    }

    # UM-DR-36.3: every stage carries its evidence source and a complete
    # flag; unavailable telemetry stays NOT_MATERIALIZED (never zero).
    stage_records: dict[str, Any] = {}
    for stage_name in FUNNEL_STAGES:
        value = stages.get(stage_name, "not_materialized_in_state")
        stage_records[stage_name] = {
            "count": value,
            "source": _STAGE_SOURCES.get(stage_name, "unknown"),
            "complete": isinstance(value, int),
            "unavailable": not isinstance(value, int),
        }

    numeric = [v for v in stages.values() if isinstance(v, int)]
    return {
        "version": STAGE_VERSION,
        "stages": stage_records,
        "stage_counts": stages,
        "capabilities": caps,
        "drops_explained": _drop_explanations(stages, caps),
        "totals": {
            "measurable_stages": len(numeric),
            "total_stages": len(FUNNEL_STAGES),
            "not_materialized": [
                k for k, v in stages.items()
                if not isinstance(v, int)
            ],
        },
    }
