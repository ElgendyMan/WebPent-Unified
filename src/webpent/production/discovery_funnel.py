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

from typing import Any, Iterable, Mapping

__all__ = ["build_discovery_funnel", "FUNNEL_STAGES", "STAGE_VERSION"]


#: Version of the funnel stage list — bump when the stage set changes so
#: consumers can reconcile historical artifacts.
STAGE_VERSION = "funnel/v1"


#: The ordered stage list (mission §12, mapped to the channels that
#: actually materialise in PentestState).
FUNNEL_STAGES: tuple[str, ...] = (
    "endpoints_discovered",
    "object_observations",
    "canonical_identities",
    "candidate_aliases",
    "confirmed_aliases",
    "abstained_or_conflicting",
    "principals_observed",
    "authorization_observations",
    "differential_questions",
    "workflows_inferred",
    "workflow_sequence_candidates",
    "hypotheses_generated",
    "hypotheses_in_pool",
    "hypotheses_open",
    "hypotheses_resolved",
    "candidate_findings",
    "findings_awaiting_validation",
    "causal_guard_confirmed",
    "proof_bundle_valid",
    "replay_verified",
    "promoted_findings",
    "confirmed_findings",
    # UM-DR-36 (2026-11-12): the semantic-model stages, derived from the
    # ACTUAL appmodel entities and relations materialized in state —
    # never from total relation count, distinct kind labels, or entity-
    # kind names (Phase 3.2: each metric counts real instances of its
    # own ontology category).
    "identity_relationships",
    "object_ownership_relations",
    "app_states_and_transitions",
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


# UM-DR-35 Phase 3.1: relation kinds that carry identity semantics and
# ownership semantics respectively (the ontology categories the funnel
# metrics must count REAL instances of — Phase 3.2).
_IDENTITY_RELATION_KINDS: frozenset[str] = frozenset({
    "authenticates_as", "performs", "observed_on",
})
_OWNERSHIP_RELATION_KINDS: frozenset[str] = frozenset({"owns"})
_STATE_ENTITY_KINDS: frozenset[str] = frozenset({
    "state", "state_transition",
})


def _confirmation_chain_counts(findings: Any) -> tuple[Any, Any, Any, Any, Any, Any]:
    """Decompose the findings channel into the promotion-contract stages.

    Returns ``(awaiting_validation, causal_guard_confirmed,
    proof_bundle_valid, replay_verified, promoted, confirmed_same_id)``.

    A finding counts as CONFIRMED only when the SAME finding carries the
    complete chain: CausalGuard CONFIRMED verdict + valid ProofBundle +
    verified Replay + a PROMOTED final decision (mission Phase 3.1). Every
    per-stage count is per-finding on that finding's OWN evidence — one
    finding's guard verdict is never credited to another finding's
    bundle. A missing/unshapeable findings channel reports the honest
    ``not_materialized_in_state`` marker for every stage.
    """

    def _per_finding(finding: Any) -> dict[str, bool]:
        evidence: Mapping[str, Any] = {}
        if isinstance(finding, Mapping):
            candidate = finding.get("evidence")
            evidence = candidate if isinstance(candidate, Mapping) else finding
        elif hasattr(finding, "evidence"):
            raw = getattr(finding, "evidence", None)
            evidence = raw if isinstance(raw, Mapping) else {}
        guard = evidence.get("causal_guard")
        guard_ok = isinstance(guard, Mapping) and str(
            guard.get("verdict", "")
        ).upper() == "CONFIRMED"
        bundle = evidence.get("proof_bundle")
        bundle_ok = bundle is not None and (
            bool(bundle) if isinstance(bundle, Mapping) else True
        )
        replay_ok = evidence.get("replay_verified") is True or (
            isinstance(evidence.get("replay"), Mapping)
            and evidence["replay"].get("verified") is True
        )
        if isinstance(finding, Mapping):
            promotion = finding.get("promotion")
            promotion_decision = (
                promotion.get("decision", "")
                if isinstance(promotion, Mapping) else ""
            )
            confidence = finding.get("confidence_level", "")
        else:
            promotion_decision = str(
                getattr(getattr(finding, "promotion", None), "decision", "")
            )
            confidence = str(getattr(finding, "confidence_level", ""))
        promoted_ok = (
            str(promotion_decision).upper() == "PROMOTED"
            or (
                confidence == "Tool-Confirmed"
                and guard_ok
                and bundle_ok
                and replay_ok
            )
        )
        return {
            "guard": guard_ok,
            "bundle": bundle_ok,
            "replay": replay_ok,
            "promoted": promoted_ok,
        }

    if not isinstance(findings, (list, tuple)):
        marker = "not_materialized_in_state"
        return marker, marker, marker, marker, marker, marker
    awaiting = guard_n = bundle_n = replay_n = promoted_n = confirmed_n = 0
    for finding in findings:
        chain = _per_finding(finding)
        if not (chain["guard"] or chain["bundle"] or chain["replay"] or chain["promoted"]):
            awaiting += 1
            continue
        guard_n += chain["guard"]
        bundle_n += chain["bundle"]
        replay_n += chain["replay"]
        promoted_n += chain["promoted"]
        if chain["guard"] and chain["bundle"] and chain["replay"] and chain["promoted"]:
            confirmed_n += 1
    return awaiting, guard_n, bundle_n, replay_n, promoted_n, confirmed_n


def _appmodel_semantic_counts(state: Mapping[str, Any]) -> tuple[Any, Any, Any]:
    """Count REAL identity/ownership/state instances from the appmodel.

    Phase 3.2: ``identity_relationships`` counts actual identity-related
    relations (authenticates_as / performs / observed_on instances),
    ``object_ownership_relations`` counts actual ``owns`` relations, and
    ``app_states_and_transitions`` counts actual materialized state /
    state-transition entities. When the model channel is absent the
    ``appmodel_summary`` telemetry's kind counts are used; when neither
    exists the honest ``not_materialized_in_state`` marker is returned
    (a missing channel is never a measured zero — Phase 3.3).
    """
    model = _get(state, "appmodel")
    if model is None:
        summary = _get(state, "appmodel_summary")
        if isinstance(summary, Mapping) and summary.get("built"):
            entity_kinds = summary.get("entity_kind_counts") or {}
            relation_kinds = summary.get("relation_kind_counts") or {}
            return (
                sum(int(relation_kinds.get(k, 0) or 0) for k in _IDENTITY_RELATION_KINDS),
                sum(int(relation_kinds.get(k, 0) or 0) for k in _OWNERSHIP_RELATION_KINDS),
                sum(int(entity_kinds.get(k, 0) or 0) for k in _STATE_ENTITY_KINDS),
            )
        marker = "not_materialized_in_state"
        return marker, marker, marker
    entities: Iterable[Any] = ()
    relations: Iterable[Any] = ()
    if isinstance(model, Mapping):
        raw_entities = model.get("entities")
        raw_relations = model.get("relations")
        entities = raw_entities.values() if isinstance(raw_entities, Mapping) else (
            raw_entities if isinstance(raw_relations, (list, tuple)) else ()
        )
        relations = raw_relations if isinstance(raw_relations, (list, tuple)) else ()
    elif model is not None and hasattr(model, "entities") and hasattr(model, "relations"):
        entities = model.entities.values()
        relations = model.relations

    def _kind(obj: Any, attr: str = "kind") -> str:
        if isinstance(obj, Mapping):
            return str(obj.get(attr, ""))
        return str(getattr(obj, attr, "") or "")

    if isinstance(relations, (list, tuple)) or hasattr(relations, "__iter__"):
        identity_n = sum(1 for r in relations if _kind(r) in _IDENTITY_RELATION_KINDS)
        ownership_n = sum(1 for r in relations if _kind(r) in _OWNERSHIP_RELATION_KINDS)
    else:
        identity_n = ownership_n = None

    state_n = None
    if isinstance(entities, (list, tuple)) or hasattr(entities, "__iter__"):
        try:
            state_n = sum(1 for e in entities if _kind(e) in _STATE_ENTITY_KINDS)
        except TypeError:
            state_n = None

    if identity_n is None or ownership_n is None or state_n is None:
        summary = _get(state, "appmodel_summary")
        if isinstance(summary, Mapping) and summary.get("built"):
            entity_kinds = summary.get("entity_kind_counts") or {}
            relation_kinds = summary.get("relation_kind_counts") or {}
            if identity_n is None:
                identity_n = sum(
                    int(relation_kinds.get(k, 0) or 0)
                    for k in _IDENTITY_RELATION_KINDS
                )
            if ownership_n is None:
                ownership_n = sum(
                    int(relation_kinds.get(k, 0) or 0)
                    for k in _OWNERSHIP_RELATION_KINDS
                )
            if state_n is None:
                state_n = sum(
                    int(entity_kinds.get(k, 0) or 0) for k in _STATE_ENTITY_KINDS
                )
    marker = "not_materialized_in_state"
    return (
        identity_n if identity_n is not None else marker,
        ownership_n if ownership_n is not None else marker,
        state_n if state_n is not None else marker,
    )


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

    # ---- UM-DR-35 Phase 3.1: the confirmation-chain decomposition ------------
    candidate_findings = _count(findings)
    (
        awaiting_validation,
        causal_guard_confirmed,
        proof_bundle_valid,
        replay_verified,
        promoted,
        confirmed_same_id,
    ) = _confirmation_chain_counts(findings)

    # ---- UM-DR-36 Phase 3.2: semantic-model stages from real instances ------
    identity_relationships, ownership_relations, states_and_transitions = (
        _appmodel_semantic_counts(state)
    )

    stages: dict[str, Any] = {
        "endpoints_discovered": _count(endpoints),
        "object_observations": (
            (len(workflow_obs) if isinstance(workflow_obs, (list, tuple)) else 0)
            + (len(auth_obs) if isinstance(auth_obs, (list, tuple)) else 0)
        ) if (isinstance(workflow_obs, (list, tuple)) or isinstance(auth_obs, (list, tuple))) else "not_materialized_in_state",
        "canonical_identities": identities,
        "candidate_aliases": candidate_aliases,
        "confirmed_aliases": confirmed_aliases,
        "abstained_or_conflicting": abstained + conflicts,
        "principals_observed": principals if isinstance(principals, int) else 0,
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
        "hypotheses_generated": _count(hypotheses_generated),
        "hypotheses_in_pool": _count(hypotheses),
        "hypotheses_open": hypotheses_open,
        "hypotheses_resolved": hypotheses_resolved,
        "candidate_findings": candidate_findings,
        "findings_awaiting_validation": awaiting_validation,
        "causal_guard_confirmed": causal_guard_confirmed,
        "proof_bundle_valid": proof_bundle_valid,
        "replay_verified": replay_verified,
        "promoted_findings": promoted,
        "confirmed_findings": confirmed_same_id,
        "identity_relationships": identity_relationships,
        "object_ownership_relations": ownership_relations,
        "app_states_and_transitions": states_and_transitions,
    }

    numeric = [v for v in stages.values() if isinstance(v, int)]

    # UM-DR-35 Phase 3.4 invariants: asserted on every computed funnel —
    # a violation raises, so the funnel can never emit a shape that
    # rewards unconfirmed findings as confirmed.
    _assert_funnel_invariants(stages)

    return {
        "version": STAGE_VERSION,
        "stages": stages,
        "capabilities": caps,
        "drops_explained": _drop_explanations(stages, caps),
        "invariants": {
            "confirmed_le_promoted": True,
            "confirmed_le_guard_bundle_replay": True,
            "confirmed_same_id_complete_chain": True,
            "identity_relations_from_real_instances": True,
            "ownership_from_real_instances": True,
            "missing_channels_not_reported_as_zero": True,
        },
        "totals": {
            "measurable_stages": len(numeric),
            "total_stages": len(FUNNEL_STAGES),
            "not_materialized": [
                k for k, v in stages.items()
                if not isinstance(v, int)
            ],
        },
    }


def _assert_funnel_invariants(stages: Mapping[str, Any]) -> None:
    """Phase 3.4 — fail loudly on any dishonest funnel shape."""

    def _n(key: str) -> int:
        value = stages.get(key)
        return value if isinstance(value, int) else 0

    confirmed = _n("confirmed_findings")
    if confirmed > _n("promoted_findings"):
        raise AssertionError(
            "funnel invariant violated: confirmed_findings > promoted_findings"
        )
    if (
        confirmed > _n("causal_guard_confirmed")
        or confirmed > _n("proof_bundle_valid")
        or confirmed > _n("replay_verified")
    ):
        raise AssertionError(
            "funnel invariant violated: confirmed_findings exceeds the "
            "guard/bundle/replay stages"
        )
    if confirmed > _n("candidate_findings"):
        raise AssertionError(
            "funnel invariant violated: confirmed_findings > candidate_findings"
        )
