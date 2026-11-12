"""UM-DR-32 §6/§8 — the unified identity-workflow reasoning node.

One flag-gated, bounded, advisory LangGraph node that connects the four
UM-DR-32 capabilities into the REAL production campaign path:

    observed evidence → object identity → alias graph →
    multi-identity context → workflow/state model → hypotheses →
    (existing strategist / stateful discovery / validator routes)

Data flow (§8): the node reads ONLY real state channels (endpoint
inventory, workflow observations, identity profiles, authorization
observations), builds the typed registries, and emits:

  * ``object_identity_registry``    — the identity registry projection;
  * ``identity_alias_graph``        — the alias/representation overlay;
  * ``multi_identity_reasoning``    — principals (public), matrix
                                      coverage, differential questions;
  * ``composite_workflow_candidates`` — workflows + bounded sequences;
  * ``identity_research_hints``     — ordering-only scheduling hints
                                      consumed by stateful discovery
                                      (same budget, §8 integration
                                      requirement);
  * ``hypotheses``                  — deterministic, deduplicated
                                      hypotheses (privilege_differential,
                                      composite workflow invariants).

The node NEVER confirms anything, never mutates findings, and never
changes authorization scope: CausalGuard (cqa_v2.guarded_causal_evaluate)
remains the sole confirmation authority; the strategist's promotion
rules and the executor's scope gates are untouched.

Fail-closed: every sub-capability is individually flagged and defaults
to OFF; with all flags off the node is not even wired (byte-comparable
graph shape, the UM-DR-31 precedent) and a stale-checkpoint replay
through it returns ``{}`` (runtime double-gate).
"""
from __future__ import annotations

from typing import Any, Mapping

from webpent.production.adaptive_research import (
    _CLASS_COST_LOOKUP,
    _CLASS_RISK_LOOKUP,
    _DEFAULT_CLASS_COST,
    _DEFAULT_CLASS_RISK,
    _admit_endpoint,
    _campaign_origin,
    _hypothesis_id,
    hypothesis_fingerprint,
)
from webpent.production.object_identity import (
    ObjectIdentityRegistry,
    observations_from_campaign_state,
)

__all__ = [
    "IDENTITY_WORKFLOW_NODE_NAME",
    "identity_workflow_enabled",
    "identity_workflow_node",
    "wire_identity_workflow",
]

IDENTITY_WORKFLOW_NODE_NAME = "identity_workflow"


def identity_workflow_enabled() -> bool:
    """Master gate: at least one UM-DR-32 capability flag is on AND the
    mandatory bounds are present (fail-closed on missing limits)."""
    try:
        from webpent.config.settings import get_settings
        settings = get_settings()
        return any((
            bool(settings.enable_object_identity),
            bool(settings.enable_alias_resolution),
            bool(settings.enable_multi_identity_reasoning),
            bool(settings.enable_composite_workflows),
        ))
    except Exception:
        return False


def _settings() -> Any:
    from webpent.config.settings import get_settings
    return get_settings()


def _capabilities_on(settings: Any) -> dict[str, bool]:
    return {
        "object_identity": bool(settings.enable_object_identity),
        "alias_resolution": bool(settings.enable_alias_resolution),
        "multi_identity": bool(settings.enable_multi_identity_reasoning),
        "composite_workflows": bool(settings.enable_composite_workflows),
    }


# ---------------------------------------------------------------------------
# hypothesis construction (deterministic, deduplicated by id)
# ---------------------------------------------------------------------------

def _hypothesis_privilege_differential(
    question: Mapping[str, Any], *, target_url: str,
) -> Any | None:
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin

    endpoint = str(question.get("target_representation") or "")
    obj = str(question.get("target_object_ref") or "")
    if not obj:
        return None
    fingerprint = hypothesis_fingerprint(
        target_url=endpoint or target_url,
        vuln_class="privilege_differential",
        objective_key=f"differential:{obj}",
        principal_refs=[
            str(question.get("owner_principal") or ""),
            str(question.get("foreign_principal") or ""),
        ],
        preconditions=["observed-owner-allowed-operation"],
        state_keys=[],
    )
    return Hypothesis(
        id=_hypothesis_id(fingerprint),
        target_url=endpoint or target_url,
        statement=(
            f"Object {obj} allows an operation for its owner; can the "
            f"{question.get('foreign_principal') or 'foreign'!s} principal "
            "perform it too (privilege differential with negative control)?"
        )[:500],
        vuln_class="privilege_differential",
        status="unexplored",
        confidence_score=0.55,
        evidence_refs=list(question.get("evidence_refs") or [])[:8],
        origin=HypothesisOrigin.INVARIANT,
        origin_detail=(
            f"umdr32_identity_workflow fp={fingerprint} "
            f"question={question.get('question_id')}"
        )[:500],
        estimated_cost=_CLASS_COST_LOOKUP.get(
            "privilege_differential", _DEFAULT_CLASS_COST),
        info_gain=0.6,
        risk=_CLASS_RISK_LOOKUP.get(
            "privilege_differential", _DEFAULT_CLASS_RISK),
        preconditions=["observed-owner-allowed-operation"],
        expected_behavior=(
            "If the differential is real, the foreign principal's request "
            "on the target object succeeds while its negative-control "
            "request is denied — a contrast the causal guard can evaluate."
        )[:500],
        negative_control=(
            "The foreign principal's request on the blanket-restricted "
            "control object must be denied; the owner's request on the "
            "target must succeed."
        )[:500],
        alternatives=["the boundary is enforced and the differential is clean"],
        hint_provenance=["umdr32_multi_identity"],
        request_method="GET",
    )


def _hypothesis_workflow_invariant(
    candidate: Mapping[str, Any], *, target_url: str,
) -> Any | None:
    from webpent.models.hypothesis import Hypothesis, HypothesisOrigin

    steps = list(candidate.get("steps") or [])
    if not steps:
        return None
    last = steps[-1] if isinstance(steps[-1], Mapping) else {}
    endpoint = str(last.get("endpoint") or "")
    invariant = str(candidate.get("invariant") or "")
    if not invariant or not endpoint:
        return None
    fingerprint = hypothesis_fingerprint(
        target_url=endpoint or target_url,
        vuln_class="business_logic",
        objective_key=f"invariant:{invariant}",
        principal_refs=[],
        preconditions=[f"observed-workflow:{candidate.get('workflow_id')}"],
        state_keys=[str(last.get("from_state") or ""), str(last.get("to_state") or "")],
    )
    return Hypothesis(
        id=_hypothesis_id(fingerprint),
        target_url=endpoint or target_url,
        statement=(
            f"Composite sequence tests business invariant '{invariant}': "
            f"{str(candidate.get('hypothesis') or '')[:300]}"
        )[:500],
        vuln_class="business_logic",
        status="unexplored",
        confidence_score=0.5,
        evidence_refs=list(candidate.get("invariant_supporting_refs") or [])[:8],
        origin=HypothesisOrigin.INVARIANT,
        origin_detail=(
            f"umdr32_composite_workflow fp={fingerprint} "
            f"sequence={candidate.get('sequence_id')}"
        )[:500],
        estimated_cost=_CLASS_COST_LOOKUP.get("business_logic", _DEFAULT_CLASS_COST),
        info_gain=0.55,
        risk=_CLASS_RISK_LOOKUP.get("business_logic", _DEFAULT_CLASS_RISK),
        preconditions=[f"observed-workflow:{candidate.get('workflow_id')}"],
        expected_behavior=(
            "If the invariant is violated, the bounded sequence produces a "
            "state/authorization contrast against its control run that the "
            "causal guard can evaluate."
        )[:500],
        negative_control=(
            "The positive-control run of the same sequence from a reset "
            "state under the observed actor must behave as observed."
        )[:500],
        alternatives=["the invariant holds and the sequence outcome is clean"],
        hint_provenance=["umdr32_composite_workflow"],
        request_method=str(last.get("method") or "GET").upper()[:10],
    )


# ---------------------------------------------------------------------------
# the node
# ---------------------------------------------------------------------------

def identity_workflow_node(state: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — one bounded identity/workflow reasoning pass.

    Runtime double-gate (stale checkpoints replay safely), bounded
    outputs, advisory only. Returns ONLY declared channels.
    """
    if not identity_workflow_enabled():
        return {}
    settings = _settings()
    caps = _capabilities_on(settings)
    get = state.get if hasattr(state, "get") else (lambda k, d=None: d)

    target_url = str(get("base_url") or get("target_url") or "")
    base_url = target_url
    campaign_origin = _campaign_origin(base_url)
    update: dict[str, Any] = {}
    telemetry: dict[str, Any] = {
        "capabilities": caps,
        "hypotheses_generated": 0,
        "hypothesis_origins": {},
    }

    # 1. Object identity registry (§4)
    registry = ObjectIdentityRegistry(
        max_identities=int(getattr(settings, "max_object_identities", 5000)),
    )
    observations = observations_from_campaign_state(state)
    for obs in observations:
        registry.ingest(obs)
    if caps["object_identity"]:
        update["object_identity_registry"] = {
            "registry": registry.as_dict(),
        }

    # 2. Alias resolution overlay (§5) — depends on the registry
    if caps["alias_resolution"]:
        from webpent.production.alias_resolution import AliasResolver

        resolver = AliasResolver(registry)
        resolver.resolve(
            observations,
            max_pairs=int(getattr(settings, "max_alias_pairs", 500)),
        )
        update["identity_alias_graph"] = {"graph": resolver.as_dict()}

    # 3. Multi-identity reasoning (§6)
    matrix = None
    questions: list[Mapping[str, Any]] = []
    if caps["multi_identity"]:
        from webpent.production.multi_identity import (
            matrix_from_observations,
            principals_from_state,
        )

        principals = principals_from_state(state)
        auth_observations = [
            o for o in (get("authorization_observations") or [])
            if isinstance(o, Mapping)
        ]
        # evidence from the identity layer: observed GETs whose workflow
        # observation named an explicit principal (unknown principal ->
        # the row is skipped: the matrix never fabricates actors)
        known_refs = {p.principal_ref for p in principals}
        identity_evidence = [
            {
                "principal_ref": str(obs.attributes.get("identity_ref") or ""),
                "tenant": obs.tenant,
                "object_ref": f"{obs.resource_type}:{obs.object_id}",
                "operation": "read",
                "object_state": "unknown",
                "outcome": "allowed",
                "evidence_refs": [obs.observation_ref] if obs.observation_ref else [],
            }
            for obs in observations
            if obs.identity_anchor_fields()[2] and obs.method.upper() == "GET"
            and str(obs.attributes.get("identity_ref") or "") in known_refs
        ]
        matrix = matrix_from_observations(
            principals, list(auth_observations) + identity_evidence,
        )
        questions = matrix.differential_questions(
            max_questions=int(
                getattr(settings, "max_identity_hypotheses", 12)),
        )
        update["multi_identity_reasoning"] = {
            "principals": [p.public_dict() for p in matrix.principals()],
            "coverage": matrix.coverage(),
            "differential_questions": [q.as_dict() for q in questions],
        }

    # 4. Composite workflows (§7) — derived from observed transitions
    candidates: list[Mapping[str, Any]] = []
    if caps["composite_workflows"]:
        from webpent.production.composite_workflows import (
            build_sequence_candidates,
            build_workflows_from_observations,
        )

        workflows = build_workflows_from_observations(
            [o for o in (get("workflow_observations") or []) if isinstance(o, Mapping)],
            max_workflows=int(getattr(settings, "max_workflow_candidates", 8)) * 4,
        )
        sequences = build_sequence_candidates(
            workflows,
            max_depth=int(getattr(settings, "max_workflow_sequence_depth", 4)),
            max_candidates=int(getattr(settings, "max_workflow_candidates", 8)),
        )
        candidates = [c.as_dict() for c in sequences]
        update["composite_workflow_candidates"] = candidates

    # 5. Hypotheses (deterministic ids, deduped by the merge reducer)
    new_hypotheses: list[Any] = []
    for question in questions:
        hypothesis = _hypothesis_privilege_differential(
            question.as_dict() if hasattr(question, "as_dict") else question,
            target_url=target_url,
        )
        if hypothesis is not None:
            new_hypotheses.append(hypothesis)
            telemetry["hypothesis_origins"]["multi_identity"] = (
                telemetry["hypothesis_origins"].get("multi_identity", 0) + 1)
    for candidate in candidates:
        hypothesis = _hypothesis_workflow_invariant(
            candidate, target_url=target_url,
        )
        if hypothesis is not None:
            new_hypotheses.append(hypothesis)
            telemetry["hypothesis_origins"]["composite_workflow"] = (
                telemetry["hypothesis_origins"].get("composite_workflow", 0) + 1)
    # suppress hypotheses already in the pool (open or closed)
    pool = _pool_index(get("hypotheses"))
    fresh = [
        h for h in new_hypotheses
        if str(getattr(h, "id", "")) not in pool
    ]
    if fresh:
        update["hypotheses"] = fresh
    telemetry["hypotheses_generated"] = len(fresh)

    # 6. Identity-aware research hints (§8: influence real case
    #    selection — ordering only, same budget, the UM-DR-31 contract).
    hints: dict[str, float] = {}
    if caps["alias_resolution"] and "identity_alias_graph" in update:
        graph = update["identity_alias_graph"]["graph"]
        for rel in graph.get("relationships", []):
            if rel.get("state") != "confirmed_same_object":
                continue
            for side in (rel.get("source"), rel.get("alternate")):
                if not side:
                    continue
                admitted, _rej = _admit_endpoint(
                    str(side), campaign_origin, base_url)
                if not admitted:
                    continue
                from urllib.parse import urlsplit
                parts = [
                    p for p in urlsplit(admitted).path.strip("/").split("/")
                    if p
                ]
                if len(parts) >= 2:
                    directory = "/".join(parts[:-1])
                    # a confirmed alias pair is a cross-representation
                    # differential opportunity: high-priority ordering hint
                    hints[directory] = max(hints.get(directory, 0.0), 0.9)
    if caps["multi_identity"] and questions:
        for question in questions:
            obj = str((question.as_dict() if hasattr(question, "as_dict")
                       else question).get("target_object_ref") or "")
            # single-segment surface hints from object resource types
            token = obj.split(":", 1)[0].lower()
            if len(token) >= 3:
                hints[token] = max(hints.get(token, 0.0), 0.7)
    if hints:
        update["identity_research_hints"] = dict(sorted(hints.items())[:64])

    update["identity_workflow"] = telemetry

    # UM-DR-36.6: Expected Behavior Model — evidence-backed rules with
    # explicit uncertainty, derived from the SAME channels this node already
    # consumed (workflow observations, identity registry). The model feeds
    # hypothesis generation through unresolved questions (ordering-only
    # hints); it NEVER confirms, admits, or schedules by itself.
    try:
        from webpent.production.expected_behavior import build_expected_behavior

        behavior_model = build_expected_behavior(state)
        update["expected_behavior_model"] = behavior_model.to_dict()
        behavior_hints = {
            question[:120]: 0.45
            for question in behavior_model.unresolved_questions[:16]
        }
        if behavior_hints:
            merged_hints = dict(update.get("identity_research_hints") or {})
            for key, value in behavior_hints.items():
                merged_hints[key] = max(merged_hints.get(key, 0.0), value)
            update["identity_research_hints"] = dict(
                sorted(merged_hints.items())[:64])
        telemetry["expected_behavior"] = {
            "rule_count": behavior_model.to_dict()["rule_count"],
            "unresolved_question_count": behavior_model.to_dict()["unresolved_question_count"],
        }
    except (AttributeError, ImportError, KeyError, RuntimeError, TypeError, ValueError):
        # measurement/context only: never blocks the identity workflow
        pass
    return update


def _pool_index(hypotheses: Any) -> dict[str, str]:
    index: dict[str, str] = {}
    for hypothesis in hypotheses or []:
        if isinstance(hypothesis, Mapping):
            hid, status = hypothesis.get("id"), hypothesis.get("status")
        else:
            hid = getattr(hypothesis, "id", None)
            status = getattr(hypothesis, "status", None)
        if hid is not None:
            index[str(hid)] = str(status or "unexplored")
    return index


def wire_identity_workflow(graph: Any) -> None:
    """Additive wiring (the coverage_gap_report pattern): the node is
    inserted BEFORE the strategist line by the builder's conditional
    redirect helpers; this helper only registers the node itself."""
    graph.add_node(
        IDENTITY_WORKFLOW_NODE_NAME,
        identity_workflow_node,
    )
