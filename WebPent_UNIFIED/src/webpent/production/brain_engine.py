"""UM-DR-47 Phase W — wire the researcher brain into the campaign engine.

The 46 brain modules were advisory-only (``influence_contract``:
"advisory for research prioritization only"). This module is the
WIRING: the brain's deterministic outputs become the actual inputs
of campaign target selection and experiment ordering, behind one
fail-closed feature flag (``enable_brain_engine`` / env
``WEBPENT_ENABLE_BRAIN_ENGINE``).

W1 — SKG QUERIES DRIVE SELECTION: ``get_all_paths_to``,
``ownership_changers``, ``reads_without_authz_marker`` and the
coverage cells are evaluated into a :class:`BrainPriorityContext`
that feeds the priority variables for every hypothesis — the
knowledge graph steers what the campaign tests next, not a static
list.

W2 — HYPOTHESES FROM THE BRAIN, RANKED BY REAL info_gain:
contradiction/invariant/coverage-gap/chain-step hypotheses carry a
deterministic ``expected_information_gain``; ranking uses the W3
formula, never list order or count-based tie-breaks.

W3 — THE LITERAL PRIORITY FORMULA (owner vision §6, restored by
UM-DR-47 after it was dropped in 46):

    Priority = (ExpectedInformationGain × Impact × Confidence)
               / (Cost + Risk)

a pure function with declared estimators, plus sensitivity tests
(tests/test_umdr47_w3_priority.py: flipping any single variable
flips the ranking).

W4 — COVERAGE GAPS BECOME RESEARCH TASKS: unverified
(resource × principal × operation) cells are emitted as canonical
hypotheses executed inside the same campaign through the ordinary
authorized path.

W5 — CHAINS EXECUTE AS SEQUENTIAL STEPS: attack chains are
decomposed into ordered step hypotheses; step N is only rankable
after step N-1 is confirmed — each step gets its own proof through
the standard machinery and CausalGuard remains the sole
confirmation authority.

Hard limits (unchanged from 46): no network I/O, no authorization,
no scope expansion, never a finding, never a confirmation. The
engine reorders and enriches; it does not execute anything itself.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from webpent.models.hypothesis import Hypothesis
from webpent.researcher.behavioral_layer import (
    DENSITY_EIG_WEIGHT,
    INVARIANT_IMPACT,
)

logger = logging.getLogger(__name__)

__all__ = [
    "BRAIN_ENGINE_FLAG_ENV",
    "BRAIN_ENGINE_FLAG_SETTINGS",
    "brain_engine_enabled",
    "priority_formula",
    "BrainPriorityContext",
    "build_brain_context",
    "estimate_priority_inputs",
    "brain_priority",
    "rank_with_brain",
    "coverage_gap_hypotheses",
    "chain_step_hypotheses",
    "brain_engine_node",
    "state_context_key",
]

BRAIN_ENGINE_FLAG_ENV = "WEBPENT_ENABLE_BRAIN_ENGINE"
BRAIN_ENGINE_FLAG_SETTINGS = "enable_brain_engine"

# The state channel where the node's summary lands (bounded advisory
# channel, same family as ``researcher_brain``).
BRAIN_ENGINE_CHANNEL = "brain_engine"
STATE_CONTEXT_KEY = "brain_engine_context"


def brain_engine_enabled() -> bool:
    """Fail-closed flag: the wiring is OFF unless explicitly enabled."""
    try:
        from webpent.config.settings import get_settings
        return bool(getattr(get_settings(), BRAIN_ENGINE_FLAG_SETTINGS, False))
    except (AttributeError, ImportError, KeyError, OSError, RuntimeError,
            TypeError, ValueError):
        # the builder._attack_graph_enabled precedent's exact set
        return False


# ---------------------------------------------------------------------------
# W3 — the literal priority formula
# ---------------------------------------------------------------------------

_EPSILON = 1e-6


def priority_formula(
    *,
    expected_information_gain: float,
    impact: float,
    confidence: float,
    cost: float,
    risk: float,
) -> float:
    """Priority = (EIG × Impact × Confidence) / (Cost + Risk).

    Pure function. All inputs are clamped to [0, 1] EXCEPT ``cost``
    which is a request-count estimate clamped to [0, +inf) (a
    differential triple is ~3 requests). The denominator is floored
    by ``_EPSILON`` so a zero-cost/zero-risk hypothesis yields a
    bounded value instead of a division by zero. Result is not
    clamped above (the caller normalises); a higher value always
    means "test this next".
    """
    eig = max(0.0, min(1.0, float(expected_information_gain)))
    imp = max(0.0, min(1.0, float(impact)))
    conf = max(0.0, min(1.0, float(confidence)))
    cost = max(0.0, float(cost))
    risk = max(0.0, min(1.0, float(risk)))
    numerator = eig * imp * conf
    denominator = cost + risk + _EPSILON
    return numerator / denominator


# ---------------------------------------------------------------------------
# W1 — the SKG-derived selection context
# ---------------------------------------------------------------------------

@dataclass
class BrainPriorityContext:
    """Deterministic per-campaign context built from the SKG + brain.

    Built ONCE per strategist pass (and cached on the state dict) so
    scoring N hypotheses costs one SKG evaluation, not N.
    """

    model: Any = None                     # ApplicationModel (SKG)
    built: bool = False
    error: str = ""
    # W1 query material
    sensitive_reachable: dict[str, float] = field(default_factory=dict)
    ownership_changer_targets: set[str] = field(default_factory=set)
    unauthz_read_targets: set[str] = field(default_factory=set)
    # W4 coverage material
    coverage_cells: list[dict[str, Any]] = field(default_factory=list)
    unverified_cells: list[dict[str, Any]] = field(default_factory=list)
    verified_refs: frozenset[str] = frozenset()
    # W5 chain material
    chains: list[dict[str, Any]] = field(default_factory=list)
    # estimated request cost per target path (experiment planner)
    plan_costs: dict[str, float] = field(default_factory=dict)
    # blast-radius signal per target path (write operations without
    # an authorization marker — the brain's own QC risk signal)
    risk_targets: dict[str, float] = field(default_factory=dict)
    # UM-DR-52 W1/A3: behavioral evidence over the same SKG model
    # (transition density / contradiction backing / invariant-backed
    # write surface + the mined A2 specs). None when it never built;
    # its dicts are empty when the model carries no behavioral
    # signals, which makes every formula term a NO-OP.
    behavioral: Any = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def as_summary(self) -> dict[str, Any]:
        return {
            "built": self.built,
            "error": self.error[:200] if self.error else "",
            "sensitive_reachable_count": len(self.sensitive_reachable),
            "ownership_changer_targets": len(self.ownership_changer_targets),
            "unauthz_read_targets": len(self.unauthz_read_targets),
            "coverage_cells": len(self.coverage_cells),
            "unverified_cells": len(self.unverified_cells),
            "chains": len(self.chains),
            "behavioral": (
                self.behavioral.as_summary()
                if self.behavioral is not None else None
            ),
            "influence_contract": (
                "wired (UM-DR-47 W + UM-DR-52 W1): SKG queries + brain "
                "estimates + behavioral evidence steer selection ordering "
                "and the decided priority — still never authorizes, never "
                "confirms, never bypasses CausalGuard/ProofBundle/Replay"
            ),
            **({"diagnostics": self.diagnostics} if self.diagnostics else {}),
        }


def state_context_key() -> str:
    """Private state key used to cache the context within one pass."""
    return STATE_CONTEXT_KEY


def build_brain_context(state: Any) -> BrainPriorityContext:
    """Evaluate the SKG queries + researcher modules into a context.

    Deterministic: same state ⇒ same context (no clock, no network).
    Any failure degrades to ``built=False`` (ranking falls back to the
    legacy score — fail-safe, never fail-open).
    """
    ctx = BrainPriorityContext()
    try:
        from webpent.appmodel.skg import build_security_knowledge_graph
        from webpent.appmodel.skg_queries import (
            get_all_paths_to,
            ownership_changers,
            reads_without_authz_marker,
        )
        from webpent.researcher.attack_chains import compose_attack_chains
        from webpent.researcher.coverage_intel import skg_coverage_cells
        from webpent.researcher.experiment_planner import plan_experiments
        from webpent.researcher.brain import classify_endpoint_behavior

        # THE WIRING: the SKG builds from the real state PLUS the
        # derived channels (crawl object variance + bac coverage
        # ledger) — the data fix without which the brain never saw
        # resources in production.
        model = build_security_knowledge_graph(_augmented_state_for_skg(state))
        ctx.model = model

        # --- W1a: reachability of sensitive resources ---
        # A sensitive resource = the target of an unmarked ownership
        # change (control) or an unmarked read (information). Every
        # endpoint that can REACH such a resource via the SKG gets a
        # reachability weight — impact fuel for the formula.
        sensitive_ids: set[str] = set()
        for row in ownership_changers(model):
            _fold_target(ctx.ownership_changer_targets, row)
            rid = str(row.get("resource_id") or "")
            if rid:
                sensitive_ids.add(rid)
                _bump(ctx.sensitive_reachable, str(row.get("endpoint_path") or ""), 0.8)
        for row in reads_without_authz_marker(model):
            _fold_target(ctx.unauthz_read_targets, row)
            for rid in row.get("resource_ids", []) or []:
                if rid:
                    sensitive_ids.add(str(rid))
            _bump(ctx.sensitive_reachable, str(row.get("path") or ""), 0.6)
        for resource_id in sorted(sensitive_ids):
            try:
                result = get_all_paths_to(model, resource_id)
            except Exception:  # noqa: BLE001 — advisory query
                continue
            for path in result.get("paths", []) or []:
                for node_id, node_label in zip(
                    path.get("node_ids", []) or [],
                    path.get("node_labels", []) or [],
                ):
                    node = model.entities.get(node_id)
                    if node is None or str(node.kind) != "endpoint":
                        continue
                    _bump(
                        ctx.sensitive_reachable,
                        str(node.metadata.get("path") or node_label),
                        0.5 + 0.5 * result.get("path_count", 1) / 4.0,
                    )

        # --- W4: coverage cells (verified vs unverified) ---
        verified = _verified_refs_from_state(state)
        ctx.verified_refs = verified
        ctx.coverage_cells = skg_coverage_cells(model, verified)
        ctx.unverified_cells = [
            c for c in ctx.coverage_cells if c.get("status") != "verified"
        ]

        # --- W5: attack chains ---
        ctx.chains = compose_attack_chains(model)

        # --- cost estimates from the experiment planner ---
        # The planner emits one differential plan per modeled target;
        # the guarded triple (baseline/candidate/negative-control)
        # costs 3 requests by contract — the planner's own bound.
        for plan in plan_experiments(model):
            target = plan.get("target") or {}
            endpoint_path = str(target.get("endpoint_path") or "")
            if endpoint_path:
                ctx.plan_costs.setdefault(endpoint_path, 3.0)
            resource_label = str(target.get("resource_label") or "")
            if resource_label:
                ctx.plan_costs.setdefault(resource_label, 3.0)

        # --- risk signal: state-changing endpoints without authz ---
        profiles = classify_endpoint_behavior(model)
        for profile_id, profile in profiles.items():
            writes = bool(profile.get("writes"))
            authz = bool(profile.get("authz_marked"))
            path = str(profile.get("path") or "")
            if path:
                # unmarked write surface ⇒ higher probing risk
                ctx.risk_targets[path] = (
                    (0.7 if writes and not authz else 0.4 if writes else 0.15)
                )

        # --- UM-DR-52 W1: behavioral evidence over the same model ---
        # A1 state machines + five measured questions, A2 invariant
        # specs, A3 ranking evidence — one deterministic pass. Its
        # failure degrades the behavioral terms to no-ops, never the
        # whole context (fail-safe, same contract as every query).
        try:
            from webpent.researcher.behavioral_layer import (
                behavioral_ranking_evidence,
            )
            ctx.behavioral = behavioral_ranking_evidence(model)
        except Exception as exc:  # noqa: BLE001 — fail-safe context
            logger.debug("brain_engine: behavioral evidence failed: %s", exc)
            ctx.behavioral = None

        ctx.built = True
        ctx.diagnostics = {
            "entity_count": len(model.entities),
            "relation_count": len(model.relations),
        }
    except Exception as exc:  # noqa: BLE001 — fail-safe context
        ctx.built = False
        ctx.error = str(exc)
        logger.warning("brain_engine: context build failed: %s", exc)
    return ctx


def _fold_target(bucket: set[str], row: dict[str, Any]) -> None:
    for key in ("endpoint_path", "path", "target", "endpoint"):
        value = row.get(key)
        if value:
            bucket.add(str(value))


def _bump(bucket: dict[str, float], key: str, weight: float) -> None:
    if not key:
        return
    bucket[key] = min(1.0, max(bucket.get(key, 0.0), float(weight)))


def _verified_refs_from_state(state: Any) -> frozenset[str]:
    """Confirmed findings' evidence refs = the verified coverage set."""
    refs: set[str] = set()
    findings = _get(state, "findings") or []
    try:
        for f in findings:
            evidence = (f or {}).get("evidence") if isinstance(f, dict) else None
            if isinstance(evidence, dict):
                for ref in evidence.get("refs", []) or []:
                    refs.add(str(ref))
            # AVI-lane promotions carry evidence_refs directly
            refs.update(
                str(r) for r in ((f or {}).get("evidence_refs") or []) if r
            )
    except Exception:  # noqa: BLE001 — advisory
        pass
    return frozenset(refs)


def _get(state: Any, key: str) -> Any:
    if isinstance(state, dict):
        return state.get(key)
    return getattr(state, key, None)


# ---------------------------------------------------------------------------
# W3 variable estimators (each variable, where it comes from)
# ---------------------------------------------------------------------------

_SEVERITY_BY_VULN_CLASS = {
    "auth_bypass": 1.0,
    "idor": 0.95,
    "privilege_differential": 0.95,
    "multi_step_auth_bypass": 0.9,
    "tenant_isolation": 0.9,
    "mass_assignment": 0.8,
    "business_logic": 0.7,
    "race_condition": 0.75,
    "info_disclosure": 0.55,
}


def _vuln_class_str(hyp: Hypothesis) -> str:
    vc = getattr(hyp, "vuln_class", "")
    return (vc.value if hasattr(vc, "value") else str(vc) or "").lower()


def estimate_priority_inputs(hyp: Hypothesis, ctx: BrainPriorityContext) -> dict[str, float]:
    """Estimate the five formula variables for one hypothesis.

    Sources (declared, deterministic):
      ExpectedInformationGain — the hypothesis's own ``info_gain``
        (RC-6, from the evolution engine) or, when unscored, the
        SKG-derived density of unverified coverage cells around the
        hypothesis's target (W4 fuel).
      Impact — vuln-class severity × SKG reachability of the target
        (W1: does this target sit on a path to a sensitive
        capability?).
      Confidence — the hypothesis's own ``confidence_score``.
      Cost — the experiment planner's request estimate for the
        differential triple (default 3).
      Risk — the brain's endpoint profile risk (state-changing
        surface without an authorization marker).

    UM-DR-52 W1/A3 behavioral terms (on top of the four sources,
    each a NO-OP when the evidence is absent — declared constants in
    ``behavioral_layer``, imported here so one SSOT holds):
      transition density raises EIG of targets that drive the
      observed workflow; contradiction backing raises confidence on
      evidence-conflicted endpoints; invariant backing raises impact
      of invariant-guarded write surfaces. Sources stay declared +
      deterministic + evidence-ref'd.
    """
    target = str(getattr(hyp, "target_url", "") or "")
    path = target.rsplit("/", 1)[-1] if target else ""

    # ExpectedInformationGain
    eig = getattr(hyp, "info_gain", None)
    if eig is None:
        eig = _skg_info_gain(target, path, ctx)

    # Impact = severity × reachability
    severity = _SEVERITY_BY_VULN_CLASS.get(_vuln_class_str(hyp), 0.5)
    reach = _reachability(target, path, ctx)
    impact = severity * (0.5 + 0.5 * reach)

    # Confidence
    confidence = float(getattr(hyp, "confidence_score", None) or 0.5)

    # Cost (requests for the guarded differential)
    cost = _lookup_by_substring(ctx.plan_costs, target, path, default=3.0)

    # Risk
    risk = _lookup_by_substring(ctx.risk_targets, target, path, default=0.2)

    # UM-DR-52 W1/A3: the behavioral terms
    if ctx.behavioral is not None:
        density, contrad, invar = ctx.behavioral.backing_for(target)
        eig = eig + (1.0 - float(eig or 0.0)) * DENSITY_EIG_WEIGHT * density
        confidence = min(1.0, confidence + contrad)
        impact = min(1.0, impact + INVARIANT_IMPACT * invar)

    return {
        "expected_information_gain": max(0.0, min(1.0, float(eig or 0.0))),
        "impact": max(0.0, min(1.0, float(impact))),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "cost": max(0.0, float(cost)),
        "risk": max(0.0, min(1.0, float(risk))),
    }



# ---------------------------------------------------------------------------
# THE WIRING DATA FIX — derive the 46 fixture-only SKG channels from
# REAL campaign data (the root cause the 46 closeout missed: the brain
# was "advisory" because its input channels never existed in the
# production flow — skg_evidence and object_identity_observations had
# no writer outside test fixtures, so the SKG always built without
# resources/relations and the brain could never change anything).
# ---------------------------------------------------------------------------

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MAX_DERIVED_OBJECTS = 64
_MAX_DERIVED_EVIDENCE = 96


def _derived_wiring_channels(state: Any) -> tuple[list, list]:
    """(object_identity_observations, skg_evidence) derived from the
    campaign's own recorded data — deterministic, evidence-ref'd:

    * crawled route paths with a VARYING object segment → object
      identity observations (the crawl literally observed these
      resource instances) + endpoint resource_access reads;
    * bac_observations (the access_control node's real records) →
      ownership_change evidence rows per tested identity — the
      authorization-coverage ledger as SKG relations.
    """
    crawled = _get(state, "crawled_data") or {}
    routes = crawled.get("openapi_routes") if isinstance(crawled, dict) else None
    routes = [r for r in (routes or []) if isinstance(r, dict)]

    oi_out: list[dict[str, Any]] = []
    skg_out: list[dict[str, Any]] = []
    seen_objects: set[str] = set()

    # -- 1. object variance from the crawled surface --
    groups: dict[str, set[str]] = {}
    for route in routes:
        path = str(route.get("path") or "")
        segments = [s for s in path.split("?")[0].split("/") if s]
        if len(segments) < 2:
            continue
        prefix = "/".join(segments[:-1])
        groups.setdefault(prefix, set()).add(segments[-1])
    for prefix, lasts in sorted(groups.items()):
        if len(lasts) < 2:
            continue  # a fixed endpoint — no object variance
        resource_type = prefix.rsplit("/", 1)[-1]
        for last in sorted(lasts):
            if len(seen_objects) >= _MAX_DERIVED_OBJECTS:
                break
            object_id = last
            ref = f"umdr47-w-crawl:{prefix}/{last}"
            seen_objects.add(f"{resource_type}:{object_id}")
            oi_out.append({
                "resource_type": resource_type,
                "object_id": object_id,
                "observation_ref": ref,
                "endpoint": f"/{prefix}/{last}",
            })
            # the endpoint-level READ relation (chain composition fuel)
            skg_out.append({
                "evidence_kind": "resource_access",
                "endpoint": f"/{prefix}/{last}",
                "resource": f"{resource_type}:{object_id}",
                "operation": "read",
                "evidence_refs": [ref],
            })

    # -- 2. authorization-coverage ledger from bac_observations --
    for i, record in enumerate((_get(state, "bac_observations") or [])[:32]):
        if not isinstance(record, dict):
            continue
        resource_url = str(record.get("resource_url") or "").split("?")[0]
        object_id = str(record.get("object_id") or "")
        if not (resource_url and object_id):
            continue
        segments = [s for s in resource_url.split("/") if s]
        resource_type = (
            segments[-2] if len(segments) >= 2 and segments[-2] != object_id
            else "resource"
        )
        resource = f"{resource_type}:{object_id}"
        rows = record.get("observations") or []
        if not isinstance(rows, list):
            rows = []
        for row in rows[:8]:
            if not isinstance(row, dict):
                continue
            identity = str(row.get("identity") or "").strip()
            if not identity:
                continue
            method = str(row.get("method") or "GET").upper()
            operation = "write" if method in _WRITE_METHODS else "read"
            skg_out.append({
                "evidence_kind": "ownership_change",
                "endpoint": resource_url,
                "resource": resource,
                "attribute": "authorization_probe",
                "operation": operation,
                "actor": identity,
                "evidence_refs": [f"umdr47-w-bac:{i}"],
            })
        if len(skg_out) >= _MAX_DERIVED_EVIDENCE:
            break
    return oi_out, skg_out


def _augmented_state_for_skg(state: Any) -> Any:
    """The state view the SKG builds from: the real channels PLUS the
    derived wiring channels (advisory-only derivation — the state
    itself is never mutated; real recorded data always wins)."""
    oi_derived, skg_derived = _derived_wiring_channels(state)
    # F2.3 protocol depth: GraphQL operations, WS sessions and OAuth
    # trust boundaries as SKG-shaped records (protocol_depth module)
    try:
        from webpent.researcher.protocol_depth import (
            graphql_skg_records,
            oauth_trust_boundary_records,
            websocket_session_records,
        )
        crawled = _get(state, "crawled_data") or {}
        if isinstance(crawled, dict):
            skg_derived = skg_derived + graphql_skg_records(crawled)
            skg_derived = skg_derived + oauth_trust_boundary_records(
                crawled, _get(state, "identity_profiles"))
            ws_recs = websocket_session_records(crawled)
            if ws_recs:
                existing_wf = list(
                    _get(state, "workflow_observations") or [])
                if isinstance(state, dict):
                    state = {
                        **state,
                        "workflow_observations": existing_wf + ws_recs,
                    }
    except Exception:  # noqa: BLE001 — advisory derivation
        pass
    if not (oi_derived or skg_derived):
        return state
    if isinstance(state, dict):
        augmented = dict(state)
        existing_oi = list(state.get("object_identity_observations") or [])
        augmented["object_identity_observations"] = existing_oi + oi_derived
        existing_skg = list(state.get("skg_evidence") or [])
        augmented["skg_evidence"] = existing_skg + skg_derived
        return augmented
    # non-dict state: a dict view with the derived channels
    view = {
        k: getattr(state, k, None) for k in (
            "crawled_data", "identity_profiles", "session_cookies",
            "authorization_observations", "object_identity_observations",
            "workflow_observations", "skg_evidence", "findings",
        )
    }
    view["object_identity_observations"] = (
        list(view.get("object_identity_observations") or []) + oi_derived
    )
    view["skg_evidence"] = list(view.get("skg_evidence") or []) + skg_derived
    return view


def _lookup_by_substring(
    bucket: dict[str, float],
    target: str,
    path: str,
    *,
    default: float,
) -> float:
    """Exact key, then substring match (paths are keys, targets are URLs)."""
    if target in bucket:
        return float(bucket[target])
    if path and path in bucket:
        return float(bucket[path])
    best: float | None = None
    for key, value in bucket.items():
        if key and key in target:
            best = float(value) if best is None else best
            break
    return default if best is None else best


def _skg_info_gain(target: str, path: str, ctx: BrainPriorityContext) -> float:
    """Unscored hypothesis: EIG from unverified-cell density (W4).

    A target that sits in MANY unverified cells carries more expected
    information than one whose cells are already verified — the
    literal reading of RC-6's "cells still unverified".
    """
    if not ctx.built or not ctx.coverage_cells:
        return 0.5
    hits = [
        c for c in ctx.unverified_cells
        if target and target in str(c.get("cell_key", ""))
        or path and path in str(c.get("cell_key", ""))
    ]
    if not hits:
        return 0.3
    density = len(hits) / max(1, len(ctx.coverage_cells))
    return max(0.3, min(1.0, 0.3 + 0.7 * density))


def _reachability(target: str, path: str, ctx: BrainPriorityContext) -> float:
    """W1: how strongly does this target sit on sensitive paths?"""
    if not ctx.built:
        return 0.5
    best = 0.0
    for label, weight in ctx.sensitive_reachable.items():
        if label and (label in target or target.endswith(label) or label in path):
            best = max(best, weight)
    if target in ctx.ownership_changer_targets or path in ctx.ownership_changer_targets:
        best = max(best, 0.8)
    if target in ctx.unauthz_read_targets or path in ctx.unauthz_read_targets:
        best = max(best, 0.6)
    return best if best > 0.0 else 0.2


def brain_priority(hyp: Hypothesis, ctx: BrainPriorityContext) -> float:
    """Apply the literal W3 formula to one hypothesis (context-bound)."""
    inputs = estimate_priority_inputs(hyp, ctx)
    return priority_formula(**inputs)


# ---------------------------------------------------------------------------
# W2 — ranking by the formula
# ---------------------------------------------------------------------------

def rank_with_brain(
    hypotheses: list[Hypothesis],
    ctx: BrainPriorityContext,
) -> list[tuple[Hypothesis, float]]:
    """Rank open hypotheses by the W3 formula, deterministic.

    "Open" matches :meth:`Hypothesis.is_open` EXACTLY (unexplored /
    investigating — ``learned`` is closed), so the brain path and the
    legacy path rank the same pool. deterministic-match hypotheses
    still sort first (the V9 P0 Fix 2-B guarantee is preserved by
    every ranking mode); ties break by ``created_at`` then ``id`` —
    never by list position or count.
    """
    _open = {"unexplored", "investigating"}

    def _status(h: Hypothesis) -> str:
        raw = str(getattr(h, "status", ""))
        return raw.split(".")[-1].lower() if raw else ""

    scored: list[tuple[Hypothesis, float]] = []
    for h in hypotheses:
        if _status(h) not in _open:
            continue
        # W5 gate: a chained step is only rankable when its
        # predecessor is confirmed (sequential execution, per-step
        # proof) — see chain_step_hypotheses for the metadata.
        gate = _chain_step_gate(h, hypotheses)
        if gate is None or gate:
            score = brain_priority(h, ctx)
        else:
            score = 0.0
        scored.append((h, score))
    scored.sort(
        key=lambda t: (
            0 if bool(getattr(t[0], "deterministic_match", False)) else 1,
            -t[1],
            (
                t[0].created_at.isoformat()
                if hasattr(t[0].created_at, "isoformat")
                else str(t[0].created_at)
            ),
            str(t[0].id),
        )
    )
    return scored


def _chain_step_gate(h: Hypothesis, pool: list[Hypothesis]) -> bool | None:
    """None = not a chained step; True = gate open; False = gate closed.

    Step N of a chain is rankable only while its predecessor
    (step N-1 of the same chain) is still open — the predecessor
    ranks first, executes first, and only when it closes (confirmed
    or refuted) does the next step become selectable. Each step
    still produces its OWN guarded differential proof.
    """
    contract = getattr(h, "evidence_contract", None)
    if not isinstance(contract, dict):
        return None
    step = contract.get("chain_step")
    if not isinstance(step, dict) or "chain_id" not in step:
        return None
    index = int(step.get("index", 0) or 0)
    if index <= 0:
        return True  # first step — always rankable
    predecessor_key = str(step.get("predecessor_id") or "")
    by_id = {str(x.id): x for x in pool}
    predecessor = by_id.get(predecessor_key)
    if predecessor is None:
        # the predecessor is gone (closed and pruned) — treat the
        # gate as open so a lone step is never silently starved
        return True
    status = str(getattr(predecessor, "status", ""))
    status = status.split(".")[-1].lower()
    return status not in {"unexplored", "investigating"}


# ---------------------------------------------------------------------------
# W4 — coverage gaps become research tasks
# ---------------------------------------------------------------------------

_MAX_COVERAGE_TASKS = 12


def coverage_gap_hypotheses(
    ctx: BrainPriorityContext,
    target_url: str,
) -> list[Hypothesis]:
    """Unverified coverage cells → canonical research-task hypotheses.

    These are executed INSIDE the same campaign through the ordinary
    authorized path (strategist → payload/AVI → CausalGuard), with
    results — not a report paragraph.
    """
    import hashlib
    from uuid import NAMESPACE_URL, uuid5

    from webpent.production.hypothesis_adapter import canonical_hypothesis

    tasks: list[Hypothesis] = []
    for cell in ctx.unverified_cells[:_MAX_COVERAGE_TASKS]:
        resource = str(cell.get("resource_label", ""))
        principal = str(cell.get("principal_label", ""))
        operation = str(cell.get("operation", ""))
        blob = hashlib.sha256(
            f"{target_url}|{cell.get('cell_key', '')}".encode("utf-8")
        ).hexdigest()[:40]
        tasks.append(canonical_hypothesis(
            id=uuid5(NAMESPACE_URL, f"webpent:umdr47w4:{blob}"),
            statement=(
                f"Research task: verify the coverage cell "
                f"{resource} × {principal} × {operation} — the observed "
                f"authorization relationship is not yet backed by a "
                f"confirmed differential experiment"
            ),
            vuln_class="privilege_differential",
            origin="researcher_brain",
            origin_detail=(
                f"UM-DR-47 W4 coverage gap; cell_id={cell.get('cell_id')}; "
                f"evidence_refs={len(cell.get('evidence_refs', []))}"
            ),
            target_url=target_url,
            expected_behavior=(
                "a guarded differential on the cell's operation either "
                "confirms the modeled authorization relationship or "
                "refutes the model — both outcomes close the cell"
            ),
            negative_control=(
                "replay the operation as the cell's principal AND as a "
                "foreign principal; the differential must reproduce under "
                "sealed replay"
            ),
            deterministic_match=True,
            info_gain=min(1.0, 0.4 + 0.2 * len(cell.get("evidence_refs", []))),
            evidence_contract={
                "evidence_refs": list(cell.get("evidence_refs", []))[:8],
                "appmodel_hint": {"kind": "coverage_gap"},
            },
        ))
    return tasks


# ---------------------------------------------------------------------------
# W5 — chains execute as sequential steps
# ---------------------------------------------------------------------------

_CHAIN_VULN_CLASS = {
    "info_authz_composition": "idor",
    "workflow_bypass_chain": "auth_bypass",
    "cross_surface_chain": "auth_bypass",
}

_MAX_CHAIN_STEPS = 16


def chain_step_hypotheses(
    ctx: BrainPriorityContext,
    target_url: str,
) -> list[Hypothesis]:
    """Attack chains → ordered step hypotheses with per-step proof.

    Each chain from ``compose_attack_chains`` becomes a sequence of
    hypotheses — one per ``step`` of the chain's recorded steps. Step
    N carries ``chain_step`` metadata with its predecessor's id;
    :func:`rank_with_brain` releases step N only after step N-1
    closes (confirmed or refuted) — sequential execution with an
    individual guarded proof per step. The chain as a whole NEVER
    becomes a finding: each step's confirmation stays under
    CausalGuard.
    """
    import hashlib
    from uuid import NAMESPACE_URL, uuid5

    from webpent.production.hypothesis_adapter import canonical_hypothesis

    steps_out: list[Hypothesis] = []
    for chain in ctx.chains[:4]:
        chain_id = str(chain.get("chain_id", ""))
        chain_kind = str(chain.get("kind", ""))
        nodes = [
            s for s in (chain.get("steps") or [])
            if isinstance(s, dict)
        ][:_MAX_CHAIN_STEPS]
        predecessor_id: str | None = None
        for index, step in enumerate(nodes):
            step_path = str(step.get("path") or step.get("endpoint_path") or "")
            step_kind = str(step.get("kind", ""))
            blob = hashlib.sha256(
                f"{chain_id}|{index}|{step_path}|{step_kind}".encode("utf-8")
            ).hexdigest()[:40]
            step_id = str(uuid5(NAMESPACE_URL, f"webpent:umdr47w5:{blob}"))
            steps_out.append(canonical_hypothesis(
                id=step_id,
                statement=(
                    f"Chain step {index + 1}/{len(nodes)} of {chain_kind}: "
                    f"prove the '{step_kind}' leg at {step_path} "
                    f"individually with a guarded differential — the "
                    f"chain only advances when this step closes"
                ),
                vuln_class=_CHAIN_VULN_CLASS.get(
                    chain_kind, "auth_bypass"),
                origin="researcher_brain",
                origin_detail=(
                    f"UM-DR-47 W5 chain execution; chain_id={chain_id}; "
                    f"step={index + 1}/{len(nodes)}"
                ),
                target_url=target_url,
                expected_behavior=(
                    f"{chain.get('preconditions', 'the chain composition '
                     'replays under the scoped principals')}"
                ),
                negative_control=(
                    "replay this step as the chain's starting principal AND "
                    "the step's authorized principal; the differential must "
                    "reproduce under sealed replay"
                ),
                deterministic_match=index == 0,
                info_gain=0.75 if index == 0 else 0.6,
                evidence_contract={
                    "evidence_refs": list(step.get("evidence_refs", []))[:8],
                    "chain_step": {
                        "chain_id": chain_id,
                        "index": index,
                        "total": len(nodes),
                        "predecessor_id": predecessor_id,
                        "step_path": step_path,
                    },
                },
            ))
            predecessor_id = step_id
    return steps_out


# ---------------------------------------------------------------------------
# The graph node — the wiring point in the advisory chain
# ---------------------------------------------------------------------------

def _resolve_target_url(state: Any) -> str:
    """target_url, else base_url, else the Target object's url."""
    for key in ("target_url", "base_url"):
        value = _get(state, key)
        if value:
            return str(value)
    target = _get(state, "target")
    if target is not None:
        url = target.get("url") if isinstance(target, dict) else getattr(target, "url", None)
        if url:
            return str(url)
    return ""


def brain_engine_node(state: Any) -> dict[str, Any]:
    """UM-DR-47 W node: enrich + steer; never execute, never confirm.

    Wired (flag-gated) on the strategist-bound redirect — it runs
    after the testing lanes produced authorization observations. Emits
    W4 coverage-gap research tasks, W5 chain-step hypotheses and the
    UM-DR-52 W1 behavioral invariant hypotheses into the pool, and
    records the wiring summary on the ``brain_engine`` channel.
    """
    target_url = _resolve_target_url(state)
    ctx = build_brain_context(state)

    hypotheses: list[Hypothesis] = []
    if ctx.built:
        hypotheses.extend(coverage_gap_hypotheses(ctx, target_url))
        hypotheses.extend(chain_step_hypotheses(ctx, target_url))
        # UM-DR-52 W1/A2: mined invariant specs → canonical research
        # hypotheses through the same legal adapter path — they enter
        # the strategist's ranking like every other hypothesis and
        # gain no confirmation authority from this layer.
        if ctx.behavioral is not None and ctx.behavioral.invariant_specs:
            try:
                from webpent.researcher.behavioral_layer import (
                    invariant_hypotheses,
                )
                hypotheses.extend(invariant_hypotheses(
                    list(ctx.behavioral.invariant_specs), target_url))
            except Exception:  # noqa: BLE001 — advisory emission
                pass
    # F2.3: the cross-protocol hypothesis (OAuth boundary × GraphQL
    # mutation) — one REAL candidate when both surfaces are evidenced
    f23 = None
    try:
        from webpent.researcher.protocol_depth import cross_surface_hypothesis
        from webpent.production.hypothesis_adapter import canonical_hypothesis

        f23 = cross_surface_hypothesis(
            ctx.model, _get(state, "crawled_data") or {})
        if f23 is not None:
            hypotheses.append(canonical_hypothesis(
                id=f23["id"],
                statement=f23["statement"],
                vuln_class=f23["vuln_class"],
                origin=f23["origin"],
                origin_detail=f23["origin_detail"],
                target_url=target_url,
                expected_behavior=f23["expected_behavior"],
                negative_control=f23["negative_control"],
                info_gain=f23.get("info_gain"),
                evidence_contract=f23.get("evidence_contract"),
            ))
    except Exception:  # noqa: BLE001 — advisory emission
        f23 = None

    summary = dict(ctx.as_summary())
    summary["f23_cross_surface_hypothesis"] = f23 is not None
    return {
        BRAIN_ENGINE_CHANNEL: summary,
        STATE_CONTEXT_KEY: {
            "built": ctx.built,
            "sensitive_reachable": dict(ctx.sensitive_reachable),
            "ownership_changer_targets": sorted(ctx.ownership_changer_targets),
            "unauthz_read_targets": sorted(ctx.unauthz_read_targets),
            "coverage_cell_count": len(ctx.coverage_cells),
            "unverified_cell_count": len(ctx.unverified_cells),
            "chain_count": len(ctx.chains),
        },
        "hypotheses": hypotheses,
    }
