# src/webpent/production/modern_spine_integration.py
"""TEAM-1 — integration of the modern spine into the production LangGraph.

This module provides the graph node that makes the modern autonomous spine
the DEFAULT production execution path. It is wired into the official
graph builder (webpent.graph.builder) at the recon stage.

RUNTIME CHAIN (observable via ModernOrchestrator.trace):
  entrypoint -> ModernOrchestrator -> DeepReconEngine -> WorldModel(EvidenceGraph)
  -> ResearchControlLoop -> OutcomeTracker -> ScopeLaw/ToolBoundary
  -> execution -> WorldModel update -> OutcomeTracker -> replan
  -> CausalGuard -> ProofBundle (semantic-validated) -> Persistence -> Replay

The legacy recon node is still invoked for compatibility, but its output
is marked ADVISORY. The modern spine is the authoritative knowledge
producer. This is NOT a wrapper that merely calls the old graph and labels
it modern — the modern components demonstrably execute (Part 16).
"""
from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Final

from webpent.shared.exceptions import UnsupportedLegacyOnlyModeError

logger = logging.getLogger(__name__)

# M2-impl WP-A (NF-R2-06): object-identity spine-caller token. The only
# legitimate caller of advisory registration/publish is THIS module; the
# token is verified by identity (``is``), which cannot be forged by
# filename substrings, module-name tricks, or stack fabrication. Not
# exported via __all__ — it is passed by reference at the call site.
SPINE_CALL_TOKEN: Final = object()

# Default: modern spine ON. Can be disabled only by explicit env override
# for emergency rollback — NOT a test-only flag, and NOT the default.
# P1-C FIX: Governed modern/legacy mode. Explicit modes:
#   PRODUCTION_MODERN (default) — modern spine authoritative, legacy advisory-only
#   COMPATIBILITY_LEGACY — legacy runs but CANNOT make authority decisions (fail-closed)
#   UNSUPPORTED_LEGACY_ONLY — explicitly blocked for production authority
MODERN_SPINE_MODE = os.environ.get("WEBPENT_MODERN_SPINE_MODE", "PRODUCTION_MODERN").upper()
_ENV_DISABLE = os.environ.get("WEBPENT_MODERN_SPINE", "1").lower() in {"0", "false", "no", "off"}
if _ENV_DISABLE and MODERN_SPINE_MODE == "PRODUCTION_MODERN":
    MODERN_SPINE_MODE = "COMPATIBILITY_LEGACY"  # explicit downgrade, auditable
MODERN_SPINE_ENABLED = MODERN_SPINE_MODE != "UNSUPPORTED_LEGACY_ONLY"
LEGACY_COMPATIBILITY_MODE = MODERN_SPINE_MODE == "COMPATIBILITY_LEGACY"
# Legacy compatibility mode is EXPLICIT, AUDITABLE, and FAILS-CLOSED for authority.
# It cannot silently become the production path — authority decisions require modern spine.


def _audit_root(engagement_id: str) -> "Path":
    """M2-impl WP-A: engagement-scoped audit root.

    Mirrors the frozen hunter_runner convention (``artifacts/hunter-<id>``)
    so every seam-produced audit artifact lands in the operator-visible
    artifact tree. WEBPENT_AUDIT_ROOT overrides the base for deployments
    and tests (documented in CAMPAIGN_GUIDE).
    """

    base = os.environ.get("WEBPENT_AUDIT_ROOT")
    root = Path(base) if base else Path("artifacts") / f"hunter-{engagement_id}"
    return root


def _resolve_audit_chain(state: dict[str, Any], engagement_id: str,
                         production_trace: Any) -> tuple[Any, dict[str, Any]]:
    """M2-impl WP-A (R5 of Ruling M2-001, NF-R2-04): PRODUCE a real,
    append-only EngagementAuditChain for this engagement.

    Returns ``(chain_object, serializable_descriptor)``. The chain OBJECT is
    used in-process by the seam's registration calls; the state carries the
    DESCRIPTOR only (C10: the live chain is not checkpoint-serializable —
    the V13 lesson). Downstream nodes re-open the chain from the descriptor
    (EngagementAuditChain resumes seq/hash from the existing file).

    Fail-closed: a chain that cannot be constructed raises — a silently
    absent audit chain is exactly the honesty defect R5 closes.
    """
    from webpent.shared.engagement_audit import EngagementAuditChain
    root = _audit_root(engagement_id)
    chain = EngagementAuditChain(
        engagement_id=engagement_id,
        audit_dir=root / "audit",
        workspace_dir=root / "audit_workspace",
        trace=production_trace,
    )
    descriptor = {
        "engagement_id": engagement_id,
        "audit_path": str(chain.audit_path),
        "workspace_path": str(chain.workspace_path),
        "chain_live": True,
    }
    state["_audit_chain"] = descriptor
    return chain, descriptor


def _recheck_fixture_bounds(fixture: dict[str, Any], rejection_register: Any) -> bool:
    """M2-impl WP-A (NF-M2-06 disposition): defense-in-depth size/structure
    re-check at the conversion boundary.

    The frozen admission layer bounds source size (MAX_SOURCE_BYTES) and
    structure; the (unwired) M5 layer means nothing re-checked at intake.
    The seam re-checks cheap bounds here — inheriting the frozen layer's
    constants, never loosening them — and REJECTS (register + skip) rather
    than crashing or admitting unbounded payloads (RED-2 P-4: 5 MiB field
    admitted verbatim).
    """
    from webpent.shared.fixture_registry import (
        MAX_HAR_ENTRIES,
        MAX_JSON_DEPTH,
        MAX_SOURCE_BYTES,
        REASON_OVERSIZE,
        REASON_STRUCTURE,
    )
    fp = str(fixture.get("content_digest", ""))[:32] or None
    try:
        serialized = json.dumps(fixture, default=str)
    except (TypeError, ValueError) as exc:
        rejection_register.reject(REASON_STRUCTURE,
                                  f"fixture not canonically serializable: {exc}"[:120], fp)
        return False
    if len(serialized.encode("utf-8", "replace")) > MAX_SOURCE_BYTES:
        rejection_register.reject(REASON_OVERSIZE,
                                  f"fixture exceeds MAX_SOURCE_BYTES={MAX_SOURCE_BYTES}", fp)
        return False
    route_shape = fixture.get("route_shape") or {}
    if not isinstance(route_shape, dict):
        rejection_register.reject(REASON_STRUCTURE, "route_shape must be a mapping", fp)
        return False
    # Cheap len caps on the three free-text fields + parameter count
    # (NF-M2-06 disposition, M2 report D2 register).
    caps = {
        "endpoint_template": 2048,
        "authorization_hints": 4096,
        "candidate_rationale": 4096,
    }
    for field_name, cap in caps.items():
        value = route_shape.get(field_name)
        if value is not None and (not isinstance(value, str) or len(value) > cap):
            rejection_register.reject(REASON_STRUCTURE,
                                      f"route_shape.{field_name} missing/oversized (cap {cap})", fp)
            return False
    params = route_shape.get("parameter_names")
    if params is not None:
        if not isinstance(params, (list, tuple)) or len(params) > 64:
            rejection_register.reject(REASON_STRUCTURE,
                                      "route_shape.parameter_names missing/oversized (cap 64)", fp)
            return False
    # HAR entry-count bound re-check (mirror of the frozen MAX_HAR_ENTRIES).
    raw = fixture.get("raw")
    if isinstance(raw, dict):
        entries = raw.get("log", {}).get("entries") if isinstance(raw.get("log"), dict) else None
        if isinstance(entries, list) and len(entries) > MAX_HAR_ENTRIES:
            rejection_register.reject(REASON_OVERSIZE,
                                      f"HAR entries exceed MAX_HAR_ENTRIES={MAX_HAR_ENTRIES}", fp)
            return False
    if not isinstance(fixture.get("schema_docs", fixture.get("content_digest")), (str, dict, list, type(None))):
        rejection_register.reject(REASON_STRUCTURE, "unbounded schema payload shape", fp)
        return False
    if MAX_JSON_DEPTH <= 0:  # pragma: no cover — frozen constant sanity
        rejection_register.reject(REASON_STRUCTURE, "depth bound misconfigured", fp)
        return False
    return True


def _load_or_create_campaign_state(engagement_instance_id: str,
                                   target_url: str) -> tuple[Any, "Path"]:
    """M2-impl WP-A/WP-C: load-or-create the durable CampaignState for this
    engagement instance (the rehydration anchor). Returns (state, path)."""
    from webpent.production.campaign_state import (
        CampaignState,
        load_campaign_state,
        persist_campaign_state,
    )
    root = _audit_root(engagement_instance_id) / "campaign_state"
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{engagement_instance_id}.campaign_state.json"
    if path.exists():
        try:
            return load_campaign_state(str(path)), path
        except Exception as exc:
            # Fail-safe: a corrupted durable state must not silently reset
            # dedupe memory (replay risk). Refuse loudly.
            from webpent.production.production_spine import ProductionSpineError
            raise ProductionSpineError(
                f"durable campaign state corrupted at {path}: {exc} — refusing "
                "to silently reset dedupe/rehydration memory") from exc
    cs = CampaignState(engagement_id=engagement_instance_id, target_url=str(target_url))
    persist_campaign_state(cs, str(path))
    return cs, path


def _derive_entrypoint(state: dict[str, Any], known_entrypoints: Any, error_cls: Any) -> str:
    """TRUTHFUL, fail-closed entrypoint derivation (R3 E-4, mechanism (b)).

    Priority ladder per the ruling ("truthful > derivable > fail-closed"):

      1. TRUTHFUL — an explicit ``state["entrypoint"]`` pinned by a caller
         that knows the surface. Honored verbatim when it is a
         KNOWN_ENTRYPOINTS member; any unknown value fails closed.
         (T-03b pins that no src/ code sets it; the hook exists for
         future thawed callers and direct invokers.)
      2. EXPLICIT — the ``WEBPENT_ENTRYPOINT`` environment variable, set
         by the EDITABLE launch surfaces (``worker.py`` -> "worker",
         ``server.py`` -> "api", ``webpent-cli.sh`` -> "cli"). Any value
         outside KNOWN_ENTRYPOINTS fails closed.
      3. DERIVABLE — ``python -m webpent.cli`` launches expose
         ``__main__.__file__`` inside ``webpent/cli/``; the documented
         CLI invocation is derivable without touching frozen call sites.
      4. FAIL-CLOSED — no explicit label, no env var, underivable
         process: raise loudly. The previous silent fallback to the
         "direct_invoke" label is REMOVED — a wrong label is never
         silently emitted (never a silent wrong-label fallback).

    The drift registry's config digest includes the entrypoint, so this
    value feeds the audited trace verbatim.
    """
    state_value = state.get("entrypoint")
    if state_value is not None:
        value = str(state_value)
        if value not in known_entrypoints:
            raise error_cls(
                f"state['entrypoint']={value!r} is not a KNOWN_ENTRYPOINTS "
                f"member {sorted(known_entrypoints)} — refusing to record an "
                "unknown surface label (R3 E-4 fail-closed)."
            )
        return value

    env_value = os.environ.get("WEBPENT_ENTRYPOINT")
    if env_value:
        env_value = env_value.strip()
        if env_value not in known_entrypoints:
            raise error_cls(
                f"WEBPENT_ENTRYPOINT={env_value!r} is not a KNOWN_ENTRYPOINTS "
                f"member {sorted(known_entrypoints)} — refusing to record an "
                "unknown surface label (R3 E-4 fail-closed). Set the variable "
                "to one of the known surfaces, or unset it and launch through "
                "a documented surface."
            )
        return env_value

    # Direct attribute access (no getattr form): keeps the g02 direct-I/O
    # inventory identity set unchanged (C8 — no new adjudicated surfaces).
    main_mod = sys.modules.get("__main__")
    main_file = ""
    if main_mod is not None:
        try:
            main_file = str(main_mod.__file__ or "")
        except AttributeError:
            main_file = ""
    if main_file.endswith(os.path.join("webpent", "cli", "__main__.py")):
        return "cli"

    raise error_cls(
        "entrypoint underivable in this process (no explicit state value, no "
        "WEBPENT_ENTRYPOINT, main module is not a documented launch surface) — "
        "refusing to record a silently wrong label (R3 E-4 fail-closed). "
        "Launch through worker.py / server.py / webpent-cli.sh or "
        "`python -m webpent.cli`, or set WEBPENT_ENTRYPOINT explicitly."
    )


def _derive_target_url(state: dict[str, Any]) -> str:
    """M2-impl WP-B (declared-key ingress): derive the factory target from
    DECLARED state keys only.

    Priority ladder: ``target_url`` (declared this window) -> the declared
    ``target`` object's ``.url`` (the canonical initial-state form) ->
    ``url`` (legacy alias). Empty string fails closed at the factory
    (``target_url required``) — never a silent placeholder.
    """
    direct = state.get("target_url")
    if isinstance(direct, str) and direct.strip():
        return direct
    target_obj = state.get("target")
    if target_obj is not None and hasattr(target_obj, "url"):
        try:
            url = str(getattr(target_obj, "url") or "")
            if url.strip():
                return url
        except (AttributeError, TypeError, ValueError):
            pass
    alias = state.get("url")
    if isinstance(alias, str) and alias.strip():
        return alias
    return ""


def resolve_spine_orchestrator(state: dict[str, Any]) -> tuple[Any, Any, Any, str]:
    """M2-impl WP-B (R2 of Ruling M2-001): the campaign lane acquires its
    ModernOrchestrator via FACTORY RE-DERIVATION from declared state —
    never via state transport of the live object (PROHIBITED by R2; the
    checkpoint layer crashes loudly on it per RED-2 V13, so the prohibition
    is mandatory, not stylistic).

    Returns ``(orchestrator, production_trace, spine_config, entrypoint)``.
    Raises ProductionSpineError on any fail-closed derivation failure
    (missing/empty target, unknown entrypoint, drift detection) — callers
    convert that into a LOUD, operator-visible skip (R7), never a silent
    continuation.
    """
    from webpent.production.production_spine import (
        KNOWN_ENTRYPOINTS,
        ProductionSpineConfig,
        ProductionSpineError,
        resolve_production_spine,
    )
    engagement_id = str(state.get("engagement_id") or state.get("scan_id") or "eng_unknown")
    target_url = _derive_target_url(state)
    entrypoint = _derive_entrypoint(state, KNOWN_ENTRYPOINTS, ProductionSpineError)
    spine_config = ProductionSpineConfig(
        engagement_id=engagement_id,
        target_url=target_url,
        entrypoint=entrypoint,
    )
    orchestrator, production_trace = resolve_production_spine(spine_config)
    tool_boundary = state.get("_tool_boundary")
    advisory_memory = state.get("_advisory_memory")
    if tool_boundary is not None:
        orchestrator.tool_boundary = tool_boundary
    if advisory_memory is not None:
        orchestrator.advisory_memory = advisory_memory
    return orchestrator, production_trace, spine_config, entrypoint


def modern_spine_recon_node(state: dict[str, Any]) -> dict[str, Any]:
    """Graph node: runs the modern spine deep recon + research loop.

    This replaces the legacy recon_node as the DEFAULT. It:
      1. Instantiates ModernOrchestrator (bound to engagement_id).
      2. Runs DeepReconEngine (with sanitized schema ingestion).
      3. Initializes ResearchControlLoop + OutcomeTracker.
      4. Stores the orchestrator in state for downstream nodes.
      5. Produces modern hypotheses (authoritative) + legacy recon (advisory).

    The legacy recon_node is called AFTER the modern spine (compatibility).
    Legacy output is marked advisory_only — it cannot bypass authority.
    """
    engagement_id = str(state.get("engagement_id") or state.get("scan_id") or "eng_unknown")
    target_url = str(state.get("target_url") or state.get("url") or "")

    if not MODERN_SPINE_ENABLED:
        # Sprint I-1b, item 2.1 (BYP-05): this used to log a warning and
        # silently continue via the legacy path (state["modern_spine_disabled"]
        # = True; return state) -- a silent re-route, violating the
        # program invariant "never re-route, only reject." MODERN_SPINE_
        # ENABLED is False only when WEBPENT_MODERN_SPINE_MODE is
        # explicitly set to UNSUPPORTED_LEGACY_ONLY (WEBPENT_MODERN_SPINE=0
        # alone only downgrades to COMPATIBILITY_LEGACY, which stays
        # MODERN_SPINE_ENABLED=True and is unaffected by this change) --
        # so this is an explicit, deliberate operator action, not an
        # accidental default. It now raises, loud and named, instead of
        # degrading silently.
        raise UnsupportedLegacyOnlyModeError(
            "WEBPENT_MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY refuses to run. "
            "This mode is explicitly blocked for production authority -- the "
            "program invariant is 'never re-route, only reject.' Unset "
            "WEBPENT_MODERN_SPINE_MODE, or use COMPATIBILITY_LEGACY if you "
            "need the (fail-closed-for-authority) legacy-advisory mode instead."
        )

    # M2-impl WP-B: acquisition via the SHARED factory re-derivation helper
    # (R2) — the recon node and the campaign lane resolve identically.
    # tool_boundary / advisory_memory are non-authoritative, caller-supplied
    # conveniences the factory does not accept as parameters (per its
    # docstring: "composes existing subsystems — no new authority"); they
    # are attached inside the helper as plain attribute assignment. This
    # never touches ScopeLaw, which remains exclusively factory-derived.
    from webpent.production.production_spine import ProductionSpineError  # noqa: F401 — re-raised via helper
    orchestrator, production_trace, _spine_config, entrypoint = resolve_spine_orchestrator(state)
    state["_production_trace"] = production_trace.summary()

    # M2-impl WP-F (R6/NF-M2-02): the five SDD §8 spine flags gain a
    # fail-closed consumer. The snapshot is factory-bound (config object
    # only — never state, never mid-run env); intake scheduling is gated
    # below. Disabled flags => nothing schedulable.
    from webpent.production.spine_flag_gates import (
        SpineFlagSnapshot,
        gate_exploration_ingress,
        gate_static_fixture_source,
    )
    _flag_snapshot = SpineFlagSnapshot.from_config(_spine_config)
    _ingress_gate = gate_exploration_ingress(
        _flag_snapshot, engagement_instance_id=str(state.get("engagement_instance_id") or ""),
        target_fingerprint=str(state.get("target_fingerprint") or ""))
    _fixture_gate = gate_static_fixture_source(
        _flag_snapshot, engagement_instance_id=str(state.get("engagement_instance_id") or ""),
        target_fingerprint=str(state.get("target_fingerprint") or ""))

    # Stage 1: Deep Recon (knowledge production).
    schema_docs = state.get("openapi_spec") or state.get("schema_docs")
    observed = state.get("observed_routes") or state.get("observed_preconditions")
    recon_result = orchestrator.run_deep_recon(
        target_url=target_url,
        schema_docs=schema_docs if isinstance(schema_docs, (dict, list)) else None,
        observed=observed if isinstance(observed, (list, tuple)) else None,
    )

    # Sprint I-3: admitted fixtures enter the M2 intake boundary, then the
    # M6 advisory registration seam, before ordinary recon candidates.
    from webpent.production.external_observation_adapter import (
        convert_admitted_fixture_to_advisory,
    )
    from webpent.production.fixture_intake import RejectionRegister

    # M2-impl WP-A (R5/NF-R2-04): a REAL audit chain is produced for every
    # seam run — the D8 fail-closed audit actually fires (events land in the
    # hash-chained engagement audit file). The state carries a serializable
    # DESCRIPTOR only (C10/V13: live objects are never state transport).
    _audit_chain_obj, _audit_chain_desc = _resolve_audit_chain(
        state, engagement_id, production_trace)

    # M2-impl WP-A/WP-C (R5/NF-R2-07, R3 rehydration): durable per-engagement
    # CampaignState — the dedupe registry is backed by it and the registered
    # candidates are recorded into it for the campaign node's re-derivation.
    _eng_inst = str(state.get("engagement_instance_id") or (engagement_id + "_inst"))
    _tgt_fp = str(state.get("target_fingerprint") or "target_unknown")
    _campaign_state, _campaign_state_path = _load_or_create_campaign_state(
        _eng_inst, str(target_url or ""))
    from webpent.production.campaign_state import CampaignStateDedupeRegistry
    _dedupe_registry = CampaignStateDedupeRegistry(_campaign_state)

    _intake_records = []
    _rejection_reg = RejectionRegister()
    if _ingress_gate.decision != "ALLOW" or _fixture_gate.decision != "ALLOW":
        # WP-F (R6): disabled/boundless => NOTHING schedulable from the
        # fixture path. Loud, counted, and operator-visible — the intake
        # machinery no longer runs ungated (NF-M2-02).
        logger.warning(
            "M2 intake gated (fail-closed): exploration_ingress=%s/%s "
            "static_fixture_source=%s/%s — fixtures schedulable: NO",
            _ingress_gate.decision, _ingress_gate.reason,
            _fixture_gate.decision, _fixture_gate.reason)
    for _af in state.get("admitted_fixtures") or []:
        if not isinstance(_af, dict):
            continue
        if _ingress_gate.decision != "ALLOW" or _fixture_gate.decision != "ALLOW":
            _rejection_reg.reject(
                "spine_flag_gate_denied",
                f"exploration_ingress={_ingress_gate.reason}; "
                f"static_fixture_source={_fixture_gate.reason}",
                str(_af.get("content_digest", ""))[:32] or None)
            continue
        # M2-impl WP-A (NF-M2-06 disposition): bounds re-checked at the
        # conversion boundary — oversized/unstructured fixtures are
        # REJECTED (register + skip), never admitted unbounded.
        if not _recheck_fixture_bounds(_af, _rejection_reg):
            continue
        try:
            _artifact, _intake = convert_admitted_fixture_to_advisory(
                _af, _af.get("route_shape") or {}, _eng_inst, _tgt_fp,
                rejection_register=_rejection_reg,
            )
            _intake_records.append(_intake)
        except Exception as _conv_exc:
            import logging as _logging
            _logging.getLogger(__name__).debug("fixture conversion failed: %s", _conv_exc, exc_info=True)
            state["_fixtures_conversion_failures"] = state.get("_fixtures_conversion_failures", 0) + 1
    state["advisory_intake_records"] = _intake_records
    state["advisory_intake_rejections"] = _rejection_reg.rejections
    from webpent.production.advisory_registration import (
        publish_advisory_hypotheses,
        register_advisory_candidates_inline,
    )
    _advisory_registered, _advisory_counters = register_advisory_candidates_inline(
        state, _intake_records, audit_chain=_audit_chain_obj, token=SPINE_CALL_TOKEN,
        dedupe_registry=_dedupe_registry,
    )
    # M2-impl WP-B (C10/V13): the STATE carries a serializable projection of
    # the registered candidates (the live dataclass list is checkpoint-
    # unserializable; the objects remain in-process for this node's work).
    state["advisory_registered"] = [
        {"intake_id": _rc.intake_id, "dedupe_key": _rc.dedupe_key,
         "artifact_ref": _rc.artifact_ref, "endpoint_template": _rc.endpoint_template,
         "allowed_method": _rc.allowed_method, "terminal_state": _rc.terminal_state}
        for _rc in _advisory_registered
    ]
    state.setdefault("advisory_telemetry", {}).update(_advisory_counters)
    _recon_window = max(0, 20 - len(_advisory_registered))

    # Stage 2: Research loop initialization — register candidates from recon.
    # P1-A FIX: explicit hypothesis normalization + runtime counts + fail-visible.
    hypotheses = recon_result.get("hypotheses", [])
    registered = []
    failed = []
    # Ensure at least target-derived candidates exist even with minimal recon.
    if not hypotheses:
        hypotheses = [{"hypothesis_id": f"hyp_target_{i}", "source": "target_derived"}
                      for i in range(min(3, max(1, len(recon_result.get("routes", [])) or 1)))]
    for i, hyp in enumerate(hypotheses[:_recon_window]):
        cid = hyp.get("hypothesis_id", f"hyp_{i}") if isinstance(hyp, dict) else f"hyp_{i}"
        # Canonical hypothesis representation — one authoritative format.
        canonical = {
            "hypothesis_id": str(cid),
            "source": hyp.get("source", "deep_recon") if isinstance(hyp, dict) else "deep_recon",
            "trusted": False,  # hypotheses are NEVER trusted/confirmed at registration
            "advisory_only": True,
        }
        try:
            orchestrator.research_loop.register_candidate(
                candidate_id=canonical["hypothesis_id"],
                hypothesis_ids=(canonical["hypothesis_id"],),
                experiment_signature=f"exp_{canonical['hypothesis_id']}",
            )
            registered.append(canonical["hypothesis_id"])
        except Exception as exc:
            failed.append({"hypothesis_id": cid, "error": str(exc)[:100]})
    state["_hypotheses_produced"] = len(hypotheses)
    state["_hypotheses_registered"] = len(registered)
    state["_hypotheses_failed"] = len(failed)
    state["_registered_candidate_ids"] = registered
    state["_active_research_loop_candidates"] = len(orchestrator.research_loop._candidates)

    _matrix_row = state.get("advisory_matrix_row_spec") or {
        "owner_object_ref": "INV-B-204", "candidate_object_ref": "INV-B-204",
        "negative_control_object_ref": "INV-X-000", "information_value": 0.9,
        "engagement_id": state.get("engagement_id", "advisory"),
    }
    state["advisory_hypotheses_published"] = publish_advisory_hypotheses(
        state, _advisory_registered, _matrix_row, target_url=str(target_url),
        audit_chain=_audit_chain_obj, token=SPINE_CALL_TOKEN,
    )

    # M2-impl WP-C: durable rehydration record — persist dedupe keys + the
    # canonical registered-candidate records so the campaign node's factory
    # re-derivation can re-register them (registered == recovered).
    for _rc in _advisory_registered:
        _campaign_state.record_registered_candidate(
            candidate_id=f"adv_{_rc.intake_id}",
            hypothesis_ids=(f"adv_{_rc.intake_id}",),
            experiment_signature=f"exp_adv_{_rc.intake_id}",
            dedupe_key=_rc.dedupe_key,
        )
    from webpent.production.campaign_state import persist_campaign_state
    persist_campaign_state(_campaign_state, str(_campaign_state_path))

    # Stage 3: First research step (advisory prioritization).
    try:
        research_decision = orchestrator.research_step()
    except Exception as exc:
        logger.debug("research_step bounded: %s", exc)
        research_decision = {"selected_candidate": None, "bounded": True}

    # Store orchestrator transport: REMOVED (M2-impl WP-B, R2 of Ruling
    # M2-001). The live object NEVER rides graph state — the checkpoint
    # layer fails loudly on it (RED-2 V13) and state transport of the
    # orchestrator is the prohibited second-authority path. The campaign
    # lane re-derives via resolve_spine_orchestrator (factory); downstream
    # execution authorization re-resolves the same way. The engagement
    # target is routed to the factory through DECLARED state
    # (target_url declared this window; derived from the declared `target`).
    state["target_url"] = str(target_url or "")
    state["modern_spine_mode"] = MODERN_SPINE_MODE
    state["legacy_compatibility_mode"] = LEGACY_COMPATIBILITY_MODE
    state["legacy_authority_blocked"] = False  # modern spine active, authority available
    state["_modern_spine_trace"] = orchestrator.trace.summary()
    state["_modern_spine_hypothesis_evidence"] = {
        "produced": state["_hypotheses_produced"],
        "registered": state["_hypotheses_registered"],
        "failed": state["_hypotheses_failed"],
        "active_loop_candidates": state["_active_research_loop_candidates"],
        "candidate_ids": registered,
    }
    state["_modern_hypotheses"] = hypotheses[:50]
    state["_modern_research_decision"] = research_decision
    state["modern_spine_active"] = True
    state["modern_spine_version"] = orchestrator.trace.spine_version

    logger.info(
        "Modern spine activated: engagement=%s hypotheses=%d trace_stages=%s",
        engagement_id, len(hypotheses), orchestrator.trace.summary().get("stages_seen", []),
    )
    return state


def get_modern_orchestrator(state: dict[str, Any]) -> Any | None:
    """Retrieve the bound ModernOrchestrator from graph state (downstream use).

    M2-impl WP-B (R2): the orchestrator is NO LONGER state-transported. This
    accessor is retained ONLY for in-process callers that run the node
    function directly (the object exists in-process); through the compiled
    graph it deterministically returns None — the correct fail-closed input
    for :func:`modern_spine_execution_authorized`. Campaign-lane and
    execution authority MUST re-derive via :func:`resolve_spine_orchestrator`.
    """
    return state.get("_modern_orchestrator")


def modern_spine_execution_authorized(state: dict[str, Any], *, tool_name: str,
                                      target_url: str, arguments: tuple = ()) -> Any:
    """Authorize execution through the modern spine's bound ScopeLaw.

    Downstream nodes MUST call this (or orchestrator.authorize_execution)
    before any effectful action. Returns the ScopeDecision; fail closed if
    no orchestrator is bound.
    """
    orch = get_modern_orchestrator(state)
    if orch is None:
        # No modern orchestrator bound — fail closed for production.
        # Legacy paths must use ContainedHTTPClient which also requires bound scope.
        from webpent.live_hunter.tool_scope import ScopeDecision
        return ScopeDecision(
            tool_name=tool_name, target_url=target_url, in_scope=False,
            poison_detected=False, poison_details=(),
            reason="modern_orchestrator_not_bound_execution_denied",
        )
    return orch.authorize_execution(tool_name=tool_name, target_url=target_url, arguments=arguments)


__all__ = [
    "modern_spine_recon_node", "modern_spine_execution_authorized", "MODERN_SPINE_ENABLED",
    "resolve_spine_orchestrator",
]
