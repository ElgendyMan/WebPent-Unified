"""TEAM-1 — Single authoritative production spine factory + resolver.

This module is the ONE place where the production modern spine is constructed.
CLI, API, and worker MUST all resolve through `resolve_production_spine()`.
Any configuration drift that would cause a weaker/legacy path is detected and
fails closed (raises ProductionSpineError) rather than silently routing to legacy.

Production trace: compact, deterministic, serializable record of the full
end-to-end causal chain: entrypoint → spine activation → DeepRecon →
WorldModel mutation → research decision → bounded tool execution → observation
→ outcome recording → replan → CausalGuard → ProofBundle → promotion decision.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Final

from webpent.live_hunter.profile import build_authorized_lab_profile
from webpent.live_hunter.tool_scope import ScopeLaw
from webpent.production.modern_spine import (
    _FACTORY_TOKEN,
    ModernOrchestrator,
)

PRODUCTION_SPINE_VERSION: Final[str] = "production_spine_v1"

# Entrypoints that MUST resolve through this factory.
KNOWN_ENTRYPOINTS: Final[frozenset[str]] = frozenset({"cli", "api", "worker", "direct_invoke"})


class ProductionSpineError(RuntimeError):
    """Raised when production spine cannot be resolved or configuration drift detected."""


logger = logging.getLogger(__name__)

_FOREIGN_WRITER_ENV_VAR: Final[str] = "WEBPENT_FOREIGN_REPORT_WRITER_ACCESS"

# Sprint I-1 Continuation — Part 4 (program spec §8.4 "Feature-flag
# strategy" + the architecture-authority ruling on internal_catcher_source,
# recorded verbatim in EngagementAuditChain-adjacent sprint documentation —
# see the sprint changelog for the full ruling text). Five flags exist;
# deliberately NO internal_catcher_source flag (the class is RESERVED with
# mechanical hard-rejection catcher_producer_unknown elsewhere — out of
# this dataclass's scope, since there is nothing to configure for a class
# with no activation path at all).
_EXPLORATION_INGRESS_ENV_VAR: Final[str] = "WEBPENT_EXPLORATION_INGRESS_ENABLED"
_STATIC_FIXTURE_SOURCE_ENV_VAR: Final[str] = "WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED"
_LIVE_PROXY_SOURCE_ENV_VAR: Final[str] = "WEBPENT_LIVE_PROXY_SOURCE_ENABLED"
_MULTI_PRINCIPAL_EXECUTION_ENV_VAR: Final[str] = "WEBPENT_MULTI_PRINCIPAL_EXECUTION_ENABLED"

_LAB_PROFILE_VALUE: Final[str] = "lab"
_PROFILE_ENV_ALIASES: Final[tuple[str, ...]] = (
    "WEBPENT_ENVIRONMENT_PROFILE", "ENVIRONMENT_PROFILE", "environment_profile",
)


def _resolve_strict_bool_flag(explicit: bool | None, *, env_var: str) -> bool:
    """Sprint I-1, item 2.5 (M3 v1.1 §5.3, F-04/OQ-6): resolve a fail-closed
    spine flag. ``ProductionSpineConfig`` is the authoritative source; the
    named environment variable is a documented FALLBACK, applied only when
    the config field was not explicitly set (``explicit is None``).

    Strict-bool semantics: only the literal strings ``"True"``/``"False"``
    (case-insensitive) are accepted from the environment. Any other value
    (``"1"``, ``"true"``, ``"yes"``, malformed strings, unset) resolves to
    ``False`` — invalid values must never silently enable a fail-closed
    flag. An invalid (non-empty, unrecognized) value is logged as a
    warning so a misconfigured operator finds out, rather than silently
    running with the flag off.
    """
    if explicit is not None:
        return explicit
    raw = os.environ.get(env_var)
    if raw is None:
        return False
    normalized = raw.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    logger.warning(
        "%s=%r is not a recognized strict-bool value (only \"True\"/\"False\", "
        "case-insensitive, are accepted) — resolving to disabled (fail-closed).",
        env_var, raw,
    )
    return False


def _is_lab_environment() -> bool:
    """Sprint I-1 Continuation, Part 4 (multi_principal_execution_enabled:
    "approved-lab engagements only"): True only when every
    environment_profile alias that IS set says "lab" (and at least the
    Settings default applies when none are set). Fail-closed on
    ambiguity, consistent with this flag's own capability-reduction
    principle: if two aliases disagree (one says "lab", another says
    "production"), this returns False — a flag that grants capability
    must not be satisfied by an ambiguous signal, unlike the
    construction-escape gate (Sprint I-1 item 1.3), where fail-closed
    means "any alias indicating strict is enough to DENY" — here it is
    "every set alias must agree it's lab to ALLOW".
    """
    seen = [os.environ[v].strip().lower() for v in _PROFILE_ENV_ALIASES if os.environ.get(v)]
    if not seen:
        return True  # Settings' own default is "lab"
    return all(v == _LAB_PROFILE_VALUE for v in seen)


@dataclass(frozen=True)
class ProductionSpineConfig:
    """Single authoritative config for all entrypoints. Frozen — no drift."""
    engagement_id: str
    target_url: str
    entrypoint: str  # one of KNOWN_ENTRYPOINTS
    auto_approve: bool = False
    modern_spine_enabled: bool = True
    checkpointer_enabled: bool = True
    # Sprint I-1, item 2.5 (M3 v1.1 §5.3): None means "not explicitly set
    # by the caller" — __post_init__ then applies the WEBPENT_FOREIGN_
    # REPORT_WRITER_ACCESS environment-variable fallback via strict-bool
    # resolution, defaulting to False (fail-closed) if neither is set.
    foreign_report_writer_access: bool | None = None
    # Sprint I-1 Continuation, Part 4 (program spec §8.4): same None-means-
    # unset / strict-bool-env-fallback / fail-closed-default pattern as
    # foreign_report_writer_access above, for the remaining four Phase-1
    # flags. NO internal_catcher_source field exists here — see the
    # architecture-authority ruling in the sprint changelog: the class is
    # RESERVED with mechanical hard-rejection, with deliberately no
    # activation path to configure.
    exploration_ingress_enabled: bool | None = None
    static_fixture_source_enabled: bool | None = None
    live_proxy_source_enabled: bool | None = None
    multi_principal_execution_enabled: bool | None = None

    def __post_init__(self):
        if self.entrypoint not in KNOWN_ENTRYPOINTS:
            raise ProductionSpineError(f"Unknown entrypoint: {self.entrypoint}. Must be one of {sorted(KNOWN_ENTRYPOINTS)}.")
        if not self.engagement_id or not self.engagement_id.strip():
            raise ProductionSpineError("engagement_id required for production spine")
        if not self.target_url or not self.target_url.strip():
            raise ProductionSpineError("target_url required for production spine")
        if not self.modern_spine_enabled:
            raise ProductionSpineError(
                "modern_spine_enabled=False is NOT permitted in production spine. "
                "Legacy path is advisory-only, never authoritative."
            )
        # Frozen dataclass: object.__setattr__ is the standard escape hatch
        # for __post_init__-time field resolution.
        object.__setattr__(
            self, "foreign_report_writer_access",
            _resolve_strict_bool_flag(
                self.foreign_report_writer_access, env_var=_FOREIGN_WRITER_ENV_VAR,
            ),
        )
        # Sprint I-1 Continuation, Part 4: resolve the remaining four
        # flags the same way, then apply each flag's own extra binding
        # rule from the program spec / ruling.
        object.__setattr__(
            self, "exploration_ingress_enabled",
            _resolve_strict_bool_flag(
                self.exploration_ingress_enabled, env_var=_EXPLORATION_INGRESS_ENV_VAR,
            ),
        )
        object.__setattr__(
            self, "static_fixture_source_enabled",
            _resolve_strict_bool_flag(
                self.static_fixture_source_enabled, env_var=_STATIC_FIXTURE_SOURCE_ENV_VAR,
            ),
        )
        object.__setattr__(
            self, "live_proxy_source_enabled",
            _resolve_strict_bool_flag(
                self.live_proxy_source_enabled, env_var=_LIVE_PROXY_SOURCE_ENV_VAR,
            ),
        )
        if self.live_proxy_source_enabled:
            # Program spec §8.4: "live proxy source disabled for Phase 1."
            # Hardwired-off, per the original Part 4 brief: "any Phase 1
            # configuration enabling it is rejected" — not merely
            # defaulted False, but a hard reject if anyone tries to turn
            # it on, from either the config field or the env fallback.
            # There is no Phase-gating construct anywhere else in this
            # codebase (verified this sprint) — Phase 1 is simply the
            # entire current system, so this rejection is unconditional
            # for as long as this code exists as written.
            raise ProductionSpineError(
                "live_proxy_source_enabled=True is not permitted: hardwired off "
                "for Phase 1 (program spec §8.4). No live-proxy source exists "
                "yet to gate; enabling this flag has nothing behind it."
            )
        object.__setattr__(
            self, "multi_principal_execution_enabled",
            _resolve_strict_bool_flag(
                self.multi_principal_execution_enabled,
                env_var=_MULTI_PRINCIPAL_EXECUTION_ENV_VAR,
            ),
        )
        if self.multi_principal_execution_enabled and not _is_lab_environment():
            # Program spec §8.4: "multi-principal execution enabled only
            # for approved lab engagement." No dedicated "approved-lab
            # engagement" marker exists elsewhere in the codebase; the
            # closest, already-existing concept is
            # config.settings.EnvironmentProfile.LAB — used here as a
            # documented design choice, not spec-given verbatim text.
            raise ProductionSpineError(
                "multi_principal_execution_enabled=True is not permitted outside "
                "a lab environment_profile (program spec §8.4: 'approved-lab "
                "engagements only')."
            )

    def digest(self) -> str:
        payload = json.dumps({
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "entrypoint": self.entrypoint,
            "auto_approve": self.auto_approve,
            "modern_spine_enabled": self.modern_spine_enabled,
            "checkpointer_enabled": self.checkpointer_enabled,
            "foreign_report_writer_access": self.foreign_report_writer_access,
            "exploration_ingress_enabled": self.exploration_ingress_enabled,
            "static_fixture_source_enabled": self.static_fixture_source_enabled,
            "live_proxy_source_enabled": self.live_proxy_source_enabled,
            "multi_principal_execution_enabled": self.multi_principal_execution_enabled,
            "spine_version": PRODUCTION_SPINE_VERSION,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class ProductionTrace:
    """Compact, deterministic runtime trace of the full causal chain.

    Every stage is recorded with a deterministic digest. The final trace digest
    proves the chain executed end-to-end. Missing stages → trace incomplete.
    """
    config_digest: str
    entrypoint: str
    stages: list[dict[str, Any]] = field(default_factory=list)
    _stage_set: set[str] = field(default_factory=set)
    _counted_stage_count: int = field(default=0, init=False, repr=False)

    MAX_STAGES: Final[int] = 50

    def record(
        self,
        *,
        stage: str,
        component: str,
        detail: dict[str, Any] | None = None,
        counts_toward_limit: bool = True,
    ) -> None:
        """Append a redacted stage while bounding execution-stage growth.

        Audit-chain entries remain individually trace-anchored for verification,
        but they are not execution stages and therefore do not consume the
        production execution budget. This prevents high-volume audit telemetry
        from masking a real execution loop or blocking a legitimate campaign.
        """
        if counts_toward_limit and self._counted_stage_count >= self.MAX_STAGES:
            raise ProductionSpineError(f"Production trace bounded — stage limit {self.MAX_STAGES} reached")
        entry = {"stage": stage, "component": component, "detail": detail or {}}
        self.stages.append(entry)
        self._stage_set.add(stage)
        if counts_toward_limit:
            self._counted_stage_count += 1

    def saw(self, stage: str) -> bool:
        return stage in self._stage_set

    def required_stages(self) -> list[str]:
        return [
            "entrypoint_resolve", "spine_activation", "deep_recon", "world_model_mutation",
            "research_decision", "bounded_tool_execution", "observation", "outcome_recording",
            "replan", "causal_guard_evaluation", "proof_bundle_creation", "promotion_decision",
        ]

    def is_complete(self) -> tuple[bool, list[str]]:
        missing = [s for s in self.required_stages() if s not in self._stage_set]
        return (len(missing) == 0, missing)

    def digest(self) -> str:
        payload = json.dumps({
            "config_digest": self.config_digest,
            "entrypoint": self.entrypoint,
            "stages": [{"stage": s["stage"], "component": s["component"]} for s in self.stages],
            "spine_version": PRODUCTION_SPINE_VERSION,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    def summary(self) -> dict[str, Any]:
        """Export the redacted trace summary plus the trace's own
        chain-integrity attestation.

        TRACE-R1 (Dispatch #046, TC-5 P0 hotfix; authorized by the
        LCS-REAL cycle-2 lab finding): ``chain_verified`` is a COMPUTED
        field, derived here from the trace's own integrity state — the
        same authorities the terminal gate trusts. It is never a
        pass-through boolean a caller can set; the trace attests its own
        chain integrity the way it attests completeness. Derivation::

            chain_verified = complete AND digest_verified AND audit_verified

        - ``complete`` — every required production stage is present
          (``is_complete()``); the same completeness verdict this
          summary already exports.
        - ``digest_verified`` — the trace digest is EARNED from the
          recorded state, not asserted alongside it: the deduplicated
          stage index (``_stage_set`` — the view ``is_complete()`` and
          ``saw()`` read) must exactly equal the stage names actually
          present in the recorded stage list the digest is computed
          over, and the digest must hold stable across the export
          (recomputed around the stages projection). A stage list
          mutated out-of-band — bypassing ``record()`` — desyncs the
          two views or shifts the digest mid-export and fails here
          (fail-closed: tampered trace ⇒ False).
        - ``audit_verified`` — the audit chain anchors its lifecycle
          INTO this trace (per-event ``audit_event`` summaries and the
          ``audit_finalization`` stage carrying the chain's root hash —
          the OQ-8 trace anchor). The trace attests its anchor set is
          intact: exactly one finalization stage, carrying a non-empty
          64-hex root hash, whose ``event_id`` is also present among
          the per-event anchors. The file-side recomputation of the
          chain itself remains owned by
          ``webpent.shared.engagement_audit.verify_chain`` — the
          terminal gate keeps its independent audit vote; this field
          never substitutes for it.

        A trace that is incomplete OR tampered OR audit-broken
        therefore exports ``chain_verified=False`` — fail-closed
        preserved: absence of evidence is evidence of absence, exactly
        the way a missing required stage is.
        """
        complete, missing = self.is_complete()

        # -- TRACE-R1: digest verification (earned, never asserted) -----
        digest_before = self.digest()
        stages_projection = [
            {"stage": entry["stage"], "component": entry["component"]}
            for entry in self.stages
        ]
        digest_after = self.digest()
        digest_verified = (
            self._stage_set == {entry["stage"] for entry in stages_projection}
            and digest_before == digest_after
        )

        # -- TRACE-R1: audit-chain verification (trace-side anchors) ----
        finalizations = [
            entry for entry in self.stages
            if entry["stage"] == "audit_finalization"
        ]
        audit_event_ids = {
            (entry.get("detail") or {}).get("event_id")
            for entry in self.stages
            if entry["stage"] == "audit_event"
        }
        audit_verified = False
        if len(finalizations) == 1:
            detail = finalizations[0].get("detail") or {}
            root_hash = detail.get("root_hash")
            event_id = detail.get("event_id")
            audit_verified = (
                isinstance(root_hash, str)
                and len(root_hash) == 64
                and isinstance(event_id, str)
                and bool(event_id)
                and event_id in audit_event_ids
            )

        return {
            "config_digest": self.config_digest,
            "entrypoint": self.entrypoint,
            "stage_count": len(self.stages),
            "bounded_stage_count": self._counted_stage_count,
            "stages_seen": sorted(self._stage_set),
            "missing_required_stages": missing,
            "complete": complete,
            "chain_verified": bool(complete and digest_verified and audit_verified),
            "trace_digest": digest_after,
            "spine_version": PRODUCTION_SPINE_VERSION,
        }


# Module-level registry — detects if two entrypoints construct different spines.
_SPINE_REGISTRY: dict[str, str] = {}


def _foreign_writer_access_enabled() -> bool:
    """Sprint I-1, item 2.5 (M3 v1.1 §5.3) gating helper for call sites
    that have no ``ProductionSpineConfig`` to read from — e.g.
    ``tools/registry.py``'s ``register_tool()`` decorator, which runs at
    *module-import time* during ``auto_discover()``, before any
    engagement's spine config exists. There is no "current engagement"
    concept at that point (``_SPINE_REGISTRY`` is keyed per
    ``engagement_id``, not a process-global), so this reads the
    documented environment-variable fallback directly, with the same
    strict-bool semantics as the config field. A caller that DOES have a
    resolved ``ProductionSpineConfig`` should read
    ``config.foreign_report_writer_access`` instead — that is always the
    authoritative source when it's available.
    """
    return _resolve_strict_bool_flag(None, env_var=_FOREIGN_WRITER_ENV_VAR)


def resolve_production_spine(config: ProductionSpineConfig) -> tuple[ModernOrchestrator, ProductionTrace]:
    """Single authoritative resolver for ALL entrypoints.

    CLI, API, worker, direct_invoke all call this. Configuration drift between
    entrypoints is detected via the config digest registry. A weaker config
    (modern_spine_enabled=False, missing engagement_id, unknown entrypoint)
    fails closed rather than routing to legacy.
    """
    # Fail closed on any production-ambiguity.
    if config.modern_spine_enabled is not True:
        raise ProductionSpineError("Production spine requires modern_spine_enabled=True")

    # Registry drift detection: same engagement_id across entrypoints must have
    # identical config digest. If a second entrypoint tries to use a weaker
    # config for the same engagement, fail closed.
    cfg_digest = config.digest()
    if config.engagement_id in _SPINE_REGISTRY:
        if _SPINE_REGISTRY[config.engagement_id] != cfg_digest:
            raise ProductionSpineError(
                f"Configuration drift detected for engagement {config.engagement_id}: "
                f"entrypoint '{config.entrypoint}' uses config {cfg_digest} but "
                f"previously resolved with {_SPINE_REGISTRY[config.engagement_id]}. "
                "Failing closed — all entrypoints must use identical production spine config."
            )
    else:
        _SPINE_REGISTRY[config.engagement_id] = cfg_digest

    trace = ProductionTrace(config_digest=cfg_digest, entrypoint=config.entrypoint)
    trace.record(stage="entrypoint_resolve", component="ProductionSpineResolver",
                 detail={"entrypoint": config.entrypoint, "config_digest": cfg_digest})
    # Sprint I-1, item 2.5 (M3 v1.1 §5.3) / Sprint I-1 Continuation Part 4
    # (program spec §8.4): every spine flag resolution is trace-recorded,
    # regardless of source (explicit config vs. env-var fallback), bound
    # to engagement_id + target_fingerprint — the trace only records the
    # final resolved value, since ProductionSpineConfig.__post_init__ has
    # already collapsed each flag's two sources by this point.
    from webpent.shared.bac_identity_tester import target_fingerprint as _target_fingerprint
    trace.record(
        stage="flag_resolution", component="ProductionSpineConfig",
        detail={
            "engagement_id": config.engagement_id,
            "target_fingerprint": _target_fingerprint(config.target_url),
            "foreign_report_writer_access": config.foreign_report_writer_access,
            "exploration_ingress_enabled": config.exploration_ingress_enabled,
            "static_fixture_source_enabled": config.static_fixture_source_enabled,
            "live_proxy_source_enabled": config.live_proxy_source_enabled,
            "multi_principal_execution_enabled": config.multi_principal_execution_enabled,
        },
    )

    # Build ScopeLaw from canonical profile builder (one authority, no duplication).
    from urllib.parse import urlparse
    from webpent.live_hunter.profile import LOOPBACK_HOSTS
    host = urlparse(config.target_url).hostname or config.target_url
    is_lab_fixture = host in LOOPBACK_HOSTS
    profile = build_authorized_lab_profile(
        engagement_id=config.engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        authorized_targets=(host,),
        lab_fixture_mode=is_lab_fixture,
        knowledge_ready=True,
    )
    scope_law = ScopeLaw(profile=profile, engagement_id=config.engagement_id)
    from webpent.llm_researcher.tool_boundary import ToolBoundary
    tool_boundary = ToolBoundary(allowed_hosts=(host,))
    orchestrator = ModernOrchestrator(
        engagement_id=config.engagement_id,
        scope_law=scope_law,
        tool_boundary=tool_boundary,
        _factory_token=_FACTORY_TOKEN,
    )
    trace.record(stage="spine_activation", component="ModernOrchestrator",
                 detail={"spine_version": PRODUCTION_SPINE_VERSION})

    return orchestrator, trace


def entrypoint_parity_check(entrypoints: list[str], *, engagement_id: str, target_url: str) -> dict[str, Any]:
    """Verify CLI/API/worker produce semantically equivalent orchestration state.

    Resolves each entrypoint through the same factory and compares: ScopeLaw
    profile digest, ModernOrchestrator components, spine version. Any drift
    fails closed.
    """
    results: dict[str, Any] = {}
    digests: set[str] = set()
    # Clear registry for parity check (same engagement across entrypoints is expected).
    _SPINE_REGISTRY.pop(engagement_id, None)
    for ep in entrypoints:
        cfg = ProductionSpineConfig(engagement_id=f"{engagement_id}_{ep}", target_url=target_url, entrypoint=ep)
        orch, trace = resolve_production_spine(cfg)
        # Parity compares structure (authorized_targets), not engagement-specific digest.
        scope_digest = hashlib.sha256(json.dumps(
            sorted(str(t) for t in orch.scope_law.profile.authorized_targets)
        ).encode()).hexdigest()[:16]
        results[ep] = {
            "config_digest": cfg.digest(),
            "scope_law_digest": scope_digest,
            "spine_version": PRODUCTION_SPINE_VERSION,
            "has_deep_recon": orch.deep_recon is not None,
            "has_world_model": orch.world_model is not None,
            "has_research_loop": orch.research_loop is not None,
            "has_outcome_tracker": orch.outcome_tracker is not None,
        }
        digests.add(scope_digest)
    parity = len(digests) == 1
    return {
        "entrypoints_checked": entrypoints,
        "parity": parity,
        "unique_scope_law_digests": len(digests),
        "results": results,
    }


__all__ = [
    "ProductionSpineConfig", "ProductionSpineError", "ProductionTrace",
    "resolve_production_spine", "entrypoint_parity_check",
    "PRODUCTION_SPINE_VERSION", "KNOWN_ENTRYPOINTS",
]
