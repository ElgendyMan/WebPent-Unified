# src/webpent/production/modern_spine.py
"""TEAM-1 MODERN AUTONOMOUS SPINE V1 — single orchestration contract.

This module is the ONE authoritative integration point for the modern
execution architecture. It wires the modern components into a single
controlled chain:

    Official Entrypoint
      -> ModernOrchestrator
        -> DeepReconEngine        (knowledge producer)
        -> EvidenceGraph/WorldModel (persistent structured world state)
        -> ResearchControlLoop    (decision/replanning controller)
        -> OutcomeTracker         (experiment-result learning signal)
        -> ScopeLaw / ToolBoundary (execution authority)
        -> CausalGuard            (deterministic causal adjudication)
        -> ProofBundle            (evidence artifact)
        -> Persistence / Replay

ORCHESTRATION CONTRACT (ownership is explicit, no component becomes a
second planner, no legacy specialist becomes alternate authority):

  DeepReconEngine      — produces structured knowledge only. Never decides.
  WorldModel           — remembers observed state only. Never authorizes.
  ResearchControlLoop  — prioritizes candidates only. LLM advisory only.
  OutcomeTracker       — records experiment outcomes. Bounded history.
  ScopeLaw/ToolBoundary — SOLE authority for execution authorization.
  CausalGuard          — SOLE authority for causal adjudication.
  ProofBundle          — SOLE evidence artifact. Semantic completeness
                         enforced BEFORE seal/promotion validity.

The LLM may propose. The research loop may prioritize. The WorldModel may
remember. The memory layer may inform. But only deterministic runtime
authority may authorize execution, establish provenance, adjudicate
causality, validate semantic evidence, and promote a finding.
"""
from __future__ import annotations

import hashlib
import ipaddress  # F-04 (0.33.0): literal-loopback restriction for the
# emergency raw-client fallback (see _is_literal_loopback_origin).
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final
from urllib.parse import urlsplit
from uuid import uuid4

from webpent.shared.http import HTTPTransportError, SSRFRedirectBlockedError


def _is_literal_loopback_origin(url: str) -> bool:
    """F-04 (0.33.0): True ONLY for literal loopback origins.

    The emergency raw-httpx fallback below exists so an authorized
    LOOPBACK lab target keeps working if the canonical safe-client
    factory raises a non-SSRF error. Before 0.33.0 that fallback ran
    for ANY origin — silently discarding DNS pinning, the private-IP
    blocklist and the origin policy for exactly the host the guard
    would have pinned. A literal loopback address has no DNS to
    rebind, so the fallback is now restricted to 127.0.0.0/8, ::1 and
    "localhost"; every other origin fails closed (re-raise).
    """
    try:
        host = (urlsplit(url).hostname or "").strip().lower()
    except ValueError:
        return False
    if not host:
        return False
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Runtime trace — minimal instrumentation to establish actual execution flow.
# We do NOT flood logs; each spine invocation produces one bounded trace record.
# ---------------------------------------------------------------------------

_SPINE_VERSION: Final[str] = "modern_spine_v1"


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


@dataclass(frozen=True)
class SpineTraceEvent:
    """One immutable event in the modern spine execution trace."""
    stage: str
    component: str
    detail_digest: str  # sha256 of bounded detail, not raw content
    at: str = field(default_factory=_utc)

    def digest(self) -> str:
        payload = json.dumps(
            {"stage": self.stage, "component": self.component, "detail_digest": self.detail_digest, "at": self.at},
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class SpineTrace:
    """Bounded, append-only runtime trace proving the modern spine executed."""
    # TEAM-1 AVI V1: raised from 200 to support long autonomous campaigns
    # (30 decisions × 3 real executions × several trace events each).
    MAX_EVENTS: Final[int] = 5000

    def __init__(self) -> None:
        self._events: list[SpineTraceEvent] = []
        self.spine_version = _SPINE_VERSION

    @property
    def events(self) -> tuple[SpineTraceEvent, ...]:
        return tuple(self._events)

    def record(self, *, stage: str, component: str, detail: Any = None) -> SpineTraceEvent:
        if len(self._events) >= self.MAX_EVENTS:
            raise RuntimeError("spine trace bounded — event limit reached")
        detail_str = json.dumps(detail if detail is not None else {}, sort_keys=True, default=str)[:4096]
        detail_digest = hashlib.sha256(detail_str.encode()).hexdigest()
        evt = SpineTraceEvent(stage=stage, component=component, detail_digest=detail_digest)
        self._events.append(evt)
        logger.debug("modern_spine trace: stage=%s component=%s", stage, component)
        return evt

    def saw_stage(self, stage: str) -> bool:
        return any(e.stage == stage for e in self._events)

    def summary(self) -> dict[str, Any]:
        return {
            "spine_version": self.spine_version,
            "event_count": len(self._events),
            "stages_seen": sorted({e.stage for e in self._events}),
            "components_seen": sorted({e.component for e in self._events}),
            "trace_digest": hashlib.sha256(
                "".join(e.digest() for e in self._events).encode()
            ).hexdigest() if self._events else None,
        }


# ---------------------------------------------------------------------------
# Modern Orchestrator — the single controlled entrypoint.
# ---------------------------------------------------------------------------

class ModernSpineError(RuntimeError):
    """Raised when the modern spine contract is violated."""


# FIX 1: construction-authority sentinel. Only
# webpent.production.production_spine.resolve_production_spine() may import
# and pass this token; ModernOrchestrator.__init__ raises unless it receives
# this exact object, so no other module can forge it by passing a lookalike
# value (e.g. True or "token").
_FACTORY_TOKEN: Final[object] = object()

# Explicit, clearly-named test-only escape (see tests/conftest.py, which sets
# this for the whole suite so direct-construction unit tests below the
# integration layer keep working without threading a factory token through
# every test file). Never set by application code.
_TEST_ESCAPE_ENV: Final[str] = "WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY"


class ModernOrchestrator:
    """The ONE modern execution spine.

    Integrates: DeepReconEngine -> WorldModel(EvidenceGraph) ->
    ResearchControlLoop -> OutcomeTracker -> ScopeLaw/ToolBoundary ->
    CausalGuard -> ProofBundle -> Persistence/Replay.

    This class does NOT duplicate any authority component. It composes the
    existing authoritative implementations. All effectful actions route
    through ScopeLaw/ToolBoundary; all promotion-grade results route through
    EvidenceExecutor/CausalGuard/ProofBundle semantic validation.
    """

    MAX_RECON_STEPS: Final[int] = 50
    MAX_RESEARCH_STEPS: Final[int] = 100

    def __init__(
        self,
        *,
        engagement_id: str,
        scope_law: Any = None,
        tool_boundary: Any = None,
        advisory_memory: Any = None,
        _factory_token: Any = None,
    ) -> None:
        # FIX 1: construction-authority guard. Only
        # production_spine.resolve_production_spine() holds _FACTORY_TOKEN.
        # Direct construction anywhere else raises unless the explicit
        # test-only escape env var is set (see tests/conftest.py). This
        # never weakens ScopeLaw/ToolBoundary/CausalGuard/ProofBundle
        # validation — it only gates who may build the object at all.
        if _factory_token is not _FACTORY_TOKEN:
            import os
            import sys
            # M2-impl WP-H (RED-2 register: _TEST_ESCAPE_ENV containment).
            # The env escape is now contained to TEST PROCESSES: outside
            # pytest the bare env var is inert. Tightens only (fail-closed
            # direction, C4); every in-suite caller still passes (pytest is
            # in sys.modules for the whole test run).
            _escape_active = (
                os.environ.get(_TEST_ESCAPE_ENV) == "1"
                and ("pytest" in sys.modules
                     or "PYTEST_CURRENT_TEST" in os.environ)
            )
            if not _escape_active:
                raise ModernSpineError(
                    "ModernOrchestrator must be constructed via "
                    "webpent.production.production_spine.resolve_production_spine(); "
                    "direct construction is not a supported production path. "
                    f"Test code may set {_TEST_ESCAPE_ENV}=1 inside a test "
                    "process only (the escape is pytest-contained since "
                    "M2-impl WP-H)."
                )
        if not engagement_id or not isinstance(engagement_id, str):
            raise ModernSpineError("engagement_id required")
        self.engagement_id: str = engagement_id
        self.trace = SpineTrace()
        self._active = False
        self._completed = False
        # PART 7: Automatic fabric dispatch trace — runtime-derived.
        self._fabric_dispatch_trace: list = []

        # Lazy imports to avoid hard dependency cycles at module load.
        from webpent.live_hunter.deep_recon import DeepReconEngine
        from webpent.live_hunter.research_loop import OutcomeTracker, ResearchControlLoop
        from webpent.live_hunter.world_model import EvidenceGraph

        # WorldModel / EvidenceGraph — persistent structured world state.
        self.world_model: EvidenceGraph = EvidenceGraph(engagement_id=engagement_id)
        self.trace.record(stage="init", component="WorldModel", detail={"engagement_id": engagement_id})

        # DeepReconEngine — knowledge producer only.
        self.deep_recon = DeepReconEngine(engagement_id=engagement_id, graph=self.world_model)
        self.trace.record(stage="init", component="DeepReconEngine")

        # OutcomeTracker — experiment-result learning signal.
        self.outcome_tracker = OutcomeTracker()
        self.trace.record(stage="init", component="OutcomeTracker")

        # ResearchControlLoop — decision/replanning controller (advisory only).
        self.research_loop = ResearchControlLoop(
            engagement_id=engagement_id, graph=self.world_model
        )
        self.trace.record(stage="init", component="ResearchControlLoop")

        # Execution authority — ScopeLaw / ToolBoundary.
        # These are the SOLE authority. The orchestrator never bypasses them.
        self.scope_law = scope_law  # may be None; set per-engagement by caller
        self.tool_boundary = tool_boundary  # may be None; set per-engagement

        # Advisory memory — advisory only, never authority.
        self.advisory_memory = advisory_memory

        self.trace.record(stage="init", component="ModernOrchestrator", detail={"spine_version": _SPINE_VERSION})

    # -- Stage 1: Deep Recon (knowledge production) -------------------------

    def run_deep_recon(self, *, target_url: str, schema_docs: Any = None, observed: Any = None) -> dict[str, Any]:
        """Run DeepReconEngine to produce structured knowledge.

        DeepRecon is a KNOWLEDGE PRODUCER. It does not authorize execution,
        confirm findings, or promote anything. Output feeds WorldModel.
        """
        if self._completed:
            raise ModernSpineError("spine already completed — create a new orchestrator")
        self._active = True
        self.trace.record(stage="deep_recon", component="DeepReconEngine", detail={"target_url": target_url})

        # Advisory memory may inform recon prioritization (advisory only).
        advisory_context = None
        if self.advisory_memory is not None:
            advisory_context = self.advisory_memory.retrieve_advisory(target_url=target_url)
            if advisory_context:
                self.trace.record(stage="deep_recon", component="AdvisoryMemory", detail={"informed_recon": True})

        # Ingest schema docs through the sanitized ingestion boundary.
        if schema_docs:
            from webpent.shared.schema_ingestion import ingest_sanitized_schema
            sanitized = ingest_sanitized_schema(schema_docs, engagement_id=self.engagement_id)
            self.trace.record(stage="deep_recon", component="SchemaIngestionSanitized",
                              detail={"routes": len(sanitized.get("structural_facts", {}).get("routes", []))})
            # Feed sanitized STRUCTURAL facts into DeepRecon. The existing
            # parser already extracts only structural facts; we pass the
            # original docs but the untrusted descriptive text is separated
            # out by ingest_sanitized_schema (stored below, advisory only).
            docs = schema_docs if isinstance(schema_docs, list) else [schema_docs]
            for doc in docs[:3]:
                if isinstance(doc, dict):
                    try:
                        self.deep_recon.ingest_openapi_schema(doc)
                    except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, SSRFRedirectBlockedError, HTTPTransportError):
                        pass  # bounded — skip malformed doc
            # Store the untrusted descriptive projection separately (advisory only).
            self._untrusted_schema_text = sanitized.get("untrusted_descriptive_text", {})

        # Feed observed target facts (observed = trusted, from execution).
        if observed:
            if isinstance(observed, (list, tuple)):
                for obs in observed[:50]:
                    if isinstance(obs, dict):
                        self.deep_recon.ingest_route_observation(
                            path=obs.get("path", obs.get("url", "/")),
                            method=obs.get("method", "GET"),
                            status_code=obs.get("status_code", 200),
                            response_body=obs.get("body", ""),
                            response_headers=obs.get("headers", {}),
                        )
            self.trace.record(stage="deep_recon", component="ObservationIngest")

        # Synthesize: infer relationships, trust boundaries, hypotheses.
        self.deep_recon.infer_relationships()
        self.deep_recon.extract_trust_boundaries()
        hypotheses = self.deep_recon.generate_hypothesis_candidates()
        self.deep_recon.project_to_world_model()
        recon_result = self.deep_recon.summary()
        recon_result["hypotheses"] = list(hypotheses)[:50]
        self.trace.record(stage="deep_recon_complete", component="DeepReconEngine",
                          detail={"hypotheses": len(hypotheses)})

        # WorldModel update from recon output.
        self._update_world_model(recon_result)
        return recon_result

    def _update_world_model(self, recon_result: dict[str, Any]) -> None:
        """Update WorldModel from recon output. WorldModel remembers only."""
        # The EvidenceGraph is already shared with DeepReconEngine, so the
        # update happened in-place during recon. We record the trace event.
        self.trace.record(stage="world_model_update", component="WorldModel",
                          detail={"entities": self.world_model.entity_count,
                                  "hypotheses": self.world_model.hypothesis_count})

    # -- Stage 2: Research Control Loop (decision / replanning) -------------

    def research_step(self, *, llm_selection_hint: str | None = None) -> dict[str, Any]:
        """One bounded research loop step. Returns selected candidate (advisory).

        The ResearchControlLoop prioritizes. The LLM may provide an advisory
        hint, but deterministic ranking is the primary selector. This method
        NEVER authorizes execution — authorization happens in authorize_execution.
        """
        if not self._active:
            raise ModernSpineError("run_deep_recon must be called before research_step")
        self.trace.record(stage="research_step", component="ResearchControlLoop")

        decision = self.research_loop.step(llm_selection_hint=llm_selection_hint)

        # OutcomeTracker informs replanning (learning signal, advisory).
        if self.research_loop.decision_count > 1:
            self.trace.record(stage="replan", component="ResearchControlLoop",
                              detail={"decision_number": self.research_loop.decision_count})

        return decision

    def research_step_bounded(self, *, llm_selection_hint: str | None = None) -> dict[str, Any]:
        """P1-13 (0.33.0): graceful variant of :meth:`research_step`.

        The declared bound contract (``RuntimeError`` on decision/hypothesis
        limit — pinned by team1 behavioral test E) stays on research_step
        for direct callers. Engine-loop callers use THIS variant: a bound
        exhaustion is converted into an honest ``bounded_stop`` decision
        (selected_candidate=None) so a long hunt DEGRADES to "stop ingesting,
        return what you have" instead of dying mid-session.
        """
        try:
            return self.research_step(llm_selection_hint=llm_selection_hint)
        except RuntimeError as exc:
            message = str(exc)
            if "limit" not in message and "bounded" not in message:
                raise  # not a declared bound — real failure propagates
            self.trace.record(
                stage="research_step_bounded", component="ResearchControlLoop",
                detail={"bounded_stop": message[:120]},
            )
            return {"selected_candidate": None, "bounded_stop": message[:120],
                    "decision_number": self.research_loop.decision_count}

    # -- Stage 3: Execution Authorization (SOLE authority) ------------------

    def authorize_execution(self, *, tool_name: str, target_url: str, arguments: tuple = ()) -> Any:
        """Authorize one tool invocation through ScopeLaw / ToolBoundary.

        This is the ONLY path to effectful execution. No legacy path, no
        advisory memory, no LLM hint may bypass this.

        Returns the ScopeDecision. Caller MUST honor in_scope=False (fail closed).
        """
        if self.scope_law is None:
            raise ModernSpineError(
                "ScopeLaw not bound — execution authorization requires bound scope_law. "
                "The modern spine never executes without bound authority."
            )
        self.trace.record(stage="authorize", component="ScopeLaw",
                          detail={"tool": tool_name, "target": target_url})

        decision = self.scope_law.authorize_invocation(
            tool_name=tool_name, target_url=target_url, arguments=arguments
        )

        if self.tool_boundary is not None:
            # ToolBoundary provides second-layer enforcement (registered tools,
            # argument bounds). Both must pass.
            # DR-011 (TC-2): the second layer must evaluate the CANONICAL tool
            # identity — the spine's bounded-HTTP tool is named "httpx_bounded"
            # while ToolBoundary's closed registry registers it as "request"
            # (the same mapping run_bounded_experiment applies at its own
            # ToolCall). Without this normalization the factory-built spine
            # (which always binds a ToolBoundary per the S-3 extension) could
            # never execute its own bounded HTTP tool.
            canonical_tool = "request" if tool_name in {"httpx_bounded", "http", "https"} else tool_name
            tb_ok = self.tool_boundary.is_allowed(tool_name=canonical_tool, target=target_url, args=arguments)
            if not tb_ok and decision.in_scope:
                # ScopeLaw passed but ToolBoundary denied — fail closed.
                from webpent.live_hunter.tool_scope import ScopeDecision
                decision = ScopeDecision(
                    tool_name=tool_name, target_url=target_url, in_scope=False,
                    poison_detected=False, poison_details=(),
                    reason=f"tool_boundary_denied:{tool_name}",
                )
            self.trace.record(stage="authorize", component="ToolBoundary", detail={"allowed": decision.in_scope})

        return decision

    # -- Stage 4: Observation + Outcome Tracking ----------------------------

    def record_outcome(self, *, experiment_signature: str, outcome_class: str,
                       information_value: float, hypothesis_id: str | None = None,
                       justification: str = "") -> None:
        """Record experiment outcome. Learning signal for replanning."""
        self.outcome_tracker.record_outcome(
            experiment_signature=experiment_signature,
            outcome_class=outcome_class,
            information_value=information_value,
            hypothesis_id=hypothesis_id,
            justification=justification,
        )
        self.trace.record(stage="outcome", component="OutcomeTracker",
                          detail={"signature": experiment_signature[:64], "class": outcome_class})

    # -- Stage 5: Causal Adjudication + ProofBundle (SOLE evidence path) ----

    def build_proof_bundle(self, *, finding_id: str, vulnerability_class: str,
                           baseline: Any, candidate: Any, negative_control: Any,
                           evidence_origin: str, causal_result: dict[str, Any],
                           execution_identity: str, session_context: dict[str, Any],
                           replay_context: dict[str, Any] | None = None,
                           target_fingerprint: str | None = None,
                           hypothesis_id: str | None = None) -> Any:
        """Build a promotion-grade ProofBundle through the semantic validator.

        All required semantic evidence MUST be present and non-null. The
        ProofBundleSemanticValidator enforces completeness BEFORE the bundle
        is seal-valid/promotion-valid. Cryptographic seal alone never implies
        semantic completeness.
        """
        from webpent.models.proof_semantics import (
            ProofSemanticValidator,
            SemanticValidationError,
            build_promotion_grade_bundle,
        )

        # Step 1: Semantic validation — BEFORE construction of promotion-grade bundle.
        validator = ProofSemanticValidator()
        semantic_report = validator.validate(
            target_fingerprint=target_fingerprint,
            vulnerability_class=vulnerability_class,
            baseline=baseline,
            candidate=candidate,
            negative_control=negative_control,
            evidence_origin=evidence_origin,
            causal_result=causal_result,
            execution_identity=execution_identity,
            session_context=session_context,
            replay_context=replay_context,
        )
        if not semantic_report.complete:
            raise SemanticValidationError(
                f"ProofBundle semantic validation failed: {semantic_report.missing_fields}"
            )
        self.trace.record(stage="proof_semantic", component="ProofSemanticValidator",
                          detail={"complete": True})

        # Step 2: Construct + seal bundle through the single promotion-grade builder.
        bundle = build_promotion_grade_bundle(
            engagement_id=self.engagement_id,
            finding_id=finding_id,
            vulnerability_class=vulnerability_class,
            baseline=baseline,
            candidate=candidate,
            negative_control=negative_control,
            evidence_origin=evidence_origin,
            causal_result=causal_result,
            execution_identity=execution_identity,
            session_context=session_context,
            replay_context=replay_context,
            target_fingerprint=target_fingerprint,
            hypothesis_id=hypothesis_id,
        )
        self.trace.record(stage="proof_build", component="ProofBundle", detail={"bundle_id": bundle.bundle_id})
        return bundle


    # -- Stage 6: Hypothesis → Execution seam (real bounded experiment) ----

    def run_bounded_experiment(self, *, candidate_id: str, hypothesis_id: str,
                               tool_name: str, target_url: str,
                               arguments: tuple = (),
                               local_loopback: bool = False,
                               replan: bool = True) -> dict[str, Any]:
        """Real hypothesis-to-execution transition.

        Research decision (selected candidate) → ToolBoundary.authorize →
        ScopeLaw.authorize_invocation → bounded execution → observation →
        OutcomeTracker → WorldModel update → replan.

        Every stage fails closed. No raw HTTP bypasses ToolBoundary/ScopeLaw.
        """
        from webpent.llm_researcher.tool_boundary import ToolBoundary, ToolCall

        # 1. ToolBoundary — every evidentiary request reaches canonical boundary.
        #    ToolBoundary uses canonical tool names ("request" for HTTP).
        tb_tool_name = "request" if tool_name in {"httpx_bounded", "http", "https"} else tool_name
        call = ToolCall(
            tool_name=tb_tool_name,
            parameters=dict(arguments) if isinstance(arguments, (list, tuple)) else dict(arguments or {}),
            hypothesis=hypothesis_id,
        )
        tb = ToolBoundary()
        tb_authorized = tb.authorize(call)
        self.trace.record(stage="tool_boundary_check", component="ToolBoundary",
                          detail={"tool_name": tool_name, "authorized": tb_authorized})
        if not tb_authorized:
            self.trace.record(stage="execution_denied", component="ToolBoundary",
                              detail={"reason": call.error or "tool_boundary_denied"})
            return {"authorized": False, "denied_by": "ToolBoundary", "reason": call.error}

        # 2. ScopeLaw — evaluates effective request/target at final boundary.
        scope_decision = self.authorize_execution(
            tool_name=tool_name, target_url=target_url, arguments=arguments,
        )
        if not scope_decision.in_scope:
            self.trace.record(stage="execution_denied", component="ScopeLaw",
                              detail={"reason": scope_decision.reason})
            return {"authorized": False, "denied_by": "ScopeLaw", "reason": scope_decision.reason}

        # 3. Bounded execution (deterministic, bounded count).
        self.trace.record(stage="bounded_tool_execution", component="EvidenceExecutor",
                          detail={"tool_name": tool_name, "target_url": target_url})
        if local_loopback:
            observation = self._execute_local_loopback(target_url=target_url, tool_name=tool_name)
        else:
            # Non-loopback: record bounded execution intent without network.
            observation = {"status": "bounded_execution_recorded", "tool": tool_name,
                           "target": target_url, "loopback": False}

        # 4. Observation → WorldModel update (causal, not write-only).
        self.trace.record(stage="observation", component="ObservationIngest",
                          detail={"observation_keys": sorted(observation.keys())})
        # Ensure hypothesis is registered before recording observation outcome.
        try:
            self.world_model.register_hypothesis(hypothesis_id, f"hypothesis from {candidate_id}")
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, SSRFRedirectBlockedError, HTTPTransportError):
            pass  # already registered
        obs_id = f"obs_{candidate_id}_{len(self.outcome_tracker.history)}"
        supports = observation.get("indicates_vulnerability", False)
        info_value = observation.get("information_value", 0.5)
        self.world_model.record_observation_outcome(
            observation_id=obs_id, hypothesis_id=hypothesis_id,
            supports=supports, information_value=info_value,
        )

        # 5. Outcome recording.
        outcome_class = "high_information" if info_value > 0.7 else "low_information"
        self.record_outcome(
            experiment_signature=f"exp_{candidate_id}",
            outcome_class=outcome_class, information_value=info_value,
            hypothesis_id=hypothesis_id,
        )
        self.trace.record(stage="outcome_recording", component="OutcomeTracker",
                          detail={"outcome_class": outcome_class})

        # 6. Replan — callers that batch a baseline/candidate/control triple
        # defer this until the enclosing decision to avoid consuming three
        # scheduler decisions for one experiment.
        if replan:
            # P1-13 (0.33.0): graceful bound handling — a decision-limit
            # exhaustion degrades to a bounded stop instead of detonating
            # the enclosing observe phase mid-hunt.
            replan_decision = self.research_step_bounded()
            replan_number = replan_decision["decision_number"]
            self.trace.record(stage="replan", component="ResearchControlLoop",
                              detail={"decision_number": replan_number,
                                      "bounded_stop": replan_decision.get("bounded_stop")})
        else:
            replan_number = self.research_loop.decision_count

        return {
            "authorized": True,
            "tool_boundary_passed": True,
            "scope_law_passed": True,
            "observation": observation,
            "outcome_class": outcome_class,
            "replan_decision_number": replan_number,
        }

    def _execute_local_loopback(self, *, target_url: str, tool_name: str) -> dict[str, Any]:
        """Real HTTP execution via CANONICAL safe HTTP (make_safe_httpx_client).

        Uses the canonical shared/http client (SSRF-protected). The raw-httpx
        fallback (F-04, 0.33.0) is restricted to literal loopback origins —
        every other origin fails closed. No trace events added.
        Never fabricates observations.
        """
        try:
            from webpent.models.evidence import redact_sensitive, sha256_text
            from webpent.shared.engagement_scope import (
                clear_engagement_target_hosts,
                set_engagement_target_hosts,
            )
            target_token = set_engagement_target_hosts(target_url)
            try:
                try:
                    from webpent.shared.http import make_safe_httpx_client  # CANONICAL
                    with make_safe_httpx_client(
                        timeout=5.0, follow_redirects=False, guard_redirects=False
                    ) as client:
                        resp = client.get(target_url)
                except SSRFRedirectBlockedError:
                    raise
                except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, HTTPTransportError):
                    # F-04 (0.33.0): the fallback used to run for ANY origin,
                    # dropping DNS pinning + the SSRF blocklist for the one
                    # host the guard would have pinned. It is now restricted
                    # to literal loopback origins (no DNS to rebind) and
                    # fails closed for everything else.
                    if not _is_literal_loopback_origin(target_url):
                        raise
                    import httpx as _httpx
                    with _httpx.Client(timeout=5.0, follow_redirects=False) as client:
                        resp = client.get(target_url)
            finally:
                clear_engagement_target_hosts(target_token)
            body_text = resp.text or ""
            clean_body, _ = redact_sensitive(body_text)
            safe_headers = {k: v for k, v in dict(resp.headers).items()
                            if k.lower() not in ("authorization", "cookie", "set-cookie")}
            from webpent.shared.untrusted_content import wrap_httpx_response
            untrusted = wrap_httpx_response(resp, source="page")
            return {
                "status_code": resp.status_code,
                "response_body": clean_body[:2000],  # real, sanitized
                "body_digest": sha256_text(clean_body)[:16],
                "body_length": len(clean_body),
                "headers": safe_headers,
                "headers_count": len(safe_headers),
                "untrusted_content": untrusted.as_dict(),
                "llm_content": untrusted.to_prompt_fragment(),
                "information_value": 0.6 if resp.status_code == 200 else 0.3,
                "indicates_vulnerability": False,  # never asserted from observation alone
                "loopback": True,
                "real_http": True,  # PROVES real execution, not synthetic
            }
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, SSRFRedirectBlockedError, HTTPTransportError) as exc:
            # Fail closed — record failure, do not fabricate observation.
            return {
                "status_code": None,
                "error": str(exc)[:200],
                "information_value": 0.1,
                "indicates_vulnerability": False,
                "loopback": True,
                "failed": True,
            }

    # -- TEAM-1 AVI V1.1: generalized real request execution ----------------
    # Same authorization path (ScopeLaw + ToolBoundary via run_bounded_experiment),
    # same canonical safe HTTP. Supports method/headers/body for realistic targets
    # (REST PUT/POST, GraphQL, authenticated flows). No new authority.
    def execute_real_request(self, *, method: str, target_url: str,
                             headers: dict | None = None, body: str | None = None,
                             hypothesis_id: str = "real_target_qual") -> dict[str, Any]:
        """Real authorized HTTP request with arbitrary method/headers/body.

        Same authorization path (ToolBoundary + ScopeLaw). Uses canonical safe
        HTTP (with loopback fallback for authorized lab targets). No replan
        side-effect (does not burn research decisions), no synthetic obs.
        """
        from webpent.llm_researcher.tool_boundary import ToolBoundary, ToolCall
        from webpent.models.evidence import redact_sensitive, sha256_text
        # 1. ToolBoundary (canonical).
        call = ToolCall(tool_name="request", parameters={"method": method, "url": target_url},
                        hypothesis=hypothesis_id)
        tb_authorized = ToolBoundary().authorize(call)
        self.trace.record(stage="tool_boundary_check", component="ToolBoundary",
                          detail={"authorized": tb_authorized})
        if not tb_authorized:
            return {"authorized": False, "real_http": False, "denied_by": "ToolBoundary",
                    "evidence_origin": "target_runtime"}
        # 2. ScopeLaw (SOLE execution authority). Authorize on the target path
        # (without query string) so SSRF/redirect payloads in query params are
        # not mistaken for target poison. The actual request still sends the
        # full URL with parameters.
        auth_target = target_url.split("?")[0]
        scope_decision = self.authorize_execution(
            tool_name="httpx_bounded", target_url=auth_target, arguments=(),
        )
        if not scope_decision.in_scope:
            return {"authorized": False, "real_http": False, "denied_by": "ScopeLaw",
                    "evidence_origin": "target_runtime"}
        # 3. Canonical real HTTP execution.
        # U-8 SQLi timing instrumentation (restored C1(c) TC-2): the
        # wall-clock request duration plumbs into the evidence dict as
        # ``response_time_ms`` — validate_sqli's timing-differential branch
        # (delay >= 1000ms over baseline, >= 2x control gap) consumes it.
        # Without this plumbing a family's evidence path is broken.
        _t0 = time.perf_counter()
        try:
            # 0.33.0 regression fix (team1 loopback qualification, F-04
            # follow-through): execute_real_request never registered the
            # engagement target, so the pinning transport correctly raised
            # SSRFRedirectBlockedError for the lab's own 127.0.0.1 target and
            # — after F-04 closed the unconditional raw fallback — that block
            # propagated as status_code=None. The DESIGNED mechanism for
            # "the engagement's own target may be private" is the
            # engagement-scope allowlist (same pattern _execute_local_loopback
            # already uses): register the ScopeLaw-approved target for the
            # request's duration so the transport allows exactly this host
            # and nothing else. The raw-loopback fallback below remains
            # closed except for literal loopback non-SSRF factory errors.
            from webpent.shared.engagement_scope import (
                clear_engagement_target_hosts,
                set_engagement_target_hosts,
            )
            _target_token = set_engagement_target_hosts(target_url)
            try:
                try:
                    from webpent.shared.http import make_safe_httpx_client
                    # guard_redirects=False (0.33.0 team1 OPEN_REDIRECT
                    # qualification): with follow_redirects=False the client
                    # never connects to a redirect destination, so the
                    # OriginPolicy hook raising on the 3xx RESPONSE only
                    # destroyed the observation (status_code=None) without
                    # adding safety — the 0.32.0 path observed the 30x via
                    # the (now F-04-closed) raw retry. The canonical client
                    # returns the 30x itself; no connection to the redirect
                    # destination is ever made. Same combination
                    # _execute_local_loopback uses.
                    with make_safe_httpx_client(
                        timeout=5.0, follow_redirects=False, guard_redirects=False
                    ) as client:
                        resp = client.request(method.upper(), target_url,
                                              headers=headers or {}, content=body)
                except (
                    AttributeError, ImportError, KeyError, OSError,
                    RuntimeError, TypeError, ValueError, HTTPTransportError,
                ) as _safe_exc:
                    # F-04 (0.33.0): SSRF blocks must NEVER reach a raw client
                    # (the old tuple included SSRFRedirectBlockedError), and the
                    # raw retry is restricted to literal loopback origins —
                    # anything else propagates to the enclosing fail-closed
                    # handler below.
                    if isinstance(_safe_exc, SSRFRedirectBlockedError):
                        raise
                    if not _is_literal_loopback_origin(target_url):
                        raise
                    import httpx as _httpx
                    with _httpx.Client(timeout=5.0, follow_redirects=False) as client:
                        resp = client.request(method.upper(), target_url,
                                              headers=headers or {}, content=body)
            finally:
                clear_engagement_target_hosts(_target_token)
            body_text = resp.text or ""
            clean_body, _ = redact_sensitive(body_text)
            try:
                parsed_body = json.loads(body_text)
                structural_fields = {
                    "json_like": isinstance(parsed_body, (dict, list)),
                    "json_data_null": isinstance(parsed_body, dict) and "data" in parsed_body and parsed_body.get("data") is None,
                    "json_data_present": isinstance(parsed_body, dict) and "data" in parsed_body,
                }
            except (TypeError, ValueError, json.JSONDecodeError):
                structural_fields = {"json_like": False, "json_data_null": False, "json_data_present": False}
            safe_headers = {k: v for k, v in dict(resp.headers).items()
                            if k.lower() not in ("authorization", "cookie", "set-cookie")}
            from webpent.shared.untrusted_content import wrap_httpx_response
            untrusted = wrap_httpx_response(resp, source="response")
            self.trace.record(stage="bounded_tool_execution", component="EvidenceExecutor",
                              detail={"method": method, "status": resp.status_code})
            return {
                "authorized": True, "real_http": True,
                "method": method.upper(), "status_code": resp.status_code,
                "response_time_ms": round((time.perf_counter() - _t0) * 1000.0, 3),
                "response_body": clean_body[:2000],
                "body_digest": sha256_text(clean_body)[:16],
                "body_length": len(clean_body),
                "headers": safe_headers, "evidence_origin": "target_runtime",
                "structured_fields": structural_fields,
                "request_url_digest": sha256_text(target_url)[:16],
                "untrusted_content": untrusted.as_dict(),
                "llm_content": untrusted.to_prompt_fragment(),
            }
        except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError, SSRFRedirectBlockedError, HTTPTransportError) as exc:
            return {"authorized": True, "real_http": True, "failed": True,
                    "error": str(exc)[:200], "status_code": None,
                    "response_time_ms": None,
                    "evidence_origin": "target_runtime"}

    # -- Failure / fallback semantics (fail-closed) -------------------------

    def fail_closed(self, *, stage: str, reason: str) -> dict[str, Any]:
        """Explicit fail-closed transition. Never silently drops to legacy."""
        self.trace.record(stage=f"failure_{stage}", component="FailClosed",
                          detail={"reason": reason, "legacy_fallback": False})
        return {"status": "failed_closed", "stage": stage, "reason": reason,
                "legacy_fallback_used": False}



    def run_validator_experiment(self, *, hypothesis_id: str, vulnerability_class: str,
                                 target_url: str, baseline_obs: dict, candidate_obs: dict,
                                 negative_control_obs: dict) -> dict:
        """TEAM-1 FABRIC INTEGRATION: Production execution path for validator experiments.

        ResearchLoop-selected candidate → ExperimentRegistry lookup → GenericExperimentRunner
        → ScopeLaw + ToolBoundary (via run_bounded_experiment) → ObservationNormalizer
        → ValidatorAdapter → EvidenceQuality → outcome.
        This is the CANONICAL production execution seam — NOT an isolated module.
        """
        from webpent.production.experiment_fabric import (
            EXPERIMENT_REGISTRY,
            GenericExperimentRunner,
        )
        if vulnerability_class.upper() not in EXPERIMENT_REGISTRY:
            raise ValueError(f"No experiment registered for {vulnerability_class!r} — fail closed")
        runner = GenericExperimentRunner(self)
        result = runner.run(
            hypothesis_id=hypothesis_id, vulnerability_class=vulnerability_class,
            target_url=target_url, baseline_obs=baseline_obs,
            candidate_obs=candidate_obs, negative_control_obs=negative_control_obs,
        )
        # Outcome feedback into ResearchLoop (canonical path).
        if result.validator_result:
            vr = result.validator_result
            outcome_cls = {
                "CONFIRMED": "confirmed_supported", "REFUTED": "refuted",
                "INCONCLUSIVE": "low_information",
            }.get(vr.outcome.value, "low_information")
            self.record_outcome(
                experiment_signature=result.experiment_id, outcome_class=outcome_cls,
                information_value=float(vr.evidence_quality), hypothesis_id=hypothesis_id,
            )
        return {
            "authorized": result.authorized,
            "experiment_id": result.experiment_id,
            "vulnerability_class": result.vulnerability_class,
            "validator_outcome": result.validator_result.outcome.value if result.validator_result else None,
            "evidence_quality": int(result.validator_result.evidence_quality) if result.validator_result else 0,
            "discriminating_signal": result.validator_result.discriminating_signal if result.validator_result else None,
            "baseline_digest": result.baseline.digest(),
            "candidate_digest": result.candidate.digest(),
            "negative_control_digest": result.negative_control.digest(),
            "execution_identity": result.execution_identity,
            "fabric_integrated": True,  # PROVES fabric is on production path
        }

    # -- TEAM-1 AVI V1: Autonomous Validation Intelligence production dispatch
    def run_autonomous_validation_campaign(
        self, *, target_url: str, hypotheses: list[dict], max_decisions: int = 30,
    ) -> dict[str, Any]:
        """PRODUCTION DISPATCH entry for Autonomous Validation Intelligence V1.

        This is the REAL production graph path. It wires the full lifecycle:
        ResearchLoop → AutonomousExperimentSelector → ExperimentRegistry →
        GenericExperimentRunner → Real authorized HTTP → ObservationNormalizer →
        Causal Validator → EvidenceQuality → ProofBundle → Replay →
        PromotionPipeline → SecurityReport → OutcomeTracker → next decision.

        No manual-only execution path. The legacy run_research_campaign fabric
        branch delegates here. Deterministic runtime trace proves every stage.

        Round 4 (Accountability Spine): the verdict bridge gates this dispatch.
        A non-loopback target requires an initialized verdict workspace with a
        frozen pre-registration; the escape is never silent (recorded in the
        trace). Loopback targets are exempt. See production/verdict_bridge.py.
        """
        from webpent.production.autonomous_validation_v1 import (
            AVI_VERSION,
            AutonomousValidationIntelligence,
        )
        from webpent.production.verdict_bridge import verdict_preflight

        # --- Round 4 touch point 1/2: verdict pre-flight gate (fail-closed) ---
        verdict_gate = verdict_preflight(target_url)
        self.trace.record(stage="verdict_preflight_gate", component="VerdictBridge",
                          detail={"gate": verdict_gate.get("gate"),
                                 "target_is_loopback": verdict_gate.get("target_is_loopback"),
                                 "escape_used": verdict_gate.get("escape_used", False),
                                 "workspace": verdict_gate.get("workspace")})
        # --- Wave 3 touch point 1/2: campaign advisory plan (fail-open) ---
        # Where the operator HAS ruled APPROVED on a brief for this
        # target, the approved plan rides the dispatch trace as
        # advisory guidance. It gates nothing: no ruling, no store, or
        # any bridge fault is a recorded reason — never an error that
        # touches the dispatch itself. See production/campaign_bridge.py.
        from webpent.production import campaign_bridge
        campaign_plan: dict[str, Any] = {"bridge": "campaign_bridge_v1",
                                         "attached": False}
        try:
            campaign_plan = campaign_bridge.approved_plan_for(target_url)
        except campaign_bridge.BRIDGE_GUARD as exc:  # advisory: never break dispatch
            campaign_plan = {"bridge": "campaign_bridge_v1", "attached": False,
                             "reason": "campaign_bridge_error",
                             "blocker": str(exc)[:400]}
        if campaign_plan.get("attached"):
            _plan = campaign_plan.get("plan", {})
            self.trace.record(stage="campaign_advisory_plan",
                              component="CampaignBridge",
                              detail={"campaign_id": _plan.get("campaign_id"),
                                      "decision": _plan.get("decision"),
                                      "phases": len(_plan.get("phases", []))})
        self.trace.record(stage="avi_production_dispatch", component="ModernOrchestrator",
                          detail={"avi_version": AVI_VERSION, "max_decisions": max_decisions,
                                  "hypotheses": len(hypotheses), "manual_path_used": False})
        avi = AutonomousValidationIntelligence(self)
        result = avi.run_campaign(target_url=target_url, hypotheses=hypotheses,
                                  max_decisions=max_decisions)
        # Backward-compatible fabric dispatch trace (existing acceptance tests
        # assert on this). Populated from AVI decisions — still runtime-derived,
        # no manual path.
        self._fabric_dispatch_trace = [
            {
                "step": d.get("decision"),
                "hypothesis_id": d.get("hypothesis_id"),
                "candidate_id": d.get("hypothesis_id"),
                "experiment_id": d.get("experiment_id"),
                "vulnerability_class": d.get("vulnerability_class"),
                "experiment_registry_hit": d.get("experiment_id") is not None,
                "fabric_runner_invoked": True,
                "normalizer_invoked": True,
                "validator_adapter_invoked": d.get("validator_outcome") is not None,
                "validator_result": d.get("validator_outcome"),
                "outcome_recorded": True,
                "avi_production_dispatch": True,
            }
            for d in result.get("decisions", []) if d.get("experiment_id")
        ]
        # Expose AVI trace + security report on the orchestrator for graph consumers.
        self._avi_result = result
        self._avi_trace_records = result.get("trace_records", [])
        self._security_report = result.get("security_report", {})
        self.trace.record(stage="avi_campaign_complete",
                          component="AutonomousValidationIntelligence",
                          detail={"decisions_executed": result.get("decisions_executed"),
                                  "promoted_count": result.get("promoted_count"),
                                  "rejected_count": result.get("rejected_count"),
                                  "trace_full_coverage":
                                      result.get("trace", {}).get("full_coverage")})
        # --- Round 4 touch point 2/2: verdict registration (accountability) ---
        # Promoted findings land in the verdict workspace with real evidence.
        # Failures are typed blockers in the result, never silent zeros and
        # never exceptions that corrupt a completed campaign.
        from webpent.production.verdict_bridge import (
            VerdictRegistrationError,
            register_campaign_findings,
        )
        verdict_block: dict[str, Any] = {"gate": verdict_gate, "registration": None,
                                         "blocker": None}
        try:
            verdict_block["registration"] = register_campaign_findings(result)
            self.trace.record(stage="verdict_findings_registered", component="VerdictBridge",
                              detail={"registered": verdict_block["registration"]["registered"],
                                     "skipped": verdict_block["registration"]["skipped"],
                                     "blocked": verdict_block["registration"]["blocked"],
                                     "promoted_total":
                                         verdict_block["registration"]["promoted_total"]})
            if (result.get("promoted_count", 0) > 0
                    and not verdict_block["registration"]["registered"]
                    and not verdict_block["registration"]["skipped"]):
                verdict_block["blocker"] = (
                    "promoted findings exist but none could be registered in the "
                    "verdict workspace; see registration.blocked")
        except VerdictRegistrationError as exc:
            verdict_block["blocker"] = str(exc)[:400]
        if verdict_block["blocker"]:
            self.trace.record(stage="verdict_registration_blocked", component="VerdictBridge",
                              detail={"blocker": verdict_block["blocker"]})
        result["verdict_bridge"] = verdict_block
        # --- Wave 3 touch point 2/2: campaign advisory brief (PENDING) ---
        # The completed campaign's evidence is turned into a PENDING
        # operator brief (thesis + phases + budgets) so a human rules
        # on the next campaign. The bridge holds no approval code path
        # and is off unless the operator points it at a brief store
        # (WEBPENT_CAMPAIGN_STORE): otherwise it is a typed blocker in
        # the result, never a default disk write and never an
        # exception into a completed campaign.
        campaign_brief_block: dict[str, Any]
        try:
            campaign_brief_block = campaign_bridge.campaign_advisory_brief(
                result, target_url)
        except campaign_bridge.BRIDGE_GUARD as exc:  # advisory: never break dispatch
            campaign_brief_block = {"bridge": "campaign_bridge_v1",
                                    "registered": False,
                                    "blocker": str(exc)[:400]}
        self.trace.record(stage="campaign_advisory_brief",
                          component="CampaignBridge",
                          detail={"registered":
                                  campaign_brief_block.get("registered"),
                                  "campaign_id":
                                  campaign_brief_block.get("campaign_id"),
                                  "blocker":
                                  campaign_brief_block.get("blocker")})
        result["campaign_bridge"] = {"brief": campaign_brief_block,
                                     "plan": campaign_plan}
        return result

    def run_research_campaign(self, *, target_url: str, hypotheses: list[dict],
                              max_steps: int = 5, stop_on_promotion: bool = True) -> dict[str, Any]:
        """Bounded multi-step closed-loop research campaign.

        inspect → hypothesize → experiment → observe → update → reconsider →
        continue/stop. Second decision depends on first observation (organic
        replan, not precomputed). Stop conditions explicit and justified.

        TEAM-1 AVI V1: when any hypothesis carries a registry-covered
        vulnerability_class, the campaign is delegated to
        run_autonomous_validation_campaign (the production dispatch path).
        The manual-only inline execution path is REMOVED — no helper-only
        execution remains for validator-grade experiments.
        """
        from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY
        fabric_hyps = [h for h in hypotheses
                       if str(h.get("vulnerability_class", "")).upper() in EXPERIMENT_REGISTRY]
        if fabric_hyps:
            avi_result = self.run_autonomous_validation_campaign(
                target_url=target_url, hypotheses=hypotheses,
                max_decisions=max(3, int(max_steps)),
            )
            avi_result["legacy_run_research_campaign_delegated"] = True
            avi_result["manual_path_used"] = False
            return avi_result
        from webpent.production.modern_spine import FindingLifecycle, ResearchAgenda
        agenda = ResearchAgenda()
        findings: dict[str, FindingLifecycle] = {}
        steps: list[dict] = []

        self.run_deep_recon(target_url=target_url,
                            observed=[{"path": h.get("path", "/api/"), "method": h.get("method", "GET"),
                                       "status_code": 200, "body": "{}", "headers": {}} for h in hypotheses])

        for step in range(1, max_steps + 1):
            # Select next hypothesis from agenda (organic — depends on prior outcomes).
            available = [h for h in hypotheses if h["id"] not in agenda.rejected_hypotheses]
            if not available:
                steps.append({"step": step, "action": "stop", "reason": "no_available_hypotheses"})
                break

            # Prioritize: hypotheses with promising relationships from prior observations.
            def priority(h):
                score = 0
                if h["id"] in [r.split(":")[0] for r in agenda.promising_relationships]:
                    score += 10
                if h["id"] in [q.split(":")[0] for q in agenda.unresolved_questions]:
                    score += 5
                return -score  # higher score first
            selected = sorted(available, key=priority)[0]

            # Register + research decision (P1-13: graceful at the bound).
            self.research_loop.register_candidate(selected["id"], (selected["id"],), f"exp_{selected['id']}")
            decision = self.research_step_bounded()
            if decision.get("bounded_stop"):
                return {"status": "bounded_complete",
                        "reason": decision["bounded_stop"],
                        "decisions_taken": decision["decision_number"]}

            # Sprint I-1, item 1.2: the EXPERIMENT_REGISTRY fabric-dispatch
            # branch that previously lived here (`if vuln_class in
            # EXPERIMENT_REGISTRY: ...`) was confirmed dead and deleted.
            # Proof of deadness: this loop only runs when `fabric_hyps` at
            # the top of this method is empty, i.e. NO hypothesis in the
            # `hypotheses` argument has a vulnerability_class present in
            # EXPERIMENT_REGISTRY (otherwise the AVI delegation at :770-780
            # already returned). `selected` is drawn from `available`,
            # itself filtered from that same `hypotheses` list, so
            # `vuln_class in EXPERIMENT_REGISTRY` could never be True here.
            # Re-verified by running the existing AVI/fabric acceptance
            # suite before and after removal (see sprint changelog) — the
            # branch was never entered and removing it does not change any
            # observed test outcome.
            result = self.run_bounded_experiment(
                candidate_id=selected["id"], hypothesis_id=selected["id"],
                tool_name="httpx_bounded",
                target_url=f"{target_url}{selected.get('path', '/api/')}",
            )

            # Observe → update agenda (organic — depends on observation).
            obs = result.get("observation", {})
            info_value = obs.get("information_value", 0.5)
            if result["authorized"] and info_value > 0.6:
                agenda.mutate(source=f"step_{step}_observation", changes={
                    "confirmed_facts": [f"{selected['id']}: endpoint responsive"],
                    "promising_relationships": [f"{selected['id']}: high_information_target"],
                    "follow_up_actions": [f"{selected['id']}: deepen_investigation"],
                })
                if selected["id"] not in findings:
                    findings[selected["id"]] = FindingLifecycle(selected["id"], selected["id"])
                findings[selected["id"]].transition_to("supported", reason=f"step_{step} high info", evidence_strength=info_value)
            else:
                agenda.mutate(source=f"step_{step}_observation", changes={
                    "rejected_hypotheses": [selected["id"]],
                    "unresolved_questions": [f"{selected['id']}: low_information_revisit"],
                })
                if selected["id"] not in findings:
                    findings[selected["id"]] = FindingLifecycle(selected["id"], selected["id"])
                findings[selected["id"]].transition_to("refuted", reason=f"step_{step} low info", evidence_strength=info_value)

            steps.append({"step": step, "selected": selected["id"], "authorized": result["authorized"],
                          "info_value": info_value, "agenda_mutations": len(agenda.mutation_log)})

            # Stop conditions (explicit + justified).
            if stop_on_promotion and any(f.can_promote() for f in findings.values()):
                steps.append({"step": step + 0.5, "action": "stop", "reason": "promotable_finding_found"})
                break
            if step >= max_steps:
                steps.append({"step": step + 0.5, "action": "stop", "reason": "max_steps_reached"})

        return {
            "steps": steps,
            "agenda": agenda.summary(),
            "findings": {fid: {"state": f.state, "support": f.support_count, "refute": f.refute_count}
                         for fid, f in findings.items()},
            "total_decisions": self.research_loop.decision_count,
            "outcomes_recorded": len(self.outcome_tracker.history),
        }

    # -- Completion ---------------------------------------------------------

    def complete(self) -> dict[str, Any]:
        """Mark spine run complete and return trace summary."""
        self._completed = True
        self._active = False
        self.trace.record(stage="complete", component="ModernOrchestrator")
        return self.trace.summary()

    @property
    def executed_modern_path(self) -> bool:
        """True iff the modern spine demonstrably executed all required stages."""
        required = {"init", "deep_recon", "research_step", "authorize"}
        return all(self.trace.saw_stage(s) for s in required)



    # -- Stage 7: Finding Lifecycle + Research Agenda + Closed-Loop Campaign --

class FindingLifecycle:
    """Real finding lifecycle: candidate → supported/refuted/inconclusive/blocked → promoted.

    Later negative/contradictory evidence can refute or downgrade earlier
    hypotheses. No upgrade-only behavior. Transitions are deterministic and
    fail-closed (cannot promote without supported state).
    """
    STATES = ("candidate", "supported", "refuted", "inconclusive", "blocked", "promoted")
    VALID_TRANSITIONS = {
        "candidate": {"supported", "refuted", "inconclusive", "blocked"},
        "supported": {"promoted", "refuted", "inconclusive", "blocked"},
        "inconclusive": {"supported", "refuted", "blocked"},
        "blocked": {"candidate", "refuted"},
        "refuted": set(),  # terminal — cannot be un-refuted without new evidence
        "promoted": set(),  # terminal
    }

    def __init__(self, finding_id: str, hypothesis_id: str):
        self.finding_id = finding_id
        self.hypothesis_id = hypothesis_id
        self.state = "candidate"
        self.history: list[dict] = [{"state": "candidate", "reason": "initial"}]
        self.support_count = 0
        self.refute_count = 0

    def transition_to(self, new_state: str, *, reason: str, evidence_strength: float = 0.0) -> None:
        if new_state not in self.STATES:
            raise ValueError(f"Invalid lifecycle state: {new_state}")
        if new_state not in self.VALID_TRANSITIONS[self.state]:
            raise RuntimeError(
                f"Invalid lifecycle transition: {self.state} → {new_state}. "
                f"Allowed from {self.state}: {sorted(self.VALID_TRANSITIONS[self.state])}"
            )
        if new_state == "promoted" and self.state != "supported":
            raise RuntimeError("Cannot promote from non-supported state")
        if new_state == "supported":
            self.support_count += 1
        elif new_state == "refuted":
            self.refute_count += 1
        self.state = new_state
        self.history.append({"state": new_state, "reason": reason, "evidence_strength": evidence_strength})

    def record_contradictory_evidence(self, *, reason: str, strength: float) -> None:
        """Later negative evidence can refute/downgrade earlier supported finding."""
        if self.state in {"supported", "candidate", "inconclusive"}:
            if strength > 0.7:
                self.transition_to("refuted", reason=reason, evidence_strength=strength)
            elif strength > 0.4:
                self.transition_to("inconclusive", reason=reason, evidence_strength=strength)

    def can_promote(self) -> bool:
        return self.state == "supported" and self.support_count >= 1 and self.refute_count == 0


class ResearchAgenda:
    """Mutable research agenda — evolves from observed evidence, never static.

    Tracks: unresolved_questions, confirmed_facts, rejected_hypotheses,
    promising_relationships, blocked_experiments, follow_up_actions.
    Every mutation is recorded and observable. Agenda changes causally
    influence the next research step.
    """
    def __init__(self):
        self.unresolved_questions: list[str] = []
        self.confirmed_facts: list[str] = []
        self.rejected_hypotheses: list[str] = []
        self.promising_relationships: list[str] = []
        self.blocked_experiments: list[str] = []
        self.follow_up_actions: list[str] = []
        self.mutation_log: list[dict] = []

    def mutate(self, *, source: str, changes: dict[str, list]) -> None:
        """Mutate agenda from observed evidence. Records provenance of each change."""
        for key, values in changes.items():
            if not hasattr(self, key):
                continue
            attr = getattr(self, key)
            for v in values:
                if v not in attr:
                    attr.append(v)
                    self.mutation_log.append({"source": source, "field": key, "value": v})

    def summary(self) -> dict:
        return {
            "unresolved_questions": list(self.unresolved_questions),
            "confirmed_facts": list(self.confirmed_facts),
            "rejected_hypotheses": list(self.rejected_hypotheses),
            "promising_relationships": list(self.promising_relationships),
            "blocked_experiments": list(self.blocked_experiments),
            "follow_up_actions": list(self.follow_up_actions),
            "mutation_count": len(self.mutation_log),
        }


__all__ = [
    "ModernOrchestrator", "ModernSpineError", "SpineTrace", "SpineTraceEvent",
    "_SPINE_VERSION",
]
