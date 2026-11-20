# tests/lab/lcs2_sweep_instrument.py
"""LCS-2 mastery-cycle sweep instrument (TC-3, Dispatch #041 §1).

The instrument that makes the improving-efficiency threshold MEASURABLE:

  * An EV-ordered decision-loop sweep executes hypotheses through the REAL
    pipeline (authorized factory -> AutonomousValidationIntelligence), each
    decision = one real HTTP triple (baseline / candidate / negative_control)
    under a FIXED request budget.
  * The brain state (EVScheduler FAMILY_BASE_RATES + LessonsLedger priors)
    is REPLAYED from the recorded outcome streams of the previous cycles —
    the adaptation loop's feed-through is deterministic and auditable, never
    hand-edited.
  * Requests are measured twice: client-side from the spine's real_execution
    proofs and server-side via a counting ASGI middleware composed at runtime
    (the fixture file itself is untouched — same lab-fixture configuration).
  * The cycle-1 brain state can be replayed as a CONTROL (fresh scheduler,
    inherited base rates, the recorded cycle-1 EV-leg inputs, no lessons) to
    bind the recorded 9.0 requests/finding baseline to a live measurement.

LEARNING-STATE REPLAY CONTRACT (zero false positives applies to lessons):
  * Only EXECUTION outcomes enter the stream (a hypothesis that was never
    executed produces NO outcome and NO lesson).
  * Cycle-1 executed: P1 IDOR live PROMOTED; N1 IDOR-on-patched REFUTED;
    T1 SQLi validator-contract leg CONFIRMED (provenance: fixture evidence
    dicts, NOT a live lane).  XSS/RFI were NEVER executed in cycle 1 — they
    therefore have no outcome and no lesson; the recon surface speaks for
    them (recon-honest construction, DR-012).
  * Lesson confidence grows by +0.1 (cap 0.95) when a later cycle
    re-validates the lesson's prediction; influence decays 10%/run of
    non-application (LessonsLedger.DECAY_RATE); lesson_priors multiplier =
    1.0 + 0.5*influence (positive) / 1.0 - 0.5*influence clamped >= 0.1
    (negative).

FLOOR THEOREM (the convergence bound of the improving trend):
  An honest full-chain finding requires at minimum
      3 requests  — the causal triple (baseline/candidate/negative_control),
                     CausalGuard's evidence contract, and
      3 requests  — the patched-lane control triple (the honesty leg: the
                     same hypothesis must REFUTE on a non-vulnerable lane),
  i.e. FLOOR = 6 requests per finding.  Fewer requests per finding is
  impossible without weakening the evidence contract.  A cycle that reaches
  the floor has converged; staying there across cycles is the stability
  proof of the learned state.
"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass, field
from typing import Any

ROOT_IMPORT_MARK = "lcs2_sweep_instrument_v1"

# ---------------------------------------------------------------------------
# The inherited brain state (snapshot semantics — replay determinism)
# ---------------------------------------------------------------------------
import importlib

_ev_module = importlib.import_module("webpent.brain.ev_scheduler")

INHERITED_BASE_RATES: dict[str, float] = copy.deepcopy(_ev_module.FAMILY_BASE_RATES)

# The cycle-1 recorded EV-leg hypothesis inputs (cycle1_verdict.json legs.ev)
# — replayed verbatim as the UNCALIBRATED brain state of the control.
CYCLE1_RECORDED_EV_INPUTS: list[dict[str, Any]] = [
    {"id": "h_sqli", "vulnerability_class": "SQLI", "recon_signal_matches": 2,
     "estimated_cost": 5, "estimated_llm_calls": 1, "chain_potential": 1.5},
    {"id": "h_xss", "vulnerability_class": "XSS", "recon_signal_matches": 1,
     "estimated_cost": 4, "estimated_llm_calls": 2, "chain_potential": 1.2},
    {"id": "h_rfi", "vulnerability_class": "RFI", "recon_signal_matches": 0,
     "estimated_cost": 12, "estimated_llm_calls": 3, "chain_potential": 1.0},
    {"id": "h_idor", "vulnerability_class": "IDOR", "recon_signal_matches": 2,
     "estimated_cost": 6, "estimated_llm_calls": 1, "chain_potential": 1.4},
]

# Recorded cycle-1 EXECUTION outcome stream (cycle1_verdict.json legs):
# only executed legs enter; XSS/RFI have no entries (never executed).
CYCLE1_OUTCOME_STREAM: list[dict[str, Any]] = [
    {"family": "IDOR", "outcome": "promoted",
     "provenance": "live P1 full-chain (lcs2_p1), cycle-1 verdict legs.p1"},
    {"family": "SQLI", "outcome": "promoted",
     "provenance": "validator-contract leg T1 (fixture evidence dicts, "
                   "NOT a live lane), cycle-1 verdict legs.t1"},
]

FLOOR_REQUESTS_PER_FINDING = 6  # causal triple (3) + control triple (3)


def reset_brain_to_inherited() -> None:
    """Restore the inherited (pre-cycle-1) FAMILY_BASE_RATES."""
    _ev_module.FAMILY_BASE_RATES.clear()
    _ev_module.FAMILY_BASE_RATES.update(copy.deepcopy(INHERITED_BASE_RATES))


def apply_outcome_stream(stream: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Replay an outcome stream through the AdaptationEngine (in-place on the
    module-level FAMILY_BASE_RATES — the same mutation path the in-run
    adaptation loop uses).  Returns the per-family rate deltas for the audit
    trail."""
    from webpent.brain.adaptation import AdaptationEngine

    scheduler = _ev_module.EVScheduler()
    engine = AdaptationEngine(scheduler)
    deltas: list[dict[str, Any]] = []
    for event in stream:
        old = _ev_module.FAMILY_BASE_RATES.get(event["family"], 0.1)
        ev = engine.record_outcome(event["family"], event["outcome"])
        new = _ev_module.FAMILY_BASE_RATES.get(event["family"], 0.1)
        deltas.append({"family": event["family"], "outcome": event["outcome"],
                       "rate_before": old, "rate_after": new,
                       "event": ev.mechanism, "provenance": event.get("provenance", "")})
    return deltas


# ---------------------------------------------------------------------------
# LessonsLedger book — run-scope lessons with the documented growth rule
#
# G-1 (v0.29.0, docs/PRODUCTION_FIX_PLAN_0270.md): the retired
# ``webpent.brain.lessons`` ledger was DELETED from the tree (declared
# removal window — "deletion is a separate announced change"). This lab
# instrument was its only non-test consumer, so it now carries a minimal
# LOCAL equivalent of exactly the ledger surface it used (record / apply /
# list / influence, run-scope auto-approval, DECAY_RATE 0.1 decay). The
# semantics below are byte-for-byte those of the deleted module — the
# replay contract and its test are unchanged.
# ---------------------------------------------------------------------------
@dataclass
class _RetiredLedgerLesson:
    """Local stand-in for the deleted ``webpent.brain.lessons.Lesson``."""

    lesson_id: str
    scope: str
    statement: str
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.5
    proposed_by: str = "system"
    approved_by: str | None = None
    applied_runs: int = 0
    outcome_feedback: list[str] = field(default_factory=list)
    last_applied_run: int = 0
    created_at: float = field(default_factory=time.time)

    def is_approved(self) -> bool:
        return self.approved_by is not None


class _RetiredLessonsLedger:
    """Local stand-in for the deleted ``webpent.brain.lessons.LessonsLedger``
    — only the surface this instrument actually used."""

    DECAY_RATE = 0.1
    MINIMUM_INFLUENCE = 0.0

    def __init__(self, store_path: object = None) -> None:
        self._lessons: dict[str, _RetiredLedgerLesson] = {}
        self._current_run = 0

    def record_lesson(
            self, lesson: _RetiredLedgerLesson) -> _RetiredLedgerLesson:
        if lesson.scope == "run":
            lesson.approved_by = "auto"
        self._lessons[lesson.lesson_id] = lesson
        return lesson

    def apply_lesson(self, lesson_id: str, run_number: int) -> bool:
        lesson = self._lessons.get(lesson_id)
        if lesson is None or not lesson.is_approved():
            return False
        lesson.applied_runs += 1
        lesson.last_applied_run = run_number
        return True

    def get_all_lessons(self) -> list[_RetiredLedgerLesson]:
        return list(self._lessons.values())

    def get_influence(
            self, lesson: _RetiredLedgerLesson, current_run: int) -> float:
        if not lesson.is_approved():
            return 0.0
        runs_since = current_run - lesson.last_applied_run
        if runs_since <= 0:
            return lesson.confidence
        return max(
            self.MINIMUM_INFLUENCE,
            lesson.confidence * ((1 - self.DECAY_RATE) ** runs_since),
        )


class LessonBook:
    """Run-scope lessons (auto-approved per the ledger's run scope) with the
    instrument's documented confidence-growth and priors mapping."""

    def __init__(self) -> None:
        self._ledger = _RetiredLessonsLedger()
        self._Lesson = _RetiredLedgerLesson
        self._by_family: dict[str, str] = {}

    def record(self, *, lesson_id: str, family: str, positive: bool,
               statement: str, confidence: float = 0.7) -> None:
        lesson = self._Lesson(
            lesson_id=lesson_id, scope="run", statement=statement,
            confidence=confidence, proposed_by="lcs2_instrument")
        self._ledger.record_lesson(lesson)  # scope=run -> auto-approved
        self._by_family[family] = lesson_id

    def revalidate(self, family: str) -> bool:
        """A later cycle re-validated the lesson's prediction: confidence
        +0.1 (cap 0.95), influence clock reset (apply_lesson)."""
        lid = self._by_family.get(family)
        if not lid:
            return False
        lesson = self._ledger.get_all_lessons()
        target = next((l for l in lesson if l.lesson_id == lid), None)
        if target is None:
            return False
        target.confidence = min(0.95, target.confidence + 0.1)
        self._ledger.apply_lesson(lid, 0)
        return True

    def priors_for(self, family: str, current_run: int) -> float:
        """lesson_priors multiplier from the family's lesson influence."""
        lid = self._by_family.get(family)
        if not lid:
            return 1.0
        lesson = next((l for l in self._ledger.get_all_lessons()
                       if l.lesson_id == lid), None)
        if lesson is None or not lesson.is_approved():
            return 1.0
        influence = self._ledger.get_influence(lesson, current_run)
        positive = "confirms" in lesson.statement or "productive" in lesson.statement
        if positive:
            return 1.0 + 0.5 * influence
        return max(0.1, 1.0 - 0.5 * influence)

    def audit(self, current_run: int) -> list[dict[str, Any]]:
        out = []
        for lesson in self._ledger.get_all_lessons():
            out.append({"lesson_id": lesson.lesson_id, "statement": lesson.statement,
                        "confidence": round(lesson.confidence, 4),
                        "influence": round(self._ledger.get_influence(lesson, current_run), 4),
                        "approved_by": lesson.approved_by})
        return out


# ---------------------------------------------------------------------------
# EV -> selector priority bridge (advisory input; deterministic final pick)
# ---------------------------------------------------------------------------
def ev_to_information_value(ranked: list[dict[str, Any]]) -> dict[str, float]:
    """Map the EVScheduler rank order into the AutonomousExperimentSelector's
    ``information_value`` advisory input: 0.9 - 0.2*rank_index for EV>0
    hypotheses, 0.05 for EV<=0 (which the sweep SKIPS — see skip policy).
    The selector's final pick stays deterministic (its own scoring); this
    bridge carries the scheduler's priority as an ADVISORY input only — no
    authority change, the spine is untouched."""
    iv: dict[str, float] = {}
    idx = 0
    for h in ranked:
        if float(h.get("ev", 0.0)) > 0.0:
            iv[h["id"]] = round(max(0.1, 0.9 - 0.2 * idx), 4)
            idx += 1
        else:
            iv[h["id"]] = 0.05
    return iv


# ---------------------------------------------------------------------------
# Recon-honest hypothesis construction (the DR-012 fix)
# ---------------------------------------------------------------------------
# The lab fixture's observed recon surface (identical across cycles — the
# fixture is unchanged): a JSON invoice API with principal-scoped object
# access and NO SQLi/XSS/RFI signals.  recon-honest construction derives
# each family's recon_signal_matches FROM this surface instead of asserting
# the cycle-1 EV-leg fixture values.
FIXTURE_RECON_SURFACE = {
    "routes": ["/api/login", "/api/invoices/me", "/api/invoices/{invoice_id}"],
    "content_type": "application/json",
    "principal_scoped_objects": True,
    "returns_user_data": True,
    "sqli_signals": 0,   # no error strings, no sql routes, no timing surfaces
    "xss_signals": 0,    # JSON content type, no reflection surface
    "rfi_signals": 0,    # no external-resource fetch parameters
}
RECON_HONEST_MATCHES: dict[str, int] = {
    "IDOR": 2,   # returns_user_data + principal_scoped_objects
    "SQLI": FIXTURE_RECON_SURFACE["sqli_signals"],
    "XSS": FIXTURE_RECON_SURFACE["xss_signals"],
    "RFI": FIXTURE_RECON_SURFACE["rfi_signals"],
}


def build_sweep_hypothesis_set(*, engagement_id: str, recon_honest: bool,
                               recorded_inputs: list[dict[str, Any]] | None = None,
                               lesson_priors: dict[str, float] | None = None
                               ) -> list[dict[str, Any]]:
    """Build the sweep hypothesis set.

    recon_honest=False replays the RECORDED cycle-1 EV-leg input values
    (the control / cycle-2-attempt-1 state).  recon_honest=True derives the
    matches from the observed fixture surface (the DR-012 correction).
    """
    lesson_priors = lesson_priors or {}
    if not recon_honest:
        base = [dict(h) for h in (recorded_inputs or CYCLE1_RECORDED_EV_INPUTS)]
        for h in base:
            h["lesson_priors"] = 1.0
        return base
    hyps: list[dict[str, Any]] = []
    common = {"engagement_id": engagement_id, "api_type": "rest"}
    # IDOR full-chain (the M4 two-principal hypothesis — cycle-1 pattern)
    hyps.append({**common, "id": f"{engagement_id}_idor",
                 "vulnerability_class": "IDOR", "path": "/api/invoices/",
                 "information_value": 0.9,
                 "recon_signal_matches": RECON_HONEST_MATCHES["IDOR"],
                 "lesson_priors": lesson_priors.get("IDOR", 1.0),
                 "estimated_cost": 6, "estimated_llm_calls": 1,
                 "chain_potential": 1.4,
                 "resource_owner": "User_B"})
    # SQLI live probe (invoice path; the validator decides on the differential)
    hyps.append({**common, "id": f"{engagement_id}_sqli",
                 "vulnerability_class": "SQLI", "path": "/api/invoices/",
                 "information_value": 0.9,
                 "recon_signal_matches": RECON_HONEST_MATCHES["SQLI"],
                 "lesson_priors": lesson_priors.get("SQLI", 1.0),
                 "estimated_cost": 5, "estimated_llm_calls": 1,
                 "chain_potential": 1.5})
    # XSS live probe (reflection surface probe on the JSON API)
    hyps.append({**common, "id": f"{engagement_id}_xss",
                 "vulnerability_class": "XSS", "path": "/api/invoices/",
                 "information_value": 0.9,
                 "recon_signal_matches": RECON_HONEST_MATCHES["XSS"],
                 "lesson_priors": lesson_priors.get("XSS", 1.0),
                 "estimated_cost": 4, "estimated_llm_calls": 2,
                 "chain_potential": 1.2})
    # RFI live probe
    hyps.append({**common, "id": f"{engagement_id}_rfi",
                 "vulnerability_class": "RFI", "path": "/api/invoices/",
                 "information_value": 0.9,
                 "recon_signal_matches": RECON_HONEST_MATCHES["RFI"],
                 "lesson_priors": lesson_priors.get("RFI", 1.0),
                 "estimated_cost": 12, "estimated_llm_calls": 3,
                 "chain_potential": 1.0})
    return hyps


def attach_idor_request_specs(hyp: dict[str, Any], *, control_invoice: str) -> dict[str, Any]:
    """Attach the M4 two-principal request specs (cycle-1 P1 pattern)."""
    def _spec(actor: str, invoice: str, actor_role: str) -> dict:
        return {"method": "GET", "path": f"/api/invoices/{invoice}",
                "headers": {"X-User": actor}, "principal_alias": actor,
                "principal_role": actor_role}
    hyp["requests"] = {
        "baseline": _spec("User_B", "INV-B-204", "owner"),
        "candidate": _spec("User_A", "INV-B-204", "foreign-user"),
        "negative_control": _spec("User_A", control_invoice, "foreign-user"),
    }
    return hyp


def attach_probe_request_specs(hyp: dict[str, Any], *, family: str) -> dict[str, Any]:
    """Attach live probe specs for the non-M4 families (no principal binding;
    X-User advisory).  Candidate carries the family payload, the negative
    control is the nonexistent-object path (404 control)."""
    if family == "SQLI":
        candidate_path = "/api/invoices/INV-B-204%27"
    elif family == "XSS":
        candidate_path = "/api/invoices/INV-B-204?x=%3Csvg%20onload%3Dalert(1)%3E"
    elif family == "RFI":
        candidate_path = "/api/invoices/INV-B-204?src=http%3A%2F%2Fexternal.example"
    else:
        candidate_path = "/api/invoices/INV-B-204"
    hyp["requests"] = {
        "baseline": {"method": "GET", "path": "/api/invoices/INV-B-204",
                     "headers": {"X-User": "User_B"}},
        "candidate": {"method": "GET", "path": candidate_path,
                      "headers": {"X-User": "User_B"}},
        "negative_control": {"method": "GET", "path": "/api/invoices/INV-NO-SUCH-999",
                             "headers": {"X-User": "User_B"}},
    }
    return hyp


# ---------------------------------------------------------------------------
# Request measurement — server-side counting middleware (runtime composition)
# ---------------------------------------------------------------------------
class RequestCounter:
    def __init__(self) -> None:
        self.count = 0
        self.paths: list[str] = []

    def snapshot(self) -> int:
        return self.count


def start_lab_server_counted(vulnerable: bool) -> tuple[Any, str, RequestCounter]:
    """Start the IDOR lab fixture with a counting ASGI middleware composed at
    RUNTIME (the fixture module/file is untouched — measurement-only
    composition).  Returns (server, base_url, counter)."""
    import threading

    import uvicorn

    from tests.lab.idor_lab_target import build_app

    counter = RequestCounter()

    class _CountingMiddleware:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope.get("type") == "http":
                counter.count += 1
                counter.paths.append(f"{scope.get('method')} {scope.get('path')}")
            await self.app(scope, receive, send)

    app_instance = build_app(vulnerable=vulnerable)
    app_instance.add_middleware(_CountingMiddleware)
    config = uvicorn.Config(app_instance, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("counted lab target server failed to start")
    port = server.servers[0].sockets[0].getsockname()[1]
    server._lab_thread = thread  # type: ignore[attr-defined]
    server._vulnerable = vulnerable  # type: ignore[attr-defined]
    return server, f"http://127.0.0.1:{port}", counter


# ---------------------------------------------------------------------------
# The sweep decision loop
# ---------------------------------------------------------------------------
SWEEP_BUDGET_REQUESTS = 6  # fixed budget: 2 decision rounds (equal for every
                           # brain state — the fair-comparison contract)


def run_sweep(*, engagement_id: str, target_url: str, hypotheses: list[dict[str, Any]],
              lesson_book: LessonBook | None, current_run: int,
              budget_requests: int = SWEEP_BUDGET_REQUESTS) -> dict[str, Any]:
    """Execute the EV-ordered decision-loop sweep through the REAL pipeline.

    Per round: EVScheduler.rank -> SKIP hypotheses with ev <= 0 (documented
    policy: a zero-probability family is an irrational spend; the skip is a
    recorded decision, not a silent drop) -> map EV rank into the selector's
    information_value (advisory bridge) -> one AVI decision (one real triple)
    -> adaptation.record_outcome (in-run learning) -> lesson re-validation ->
    re-rank.  Stops when the budget cannot cover another triple or no
    unselected non-skipped hypothesis remains.
    """
    from webpent.brain.adaptation import AdaptationEngine
    from webpent.production.autonomous_validation_v1 import (
        AutonomousValidationIntelligence,
    )
    from tests.lab.lcs2_sweep_support import (
        make_orchestrator, seal_principals, stages_delta,
    )

    scheduler = _ev_module.EVScheduler()
    engine = AdaptationEngine(scheduler)
    orch = make_orchestrator(engagement_id, target_url)
    # The IDOR family's M4 two-principal perimeter requires vault-sealed
    # principals for THIS sweep's engagement — always seal (fail-closed
    # otherwise: the triple would be BLOCKED with status 0).
    seal_principals(engagement_id, target_url)
    orch.run_deep_recon(target_url=target_url, observed=[
        {"path": "/api/invoices/", "method": "GET", "status_code": 200,
         "body": "{}", "headers": {}}])
    avi = AutonomousValidationIntelligence(orch)

    rounds: list[dict[str, Any]] = []
    spent = 0
    findings = 0
    stage_cursor = 0
    pool = list(hypotheses)
    while spent + 3 <= budget_requests and pool:
        ranked = scheduler.rank(pool)
        skipped = [{"hypothesis_id": h["id"], "ev": round(float(h.get("ev", 0.0)), 6),
                    "reason": "ev_le_0_irrational_spend"}
                   for h in ranked if float(h.get("ev", 0.0)) <= 0.0]
        active = [h for h in ranked if float(h.get("ev", 0.0)) > 0.0]
        # drop already-selected hypotheses (selector signature exclusion)
        already = {str(s) for s in getattr(avi.selector, "_selected_signatures", set())}
        active = [h for h in active if h["id"] not in already]
        if not active:
            for s in skipped:
                s.setdefault("round", len(rounds) + 1)
            rounds.append({"round": len(rounds) + 1, "skipped": skipped,
                           "executed": None, "note": "no_positive_ev_hypotheses_remaining"})
            break
        # Bridge the FULL ranked list (ev<=0 hypotheses are demoted to 0.05
        # in the selector's advisory input too), then pass ONLY the active
        # set to the decision — the skip policy is structural, not advisory.
        # The ivs are written onto the RANKED dicts (the objects the decision
        # actually receives), never the pool originals.
        iv_map = ev_to_information_value(ranked)
        for h in ranked:
            if h["id"] in iv_map:
                h["information_value"] = iv_map[h["id"]]
        stage_cursor = len(avi.trace.stages)
        avi._run_one_decision(target_url=target_url, hypotheses=active,
                              decision_number=len(rounds) + 1)
        new_stages = avi.trace.stages[stage_cursor:]
        v_proof, p_proof = stages_delta(new_stages)
        validator_outcome = (v_proof or {}).get("outcome")
        promo = ((p_proof or {}).get("decision") or "").upper()
        hid = (v_proof or {}).get("hypothesis_id") or (p_proof or {}).get("hypothesis_id")
        if promo == "PROMOTED":
            outcome = "promoted"
        elif validator_outcome in ("REFUTED",):
            outcome = "refuted"
        else:
            outcome = "inconclusive"
        family = str(next((h.get("vulnerability_class") for h in pool
                           if h.get("id") == hid), "")).upper()
        ev_recorded = engine.record_outcome(family, outcome)
        promoted_now = promo == "PROMOTED"
        if promoted_now:
            findings += 1
        if lesson_book is not None:
            if promoted_now:
                lesson_book.revalidate(family)
        rounds.append({"round": len(rounds) + 1,
                       "skipped": skipped,
                       "executed": {"hypothesis_id": hid, "family": family,
                                    "validator_outcome": validator_outcome,
                                    "promotion_decision": promo,
                                    "outcome": outcome,
                                    "requests": 3,
                                    "rate_before": ev_recorded.before_ev.get(family),
                                    "rate_after": ev_recorded.after_ev.get(family),
                                    "discriminating_signal": (v_proof or {}).get("discriminating_signal")}})
        spent += 3
        pool = [h for h in pool if h["id"] != hid]
    client_requests = spent
    return {"engagement_id": engagement_id, "rounds": rounds,
            "findings": findings, "client_requests": client_requests,
            "adaptation_events": [{"mechanism": e.mechanism, "trigger": e.trigger,
                                   "before_ev": e.before_ev, "after_ev": e.after_ev}
                                  for e in engine.get_events()]}
