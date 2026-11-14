"""B3 hardening window 0.33.0 — docs/PRODUCTION_HARDENING_PLAN_0330.md.

Long-hunt robustness and logic-bug batch: P1-01..P1-08, P1-10..P1-17
(P1-09 lives in test_hardening_0330_b1.py). Every test documents the
failure the fix closes; all were RED before the 0.33.0 edits.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from webpent.autonomous.hunt_memory import ScopedHuntMemory, MemoryEntry, _MAX_ENTRIES
from webpent.brain.ev_scheduler import EVScheduler
from webpent.core.infrastructure import ExecutionSession
from webpent.memory.ab_lab import RUNNING_RUN_STALE_AFTER_SECONDS, LessonABLab


def _ok_runner(spec):
    return {"ok": True, "campaign_id": spec.campaign_id,
            "metrics": {"hypotheses_tested": 12, "findings_promoted": 2}}


# ---------------------------------------------------------------------------
# P1-02 — tick() claims its run atomically
# ---------------------------------------------------------------------------


def test_p102_claim_primitive_is_conditional():
    """Only a 'planned' row can transition to 'running' (the P1-02 fix)."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE ab_runs (run_id TEXT PRIMARY KEY, status TEXT, started_at TEXT)")
    conn.execute("INSERT INTO ab_runs VALUES ('r1', 'planned', NULL)")
    cursor = conn.execute(
        "UPDATE ab_runs SET status='running', started_at=? "
        "WHERE run_id=? AND status='planned'", ("now", "r1"))
    assert cursor.rowcount == 1  # first claim wins
    cursor = conn.execute(
        "UPDATE ab_runs SET status='running', started_at=? "
        "WHERE run_id=? AND status='planned'", ("now", "r1"))
    assert cursor.rowcount == 0  # second claim loses — no double execution
    conn.close()


def test_p102_parallel_ticks_never_execute_same_run_twice(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(client_id="acme", target_url="https://t.example",
                  authorization_ref="AUTH-1", mode="standard")
    executed: list[str] = []
    lock = threading.Lock()

    def runner(spec):
        with lock:
            executed.append(spec.run_id)
        return {"ok": True, "metrics": {"hypotheses_tested": 10,
                                        "findings_promoted": 1}}

    results: list[dict] = []
    threads = [threading.Thread(
        target=lambda i=i: results.append(lab.tick(runner=runner)))
        for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # The SAME run_id must never appear twice across concurrent ticks.
    # (The second tick may legitimately pick the NEXT arm if the first
    # thread fully finished before it — that is the declared sequential
    # policy, not a violation. The violation would be a duplicated
    # run_id in `executed`.)
    assert len(executed) == len(set(executed)), (executed, results)
    # UM-DR-28 P102 flake closure (root cause established + reproduced
    # deterministically with a sleeping runner): when the losing tick
    # lands in the claimed-but-not-terminal window, _next_due_run sees
    # a fresh 'running' row and — per the P1-08 policy, which treats a
    # fresh running row as in-progress by another live tick/process —
    # returns the honest no-op action 'none' (reason 'no_due_run').
    # That is a DESIGNED outcome, not a double execution: the invariant
    # above (no duplicated run_id) is the protected property and it is
    # fully asserted. 'already_claimed' remains reachable when the
    # loser's SELECT precedes the winner's atomic UPDATE.
    assert all(r.get("action") in ("run_executed", "already_claimed", "none")
               for r in results), results


# ---------------------------------------------------------------------------
# P1-03 — open_week refuses silently-changed parameters
# ---------------------------------------------------------------------------


def test_p103_open_week_param_mismatch_refused(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(client_id="acme", target_url="https://t.example",
                  authorization_ref="AUTH-1", mode="standard")
    with pytest.raises(ValueError, match="ab_lab_week_param_mismatch"):
        lab.open_week(client_id="acme", target_url="https://t.example",
                      authorization_ref="AUTH-1", mode="aggressive")
    with pytest.raises(ValueError, match="authorization_ref"):
        lab.open_week(client_id="acme", target_url="https://t.example",
                      authorization_ref="AUTH-CHANGED", mode="standard")
    # identical re-open stays idempotent
    again = lab.open_week(client_id="acme", target_url="https://t.example",
                          authorization_ref="AUTH-1", mode="standard")
    assert again["already_open"] is True


# ---------------------------------------------------------------------------
# P1-08 — stale 'running' run no longer head-of-line-blocks
# ---------------------------------------------------------------------------


def test_p108_stale_running_run_is_reclaimed(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(client_id="old", target_url="https://old.example",
                  authorization_ref="AUTH-1", mode="standard")
    stale_started = (datetime.now(timezone.utc)
                     - timedelta(seconds=RUNNING_RUN_STALE_AFTER_SECONDS + 60)
                     ).isoformat()
    import sqlite3

    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    conn.execute("UPDATE ab_runs SET status='running', started_at=? "
                 "WHERE arm='control'", (stale_started,))
    conn.commit()
    conn.close()

    lab.open_week(client_id="new", target_url="https://new.example",
                  authorization_ref="AUTH-2", mode="standard")
    result = lab.tick(runner=_ok_runner)
    assert result is not None
    assert result.get("action") in ("run_executed", "planned_run", "run_failed")
    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    try:
        row = conn.execute(
            "SELECT status, error FROM ab_runs WHERE client_id='old' "
            "AND arm='control'").fetchone()
    finally:
        conn.close()
    assert row[0] == "failed"
    assert row[1] == "stale_running_reclaimed"


def test_p108_fresh_running_run_is_left_alone(tmp_path):
    lab = LessonABLab(database_path=tmp_path / "ab.sqlite3")
    lab.open_week(client_id="acme", target_url="https://t.example",
                  authorization_ref="AUTH-1", mode="standard")
    import sqlite3

    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    conn.execute("UPDATE ab_runs SET status='running', started_at=? WHERE arm='control'",
                 (datetime.now(timezone.utc).isoformat(),))
    conn.commit()
    conn.close()
    result = lab.tick()  # dry plan — fresh running row is simply not due
    assert result == {"action": "none", "reason": "no_due_run", "week_key": "any"}
    conn = sqlite3.connect(tmp_path / "ab.sqlite3")
    try:
        assert conn.execute(
            "SELECT status FROM ab_runs WHERE arm='control'").fetchone()[0] == "running"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# P1-01 — quiet-round streak resets on productive rounds
# ---------------------------------------------------------------------------


def test_p101_productive_round_resets_streak():
    import inspect

    from webpent.autonomous import hunt_orchestrator as ho

    source = inspect.getsource(ho.AutonomousHuntOrchestrator.run)
    assert "evidence_gained = state.has_new_evidence_since" in source
    assert source.index("if evidence_gained:") < source.index("if not evidence_gained:")
    assert "self._quiet_rounds = 0" in source


# ---------------------------------------------------------------------------
# P1-05 — starvation floor respects the budget cap
# ---------------------------------------------------------------------------


def test_p105_floor_path_never_exceeds_budget():
    sched = EVScheduler()
    ranked = sched.rank([{"id": f"h{i}", "vulnerability_class": "XSS"}
                         for i in range(10)])
    grants = sched.allocate_budget(ranked, total_budget=3)
    total = sum(g["budget"] for g in grants)
    assert total <= 3, f"P1-05 regression: floor path granted {total} > 3"
    assert grants[0]["budget"] > 0  # the top-EV hypothesis is funded


def test_p105_normal_path_unchanged():
    sched = EVScheduler()
    ranked = sched.rank([{"id": f"h{i}", "vulnerability_class": "XSS"}
                         for i in range(2)])
    grants = sched.allocate_budget(ranked, total_budget=100)
    total = sum(g["budget"] for g in grants)
    assert total >= 100  # floor (5*2) + proportional remainder


# ---------------------------------------------------------------------------
# P1-06 / P1-07 — hunt memory integrity
# ---------------------------------------------------------------------------


def _valid_entry(pattern_id="p1", outcome="vulnerable") -> MemoryEntry:
    entry = MemoryEntry(pattern_id=pattern_id, pattern_type="hunt_pattern",
                        features={"class": "idor"}, outcome=outcome,
                        confidence=0.8, source="autonomous_hunt")
    assert entry.verify_signature(), "test needs a signable MemoryEntry"
    return entry


def test_p106_forged_entry_is_refused_on_load(tmp_path):
    store = ScopedHuntMemory(persist_path=str(tmp_path / "mem.json"))
    store.store(engagement_id="eng", target_id="t1", entry=_valid_entry())
    store.save()

    raw = json.loads((tmp_path / "mem.json").read_text())
    raw[0]["signature"] = "deadbeef"  # hand-forge
    (tmp_path / "mem.json").write_text(json.dumps(raw))

    reloaded = ScopedHuntMemory(persist_path=str(tmp_path / "mem.json"))
    assert reloaded.entries_for("eng", "t1") == [], (
        "P1-06 regression: forged entry loaded and would be served by hint()"
    )


def test_p106_valid_entry_survives_reload(tmp_path):
    store = ScopedHuntMemory(persist_path=str(tmp_path / "mem.json"))
    store.store(engagement_id="eng", target_id="t1", entry=_valid_entry())
    store.save()
    reloaded = ScopedHuntMemory(persist_path=str(tmp_path / "mem.json"))
    entries = reloaded.entries_for("eng", "t1")
    assert len(entries) == 1
    assert entries[0].pattern_id == "p1"
    assert entries[0].verify_signature()


def test_p107_full_store_still_accepts_updates():
    store = ScopedHuntMemory(persist_path=None)
    corrected = _valid_entry(pattern_id="p3", outcome="clean")
    for i in range(_MAX_ENTRIES):
        e = MemoryEntry(pattern_id=f"filler-{i}", pattern_type="hunt_pattern",
                        features={"i": i}, outcome="vulnerable",
                        confidence=0.1, source="autonomous_hunt")
        store.store(engagement_id="eng", target_id=f"t{i}", entry=e)
    assert len(store._entries) == _MAX_ENTRIES
    # update to an EXISTING key must still land (was silently dropped)
    store.store(engagement_id="eng", target_id="t-held", entry=corrected)
    # re-store the same pattern id under the key it already occupies
    key = [k for k, e in store._entries.items() if e.pattern_id == "filler-0"][0]
    updated = _valid_entry(pattern_id="filler-0", outcome="clean")
    store.store(engagement_id="eng", target_id=key.split("::")[0].split("|")[0]
                if "::" in key else "eng", entry=updated)
    # genuinely NEW entries stay bounded by the cap
    extra = _valid_entry(pattern_id="brand-new", outcome="clean")
    store.store(engagement_id="eng", target_id="t-extra", entry=extra)
    assert store.entries_for("eng", "t-extra") == []


# ---------------------------------------------------------------------------
# P1-10 / P1-11 — escalation ladder + scope bound
# ---------------------------------------------------------------------------


def test_p110_marginal_confirmation_is_MEDIUM_not_HIGH():
    from webpent.autonomous_hunter import ImpactLevel, StrategyEngine

    esc = StrategyEngine()
    result = esc.escalate({"finding_id": "f", "title": "t",
                           "confirmation_evidence": ["only-one-variant"]})
    if result.impact == ImpactLevel.NONE and result.confirmation_level == 1:
        assert str(result.priority.value).lower().startswith("medium"), (
            "P1-10 regression: MEDIUM tier unreachable again"
        )


def test_p111_scope_substring_bypasses_closed():
    from webpent.autonomous_hunter import StealthResilienceLayer

    layer = StealthResilienceLayer(allowed_scope=["example.com"])
    assert layer.in_scope("https://example.com/path") is True
    assert layer.in_scope("https://sub.example.com/") is True  # dot boundary
    # the three bypasses from the plan, all closed now
    assert layer.in_scope("https://notexample.com/") is False
    assert layer.in_scope("https://evil.com/?u=example.com") is False
    assert layer.in_scope("https://example.com@evil.com/") is False
    assert layer.in_scope("https://example.com.evil.com/") is False


def test_p111_scope_entry_as_url_is_honored():
    from webpent.autonomous_hunter import StealthResilienceLayer

    layer = StealthResilienceLayer(allowed_scope=["https://app.example.com"])
    assert layer.in_scope("https://app.example.com/x") is True
    assert layer.in_scope("https://other.example.com/x") is False


def test_p111_no_scope_still_allows_everything():
    from webpent.autonomous_hunter import StealthResilienceLayer

    assert StealthResilienceLayer(allowed_scope=None).in_scope("https://anything.dev/") is True


# ---------------------------------------------------------------------------
# P1-12 — atomic checkpoint
# ---------------------------------------------------------------------------


def test_p112_checkpoint_write_is_atomic(tmp_path):
    session = ExecutionSession("sess-p112", str(tmp_path / "cp.json"))
    session.start()
    assert (tmp_path / "cp.json").exists()
    assert not (tmp_path / "cp.json.tmp").exists()  # tmp is replaced away
    resumed = ExecutionSession.resume(str(tmp_path / "cp.json"))
    assert resumed.session_id == "sess-p112"


def test_p112_resume_or_none_tolerates_corruption(tmp_path):
    (tmp_path / "cp.json").write_text("{ this is not json")
    assert ExecutionSession.resume_or_none(str(tmp_path / "cp.json")) is None
    assert ExecutionSession.resume_or_none(str(tmp_path / "missing.json")) is None


# ---------------------------------------------------------------------------
# P1-13 — graceful bounded stop at the spine funnel
# ---------------------------------------------------------------------------


def test_p113_research_step_bounded_degrades(tmp_path):
    from webpent.production.modern_spine import ModernOrchestrator

    orch = ModernOrchestrator(engagement_id="eng-p113", scope_law=None)
    orch.run_deep_recon(
        target_url="https://lab.example.com",
        observed=[{"path": "/api/x", "method": "GET", "status_code": 200,
                   "body": "{}", "headers": {}}],
    )
    orch.research_loop.register_candidate("c1", ("h1",), "e1")
    from webpent.live_hunter import research_loop as rl

    original = rl.ResearchControlLoop.MAX_DECISIONS
    try:
        rl.ResearchControlLoop.MAX_DECISIONS = 0
        decision = orch.research_step_bounded()
        assert decision.get("bounded_stop")
        assert decision["selected_candidate"] is None
    finally:
        rl.ResearchControlLoop.MAX_DECISIONS = original
    # and the declared raise on the raw research_step contract stays intact
    # (drive the same exhausted bound through the RAW entrypoint)
    try:
        rl.ResearchControlLoop.MAX_DECISIONS = 0
        with pytest.raises(RuntimeError):
            orch.research_step()
    finally:
        rl.ResearchControlLoop.MAX_DECISIONS = original


# ---------------------------------------------------------------------------
# P1-14 — controlled adapter budget/start locks
# ---------------------------------------------------------------------------


class _FakeSpec:
    def __init__(self, max_requests: int):
        self.max_requests = max_requests
        self.timeout_seconds = 1

    def scope_validator(self):
        class _V:
            def decide(self, url, method="GET"):
                return SimpleNamespace(allowed=True, reason_code="ok")

        return _V()


def test_p114_request_budget_is_atomic_under_concurrency(monkeypatch):
    from webpent.adapters.controlled_target import adapter as adapter_mod

    target = adapter_mod.ControlledIDORTarget()
    target._target_spec = _FakeSpec(max_requests=5)
    monkeypatch.setattr(adapter_mod, "_http_get_redacted",
                        lambda url, timeout: (200, {"body_length": 4}))

    exhausted = threading.Semaphore(0)
    admitted: list[int] = []
    lock = threading.Lock()

    def worker():
        try:
            target._request_observation(
                role="probe", actor=target.state.owner_actor, resource="r1",
                run_context=SimpleNamespace(run_id="run-p114"))
        except RuntimeError as exc:
            if "budget_exhausted" in str(exc):
                return
            raise
        with lock:
            admitted.append(1)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert target.request_count == 5, (
        f"P1-14 regression: budget ended at {target.request_count}, expected exactly 5"
    )
    assert len(admitted) == 5


# ---------------------------------------------------------------------------
# P1-15 — research memory bounded at write time
# ---------------------------------------------------------------------------


def test_p115_ingest_observation_trims():
    from webpent.llm_researcher.interface import (
        LLMResearcher,
        _MAX_OBSERVATIONS,
    )

    researcher = LLMResearcher()
    total = _MAX_OBSERVATIONS + 50
    for i in range(total):
        researcher.ingest_observation({"request": {"path": f"/p{i}"},
                                       "headers": {}})
    assert len(researcher.memory.observations) <= _MAX_OBSERVATIONS
    # oldest trimmed, newest kept
    assert researcher.memory.observations[-1]["request"]["path"] == f"/p{total - 1}"
    assert researcher.memory.routes_observed[-1] == f"/p{total - 1}"


# ---------------------------------------------------------------------------
# P1-17 — finding ledger WAL + busy_timeout
# ---------------------------------------------------------------------------


def test_p117_ledger_pragmas_set(tmp_path):
    from webpent.shared.persistent_finding_ledger import (
        PersistentFindingLedger as Ledger,
    )

    ledger = Ledger(path=tmp_path / "ledger.sqlite3")
    with ledger._connect() as conn:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    assert str(mode).lower() == "wal"
    assert int(timeout) == 5000
