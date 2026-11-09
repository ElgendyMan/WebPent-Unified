"""Team-1 generic priority-persistence fix regression tests.

Defect (Team-2 Round-2): ResearchAgenda.ingest_signal() recomputed priority
correctly on an existing branch but never persisted it to branch.priority
(only the NEW-branch path persisted it). The scheduler therefore saw the old
priority and adaptive ordering did not change.

Fix: one line in the existing-branch update path:
    branch = branch.model_copy(update={"priority": decision.priority})

All tests are deterministic, offline, target-agnostic. No thresholds changed.
"""
from __future__ import annotations

import json

from webpent.integration.research_agenda import (
    AgendaBranchState,
    AgendaSignal,
    ResearchAgenda,
)
from webpent.research_engine.agenda_bridge import AgendaBridge
from webpent.research_engine.evidence_aware_loop import EvidenceAwareAgentLoop
from webpent.research_engine.research_state import ResearchTask

ENG = "eng-priority-fix"
TGT = "target-generic"


def _signal(sid: str, hyp: str, sev: int, ev: float, note: str = "") -> AgendaSignal:
    return AgendaSignal(
        signal_id=sid,
        hypothesis_id=hyp,
        severity_potential=sev,
        evidence_strength=ev,
        exploitability=0.5,
        asset_criticality=0.5,
        confidence=0.5,
        novelty=0.5,
        exploration_cost=1,
        source_refs=("obs::generic",),
        note=note,
    )


def _task(task_id: str, priority: float = 0.1) -> ResearchTask:
    return ResearchTask(
        task_id=task_id,
        engagement_id=ENG,
        target_id=TGT,
        objective=f"obj-{task_id}",
        priority=priority,
        required_capability="http_read",
    )


# ---------------------------------------------------------------------------
# TEST 1: 20 -> 94 pattern (computed high priority is persisted)
# ---------------------------------------------------------------------------
def test_weak_then_strong_priority_persisted():
    ag = ResearchAgenda()
    d_weak = ag.ingest_signal(_signal("s-weak", "hyp::a", 2, 0.2))
    p_weak = ag.ordered_active()[0].priority
    assert d_weak.priority == p_weak  # new-branch path already correct
    d_strong = ag.ingest_signal(_signal("s-strong", "hyp::a", 9, 0.95))
    p_stored = ag.ordered_active()[0].priority
    assert p_stored == d_strong.priority  # THE FIX: computed == stored
    assert p_stored > p_weak  # priority actually escalated


# ---------------------------------------------------------------------------
# TEST 2: normal signal changes priority correctly
# ---------------------------------------------------------------------------
def test_normal_signal_priority_changes():
    ag = ResearchAgenda()
    ag.ingest_signal(_signal("s1", "hyp::b", 3, 0.3))
    before = ag.ordered_active()[0].priority
    d = ag.ingest_signal(_signal("s2", "hyp::b", 7, 0.8))
    after = ag.ordered_active()[0].priority
    assert after == d.priority
    assert after > before


# ---------------------------------------------------------------------------
# TEST 3: no-op signal leaves priority unchanged
# ---------------------------------------------------------------------------
def test_noop_signal_priority_unchanged():
    ag = ResearchAgenda()
    ag.ingest_signal(_signal("s1", "hyp::c", 5, 0.5))
    first = ag.ordered_active()[0].priority
    # re-ingest an identical-strength signal: max() inputs unchanged -> same score
    ag.ingest_signal(_signal("s1b", "hyp::c", 5, 0.5))
    second = ag.ordered_active()[0].priority
    assert first == second


# ---------------------------------------------------------------------------
# TEST 4: multiple signals -> priority persists after repeated ingest
# ---------------------------------------------------------------------------
def test_multiple_signals_priority_persistent():
    ag = ResearchAgenda()
    for i, (sev, ev) in enumerate([(2, 0.2), (4, 0.4), (6, 0.6), (9, 0.95)], 1):
        d = ag.ingest_signal(_signal(f"s{i}", "hyp::d", sev, ev))
        assert ag.ordered_active()[0].priority == d.priority
    assert ag.ordered_active()[0].priority == d.priority  # last one sticks


# ---------------------------------------------------------------------------
# TEST 5: duplicate signal -> no unintended double increment
# ---------------------------------------------------------------------------
def test_duplicate_signal_no_double_increment():
    ag = ResearchAgenda()
    d1 = ag.ingest_signal(_signal("dup", "hyp::e", 8, 0.9))
    p1 = ag.ordered_active()[0].priority
    d2 = ag.ingest_signal(_signal("dup", "hyp::e", 8, 0.9))  # same signal again
    p2 = ag.ordered_active()[0].priority
    assert p1 == p2  # identical inputs -> identical computed priority
    assert d1.priority == d2.priority


# ---------------------------------------------------------------------------
# TEST 6: priority ordering — higher-priority branch appears first
# ---------------------------------------------------------------------------
def test_priority_ordering_high_first():
    ag = ResearchAgenda()
    ag.ingest_signal(_signal("low1", "hyp::low", 1, 0.1))
    ag.ingest_signal(_signal("high1", "hyp::high", 9, 0.95))
    ordered = ag.ordered_active()
    assert ordered[0].hypothesis_id == "hyp::high"
    assert ordered[0].priority > ordered[-1].priority


# ---------------------------------------------------------------------------
# TEST 7: state serialization / model_copy — priority survives reconstruction
# ---------------------------------------------------------------------------
def test_priority_survives_state_reconstruction():
    ag = ResearchAgenda()
    ag.ingest_signal(_signal("s1", "hyp::f", 2, 0.2))
    ag.ingest_signal(_signal("s2", "hyp::f", 9, 0.95))
    branch = ag.ordered_active()[0]
    # round-trip through model_dump + model_validate (serialization boundary)
    blob = branch.model_dump(mode="json")
    restored = AgendaBranchState.model_validate(blob)
    assert restored.priority == branch.priority
    # model_copy preserves priority
    copied = branch.model_copy(update={})
    assert copied.priority == branch.priority


# ---------------------------------------------------------------------------
# TEST 8: same behavior with agenda disabled (no agenda -> no interference)
# ---------------------------------------------------------------------------
def test_agenda_disabled_loop_unaffected():
    loop = EvidenceAwareAgentLoop()
    result = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::only")],
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["ev::1"],
        required_evidence=["ev::1"],
        central_proof_verified=True,
        # agenda_bridge not passed -> disabled -> historical selection
    )
    assert result.selected_task_id == "base::only"


# ---------------------------------------------------------------------------
# Phase 5 — rabbit-hole regression: critical signal escalates and changes
# selected experiment through the canonical loop.
# ---------------------------------------------------------------------------
def test_rabbit_hole_critical_signal_changes_selection():
    bridge = AgendaBridge(engagement_id=ENG, target_id=TGT)
    # weak branch first -> it is the only agenda branch, gets selected
    bridge.ingest(_signal("weak", "hyp::weak", 1, 0.1))
    initial_priority = bridge.agenda.ordered_active()[0].priority
    loop = EvidenceAwareAgentLoop()
    base = [_task("base::low", priority=0.05)]
    kwargs = dict(
        engagement_id=ENG, target_id=TGT, tasks=base,
        available_capabilities={"http_read"}, scope_authorized=True,
        evidence_refs=["ev::1"], required_evidence=["ev::1"],
        central_proof_verified=True,
    )
    before = loop.evaluate(**kwargs, agenda_bridge=bridge)
    assert before.selected_task_id == "agenda::branch::hyp::weak"
    # critical runtime signal arrives on a different hypothesis -> higher priority
    bridge.ingest(_signal("critical", "hyp::crit", 9, 0.95))
    final_priority = [b for b in bridge.agenda.ordered_active() if b.hypothesis_id == "hyp::crit"][0].priority
    after = loop.evaluate(**kwargs, agenda_bridge=bridge)
    assert final_priority > initial_priority  # priority escalated
    assert final_priority == [b for b in bridge.agenda.ordered_active() if b.hypothesis_id == "hyp::crit"][0].priority  # persisted
    assert after.selected_task_id != before.selected_task_id  # ordering changed
    assert after.selected_task_id == "agenda::branch::hyp::crit"  # critical branch selected


# ---------------------------------------------------------------------------
# Phase 6 — negative control: weak signal must NOT dominate queue.
# ---------------------------------------------------------------------------
def test_weak_signal_does_not_dominate():
    ag = ResearchAgenda()
    ag.ingest_signal(_signal("critical", "hyp::crit", 9, 0.95))
    crit_priority = ag.ordered_active()[0].priority
    ag.ingest_signal(_signal("weak", "hyp::weak", 1, 0.05))
    ordered = ag.ordered_active()
    assert ordered[0].hypothesis_id == "hyp::crit"  # critical still first
    weak_priority = [b for b in ordered if b.hypothesis_id == "hyp::weak"][0].priority
    assert weak_priority < crit_priority  # weak gets small/zero dominance


# ---------------------------------------------------------------------------
# Phase 7 — target agnosticity: identical algorithm for Target A and B.
# ---------------------------------------------------------------------------
def test_target_agnostic_identical_priority_behavior(tmp_path):
    results = {}
    for target in ("target-a", "target-b"):
        ag = ResearchAgenda()
        d1 = ag.ingest_signal(
            _signal("s1", f"hyp::{target}", 2, 0.2, note=f"route::{target}")
        )
        d2 = ag.ingest_signal(
            _signal("s2", f"hyp::{target}", 9, 0.95, note=f"actor::{target}")
        )
        stored = ag.ordered_active()[0].priority
        results[target] = {
            "computed_weak": d1.priority, "computed_strong": d2.priority,
            "stored_strong": stored, "persisted": d2.priority == stored,
            "delta": d2.priority - d1.priority,
        }
    # algorithmic behavior identical regardless of target-specific route/actor
    assert results["target-a"] == results["target-b"]
    out = tmp_path / "agnostic.json"
    out.write_text(json.dumps({"targets": results, "target_agnostic": True}, indent=2))
    assert json.loads(out.read_text())["target_agnostic"] is True
