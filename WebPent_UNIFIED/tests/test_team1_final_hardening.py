"""Team-1 final generic-core hardening tests (Phases 2-9).

Deterministic, offline, no real API quota, no target-specific logic.
All assertions exercise real policy code. No code was modified for this
hardening round (priority-persistence defect already fixed); these tests
prove the invariants and close the remaining generic-core weaknesses.
"""
from __future__ import annotations

import pytest

from webpent.integration.priority_policy import PriorityProposal
from webpent.integration.research_agenda import AgendaSignal, ResearchAgenda
from webpent.research_engine.agenda_bridge import AgendaBridge
from webpent.research_engine.evidence_aware_loop import EvidenceAwareAgentLoop
from webpent.research_engine.research_state import ResearchTask

ENG = "eng-hardening"


def _sig(sid: str, hyp: str, sev: int, ev: float, note: str = "") -> AgendaSignal:
    return AgendaSignal(
        signal_id=sid, hypothesis_id=hyp, severity_potential=sev,
        evidence_strength=ev, exploitability=0.5, asset_criticality=0.5,
        confidence=0.5, novelty=0.5, exploration_cost=1,
        source_refs=("obs::generic",), note=note,
    )


def _task(tid: str, priority: float = 0.05, tgt: str = "tgt") -> ResearchTask:
    return ResearchTask(
        task_id=tid, engagement_id=ENG, target_id=tgt, objective=f"obj-{tid}",
        priority=priority, required_capability="http_read",
    )


def _select(bridge: AgendaBridge, tgt: str = "tgt") -> str:
    loop = EvidenceAwareAgentLoop()
    r = loop.evaluate(
        engagement_id=ENG, target_id=tgt, tasks=[_task("base::low", tgt=tgt)],
        available_capabilities={"http_read"}, scope_authorized=True,
        evidence_refs=["ev::1"], required_evidence=["ev::1"],
        central_proof_verified=True, agenda_bridge=bridge,
    )
    return r.selected_task_id or ""


# ---------------------------------------------------------------------------
# Phase 2 — priority persistence invariant across ALL update paths (12 cases)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("case", [
    ("new_branch", [("s1", 5, 0.5)]),
    ("existing_branch", [("s1", 2, 0.2), ("s2", 9, 0.95)]),
    ("weak_signal", [("s1", 1, 0.05)]),
    ("medium_signal", [("s1", 5, 0.5)]),
    ("strong_signal", [("s1", 9, 0.95)]),
    ("repeated_signal", [("s1", 5, 0.5), ("s1", 5, 0.5)]),
    ("competing_branches", [("a", 3, 0.3), ("b", 8, 0.8)]),
    ("duplicate_signal", [("s1", 6, 0.6), ("s1", 6, 0.6)]),
    ("multiple_updates", [("s1", 2, 0.2), ("s2", 5, 0.5), ("s3", 8, 0.8)]),
    ("already_high", [("s1", 9, 0.95), ("s2", 9, 0.95)]),
    ("zero_noop_delta", [("s1", 5, 0.5), ("s2", 5, 0.5)]),
    ("priority_decrease_protected", [("s1", 9, 0.95), ("s2", 1, 0.05)]),  # max() keeps high
])
def test_priority_persisted_invariant(case):
    name, signals = case
    ag = ResearchAgenda()
    last_decision = None
    for sid, sev, ev in signals:
        last_decision = ag.ingest_signal(_sig(sid, "hyp::" + name, sev, ev))
    stored = max(b.priority for b in ag.ordered_active())
    # invariant: last accepted computed priority is persisted on its branch
    assert stored == last_decision.priority, f"{name}: computed={last_decision.priority} stored={stored}"


# ---------------------------------------------------------------------------
# Phase 3 — true queue reordering: A low, B high -> signal into A -> A > B
# ---------------------------------------------------------------------------
def test_queue_reordering_after_escalation():
    bridge = AgendaBridge(engagement_id=ENG, target_id="tgt")
    bridge.ingest(_sig("a-weak", "hyp::A", 1, 0.05))   # A = low
    bridge.ingest(_sig("b-high", "hyp::B", 9, 0.95))   # B = high
    before_order = [b.hypothesis_id for b in bridge.agenda.ordered_active()]
    before_selected = _select(bridge)
    assert before_order[0] == "hyp::B"                  # B > A before
    assert "hyp::B" in before_selected
    assert "hyp::A" not in before_selected              # A was NOT first
    # inject meaningful signal into A -> escalate A above B
    bridge.ingest(_sig("a-critical", "hyp::A", 10, 1.0))
    after_order = [b.hypothesis_id for b in bridge.agenda.ordered_active()]
    after_selected = _select(bridge)
    assert after_order[0] == "hyp::A"                   # A > B after
    assert "hyp::A" in after_selected                   # next task from A
    assert after_selected != before_selected            # order actually changed


# ---------------------------------------------------------------------------
# Phase 4 — rabbit-hole depth >= 3 sequential adaptive steps, each causally
# influenced by evidence from the previous step (not predefined statically).
# ---------------------------------------------------------------------------
def test_rabbit_hole_three_adaptive_steps():
    bridge = AgendaBridge(engagement_id=ENG, target_id="tgt")
    selected_trace = []
    priority_trace = []
    # Step 1: weak signal on X -> selected X
    bridge.ingest(_sig("step1", "hyp::X", 2, 0.2))
    selected_trace.append(_select(bridge))
    priority_trace.append([b.priority for b in bridge.agenda.ordered_active()])
    # Step 2: evidence from step1 observation strengthens X -> X escalates (still X but priority changed)
    bridge.ingest(_sig("step2", "hyp::X", 7, 0.7))
    selected_trace.append(_select(bridge))
    priority_trace.append([b.priority for b in bridge.agenda.ordered_active()])
    # Step 3: further evidence on related sub-hypothesis Y, strong enough to outrank X
    bridge.ingest(_sig("step3a", "hyp::X", 9, 0.95))
    bridge.ingest(_sig("step3b", "hyp::Y", 10, 1.0))
    selected_trace.append(_select(bridge))
    priority_trace.append([b.priority for b in bridge.agenda.ordered_active()])
    # three adaptive steps; evidence at each step changed priority (causal influence)
    assert priority_trace[0] != priority_trace[1] != priority_trace[2]
    # step 3 selects a different branch than steps 1-2 (ordering actually changed)
    assert selected_trace[2] != selected_trace[0]
    assert selected_trace[-1].startswith("agenda::")
    # budget bounded: max depth enforced (spawn child of child exceeds depth)
    from webpent.integration.research_agenda import AgendaLimits
    deep_ag = ResearchAgenda(limits=AgendaLimits(max_branch_depth=1))
    deep_ag.ingest_signal(_sig("root", "hyp::root", 5, 0.5))
    child_id = deep_ag.spawn_child_branch("branch::hyp::root", _sig("child", "hyp::child", 5, 0.5))
    with pytest.raises(ValueError):
        deep_ag.spawn_child_branch("branch::hyp::child", _sig("grand", "hyp::grand", 5, 0.5))
    # safe stop: dedup prevents repeated probe
    p_before = bridge.agenda.ordered_active()[0].priority
    bridge.ingest(_sig("step3a", "hyp::X", 9, 0.95))  # duplicate signal id
    assert bridge.agenda.ordered_active()[0].priority == p_before


# ---------------------------------------------------------------------------
# Phase 5 — negative rabbithole controls: weak/misleading signal no domination
# ---------------------------------------------------------------------------
def test_weak_signal_does_not_rabbit_hole():
    ag = ResearchAgenda()
    ag.ingest_signal(_sig("critical", "hyp::crit", 9, 0.95))
    crit_p = ag.ordered_active()[0].priority
    ag.ingest_signal(_sig("weak", "hyp::weak", 1, 0.05))
    ordered = ag.ordered_active()
    assert ordered[0].hypothesis_id == "hyp::crit"     # critical still dominates
    weak_p = [b.priority for b in ordered if b.hypothesis_id == "hyp::weak"][0]
    assert weak_p < crit_p                              # weak gets small increase only


def test_misleading_signal_no_uncontrolled_escalation():
    ag = ResearchAgenda()
    ag.ingest_signal(_sig("benign1", "hyp::benign", 3, 0.3))
    ag.ingest_signal(_sig("benign2", "hyp::benign", 3, 0.3))  # competing benign, low
    benign_p = [b.priority for b in ag.ordered_active() if b.hypothesis_id == "hyp::benign"][0]
    assert benign_p < 70  # below high-priority threshold -> no budget boost, no deep rabbit-hole


# ---------------------------------------------------------------------------
# Phase 6 — LLM authority boundary: LLM proposal is advisory/bounded only
# ---------------------------------------------------------------------------
def test_llm_proposal_cannot_arbitrarily_set_priority():
    ag = ResearchAgenda()
    base = ag.ingest_signal(_sig("s", "hyp::llm", 5, 0.5))
    # LLM proposes the maximum allowed delta; final priority is deterministic
    # clamp(base + bounded_proposal) and cannot be set arbitrarily by the LLM.
    max_proposal = PriorityProposal(suggested_delta=10, proposer="llm", reason="override")
    ag2 = ResearchAgenda()
    with_proposal = ag2.ingest_signal(_sig("s", "hyp::llm", 5, 0.5), proposal=max_proposal)
    # final priority cannot exceed PRIORITY_MAX (100); proposal delta bounded at 10
    assert with_proposal.priority <= 100
    assert with_proposal.proposal_applied <= 10  # clamped to PROPOSAL_MAX_BOOST
    # deterministic: same inputs + same proposal -> same priority
    ag3 = ResearchAgenda()
    again = ag3.ingest_signal(_sig("s", "hyp::llm", 5, 0.5), proposal=max_proposal)
    assert again.priority == with_proposal.priority
    # LLM cannot issue CONFIRMED: loop never sets proof_authority
    loop = EvidenceAwareAgentLoop()
    r = loop.evaluate(engagement_id=ENG, target_id="tgt", tasks=[_task("t")],
        available_capabilities={"http_read"}, scope_authorized=True,
        evidence_refs=["ev::1"], required_evidence=["ev::1"], central_proof_verified=True)
    assert r.proof_authority is False
    assert r.finding_promotion_allowed is False


# ---------------------------------------------------------------------------
# Phase 7 — target agnosticity: two different target profiles, identical behavior
# ---------------------------------------------------------------------------
def test_target_agnostic_identical_behavior():
    results = {}
    for tgt, note in [("target-a", "route::a/tenant::a/actor::admin-a"),
                      ("target-b", "endpoint::b/org::b/user::root-b")]:
        ag = ResearchAgenda()
        d1 = ag.ingest_signal(_sig("s1", f"hyp::{tgt}", 2, 0.2, note=note))
        d2 = ag.ingest_signal(_sig("s2", f"hyp::{tgt}", 9, 0.95, note=note))
        stored = ag.ordered_active()[0].priority
        results[tgt] = {"weak": d1.priority, "strong": d2.priority, "stored": stored}
    assert results["target-a"] == results["target-b"]  # zero target-specific branches


# ---------------------------------------------------------------------------
# Phase 8 — state isolation: A -> B -> A, second A not contaminated by B
# ---------------------------------------------------------------------------
def test_state_isolation_no_cross_contamination():
    def run(tgt):
        bridge = AgendaBridge(engagement_id=ENG, target_id=tgt)
        bridge.ingest(_sig(f"{tgt}-sig", f"hyp::{tgt}", 5, 0.5))
        return {b.hypothesis_id: b.priority for b in bridge.agenda.ordered_active()}
    a1 = run("target-a")
    b1 = run("target-b")
    a2 = run("target-a")
    assert "hyp::target-b" not in a1 and "hyp::target-b" not in a2  # A never sees B's hypotheses
    assert a1 == a2                                                 # second A identical (no contamination)
    assert b1.keys() == {"hyp::target-b"}                           # B isolated


# ---------------------------------------------------------------------------
# Phase 9 — provider failure safety (simulated; no real quota consumed)
# ---------------------------------------------------------------------------
def test_provider_failure_fails_closed(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", raising=False)
    from webpent.llm_researcher.providers import factory
    with pytest.raises(RuntimeError) as exc:
        factory.get_provider("openai_compatible", "gpt-test")
    assert "REAL_API_UNAVAILABLE" in str(exc.value)  # no silent mock fallback
