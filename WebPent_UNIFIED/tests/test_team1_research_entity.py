"""Team-1 research-entity integration tests (Phase 4-9).

Deterministic, offline, no real API, no mock-LLM-as-proof. All assertions
exercise real policy code. The additive agenda hook is gated: default
(agenda_bridge=None) preserves historical behavior byte-for-byte.
"""
from __future__ import annotations

import os

import pytest

from webpent.integration.research_agenda import AgendaSignal
from webpent.integration.target_adapter import RuntimeProfile, TargetAdapter
from webpent.research_engine.agenda_bridge import AgendaBridge
from webpent.research_engine.evidence_aware_loop import EvidenceAwareAgentLoop
from webpent.research_engine.research_budget import ResearchBudget
from webpent.research_engine.research_state import ResearchState, ResearchTask
from webpent.shared.safety_gate import EngagementKillSwitch

ENG = "eng-team1-proof"
TGT = "target-local-authorized"


def _task(task_id: str, priority: float = 0.1, capability: str = "http_read") -> ResearchTask:
    return ResearchTask(
        task_id=task_id,
        engagement_id=ENG,
        target_id=TGT,
        objective=f"obj-{task_id}",
        priority=priority,
        required_capability=capability,
    )


def _high_signal(signal_id: str, hyp: str = "hyp::auth-bypass") -> AgendaSignal:
    return AgendaSignal(
        signal_id=signal_id,
        hypothesis_id=hyp,
        severity_potential=9,
        evidence_strength=0.9,
        exploitability=0.6,
        asset_criticality=0.7,
        confidence=0.8,
        novelty=0.6,
        exploration_cost=1,
        source_refs=("obs::001",),
    )


def _bridge_with_signal() -> AgendaBridge:
    bridge = AgendaBridge(engagement_id=ENG, target_id=TGT)
    bridge.ingest(_high_signal("sig::critical-auth"))
    return bridge


# ---------------------------------------------------------------------------
# Phase 4 — A/B proof: agenda enabled changes research ordering / selected
# experiment, and cannot bypass scope/budget.
# ---------------------------------------------------------------------------
def test_agenda_disabled_preserves_historical_selection():
    loop = EvidenceAwareAgentLoop()
    result = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::low-prio")],
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["ev::1"],
        required_evidence=["ev::1"],
        central_proof_verified=True,
    )
    assert result.selected_task_id == "base::low-prio"


def test_agenda_enabled_changes_selected_experiment():
    loop = EvidenceAwareAgentLoop()
    base = [_task("base::low-prio", priority=0.1)]
    kwargs = dict(
        engagement_id=ENG,
        target_id=TGT,
        tasks=base,
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["ev::1"],
        required_evidence=["ev::1"],
        central_proof_verified=True,
    )
    off = loop.evaluate(**kwargs)
    on = loop.evaluate(**kwargs, agenda_bridge=_bridge_with_signal())
    assert off.selected_task_id == "base::low-prio"
    assert on.selected_task_id != off.selected_task_id
    assert on.selected_task_id.startswith("agenda::")
    # single engagement identity preserved in both modes
    assert off.engagement_id == on.engagement_id == ENG
    assert off.target_id == on.target_id == TGT


def test_agenda_cannot_bypass_scope_authorization():
    loop = EvidenceAwareAgentLoop()
    result = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::1")],
        available_capabilities={"http_read"},
        scope_authorized=False,  # not authorized
        agenda_bridge=_bridge_with_signal(),
    )
    assert result.status.value == "blocked"
    assert result.stop_reason == "scope_authorization_required"


def test_agenda_respects_task_budget():
    budget = ResearchBudget(max_requests=1)
    loop = EvidenceAwareAgentLoop(budget=budget)
    result = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::1")],  # consumes the only slot
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["ev::1"],
        required_evidence=["ev::1"],
        central_proof_verified=True,
        agenda_bridge=_bridge_with_signal(),
    )
    # agenda task cannot be admitted (budget full) -> base task is still selected
    assert result.selected_task_id == "base::1"


# ---------------------------------------------------------------------------
# Phase 5 — rabbit-hole semantics proof (deterministic trace)
# ---------------------------------------------------------------------------
def test_rabbit_hole_trace_signal_to_causal_attempt():
    trace: list[str] = []
    bridge = AgendaBridge(engagement_id=ENG, target_id=TGT)

    # 1. initial critical signal -> agenda branch created with high priority
    bridge.ingest(_high_signal("sig::1", hyp="hyp::sqli"))
    branches = bridge.agenda.ordered_active()
    assert branches, "agenda branch created"
    trace.append("signal_ingested")
    priority0 = branches[0].priority
    assert priority0 > 0

    # 2. bounded research budget allocated
    assert branches[0].experiments_allocated >= 1
    trace.append("budget_allocated")

    # 3. new observation arrives -> same hypothesis branch updated (depth/priority)
    bridge.ingest(
        AgendaSignal(
            signal_id="sig::2",
            hypothesis_id="hyp::sqli",
            severity_potential=9,
            evidence_strength=0.95,
            exploitability=0.7,
            asset_criticality=0.7,
            confidence=0.9,
            novelty=0.5,
            exploration_cost=1,
            source_refs=("obs::002",),
        )
    )
    branches2 = bridge.agenda.ordered_active()
    assert len(branches2) == 1  # same branch, not a duplicate
    trace.append("new_observation_merged")

    # 4. follow-up experiment selected through the canonical loop
    loop = EvidenceAwareAgentLoop()
    sel = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::low", priority=0.05)],
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["obs::001", "obs::002"],
        required_evidence=["obs::001"],
        agenda_bridge=bridge,
    )
    assert sel.selected_task_id and sel.selected_task_id.startswith("agenda::")
    trace.append("followup_experiment_selected")

    # 5. causal validation attempt gated by central proof authority
    gated = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=[_task("base::low", priority=0.05)],
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["obs::001"],
        required_evidence=["obs::001"],
        central_proof_verified=False,  # not proven
        agenda_bridge=bridge,
    )
    assert gated.stop_reason == "central_verification_required"
    trace.append("causal_validation_attempt_gated")

    assert trace == [
        "signal_ingested",
        "budget_allocated",
        "new_observation_merged",
        "followup_experiment_selected",
        "causal_validation_attempt_gated",
    ]


# ---------------------------------------------------------------------------
# Phase 6 — target-agnostic isolation: Target-A config never alters Target-B
# ---------------------------------------------------------------------------
def test_target_adapter_isolation():
    adapter = TargetAdapter()
    before_b = adapter.capabilities("target-b")
    adapter.register(
        RuntimeProfile(
            profile_name="target-a",
            route_discovery=("a::route1",),
            actor_context=("a::admin",),
            state_transition_capabilities=("a::oauth",),
        )
    )
    after_b = adapter.capabilities("target-b")
    assert before_b == after_b  # unchanged
    assert adapter.get("target-b").profile_name == "generic"
    assert "a::route1" not in after_b
    # registering the same profile twice is rejected (no silent overwrite)
    with pytest.raises(ValueError):
        adapter.register(RuntimeProfile(profile_name="target-a"))


# ---------------------------------------------------------------------------
# Phase 7/8 — provider fail-closed + failure-first
# ---------------------------------------------------------------------------
def test_provider_missing_key_fails_closed(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION", raising=False)
    from webpent.llm_researcher.providers import factory

    # force re-evaluation of the gate at call time
    monkeypatch.setattr(factory.os, "environ", {k: v for k, v in os.environ.items()})
    with pytest.raises(RuntimeError) as exc:
        factory.get_provider("openai_compatible", "gpt-test-model")
    assert "REAL_API_UNAVAILABLE" in str(exc.value)


def test_budget_exhaustion_safe_stop():
    state = ResearchState(
        engagement_id=ENG, target_id=TGT, budget=ResearchBudget(max_requests=1)
    )
    state = state.admit_task(_task("t::1"))
    state = state.admit_task(_task("t::2"))
    assert len(state.tasks) == 1
    assert state.stop_reason == "task_budget_exhausted"


def test_resume_no_duplicate_completed_work():
    state = ResearchState(engagement_id=ENG, target_id=TGT)
    t = _task("t::resume")
    state = state.admit_task(t)
    state = state.admit_task(t)  # resume re-admits same task -> dedup
    assert len(state.tasks) == 1


def test_scope_mismatch_fail_closed():
    state = ResearchState(engagement_id=ENG, target_id=TGT)
    foreign = ResearchTask(
        task_id="t::evil",
        engagement_id="other-engagement",
        target_id="other-target",
        objective="x",
    )
    with pytest.raises(ValueError):
        state.admit_task(foreign)


def test_prompt_injection_in_observation_ref_rejected():
    state = ResearchState(engagement_id=ENG, target_id=TGT)
    with pytest.raises(ValueError):
        state.add_observation_ref("api_key=sk-leaked-credential")


def test_kill_switch_monotonic():
    ks = EngagementKillSwitch(engagement_id=ENG)
    assert not ks.tripped
    ks.trip("team1-test")
    assert ks.tripped
    # remains tripped (monotonic; cannot be unset)
    assert ks.tripped


# ---------------------------------------------------------------------------
# Phase 9 — single research entity: one engagement identity / state lineage
# ---------------------------------------------------------------------------
def test_single_entity_lineage_end_to_end():
    bridge = _bridge_with_signal()
    loop = EvidenceAwareAgentLoop()
    base = [_task("base::a", priority=0.1), _task("base::b", priority=0.2)]
    result = loop.evaluate(
        engagement_id=ENG,
        target_id=TGT,
        tasks=base,
        available_capabilities={"http_read"},
        scope_authorized=True,
        evidence_refs=["ev::1"],
        required_evidence=["ev::1"],
        central_proof_verified=True,
        agenda_bridge=bridge,
    )
    # every admitted task (base + agenda) shares ONE engagement/target identity
    admitted = bridge.admit_into_state(
        ResearchState(engagement_id=ENG, target_id=TGT)
    ).updated_state.tasks
    for t in [*base, *admitted]:
        assert t.engagement_id == ENG
        assert t.target_id == TGT
    # result carries the same single identity
    assert result.engagement_id == ENG
    assert result.target_id == TGT
    assert result.proof_authority is False  # loop never promotes to proof
    assert result.finding_promotion_allowed is False
