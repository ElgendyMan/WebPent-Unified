# tests/test_integration_research_agenda.py
"""Deterministic rabbit-hole/agenda tests (protocol §23 Cases A-F).

These tests prove the researcher-brain behavior required by the
protected migration protocol:

* Case A: high-severity signal → priority increases → additional
  research budget allocated → related branches can be explored.
* Case B: weak low-value signal → lower priority → limited budget.
* Case C: strong signal later disproven → priority decreases → branch
  terminates or is deprioritized.
* Case D: new evidence increases confidence → priority changes
  deterministically.
* Case E: budget exhausted → branch terminates safely.
* Case F: resume after checkpoint → completed work is not blindly
  repeated.

Plus: bounds (max active branches / depth / experiments), audit
trail, and byte-level determinism/reproducibility of decisions.
"""

from __future__ import annotations

import pytest

from webpent.integration.priority_policy import PriorityProposal
from webpent.integration.research_agenda import (
    AgendaLimits,
    AgendaSignal,
    BranchStatus,
    ResearchAgenda,
    branch_id_for,
)


def _strong_signal(
    signal_id: str = "sig-A1", hypothesis_id: str = "hyp-authz-critical"
) -> AgendaSignal:
    """Early signal: potential critical authorization flaw."""
    return AgendaSignal(
        signal_id=signal_id,
        hypothesis_id=hypothesis_id,
        severity_potential=9,
        evidence_strength=0.4,
        exploitability=0.8,
        asset_criticality=0.9,
        confidence=0.6,
        novelty=0.5,
        source_refs=["obs:1001"],
    )


def _weak_signal(signal_id: str = "sig-B1", hypothesis_id: str = "hyp-low-value") -> AgendaSignal:
    return AgendaSignal(
        signal_id=signal_id,
        hypothesis_id=hypothesis_id,
        severity_potential=1,
        evidence_strength=0.05,
        exploitability=0.1,
        asset_criticality=0.2,
        confidence=0.1,
        novelty=0.1,
    )


# ---------------------------------------------------------------------------
# Case A
# ---------------------------------------------------------------------------
def test_case_a_high_severity_signal_increases_priority_and_budget():
    agenda = ResearchAgenda()
    decision = agenda.ingest_signal(_strong_signal())
    branch = agenda.get_branch(branch_id_for("hyp-authz-critical"))

    # Priority increases into the high band and crosses the threshold.
    assert decision.priority >= agenda.limits.high_priority_threshold
    # Additional research budget allocated (base + boost).
    assert branch.experiments_allocated == (
        agenda.limits.base_experiments + agenda.limits.high_priority_budget_boost
    )
    assert branch.status is BranchStatus.ACTIVE
    # Related branches can be explored within the depth bound.
    child = _strong_signal(signal_id="sig-A2", hypothesis_id="hyp-authz-critical-child")
    agenda.spawn_child_branch(branch.branch_id, child)
    child_branch = agenda.get_branch(branch_id_for("hyp-authz-critical-child"))
    assert child_branch.depth == 1
    assert child_branch.branch_id in {b.branch_id for b in agenda.ordered_active()}


def test_case_a_related_branch_inherits_bounded_exploration():
    agenda = ResearchAgenda()
    parent = agenda.ingest_signal(_strong_signal())
    parent_branch = agenda.get_branch(branch_id_for("hyp-authz-critical"))
    # Deeper branches are depth-penalized: the child never outranks a
    # parent with identical other factors.
    child = _strong_signal(signal_id="sig-A3", hypothesis_id="hyp-authz-child-deep")
    child_decision = agenda.spawn_child_branch(parent_branch.branch_id, child)
    assert child_decision.priority < parent.priority


# ---------------------------------------------------------------------------
# Case B
# ---------------------------------------------------------------------------
def test_case_b_weak_signal_gets_low_priority_and_limited_budget():
    agenda = ResearchAgenda()
    decision = agenda.ingest_signal(_weak_signal())
    branch = agenda.get_branch(branch_id_for("hyp-low-value"))

    assert decision.priority < agenda.limits.low_priority_threshold
    # Limited budget: exactly the base allocation, no boost.
    assert branch.experiments_allocated == agenda.limits.base_experiments


# ---------------------------------------------------------------------------
# Case C
# ---------------------------------------------------------------------------
def test_case_c_refuted_signal_terminates_strong_branch():
    agenda = ResearchAgenda()
    agenda.ingest_signal(_strong_signal())
    bid = branch_id_for("hyp-authz-critical")
    before = agenda.get_branch(bid).priority

    decision = agenda.record_evidence(
        bid, evidence_strength=0.0, refuted=True, evidence_ref="obs:deadbeef"
    )
    branch = agenda.get_branch(bid)
    # Priority decreases deterministically and full disproof terminates.
    assert decision.priority < before
    assert branch.status is BranchStatus.TERMINATED
    # A terminated branch cannot consume more budget.
    allocation = agenda.request_experiment(bid)
    assert allocation.granted == 0
    assert allocation.reason == "branch_terminated"


def test_case_c_partial_refutation_deprioritizes_without_terminating():
    agenda = ResearchAgenda()
    agenda.ingest_signal(_strong_signal())
    bid = branch_id_for("hyp-authz-critical")
    before = agenda.get_branch(bid).priority

    decision = agenda.record_evidence(
        bid, evidence_strength=0.3, refuted=True, evidence_ref="obs:partial"
    )
    branch = agenda.get_branch(bid)
    assert decision.priority <= before
    # Branch is deprioritized (not terminated) when it lands below the
    # low threshold; if it stays above, it remains active but weaker.
    if decision.priority < agenda.limits.low_priority_threshold:
        assert branch.status is BranchStatus.DEPRIORITIZED
    else:
        assert branch.status is BranchStatus.ACTIVE


# ---------------------------------------------------------------------------
# Case D
# ---------------------------------------------------------------------------
def test_case_d_new_evidence_increases_priority_deterministically():
    agenda = ResearchAgenda()
    agenda.ingest_signal(_weak_signal())
    bid = branch_id_for("hyp-low-value")
    before = agenda.get_branch(bid).priority

    decision = agenda.record_evidence(
        bid, evidence_strength=0.9, evidence_ref="obs:corroboration"
    )
    after = agenda.get_branch(bid).priority
    assert after > before

    # Determinism: replaying the same evidence on a fresh agenda
    # produces the identical priority (reproducible, protocol §12).
    replay = ResearchAgenda()
    replay.ingest_signal(_weak_signal())
    replay_decision = replay.record_evidence(
        branch_id_for("hyp-low-value"),
        evidence_strength=0.9,
        evidence_ref="obs:corroboration",
    )
    assert replay_decision.priority == decision.priority
    assert replay_decision.to_audit_dict() == decision.to_audit_dict()


# ---------------------------------------------------------------------------
# Case E
# ---------------------------------------------------------------------------
def test_case_e_budget_exhaustion_terminates_branch_safely():
    limits = AgendaLimits(base_experiments=2, max_experiments_per_branch=2)
    agenda = ResearchAgenda(limits=limits)
    agenda.ingest_signal(_strong_signal())
    bid = branch_id_for("hyp-authz-critical")

    first = agenda.request_experiment(bid)
    assert first.granted == 1
    second = agenda.request_experiment(bid)
    assert second.granted == 1
    third = agenda.request_experiment(bid)
    # Safe termination: no negative budget, terminal status, audit row.
    assert third.granted == 0
    assert third.reason == "branch_terminated"
    assert agenda.get_branch(bid).status is BranchStatus.TERMINATED
    assert any(
        e.get("event") == "terminate" and e.get("reason") == "branch_budget_exhausted"
        for e in agenda.audit_trail()
    )


def test_case_e_global_budget_cap_stops_allotment():
    limits = AgendaLimits(max_total_experiments=3, base_experiments=3)
    agenda = ResearchAgenda(limits=limits)
    agenda.ingest_signal(_strong_signal())
    bid = branch_id_for("hyp-authz-critical")
    assert agenda.request_experiment(bid, requested=3).granted == 3
    # Global cap reached: another branch gets nothing (safe).
    agenda.ingest_signal(_weak_signal())
    other = agenda.request_experiment(branch_id_for("hyp-low-value"))
    assert other.granted == 0
    assert other.reason == "branch_budget_exhausted"


# ---------------------------------------------------------------------------
# Case F
# ---------------------------------------------------------------------------
def test_case_f_resume_after_checkpoint_does_not_repeat_completed_work():
    agenda = ResearchAgenda()
    agenda.ingest_signal(_strong_signal())
    strong_bid = branch_id_for("hyp-authz-critical")
    agenda.ingest_signal(_weak_signal())
    weak_bid = branch_id_for("hyp-low-value")
    agenda.mark_completed(weak_bid, marker="triage-complete")
    agenda.request_experiment(strong_bid)

    checkpoint = agenda.checkpoint()
    restored = ResearchAgenda()
    restored.restore(checkpoint)

    # Completed branch stays completed after restore.
    assert restored.get_branch(weak_bid).status is BranchStatus.COMPLETED
    assert "triage-complete" in restored.get_branch(weak_bid).completed_markers
    # Requesting work on the completed branch grants nothing.
    allocation = restored.request_experiment(weak_bid)
    assert allocation.granted == 0
    assert allocation.reason == "branch_already_completed"
    # In-flight branch state (used budget) survives restore exactly.
    assert restored.get_branch(strong_bid).experiments_used == 1
    assert restored.get_branch(strong_bid).status is BranchStatus.ACTIVE
    # Checkpoint round-trip is byte-identical.
    assert restored.checkpoint() == checkpoint


# ---------------------------------------------------------------------------
# Bounds (protocol §12)
# ---------------------------------------------------------------------------
def test_max_active_branches_enforced_with_fail_closed_creation():
    limits = AgendaLimits(max_active_branches=2, base_experiments=1)
    agenda = ResearchAgenda(limits=limits)
    agenda.ingest_signal(_strong_signal())  # priority 70 band
    agenda.ingest_signal(_weak_signal())
    # Third, weaker branch at cap → fail closed.
    with pytest.raises(ValueError, match="max_active_branches_reached"):
        agenda.ingest_signal(
            _weak_signal(signal_id="sig-B2", hypothesis_id="hyp-low-value-2")
        )
    # A strictly higher-priority newcomer may deprioritize the weakest.
    decision = agenda.ingest_signal(
        _strong_signal(signal_id="sig-A9", hypothesis_id="hyp-even-stronger")
    )
    assert decision.priority >= agenda.limits.high_priority_threshold
    statuses = {
        b.hypothesis_id: b.status for b in agenda._branches.values()
    }
    assert statuses["hyp-low-value"] is BranchStatus.DEPRIORITIZED


def test_max_branch_depth_blocks_infinite_rabbit_holes():
    limits = AgendaLimits(max_branch_depth=2, base_experiments=1)
    agenda = ResearchAgenda(limits=limits)
    agenda.ingest_signal(_strong_signal())
    root_bid = branch_id_for("hyp-authz-critical")
    child_sig = _strong_signal(signal_id="sig-C1", hypothesis_id="hyp-child-1")
    agenda.spawn_child_branch(root_bid, child_sig)
    grandchild_sig = _strong_signal(signal_id="sig-C2", hypothesis_id="hyp-grandchild-1")
    agenda.spawn_child_branch(branch_id_for("hyp-child-1"), grandchild_sig)
    with pytest.raises(ValueError, match="max_branch_depth_exceeded"):
        agenda.spawn_child_branch(
            branch_id_for("hyp-grandchild-1"),
            _strong_signal(signal_id="sig-C3", hypothesis_id="hyp-great-1"),
        )


# ---------------------------------------------------------------------------
# LLM proposal clamping (protocol §12: LLM suggests, never decides)
# ---------------------------------------------------------------------------
def test_llm_proposal_is_clamped_and_recorded_but_never_decides():
    agenda = ResearchAgenda()
    # Max allowed proposal: the model accepts ±PROPOSAL_MAX_BOOST.
    loud_proposal = PriorityProposal(
        suggested_delta=10,  # maximum influence the LLM can ever buy
        reason="llm wants this now",
        proposer="llm_researcher",
    )
    decision = agenda.ingest_signal(_weak_signal(), proposal=loud_proposal)
    branch = agenda.get_branch(branch_id_for("hyp-low-value"))
    assert abs(decision.proposal_applied) <= 10  # hard clamp
    assert decision.proposal_reason == "llm wants this now"
    assert decision.to_audit_dict()["proposal_applied"] == decision.proposal_applied
    # Even a maximal proposal cannot push a weak signal into the
    # high-priority band (deterministic policy dominates).
    assert decision.priority < agenda.limits.high_priority_threshold
    assert branch.experiments_allocated == agenda.limits.base_experiments


# ---------------------------------------------------------------------------
# Determinism / auditability
# ---------------------------------------------------------------------------
def test_ingest_is_reproducible_and_auditable():
    a1 = ResearchAgenda()
    a2 = ResearchAgenda()
    d1 = a1.ingest_signal(_strong_signal())
    d2 = a2.ingest_signal(_strong_signal())
    assert d1.to_audit_dict() == d2.to_audit_dict()
    assert a1.checkpoint() == a2.checkpoint()
    trail = a1.audit_trail()
    assert trail and trail[0]["event"] == "ingest_signal"
    assert trail[0]["branch"] == branch_id_for("hyp-authz-critical")


def test_ordered_active_is_stable_and_priority_sorted():
    agenda = ResearchAgenda()
    agenda.ingest_signal(_weak_signal())
    agenda.ingest_signal(_strong_signal())
    ordered = agenda.ordered_active()
    assert [b.hypothesis_id for b in ordered] == [
        "hyp-authz-critical",
        "hyp-low-value",
    ]


def test_terminated_branch_stays_terminated_on_new_signal():
    limits = AgendaLimits(base_experiments=1, max_experiments_per_branch=1)
    agenda = ResearchAgenda(limits=limits)
    agenda.ingest_signal(_strong_signal())
    bid = branch_id_for("hyp-authz-critical")
    agenda.request_experiment(bid)  # exhausts → terminated
    assert agenda.get_branch(bid).status is BranchStatus.TERMINATED
    agenda.ingest_signal(
        _strong_signal(signal_id="sig-A2", hypothesis_id="hyp-authz-critical")
    )
    assert agenda.get_branch(bid).status is BranchStatus.TERMINATED
    assert any(e["event"] == "ingest_rejected" for e in agenda.audit_trail())
