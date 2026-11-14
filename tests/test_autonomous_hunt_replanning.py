"""Gap-driven re-hypothesis tests (autonomous convergence, suggestion 1).

The hunt previously generated hypotheses exactly once, before the
execute loop. Every iteration after the first therefore replayed the
same planned tasks until the controller stopped with
``same_action_repeated``/``no_new_evidence``: multi-round autonomy was
nominal. These tests pin the fix: knowledge gaps observed during
iteration N become bounded, advisory hypothesis seeds for iteration
N+1, deduped against what was already tried, with no invented hosts
and no promotion authority.
"""

from __future__ import annotations

from typing import Any

from webpent.autonomous.hunt_replanning import (
    gaps_from_coverage_ledger,
    synthesize_gap_hypotheses,
)
from webpent.autonomous.hunt_state import AutonomousHuntState


def _gap(gap_id: str, description: str, severity: float, *evidence: str) -> dict[str, Any]:
    return {
        "gap_id": gap_id,
        "description": description,
        "severity": severity,
        "required_evidence": list(evidence),
        "resolved": False,
    }


def test_gap_hypotheses_are_synthesized_bounded_and_ordered() -> None:
    gaps = [
        _gap("g2", "negative control missing for /admin", 0.9),
        _gap("g1", "target-backed observation missing", 0.4),
    ]
    out = synthesize_gap_hypotheses(
        gaps,
        engagement_id="e1",
        target_url="http://127.0.0.1:9/",
        seen_hypotheses=[],
    )
    assert [h["hypothesis_id"] for h in out] == ["gap:g2", "gap:g1"]
    assert out[0]["priority"] == 0.35 + 0.4 * 0.9
    assert out[0]["target_url"] == "http://127.0.0.1:9/"
    assert out[0]["origin"] == "knowledge_gap"
    assert out[1]["priority"] == 0.35 + 0.4 * 0.4


def test_gap_synthesis_dedupes_seen_and_within_batch() -> None:
    gaps = [_gap("g1", "one", 0.5), _gap("g1", "dup id", 0.7), _gap("g2", "two", 0.5)]
    seen = [{"hypothesis_id": "gap:g2"}]
    out = synthesize_gap_hypotheses(
        gaps,
        engagement_id="e1",
        target_url="http://t/",
        seen_hypotheses=seen,
    )
    assert [h["hypothesis_id"] for h in out] == ["gap:g1"]


def test_gap_synthesis_skips_resolved_and_junk_records() -> None:
    gaps: list[Any] = [
        {**_gap("g1", "resolved already", 0.9), "resolved": True},
        {"resolved": True, "gap_id": "g2", "description": "x", "severity": 0.9},
        "junk",
        None,
        {"gap_id": "g3", "description": "   "},
        {"gap_id": "g4", "description": "real gap", "severity": 0.6},
    ]
    out = synthesize_gap_hypotheses(
        gaps, engagement_id="e1", target_url="http://t/", seen_hypotheses=[]
    )
    assert [h["hypothesis_id"] for h in out] == ["gap:g4"]


def test_gap_synthesis_is_capped_and_severity_clamped() -> None:
    gaps = [_gap(f"g{i}", f"gap {i}", 5.0) for i in range(20)]
    out = synthesize_gap_hypotheses(
        gaps, engagement_id="e1", target_url="http://t/", seen_hypotheses=[], max_new=3
    )
    assert len(out) == 3
    assert all(0.0 <= h["priority"] <= 0.75 for h in out)


def test_orchestrator_rehypothesizes_from_gaps_between_iterations() -> None:
    from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator

    class _FakeController:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            self.calls += 1
            if self.calls == 1:
                return {
                    "campaign_task_outcomes": [
                        {"status": "executed", "action_signature": "sig-1"}
                    ],
                    "knowledge_gaps": [
                        _gap("g-new", "untested parameter surface", 0.8)
                    ],
                }
            return {"campaign_task_outcomes": []}

    controller = _FakeController()
    state = AutonomousHuntState(engagement_id="e1", target_url="http://t/")
    state.target_knowledge = {
        "entities": [
            {"url": "/login", "method": "GET", "response_digest": "aa" * 32}
        ]
    }
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: {"status": "executed"},
        controller=controller,
        max_iterations=3,
    )
    result = orchestrator.run(state)
    assert controller.calls >= 2, result.summary()
    rehypothesis = [
        r
        for r in state.phase_trace
        if r.phase.value == "hypothesis" and r.detail.get("source") == "knowledge_gaps"
    ]
    assert rehypothesis, [r.as_dict() for r in state.phase_trace]
    added = rehypothesis[0].detail.get("added", 0)
    assert added >= 1
    assert any(h.get("origin") == "knowledge_gap" for h in state.hypotheses)


def test_orchestrator_without_gaps_adds_no_rehypothesis_phase() -> None:
    from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator

    class _FakeController:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            self.calls += 1
            return {"campaign_task_outcomes": []}

    controller = _FakeController()
    state = AutonomousHuntState(engagement_id="e1", target_url="http://t/")
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: {"status": "executed"},
        controller=controller,
        max_iterations=2,
    )
    orchestrator.run(state)
    rehypothesis = [
        r
        for r in state.phase_trace
        if r.phase.value == "hypothesis" and r.detail.get("source") == "knowledge_gaps"
    ]
    assert not rehypothesis
    assert controller.calls >= 1


# ---------------------------------------------------------------------------
# Critique C1/C4 regression tests: the REAL controller shapes.
#
# The first version of this feature only worked against the synthetic _gap()
# fixtures above. The real AutonomousController emits per-class coverage
# ledger entries ({key, status, attempts, gaps[], reason}) and never emits a
# knowledge_gaps key at all. These tests pin the fixed behavior.
# ---------------------------------------------------------------------------

def _ledger_entry(key: str, status: str, *gaps: str, attempts: int = 1, reason: str = ""):
    return {
        "key": key,
        "status": status,
        "attempts": attempts,
        "evidence_complete": False,
        "proof_action_id": f"action-{key}",
        "task_id": f"task-{key}",
        "reason": reason,
        "gaps": list(gaps),
    }


def test_real_controller_ledger_shape_is_synthesized() -> None:
    """C1b: a projected coverage-gap record must produce a hypothesis seed."""
    gaps = [
        _ledger_entry(
            "cloud_storage_exposure",
            "missing-validator",
            "deterministic-validator-unavailable",
        ),
        _ledger_entry("ssti", "inconclusive", "no-executor-outcome"),
    ]
    out = synthesize_gap_hypotheses(
        gaps, engagement_id="e1", target_url="http://t/", seen_hypotheses=[]
    )
    assert [h["hypothesis_id"] for h in out] == [
        "gap:cloud_storage_exposure",
        "gap:ssti",
    ]
    # missing-validator earns severity 0.9: priority 0.35 + 0.4 * 0.9 = 0.71,
    # under the 0.75 ceiling so a gap seed reorders but never dominates.
    assert out[0]["priority"] == 0.71
    assert "missing-validator" in out[0]["rationale"] or out[0]["evidence_refs"]


def test_confirmed_and_clean_ledger_statuses_are_not_gaps() -> None:
    gaps = [
        _ledger_entry("sqli", "tool_confirmed"),
        _ledger_entry("xss", "candidate"),
        _ledger_entry("idor", "not_scanned"),
    ]
    out = synthesize_gap_hypotheses(
        gaps, engagement_id="e1", target_url="http://t/", seen_hypotheses=[]
    )
    assert [h["hypothesis_id"] for h in out] == ["gap:idor"]


def test_gaps_from_coverage_ledger_derives_ordered_bounded_records() -> None:
    ledger = {
        "sqli": {"attempts": 2, "last_status": "tool_confirmed", "proof_confirmed": True},
        "cloud_storage_exposure": {
            "attempts": 0,
            "last_status": "missing-validator",
        },
        "xslt_injection": {"attempts": 0, "last_status": "human_review_only"},
        "junk": "not-a-mapping",
    }
    records = gaps_from_coverage_ledger(ledger)
    assert [r["vulnerability_class"] for r in records] == [
        "cloud_storage_exposure",
        "xslt_injection",
    ]
    assert all(r["source"] == "coverage_ledger" for r in records)
    assert records[0]["status"] == "missing-validator"
    assert records[0]["severity"] == 0.9
    # Round-trip: derived records must be synthesizable.
    seeds = synthesize_gap_hypotheses(
        records, engagement_id="e1", target_url="http://t/", seen_hypotheses=[]
    )
    assert {s["hypothesis_id"] for s in seeds} == {
        "gap:ledger:cloud_storage_exposure",
        "gap:ledger:xslt_injection",
    }


def test_gaps_from_coverage_ledger_rejects_non_mapping_and_caps() -> None:
    assert gaps_from_coverage_ledger(None) == []
    assert gaps_from_coverage_ledger("junk") == []
    ledger = {f"c{i}": {"last_status": "not_scanned"} for i in range(40)}
    assert len(gaps_from_coverage_ledger(ledger, max_gaps=5)) == 5


def test_orchestrator_derives_gaps_from_real_coverage_ledger_key() -> None:
    """C1a: a controller update carrying coverage_ledger (no knowledge_gaps)
    must populate the gap ledger and trigger re-hypothesis."""
    from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator

    class _RealShapedController:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            self.calls += 1
            if self.calls == 1:
                return {
                    "campaign_task_outcomes": [
                        {"status": "executed", "action_signature": "sig-1"}
                    ],
                    # The real controller's key set: no knowledge_gaps.
                    "coverage_ledger": {
                        "cloud_storage_exposure": {
                            "attempts": 0,
                            "last_status": "missing-validator",
                        }
                    },
                    "lifecycle_events": [],
                    "recovery_events": [],
                    "attack_graph": None,
                }
            return {"campaign_task_outcomes": []}

    controller = _RealShapedController()
    state = AutonomousHuntState(engagement_id="e1", target_url="http://t/")
    state.target_knowledge = {
        "entities": [{"url": "/login", "method": "GET", "response_digest": "aa" * 32}]
    }
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: {"status": "executed"},
        controller=controller,
        max_iterations=3,
    )
    result = orchestrator.run(state)
    assert controller.calls >= 2, result.summary()
    assert any(
        g.get("source") == "coverage_ledger" for g in state.knowledge_gaps
    ), [r.as_dict() for r in state.phase_trace]
    assert any(h.get("origin") == "knowledge_gap" for h in state.hypotheses)


def test_quiet_dedup_iterations_record_empty_phase_only_once() -> None:
    """C6: dedup-only quiet iterations must not flood the phase trace."""
    from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator

    class _DedupController:
        def __init__(self) -> None:
            self.calls = 0

        def run(self, state, *, handler, iterations=1):  # noqa: ANN001
            self.calls += 1
            if self.calls == 1:
                return {
                    "campaign_task_outcomes": [],
                    "coverage_ledger": {
                        "ssti": {"attempts": 0, "last_status": "not_scanned"}
                    },
                }
            return {"campaign_task_outcomes": []}

    controller = _DedupController()
    state = AutonomousHuntState(engagement_id="e1", target_url="http://t/")
    orchestrator = AutonomousHuntOrchestrator(
        action_executor=object(),
        handler=lambda task: {"status": "executed"},
        controller=controller,
        max_iterations=4,
    )
    orchestrator.run(state)
    empties = [
        r
        for r in state.phase_trace
        if r.status == "empty" and r.reason == "no_new_gap_hypotheses"
    ]
    assert len(empties) <= 1, [r.as_dict() for r in state.phase_trace]


def test_report_carries_hypothesis_origin_counts() -> None:
    """C7: the report must show where hypotheses came from."""
    state = AutonomousHuntState(engagement_id="e1", target_url="http://t/")
    state.hypotheses = [
        {"hypothesis_id": "h1", "pattern_id": "sqli", "priority": 0.5},
        {"hypothesis_id": "gap:a", "pattern_id": "knowledge_gap_followup",
         "priority": 0.6, "origin": "knowledge_gap"},
        {"hypothesis_id": "gap:b", "pattern_id": "knowledge_gap_followup",
         "priority": 0.5, "origin": "knowledge_gap"},
    ]
    report = state.to_report_json()
    assert report["hypothesis_origins"] == {"hunt": 1, "knowledge_gap": 2}
