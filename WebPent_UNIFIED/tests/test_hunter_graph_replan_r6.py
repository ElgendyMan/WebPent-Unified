"""r6c hunter-graph replan tests (Gap 3 + same-item advisory guard).

r5 LAB evidence: a first-attempt REFUTED verdict fell through to
advance/complete, so the production spine's unconditional ``replan``
required stage was missing (missing_required_stages=["replan"] while budgets
were NOT exhausted). These tests pin:

- first-attempt REFUTED routes to the replan node and its ``replan`` graph
  event projects the production-trace stage (graph-side only —
  hunter_runner._sync_graph_replan_trace untouched);
- second-attempt REFUTED (post-swap) advances and never loops back;
- a REFUTED same-item advisory is a NO-OP: retire-and-advance, the refuted
  hypothesis is NOT re-exploited;
- a REFUTED different-item advisory still swaps with attempt+1;
- INCONCLUSIVE retry semantics and budget are byte-unchanged;
- the replan prompt carries the feedback's REAL verdict/status_category.
"""

from __future__ import annotations

import json

from webpent.agents.hunter_contracts import (
    BudgetState,
    ExploitationResult,
    HunterState,
    HunterStatus,
    ValidationVerdict,
    Verdict,
)
from webpent.agents.hunter_graph import run_hunter_graph
from webpent.agents.hunter_runner import _sync_graph_replan_trace
from webpent.production.production_spine import ProductionTrace

HYP_A = {
    "hypothesis_id": "hyp-a",
    "hypothesis": "owner id differential on items",
    "target_endpoint": "/items/1",
    "attack_type": "IDOR",
    "priority": 90,
    "reasoning": "sequential identifier",
    "expected_behavior": "owner 200, foreign 200",
}
HYP_B = {
    "hypothesis_id": "hyp-b",
    "hypothesis": "role confusion on admin route",
    "target_endpoint": "/admin/users",
    "attack_type": "BOLA",
    "priority": 80,
    "reasoning": "privileged route reachable",
    "expected_behavior": "foreign gets 403",
}

CATALOG = [
    {
        "route": "/items/1",
        "vulnerability_class": "IDOR",
        "hypothesis_id": "hyp-a",
        "executable": True,
        "method": "GET",
    },
    {
        "route": "/admin/users",
        "vulnerability_class": "BOLA",
        "hypothesis_id": "hyp-b",
        "executable": True,
        "method": "GET",
    },
]


def _exploit_recorder(attempts: list, statuses=None):
    def exploit(h, _state):
        attempts.append((h.hypothesis_id, h.attempt, h.target_endpoint))
        return ExploitationResult(h.hypothesis_id, HunterStatus.VALIDATING, True, True, evidence={"status_code": 200})

    return exploit


def _refuted_validator(h, _result, _state):
    return ValidationVerdict(h.hypothesis_id, Verdict.REFUTED, 0.9, reason="negative control matched")


def _inconclusive_validator(h, _result, _state):
    return ValidationVerdict(h.hypothesis_id, Verdict.INCONCLUSIVE, 0.1, reason="candidate status category 401")


class _RoutingLLM:
    """Planner stub: hypotheses on the planner prompt, dict advisories on replan."""

    def __init__(self, hypotheses, advisories):
        self.hypotheses = hypotheses
        self.advisories = list(advisories)
        self.replan_messages: list[dict] = []

    def __call__(self, messages):
        system = str(messages[0]["content"])
        if "bounded replan advisor" in system:
            self.replan_messages.append(json.loads(messages[1]["content"]))
            return json.dumps(self.advisories.pop(0) if self.advisories else {})
        return json.dumps({"hypotheses": self.hypotheses})


def _other_stages_recorded() -> ProductionTrace:
    trace = ProductionTrace(config_digest="a" * 16, entrypoint="direct_invoke")
    for stage in (
        "entrypoint_resolve",
        "spine_activation",
        "deep_recon",
        "world_model_mutation",
        "research_decision",
        "bounded_tool_execution",
        "observation",
        "outcome_recording",
        "causal_guard_evaluation",
        "proof_bundle_creation",
        "promotion_decision",
    ):
        trace.record(stage=stage, component="Test")
    return trace


def test_first_attempt_refuted_produces_replan_event_and_completes_production_trace():
    llm = _RoutingLLM([HYP_A], advisories=[{}])
    attempts: list = []
    hunter = HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50))
    final = run_hunter_graph(
        hunter=hunter,
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    assert final.status is HunterStatus.COMPLETED
    assert attempts == [("hyp-a", 0, "/items/1")]  # refuted hypothesis NOT re-exploited
    replan_events = [event for event in final.graph_events if event["node"] == "replan"]
    assert len(replan_events) == 1
    trace = _other_stages_recorded()
    _sync_graph_replan_trace(trace, final.graph_events)
    assert trace.saw("replan") is True
    complete, missing = trace.is_complete()
    assert (complete, missing) == (True, [])


def test_refuted_feedback_reaches_replan_prompt_with_real_status_category():
    llm = _RoutingLLM([HYP_A], advisories=[{}])
    attempts: list = []
    run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50)),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    assert len(llm.replan_messages) == 1
    payload = llm.replan_messages[0]
    assert payload["verdict"] == "refuted"
    assert payload["status_category"] == "refuted"
    assert payload["attempt"] == 0


def test_refuted_same_item_advisory_is_noop_retire_and_advance():
    # The advisory re-selects the SAME catalog item (same hypothesis_id):
    # no swap, no re-exploitation of the refuted hypothesis.
    llm = _RoutingLLM([HYP_A, HYP_B], advisories=[{"hypothesis_id": "hyp-a"}])
    attempts: list = []
    final = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50)),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    assert final.status is HunterStatus.COMPLETED
    # A(0) refuted -> same-item advisory -> retire; B(0) refuted -> retire (no advisories left) -> complete
    assert attempts == [("hyp-a", 0, "/items/1"), ("hyp-b", 0, "/admin/users")]
    assert sum(event["node"] == "replan" for event in final.graph_events) == 2
    outcomes = [event for event in final.graph_events if event["node"] == "replan_advisory"]
    assert outcomes, "replan_advisory events expected"
    assert final.validation_verdicts[0].verdict is Verdict.REFUTED


def test_refuted_degenerate_no_proposal_advisory_retires_and_advances():
    # No hypothesis_id and no endpoint/type in the advisory: ``proposed``
    # degenerates to the current hypothesis's own route+family — the
    # same-item guard must retire the hypothesis, not re-exploit it.
    llm = _RoutingLLM([HYP_A, HYP_B], advisories=[{}])
    attempts: list = []
    final = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50)),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    assert final.status is HunterStatus.COMPLETED
    assert attempts == [("hyp-a", 0, "/items/1"), ("hyp-b", 0, "/admin/users")]


def test_refuted_different_item_advisory_swaps_with_attempt_plus_one():
    llm = _RoutingLLM([HYP_A, HYP_B], advisories=[{"hypothesis_id": "hyp-b"}])
    attempts: list = []
    final = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50)),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    assert final.status is HunterStatus.COMPLETED
    # A(0) refuted -> different-item swap accepted (attempt+1) -> B(1)
    assert attempts == [("hyp-a", 0, "/items/1"), ("hyp-b", 1, "/admin/users")]


def test_second_attempt_refuted_advances_without_new_replan_event():
    llm = _RoutingLLM([HYP_A, HYP_B], advisories=[{"hypothesis_id": "hyp-b"}])
    attempts: list = []
    final = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": CATALOG}, budget=BudgetState(max_llm_calls=50)),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_refuted_validator,
    )
    # A refuted once (attempt 0 -> replan); B refuted at attempt 1 -> ADVANCE.
    assert sum(event["node"] == "replan" for event in final.graph_events) == 1
    assert attempts == [("hyp-a", 0, "/items/1"), ("hyp-b", 1, "/admin/users")]
    assert final.status is HunterStatus.COMPLETED
    assert len(final.validation_verdicts) == 2


def test_inconclusive_retry_semantics_and_budget_unchanged():
    attempts: list = []
    final = run_hunter_graph(
        hunter=HunterState(
            surface_data={"candidate_hypotheses": [HYP_A], "candidate_catalog": []},
            budget=BudgetState(max_llm_calls=50, max_replans_per_hypothesis=2),
        ),
        exploiter=_exploit_recorder(attempts),
        validator=_inconclusive_validator,
    )
    assert attempts == [
        ("hyp-a", 0, "/items/1"),
        ("hyp-a", 1, "/items/1"),
        ("hyp-a", 2, "/items/1"),
    ]
    assert sum(event["node"] == "replan" for event in final.graph_events) == 2
    assert len(final.validation_verdicts) == 3
    assert final.status is HunterStatus.COMPLETED


def test_inconclusive_prompt_still_reports_inconclusive():
    llm = _RoutingLLM([HYP_A], advisories=[{}])
    attempts: list = []
    run_hunter_graph(
        hunter=HunterState(
            surface_data={"candidate_catalog": CATALOG},
            budget=BudgetState(max_llm_calls=50, max_replans_per_hypothesis=1),
        ),
        planner_llm=llm,
        exploiter=_exploit_recorder(attempts),
        validator=_inconclusive_validator,
    )
    assert len(llm.replan_messages) == 1
    payload = llm.replan_messages[0]
    assert payload["verdict"] == "inconclusive"
    assert payload["status_category"] == "inconclusive"
    assert payload["hypothesis_id"] == "hyp-a"
