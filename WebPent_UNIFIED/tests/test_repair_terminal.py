from webpent.agents.hunter_contracts import BudgetState, HunterState, HunterStatus
from webpent.agents.hunter_runner import _terminal_result


def _classify(
    *,
    status=HunterStatus.COMPLETED,
    budget=None,
    trace=None,
    audit=None,
    scope_halted=False,
):
    return _terminal_result(
        state=HunterState(status=status, budget=budget or BudgetState()),
        production_trace=trace or {"complete": True, "chain_verified": True},
        audit_result=audit or {"verified": True},
        scope_halted=scope_halted,
    )


def test_complete_requires_graph_trace_and_audit_completion():
    result = _classify()

    assert result["status"] == "COMPLETE"
    assert result["budget_stop"] is False
    assert result["reason"] == "graph_and_authoritative_traces_complete"


def test_completed_graph_with_incomplete_production_trace_is_not_success():
    result = _classify(
        trace={
            "complete": False,
            "chain_verified": True,
            "missing_required_stages": ["bounded_tool_execution"],
        }
    )

    assert result["status"] == "INCOMPLETE"
    assert result["reason"] == "production_trace_completion"


def test_halted_run_is_distinct_from_incomplete_run():
    result = _classify(status=HunterStatus.HALTED)

    assert result["status"] == "HALTED"
    assert result["reason"] == "campaign_halted"
    assert result["budget_stop"] is False


def test_budget_stop_is_distinct_from_halted_and_incomplete():
    result = _classify(
        status=HunterStatus.HALTED,
        budget=BudgetState(max_llm_calls=2, llm_calls=2),
    )

    assert result["status"] == "BUDGET_STOP"
    assert result["reason"] == "llm_call_budget_exhausted"
    assert result["budget_stop"] is True


def test_trace_completion_falls_back_to_full_coverage_for_legacy_summary():
    result = _classify(
        trace={"full_coverage": True, "chain_verified": True},
    )

    assert result["status"] == "COMPLETE"
    assert result["production_trace_complete"] is True
