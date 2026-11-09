from webpent.shared.coverage_ledger import project_coverage_ledger


def test_research_coverage_projects_session_progress_and_target_dimensions() -> None:
    state = {
        "campaign_ledger": {"entries": [{"id": 1, "key": "authorization"}]},
        "campaign_task_outcomes": [],
        "knowledge_gaps": [{"gap_id": "gap:one", "status": "open"}],
        "smart_information_actions": [{"action_id": "action:one"}],
        "research_decision_trace": [{"decision_id": "decision:one"}],
        "research_session": {
            "client_id": "client-a",
            "engagement_id": "engagement-a",
            "next_best_actions": [
                {"action_id": "action:one", "outcome": "executed"},
                {"action_id": "action:two", "outcome": "planned"},
            ],
            "positive_evidence_ledger": [{"evidence_id": "positive:one"}],
            "negative_evidence_ledger": [{"evidence_id": "negative:one"}],
            "failed_paths": ["path:one"],
            "promising_paths": ["path:two"],
        },
        "target_understanding": {
            "endpoint_count": 3,
            "form_count": 2,
            "identity_count": 1,
            "object_candidate_count": 4,
            "workflow_candidate_count": 2,
            "coverage_gaps": ["missing-owner-context"],
        },
    }

    coverage = project_coverage_ledger(state)["research_coverage"]

    assert coverage["open_gap_count"] == 1
    assert coverage["planned_information_action_count"] == 1
    assert coverage["executed_information_action_count"] == 1
    assert coverage["positive_evidence_count"] == 1
    assert coverage["negative_evidence_count"] == 1
    assert coverage["decision_trace_count"] == 1
    assert coverage["target_understanding"]["object_candidate_count"] == 4
    assert coverage["client_id"] == "client-a"
    assert coverage["engagement_id"] == "engagement-a"


def test_research_coverage_is_fail_closed_for_malformed_target_understanding() -> None:
    state = {
        "campaign_ledger": {"entries": []},
        "target_understanding": {
            "endpoint_count": "not-a-number",
            "form_count": -9,
            "coverage_gaps": "malformed",
        },
    }

    coverage = project_coverage_ledger(state)["research_coverage"]

    assert coverage["target_understanding"]["endpoint_count"] == 0
    assert coverage["target_understanding"]["form_count"] == 0
    assert coverage["target_understanding"]["coverage_gap_count"] == 0
