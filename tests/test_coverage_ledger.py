from webpent.shared.coverage_ledger import project_coverage_ledger


def _state(outcomes=None):
    return {
        "campaign_ledger": {
            "entries": [
                {"id": 1, "key": "header_sqli", "status": "not_observed"},
                {"id": 2, "key": "csv_ingestion_sqli", "status": "not_observed"},
                {"id": 3, "key": "xslt_injection", "status": "missing-validator"},
            ]
        },
        "proof_outcomes": outcomes or [],
    }


def test_projection_keeps_unattempted_campaigns_unscanned():
    result = project_coverage_ledger(_state())

    assert result["summary"] == {"not_scanned": 2, "missing-validator": 1}
    assert result["attempt_count"] == 0
    assert result["entries"][0]["gaps"] == ["no-executor-outcome"]


def test_projection_maps_explicit_proof_outcomes_without_guessing():
    result = project_coverage_ledger(
        _state(
            [
                {
                    "campaign_key": "header_sqli",
                    "action_id": "action-1",
                    "status": "confirmed",
                    "evidence_complete": True,
                },
                {
                    "campaign_key": "csv_ingestion_sqli",
                    "action_id": "action-2",
                    "status": "blocked_by_precondition",
                    "note": "missing worker observation",
                },
            ]
        )
    )

    assert result["summary"] == {
        "tool_confirmed": 1,
        "blocked_by_precondition": 1,
        "missing-validator": 1,
    }
    assert result["attempt_count"] == 2
    assert result["entries"][0]["proof_action_id"] == "action-1"
    assert result["entries"][1]["evidence_complete"] is False


def test_campaign_task_attempt_is_visible_without_confirmation():
    result = project_coverage_ledger(
        {
            **_state(),
            "campaign_task_outcomes": [
                {
                    "campaign_key": "header_sqli",
                    "task_id": "task-1",
                    "status": "executed",
                    "reason": "probe completed without proof oracle",
                }
            ],
        }
    )

    entry = result["entries"][0]
    assert entry["status"] == "inconclusive"
    assert entry["attempts"] == 1
    assert entry["task_id"] == "task-1"
    assert entry["evidence_complete"] is False


def test_unknown_outcome_is_not_promoted():
    result = project_coverage_ledger(
        _state(
            [
                {
                    "campaign_key": "header_sqli",
                    "action_id": "action-3",
                    "status": "maybe_vulnerable",
                }
            ]
        )
    )

    assert result["entries"][0]["status"] == "not_scanned"
