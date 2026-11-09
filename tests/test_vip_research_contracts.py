import pytest
from pydantic import ValidationError

from webpent.agents.smart_campaigns.agent import smart_campaigns_node
from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_contracts import ResearchDecisionEngine


def _candidate(**updates) -> CandidateAction:
    payload = {
        "action_id": "action:owner",
        "action_class": "identity_acquisition",
        "objective": "acquire an authorized owner context",
        "target_ref": "https://target.test/object/1",
        "gap_id": "gap:ownership",
        "expected_information_gain": 0.9,
        "likelihood": 0.8,
        "impact": 0.7,
        "evidence_potential": 0.9,
        "novelty": 0.6,
        "coverage_value": 0.9,
        "required_capabilities": ["http_read"],
        "capability": "http_read",
        "cost": 1.0,
    }
    payload.update(updates)
    return CandidateAction.model_validate(payload)


def test_research_context_is_checkpoint_safe_and_redacts_secret():
    context = ResearchContext.from_state(
        {
            "thread_id": "thread:test",
            "engagement_id": "engagement:test",
            "client_id": "client:test",
            "target_url": "https://target.test/?token=secret-value",
            "knowledge_gaps": [{"gap_id": "gap:one", "unknown": "owner"}],
        }
    )
    payload = context.as_dict()
    assert payload["checkpoint_safe"] is True
    assert payload["open_gap_ids"] == ["gap:one"]
    assert "secret-value" not in str(payload)


def test_candidate_action_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        CandidateAction(
            action_id="action:test",
            action_class="discovery",
            objective="bounded discovery",
            unsupported_authority=True,
        )


def test_research_decision_engine_fails_closed_on_missing_capability_scope_and_budget():
    engine = ResearchDecisionEngine()
    candidate = _candidate()
    assert engine.score(candidate, available_capabilities={}).status == "blocked"
    assert engine.score(
        candidate,
        available_capabilities={"http_read"},
        target_allowed=False,
    ).reasons == ("target_scope_denied",)
    assert engine.score(
        candidate,
        available_capabilities={"http_read"},
        budget_remaining=0.0,
    ).reasons == ("budget_exhausted",)


def test_research_decision_engine_penalizes_failed_revisit_until_new_evidence():
    engine = ResearchDecisionEngine()
    candidate = _candidate()
    first = engine.score(candidate, available_capabilities={"http_read"})
    failed = engine.score(
        candidate,
        available_capabilities={"http_read"},
        failed_path_fingerprints=[candidate.fingerprint()],
    )
    revisit = engine.score(
        candidate,
        available_capabilities={"http_read"},
        failed_path_fingerprints=[candidate.fingerprint()],
        new_evidence=True,
    )
    assert first.score > failed.score
    assert revisit.score == first.score
    assert "failed_path_revisit_penalty" in failed.reasons


def test_smart_campaigns_emits_typed_research_projection_without_execution():
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:test",
        "client_id": "client:test",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {"record_id": "surface:object:1", "url": "https://target.test/object/1"}
            ]
        },
        "relational_evidence": [],
        "authorization_matrix": {},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "smart_governance": {"profile": "safe-smart"},
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {"entries": []},
    }
    result = smart_campaigns_node(state)
    assert result["research_context"]["checkpoint_safe"] is True
    assert result["research_candidate_actions"]
    assert result["research_unified_decision_trace"]
    assert all(item["status"] == "ranked" for item in result["research_unified_decision_trace"])
    assert result["campaign_task_outcomes"] == [] or all(
        item["status"] != "executed" for item in result["campaign_task_outcomes"]
    )
