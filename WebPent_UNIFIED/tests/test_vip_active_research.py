from webpent.models.research import CandidateAction, ResearchContext
from webpent.shared.research_contracts import (
    ActiveResearchLoop,
    CoverageIntelligence,
    active_research_node,
)


def _candidate(action_id: str = "action:read") -> CandidateAction:
    return CandidateAction(
        action_id=action_id,
        action_class="active_probe",
        objective="read an in-scope object safely",
        target_ref="https://target.test/object/1?token=secret-value",
        required_capabilities=["http_read"],
        capability="http_read",
        expected_information_gain=0.8,
        evidence_potential=0.8,
        coverage_value=0.8,
        cost=1.0,
    )


def test_active_loop_fails_closed_without_explicit_scope_even_with_handler():
    called = []
    loop = ActiveResearchLoop()
    context = ResearchContext(
        session_id="session:test",
        engagement_id="engagement:test",
        client_id="client:test",
        budget_remaining=2.0,
    )
    result = loop.step(
        context,
        [_candidate()],
        handler=lambda candidate: called.append(candidate) or {},
        available_capabilities={"http_read"},
        target_allowed=None,
    )
    assert result.observation.status == "blocked"
    assert result.observation.reason == "target_scope_not_explicitly_allowed"
    assert called == []


def test_active_loop_updates_context_coverage_and_failed_path_memory():
    candidate = _candidate()
    context = ResearchContext(
        session_id="session:test",
        engagement_id="engagement:test",
        client_id="client:test",
        budget_remaining=2.0,
        max_depth=2,
    )
    loop = ActiveResearchLoop(
        coverage=CoverageIntelligence(
            expected_action_classes={"active_probe", "negative_control"}
        )
    )

    def handler(action):
        return {
            "observation_id": "observation:negative",
            "action_id": action.action_id,
            "action_fingerprint": action.fingerprint(),
            "status": "negative",
            "reason": "foreign identity was denied",
            "new_facts": ["foreign_denial_baseline"],
            "revisit_conditions": ["new identity", "new workflow state"],
        }

    result = loop.step(
        context,
        [candidate],
        handler=handler,
        available_capabilities={"http_read"},
        target_allowed=True,
    )
    assert result.observation.status == "negative"
    assert result.context.depth == 1
    assert result.context.budget_remaining == 1.0
    assert result.context.known_facts == ["foreign_denial_baseline"]
    assert result.coverage.coverage_score == 0.5
    assert result.coverage.uncovered_action_classes == ["negative_control"]
    assert "secret-value" not in str(result.as_dict())


def test_active_research_node_is_safe_by_default_and_persists_projection():
    candidate = _candidate()
    state = {
        "engagement_id": "engagement:test",
        "client_id": "client:test",
        "research_candidate_actions": [candidate.as_dict()],
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True}}
        },
        "action_budget": {"research_budget_remaining": 2.0},
    }
    blocked = active_research_node(state)
    assert blocked["research_active_observations"][0]["status"] == "blocked"
    assert (
        blocked["research_active_observations"][0]["reason"]
        == "target_scope_not_explicitly_allowed"
    )

    def handler(action):
        return {
            "observation_id": "observation:positive",
            "action_id": action.action_id,
            "action_fingerprint": action.fingerprint(),
            "status": "positive",
            "reason": "stable owner baseline",
            "new_facts": ["owner_context_acquired"],
            "causal_signal": False,
        }

    result = active_research_node(state, handler=handler, target_allowed=True)
    assert result["research_active_observations"][0]["status"] == "positive"
    assert result["research_context"]["depth"] == 1
    assert result["surface_coverage"]["surfaces"]
    assert result["research_failed_paths"] == []
