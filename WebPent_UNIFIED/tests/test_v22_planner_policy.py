from types import SimpleNamespace

from webpent.config.settings import Settings
from webpent.models.planner import PlannerDecisionStatus
from webpent.shared.planner_decisions import (
    build_planner_decision,
    redact_prompt_target,
)


def _state():
    return {
        "mental_model": {
            "nodes": {
                "node-1": {"kind": "endpoint"},
            }
        },
        "hypotheses": [{"id": "h-1"}],
        "available_tool_categories": ["validation", "recon", "analysis"],
    }


def test_valid_structured_proposal_passes_all_gates():
    raw = SimpleNamespace(
        content=(
            '{"action_type":"validate_hypothesis",'
            '"target_ref":"node:node-1",'
            '"hypothesis_ref":"h-1",'
            '"required_identity":null,'
            '"expected_evidence":["reproducible_request","response_delta"],'
            '"estimated_cost":3,'
            '"risk_level":"medium",'
            '"rationale":"Validate the existing hypothesis with evidence."}'
        )
    )
    proposal, audit = build_planner_decision(_state(), raw_llm_response=raw)
    assert proposal.source == "llm"
    assert audit.status == PlannerDecisionStatus.ACCEPTED.value
    assert audit.gates_failed == []
    assert "scope:target_reference" in audit.gates_passed


def test_malformed_llm_output_is_rejected_and_uses_deterministic_fallback():
    raw = SimpleNamespace(
        content=(
            '{"action_type":"observe_target",'
            '"target_ref":"engagement_target",'
            '"expected_evidence":["scope_decision"],'
            '"estimated_cost":0.5,"risk_level":"low",'
            '"rationale":"safe", "unexpected":"must be rejected"}'
        )
    )
    proposal, audit = build_planner_decision(_state(), raw_llm_response=raw)
    assert proposal.source == "deterministic"
    assert audit.fallback_used is True
    assert audit.llm_contribution == "malformed_or_unsafe_output_rejected"
    assert audit.status in {
        PlannerDecisionStatus.FALLBACK.value,
        PlannerDecisionStatus.ACCEPTED.value,
    }


def test_arbitrary_url_and_destructive_proposal_cannot_pass():
    raw = SimpleNamespace(
        content=(
            '{"action_type":"run_read_only_tool",'
            '"target_ref":"https://evil.example/execute",'
            '"expected_evidence":["proof"],"estimated_cost":1,'
            '"risk_level":"destructive","rationale":"bad"}'
        )
    )
    proposal, audit = build_planner_decision(_state(), raw_llm_response=raw)
    assert proposal.source == "deterministic"
    assert "policy:destructive_action" not in audit.gates_failed
    assert "scope:target_reference" in audit.gates_passed


def test_offline_no_llm_returns_bounded_heuristic_decision():
    proposal, audit = build_planner_decision(
        _state(), settings=Settings(enable_planner_decisions=True)
    )
    assert proposal.source == "deterministic"
    assert audit.fallback_used is True
    assert audit.status == PlannerDecisionStatus.FALLBACK.value
    assert proposal.estimated_cost <= 10


def test_prompt_target_redacts_credentials_and_sensitive_query_values():
    safe = redact_prompt_target(
        "https://user:password@example.test/items?token=abc&view=full#frag"
    )
    assert "password" not in safe
    assert "abc" not in safe
    assert "token=%5BREDACTED%5D" in safe
    assert "view=full" in safe
    assert "#frag" not in safe


def _planner_state():
    return {
        "target": SimpleNamespace(
            url="https://user:secret@example.test/items?token=abc&view=full",
            domain="example.test",
            is_portswigger_lab=False,
        ),
        "mental_model": {"nodes": {}},
        "hypotheses": [],
    }


def test_planner_node_keeps_legacy_shape_when_flag_disabled(monkeypatch):
    import webpent.agents.planner.agent as planner_agent
    from webpent.config.settings import get_settings

    monkeypatch.delenv("ENABLE_PLANNER_DECISIONS", raising=False)
    get_settings.cache_clear()
    monkeypatch.setattr(planner_agent, "_retrieve_methodologies", lambda: "")
    monkeypatch.setattr(
        planner_agent,
        "get_llm",
        lambda _task: SimpleNamespace(invoke=lambda _messages: SimpleNamespace(content="1. plan")),
    )
    result = planner_agent.planner_node(_planner_state())
    assert "messages" in result
    assert "planner_decision" not in result
    assert "planner_gate_audits" not in result
    get_settings.cache_clear()


def test_planner_provider_timeout_uses_heuristic_decision(monkeypatch):
    import webpent.agents.planner.agent as planner_agent
    from webpent.config.settings import get_settings

    monkeypatch.setenv("ENABLE_PLANNER_DECISIONS", "true")
    get_settings.cache_clear()
    monkeypatch.setattr(planner_agent, "_retrieve_methodologies", lambda: "")

    class TimeoutLLM:
        def invoke(self, _messages):
            raise TimeoutError("provider timeout")

    monkeypatch.setattr(planner_agent, "get_llm", lambda _task: TimeoutLLM())
    result = planner_agent.planner_node(_planner_state())
    assert result["planner_decision"]["source"] == "deterministic"
    assert result["planner_gate_audits"][0]["fallback_used"] is True
    assert result["planner_gate_audits"][0]["llm_contribution"] in {
        "malformed_or_unsafe_output_rejected",
        "llm_unavailable_or_disabled",
    }
    get_settings.cache_clear()


def test_proof_driven_replanning_requests_missing_oracle_evidence() -> None:
    state = _state()
    state["proof_oracle_results"] = [
        {
            "campaign_key": "download_idor",
            "status": "inconclusive",
            "missing": ["foreign_denied_control"],
            "target_ref": "engagement_target",
            "hypothesis_ref": "h-1",
        }
    ]
    proposal, audit = build_planner_decision(
        state, settings=Settings(enable_planner_decisions=True)
    )
    assert proposal.source == "proof-driven"
    assert proposal.expected_evidence == ["foreign_denied_control", "negative_control"]
    assert "negative_control" in proposal.rationale
    assert audit.status == PlannerDecisionStatus.FALLBACK.value
