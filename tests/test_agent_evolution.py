from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from webpent.agents.curiosity_engine import detect_anomalies
from webpent.agents.hunter_contracts import (
    BudgetState,
    ExploitationResult,
    HunterState,
    HunterStatus,
    ValidationVerdict,
    Verdict,
)
from webpent.agents.hunter_graph import _planner_prompt, run_hunter_graph
from webpent.agents.hunter_runner import _decision_verdict
from webpent.agents.note_taker import NoteTaker
from webpent.agents.personas import get_persona, select_personas


def test_curiosity_flags_required_structural_anomalies() -> None:
    surface = {
        "routes": [{
            "route": "/rest/items?id=1&debug=true",
            "status_code": 403,
            "content_type": "application/json",
            "response_length": 50,
            "auth_required": True,
            "parameters": [
                {"name": "debug", "location": "query", "value_shape": "query-shaped"},
                {"name": "id", "location": "query", "value_shape": "id-shaped"},
            ],
        }],
        "events": [],
    }
    kinds = {item.anomaly_type for item in detect_anomalies(surface)}
    assert {"suspicious_parameter", "sequential_identifier", "forbidden_with_data"} <= kinds


def test_personas_are_distinct_and_selectable() -> None:
    assert get_persona("stok").preferred_families != get_persona("logic").preferred_families
    assert [item.name for item in select_personas("all")] == ["nahamsec", "stok", "logic"]


def test_persona_profile_reaches_planner_prompt() -> None:
    state = HunterState(
        persona="nahamsec",
        surface_data={"persona_profile": get_persona("nahamsec").to_dict()},
    )
    prompt = _planner_prompt(state)
    rendered = "\n".join(str(item.get("content")) for item in prompt)
    assert "exposed_configuration" in rendered
    assert "INFO_DISCLOSURE" in rendered
    assert "persona_profile" in rendered


def test_notes_are_idempotent_searchable_and_redacted(tmp_path: Path) -> None:
    notes = NoteTaker(campaign_id="c1", target="http://127.0.0.1:3000", path=tmp_path / "notes.md")
    notes.append(role="planner", section="Authentication", text="token: TOPSECRET should never be stored", event_id="event-1")
    notes.append(role="planner", section="Authentication", text="token: TOPSECRET should never be stored", event_id="event-1")
    assert len(notes.entries) == 1
    rendered = notes.render_markdown()
    assert "TOPSECRET" not in rendered
    assert "REDACTED_SECRET" in rendered
    assert notes.search("authentication redacted")


class _FakeLLM:
    def __call__(self, messages):
        system = str(messages[0]["content"])
        if "Planner" in system:
            return SimpleNamespace(content='{"hypotheses":[{"hypothesis":"ID changes resource","target_endpoint":"/api/items/1","attack_type":"IDOR","priority":90,"reasoning":"sequential identifier","expected_behavior":"foreign data"}]}')
        if "Exploiter" in system:
            return SimpleNamespace(content='{"execute":true,"request_intent":"owner foreign control","control_plan":"invalid id"}')
        return SimpleNamespace(content='{"concern":"verify replay","requested_checks":["replay"]}')


def test_graph_runs_three_roles_and_honors_refutation() -> None:
    def exploit(hypothesis, state):
        return ExploitationResult(
            hypothesis_id=hypothesis.hypothesis_id,
            status=HunterStatus.VALIDATING,
            request_executed=True,
            response_received=True,
            evidence={"status_code": 200, "response_digest": "sha256:structural"},
            authority_trace=("ScopeLaw", "ToolBoundary", "M4", "AVI"),
        )

    def validate(hypothesis, result, state):
        return ValidationVerdict(
            hypothesis_id=hypothesis.hypothesis_id,
            verdict=Verdict.REFUTED,
            confidence=0.99,
            evidence_chain=("sha256:control",),
            reason="negative control matched",
        )

    state = run_hunter_graph(
        hunter=HunterState(surface_data={"candidate_catalog": []}, budget=BudgetState(max_hypotheses=2)),
        llm=_FakeLLM(),
        exploiter=exploit,
        validator=validate,
    )
    assert state.status is HunterStatus.COMPLETED
    assert state.validation_verdicts[0].verdict is Verdict.REFUTED
    nodes = {event["node"] for event in state.graph_events}
    assert {"planner", "exploiter_advisory", "validator_advisory", "validator"} <= nodes


def test_decision_classification_requires_real_promotion() -> None:
    verdict, reason, confidence, proof, replay = _decision_verdict({"promotion": {"decision": "PROMOTED", "bundle_id": "pb-1"}, "replay_verified": True})
    assert verdict is Verdict.CONFIRMED
    assert proof == "pb-1"
    assert replay is True
    verdict, *_ = _decision_verdict({"promotion": {"decision": "REJECTED"}, "validator_outcome": "REFUTED"})
    assert verdict is Verdict.REFUTED
