from __future__ import annotations

import json

from webpent.models.research import NovelBehaviorObservation
from webpent.shared import knowledge_retrieval
from webpent.shared.attack_graph import build_attack_graph
from webpent.shared.knowledge_retrieval import DecisionRetrievalRequest, retrieve_decision_context
from webpent.shared.novel_behavior import NovelBehaviorDetector


def test_novel_behavior_is_bounded_and_needs_controls_for_causal_signal():
    detector = NovelBehaviorDetector()
    observation = detector.detect(
        {"status_code": 200, "body_hash": "before", "authorization": "secret"},
        {"status_code": 302, "body_hash": "after", "authorization": "other-secret"},
        baseline_ref="b-1",
        current_ref="c-1",
        control_complete=True,
        negative_control_complete=False,
        evidence_refs=["obs-1"],
    )
    assert observation is not None
    assert observation.behavior_kind == "status_change"
    assert observation.causal_signal is False
    assert "authorization" not in observation.changed_dimensions
    assert "secret" not in json.dumps(observation.model_dump())


def test_novel_behavior_requires_negative_control_for_authorization_differential():
    detector = NovelBehaviorDetector()
    observation = detector.detect(
        {"status_code": 403, "body_length": 12},
        {"status_code": 200, "body_length": 80},
        control_complete=True,
        negative_control_complete=True,
    )
    assert observation is not None
    assert observation.behavior_kind == "authorization_differential"
    assert observation.causal_signal is True


def test_attack_graph_adds_only_existing_typed_causal_edges_and_no_findings():
    graph = build_attack_graph(
        {"nodes": {}, "edges": []},
        novel_behaviors=[
            NovelBehaviorObservation(
                observation_id="obs-novel-1",
                behavior_kind="authorization_differential",
                changed_dimensions=["status_code"],
                causal_signal=True,
                negative_control_complete=True,
            ).model_dump(mode="json")
        ],
        causal_edges=[
            {
                "kind": "causal_signal",
                "source_id": "missing-source",
                "target_id": "missing-target",
                "causal_signal": True,
                "negative_control_complete": True,
            },
            {
                "kind": "not-allowed",
                "source_id": "missing-source",
                "target_id": "missing-target",
            },
        ],
    )
    assert any(node["label"] == "novel_behavior" for node in graph["nodes"].values())
    assert not any(node["kind"] == "finding" for node in graph["nodes"].values())
    assert not any(edge["kind"] == "causal_signal" for edge in graph["edges"])


def test_decision_retrieval_is_context_specific_and_bounded(monkeypatch):
    calls = []

    def fake_retrieve(query, **kwargs):
        calls.append((query, kwargs))
        return "[RAG type=writeup rank=1]\naccess differential guidance"

    monkeypatch.setattr(knowledge_retrieval, "retrieve_knowledge_context", fake_retrieve)
    request = DecisionRetrievalRequest(
        gap_kind="authorization_ownership",
        gap_id="gap-1",
        action_class="access_control_probe",
        objective="compare owner and non-owner behavior",
        target_ref="https://lab.local/item?id=secret-value",
        identity_context="authenticated",
    )
    result = retrieve_decision_context(request, max_chars=3000)
    assert result.startswith("[RAG")
    assert calls
    query, kwargs = calls[0]
    assert "secret-value" not in query
    assert kwargs["doc_types"] == ("methodology", "writeup", "scenario", "report")
    assert kwargs["max_chars"] == 3000
