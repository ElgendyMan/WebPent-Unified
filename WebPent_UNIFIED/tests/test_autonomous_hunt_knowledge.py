"""Integration tests for the closed perception loop (Fixes F1/F2).

These tests drive the *real* components, not scripted fakes:

* ``surface_map_to_knowledge`` converts the audited crawler's SurfaceMap
  into a validated ``TargetKnowledgeV2`` with traceable evidence refs,
* the orchestrator's hypothesis phase now satisfies the real
  ``HypothesisGenerator.generate(knowledge, graph)`` contract,
* ``bootstrap_knowledge`` crawls a live local HTTP server (in-process,
  127.0.0.1) and the wired hunt proceeds from zero supplied knowledge to
  executed, sealed actions through the production executor.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from webpent.autonomous.hunt_knowledge import (
    coerce_target_knowledge,
    hypothesis_inputs,
    surface_map_to_knowledge,
)


def _surface_map_dict() -> dict:
    return {
        "routes": [
            {
                "route": "/login",
                "method": "GET",
                "status_code": 200,
                "content_type": "text/html",
                "auth_required": False,
                "login_signal": True,
                "response_digest": "aa" * 32,
                "parameters": [{"name": "next", "location": "query"}],
            },
            {
                "route": "/api/user",
                "method": "GET",
                "status_code": 200,
                "content_type": "application/json",
                "api_signal": True,
                "response_digest": "bb" * 32,
                "parameters": [],
            },
        ]
    }


def test_surface_map_to_knowledge_is_validated_and_evidence_backed() -> None:
    knowledge = surface_map_to_knowledge(
        _surface_map_dict(), engagement_id="e1", target_id="http://127.0.0.1:9/"
    )
    assert knowledge is not None
    kinds = {e.kind.value for e in knowledge.entities.values()}
    assert "endpoint" in kinds
    assert "parameter" in kinds
    endpoint = next(
        e for e in knowledge.entities.values() if e.metadata.get("path") == "/login"
    )
    assert endpoint.metadata["method"] == "GET"
    assert endpoint.evidence_refs[0] == "aa" * 32
    assert endpoint.evidence_refs[0] != ""


def test_empty_surface_map_returns_none_not_invention() -> None:
    assert surface_map_to_knowledge({"routes": []}, engagement_id="e1", target_id="t") is None
    assert surface_map_to_knowledge(None, engagement_id="e1", target_id="t") is None
    assert coerce_target_knowledge("junk", engagement_id="e1", target_id="t") is None


def test_orchestrator_hypothesis_phase_uses_real_generator_contract() -> None:
    """The Phase-1 regression: generate(knowledge, graph), not generate(dict)."""
    from webpent.autonomous.hunt_orchestrator import AutonomousHuntOrchestrator
    from webpent.autonomous.hunt_state import AutonomousHuntState
    from webpent.knowledge.model_v2 import TargetKnowledgeV2
    from webpent.research.hypothesis_generator import HypothesisGenerator

    knowledge = surface_map_to_knowledge(
        _surface_map_dict(), engagement_id="e1", target_id="http://127.0.0.1:9/"
    )
    state = AutonomousHuntState(
        engagement_id="e1",
        target_url="http://127.0.0.1:9/",
        target_knowledge=knowledge.as_dict(),
    )
    # The real generator must accept what the orchestrator passes: this
    # line is the regression guard for the generate(dict) TypeError.
    orchestrator = AutonomousHuntOrchestrator(controller=object())
    orchestrator._phase_hypothesis(state)
    record = state.phase_trace[-1]
    assert record.status == "ok", record.reason
    assert record.reason != "hypothesis_generation_failed:TypeError"
    HypothesisGenerator().generate(
        TargetKnowledgeV2.model_validate(knowledge.as_dict()),
        hypothesis_inputs(knowledge.as_dict(), engagement_id="e1", target_url="x")[1],
    )


class _Target(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # silence
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/login"):
            body = b'<html><a href="/api/user">user</a><form><input name="next"></form></html>'
            ctype = "text/html"
        elif self.path.startswith("/api/user"):
            body = json.dumps({"id": 1, "name": "demo"}).encode()
            ctype = "application/json"
        else:
            body = b'<html><a href="/login">login</a></html>'
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def local_target():
    server = HTTPServer(("127.0.0.1", 0), _Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    server.server_close()


def test_bootstrap_and_wired_hunt_from_zero_knowledge(local_target) -> None:
    """Zero supplied knowledge -> live crawl -> hypotheses -> executed action."""
    from webpent.autonomous.hunt_runtime import bootstrap_knowledge, run_wired_hunt

    knowledge = bootstrap_knowledge(
        engagement_id="e-boot", target_url=local_target
    )
    assert knowledge is not None
    paths = {e.metadata.get("path") for e in knowledge.entities.values() if "path" in e.metadata}
    assert any("login" in str(p) for p in paths)

    state = run_wired_hunt(
        engagement_id="e-boot",
        campaign_id="c-boot",
        target_url=local_target,
        target_knowledge=knowledge.as_dict(),
        max_iterations=2,
        bootstrap=False,
    )
    executed = [o for o in state.outcomes if str(o.get("status")) == "executed"]
    assert executed, state.summary()
    assert state.summary()["counts"]["outcomes"] >= 1


def test_run_wired_hunt_self_bootstraps_when_no_knowledge(local_target) -> None:
    from webpent.autonomous.hunt_runtime import run_wired_hunt

    events: list[dict] = []
    state = run_wired_hunt(
        engagement_id="e-auto",
        campaign_id="c-auto",
        target_url=local_target,
        max_iterations=2,
        event_sink=events.append,
    )
    summary = state.summary()
    assert summary["counts"]["outcomes"] >= 1, summary
    assert events, "event sink received nothing"
    phases = {e["phase"] for e in events}
    assert "hypothesis" in phases
    assert "execute" in phases


def test_memory_persists_across_instances(tmp_path) -> None:
    from webpent.autonomous.hunt_memory import ScopedHuntMemory
    from webpent.smart.memory_engine import MemoryEntry

    path = tmp_path / "memory.json"
    first = ScopedHuntMemory(persist_path=str(path))
    first.store(
        engagement_id="e1",
        target_id="t1",
        entry=MemoryEntry(
            pattern_id="sqli",
            pattern_type="hunt_pattern",
            features={"vulnerability_class": "sqli"},
            outcome="vulnerable",
            confidence=0.7,
            source="autonomous_hunt",
        ),
    )
    first.save()
    second = ScopedHuntMemory(persist_path=str(path))
    hints = second.hint(engagement_id="e1", target_id="t1")
    assert hints.get("sqli", 0.0) > 0
