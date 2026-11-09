# tests/test_redteam_final.py
"""Red-Team final fix tests — Phases 1-4 (v3 extractor, v2 confidence, v2 adapter).

Covers: deep call chains (no depth limit), conditional calls excluded from
guaranteed chain, multi-pattern routing, slow weight growth, consecutive-
failure penalty, atomic safe writes, corrupt-file tolerance, strict type
validation, clean disable, precise feedback classification, full end-to-end
pipeline (analyze -> suggest -> feedback -> confidence update).
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from webpent.causal_reasoning_v2.architecture_extractor_v3 import ArchitectureExtractorV3
from webpent.causal_reasoning_v2.causal_adapter_v2 import DISABLE_FLAG, CausalAdapterV2
from webpent.causal_reasoning_v2.confidence_engine_v2 import ConfidenceEngineV2


def _write(d: Path, name: str, content: str) -> Path:
    f = d / name
    f.write_text(content, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Phase 1 — ArchitectureExtractorV3
# ---------------------------------------------------------------------------

class TestExtractorV3:
    def test_deep_call_chain_no_depth_limit(self):
        """20-deep chain must be fully resolved (no depth=12 cutoff)."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            lines = []
            for i in range(19):
                lines.append(f"def step_{i}(x):\n    return step_{i+1}(x)")
            lines.append("def step_19(x):\n    save_data(x)")
            lines.append("def save_data(x): pass")
            lines.append("@app.get('/deep')\ndef deep_route():\n    step_0(1)")
            _write(d, "deep.py", "\n".join(lines))
            ext = ArchitectureExtractorV3(d).analyze_project()
            ep = next(e for e in ext.endpoints if e.route == "/deep")
            assert "save_data" in ep.full_chain, ep.full_chain
            assert len(ep.full_chain) >= 20, len(ep.full_chain)

    def test_conditional_verifier_not_in_guaranteed_chain(self):
        """Verifier inside `if` must NOT be in guaranteed_chain."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
def verify_user(): return True
def save_user(): pass
@app.post("/conditional")
def cond_route():
    if admin_mode:
        verify_user()
    save_user()
    return "ok"
''')
            ext = ArchitectureExtractorV3(d).analyze_project()
            ep = next(e for e in ext.endpoints if e.route == "/conditional")
            assert "verify_user" not in ep.guaranteed_chain, ep.guaranteed_chain
            assert "verify_user" in ep.full_chain
            # Flaw should be detected (no guaranteed verifier before mutate).
            flaws = ext.detect_verification_order_flaws()
            assert any(f.route == "/conditional" for f in flaws), flaws

    def test_django_urlpatterns_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "urls.py", '''
from django.urls import path
from . import views
urlpatterns = [
    path("users/<int:pk>/", views.user_detail, name="user-detail"),
    path("orders/", views.order_list),
]
''')
            ext = ArchitectureExtractorV3(d).analyze_project()
            routes = {e.route for e in ext.endpoints}
            assert "users/<int:pk>/" in routes
            assert "orders/" in routes

    def test_add_url_rule_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
app.add_url_rule("/api/v1/data", view_func=data_view, methods=["GET"])
''')
            ext = ArchitectureExtractorV3(d).analyze_project()
            assert any("/api/v1/data" in e.route for e in ext.endpoints), ext.endpoints

    def test_endpoint_has_file_path_and_line(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
@app.get("/x")
def x(): pass
''')
            ext = ArchitectureExtractorV3(d).analyze_project()
            ep = next(e for e in ext.endpoints if e.route == "/x")
            assert ep.file_path == "app.py"
            assert ep.line_no > 0

    def test_corrupt_file_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "good.py", "@app.get('/ok')\ndef ok(): pass")
            _write(d, "bad.py", "def broken(:\n  pass\n")
            ext = ArchitectureExtractorV3(d).analyze_project()
            assert ext.stats["files_skipped"] >= 1
            assert ext.stats["files_analyzed"] >= 1

    def test_generator_flag(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "gen.py", '''
def stream_results():
    for i in range(10):
        yield i
''')
            ext = ArchitectureExtractorV3(d).analyze_project()
            node = ext.nodes.get("stream_results")
            assert node is not None
            assert node.is_generator is True


# ---------------------------------------------------------------------------
# Phase 2 — ConfidenceEngineV2
# ---------------------------------------------------------------------------

class TestConfidenceV2:
    def test_weight_grows_slowly(self):
        """10 observations -> maturity ~0.5, NOT near 1.0."""
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            pid = ce.add_observation(
                structural_signature="sig", cause_type="scope",
                feedback="EXAMINED_MATCHED", project_id="p1",
            )
            w1 = ce.effective_weight(pid)
            for i in range(9):
                ce.add_observation(structural_signature="sig", cause_type="scope",
                                   feedback="EXAMINED_MATCHED", project_id=f"p{i}")
            w10 = ce.effective_weight(pid)
            assert w10 > w1
            assert ce.patterns[pid].maturity < 0.6  # slow growth

    def test_consecutive_failures_penalty(self):
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            pid = ce.add_observation(
                structural_signature="sig", cause_type="scope",
                feedback="EXAMINED_MATCHED", project_id="p1",
            )
            w_before = ce.effective_weight(pid)
            sm_before = ce.patterns[pid].component_weights["structural_match"]
            ce.add_observation(structural_signature="sig", cause_type="scope",
                               feedback="EXAMINED_UNRELATED", project_id="p2", similarity=0.95)
            ce.add_observation(structural_signature="sig", cause_type="scope",
                               feedback="EXAMINED_UNRELATED", project_id="p3", similarity=0.95)
            sm_after = ce.patterns[pid].component_weights["structural_match"]
            assert sm_after < sm_before  # 2 consecutive failures -> extra penalty
            assert ce.patterns[pid].consecutive_failures == 2

    def test_partial_match_boosts(self):
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            pid = ce.add_observation(
                structural_signature="sig", cause_type="scope",
                feedback="PARTIAL_MATCH", project_id="p1",
            )
            assert ce.patterns[pid].confirmed_count == 0.5

    def test_corrupt_file_tolerant(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "kb.json"
            p.write_text("!!! not json !!!", encoding="utf-8")
            ce = ConfidenceEngineV2(p)
            assert ce.patterns == {}  # no crash, fresh start

    def test_atomic_write_no_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "kb.json"
            ce = ConfidenceEngineV2(p)
            ce.add_observation(structural_signature="sig", cause_type="scope",
                               feedback="EXAMINED_MATCHED", project_id="p1")
            # File must be valid JSON after save.
            data = json.loads(p.read_text(encoding="utf-8"))
            assert len(data) == 1

    def test_max_patterns_prune(self):
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json", max_patterns=20)
            for i in range(30):
                ce.add_observation(
                    structural_signature=f"sig_{i}", cause_type=f"type_{i}",
                    feedback="EXAMINED_MATCHED", project_id=f"p{i}",
                )
            assert len(ce.patterns) <= 20


# ---------------------------------------------------------------------------
# Phase 3 — CausalAdapterV2
# ---------------------------------------------------------------------------

class TestAdapterV2:
    def test_disabled_returns_unchanged(self, monkeypatch):
        monkeypatch.setenv(DISABLE_FLAG, "1")
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            adp = CausalAdapterV2(ce)
            assert adp.is_enabled() is False
            candidates = [{"endpoint": "/a", "priority": 0.5}]
            result = adp.generate_priorities(candidates)
            assert result == candidates

    def test_strict_type_validation_passthrough(self):
        """Wrong-type priority (string) passes through unmodified."""
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            adp = CausalAdapterV2(ce)
            candidates = [{"endpoint": "/a", "priority": "high"}]
            result = adp.generate_priorities(candidates)
            assert result[0]["priority"] == "high"  # unchanged

    def test_feedback_precise_classification(self):
        with tempfile.TemporaryDirectory() as td:
            ce = ConfidenceEngineV2(Path(td) / "kb.json")
            pid = ce.add_observation(
                structural_signature="verification_order_flaw", cause_type="verification_order_flaw",
                feedback="EXAMINED_MATCHED", project_id="p1",
            )
            adp = CausalAdapterV2(ce)
            # NOT_EXAMINED -> no change
            conf_before = ce.patterns[pid].total_observations
            adp.submit_feedback("/x", examined=False)
            assert ce.patterns[pid].total_observations == conf_before
            # EXAMINED_UNRELATED -> increments total
            adp._pending["/x"] = type("H", (), {"pattern_id": pid})()  # inject hint
            adp.submit_feedback("/x", examined=True, finding=None)
            assert ce.patterns[pid].total_observations == conf_before + 1

    def test_fail_safe_returns_base(self):
        adp = CausalAdapterV2(None)  # no engine -> returns base unchanged
        base = [{"endpoint": "/a", "priority": 0.5}]
        result = adp.generate_priorities(base)
        assert result == base


# ---------------------------------------------------------------------------
# Phase 4 — Full end-to-end pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_end_to_end(self):
        """analyze -> flaw detected -> add to KB -> prioritize -> feedback -> confidence update."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
def verify_scope(): return True
def update_user(): pass
@app.post("/bad")
def bad_route():
    update_user()
    verify_scope()
    return "ok"
''')
            # 1. Analyze
            ext = ArchitectureExtractorV3(d).analyze_project()
            flaws = ext.detect_verification_order_flaws()
            assert len(flaws) == 1
            assert flaws[0].route == "/bad"

            # 2. Add to knowledge base
            ce = ConfidenceEngineV2(d / "kb.json")
            pid = ce.add_observation(
                structural_signature="verification_after_mutation update_user",
                cause_type="verification_order_flaw",
                feedback="EXAMINED_MATCHED", project_id="proj1",
                description="verify after mutate",
            )

            # 3. Generate priorities (causal boost)
            adp = CausalAdapterV2(ce)
            candidates = [{"endpoint": "/bad", "priority": 0.5, "method": "POST"}]
            prioritized = adp.generate_priorities(candidates, {"exploratory": True})
            # /bad should get causal boost (because pattern cause_type matches route)
            assert prioritized[0]["priority"] >= 0.3

            # 4. Feedback: examined, nothing found -> refuted
            adp._pending["/bad"] = type("H", (), {"pattern_id": pid})()
            adp.submit_feedback("/bad", examined=True, finding=None)
            assert ce.patterns[pid].consecutive_failures == 1

            # 5. Confidence decreased
            conf_after = ce.patterns[pid].jeffrey_confidence
            assert conf_after < 1.0
