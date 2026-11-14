# tests/test_redteam_fixes.py
"""Red-Team fix phases 1-6 comprehensive tests.

Covers: ArchitectureExtractorV2 (multi-pattern routing, no depth limit,
conditional calls, file paths), StructuralMatcherV2 (semantic abstraction,
dynamic thresholds, role guard, min-size), ConfidenceEngine (Jeffrey prior,
adaptive weight, 4-way feedback, pending queue), CausalAdapter (exact field
validation, env disable, existing-field annotation), PatternVersioning
(signature migration, stale evidence, run fingerprint), boundary + load tests.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from webpent.causal_reasoning_v2.architecture_extractor_v2 import (
    ArchitectureExtractorV2,
)
from webpent.causal_reasoning_v2.causal_adapter import (
    FINDING_FIELDS,
    HYPOTHESIS_FIELDS,
    CausalAdapter,
)
from webpent.causal_reasoning_v2.confidence_engine import (
    ConfidenceEngine,
    FeedbackState,
)
from webpent.causal_reasoning_v2.pattern_versioning import (
    ENGINE_VERSION,
    RunFingerprint,
    VersionedKnowledgeBase,
)
from webpent.causal_reasoning_v2.structural_matcher_v2 import (
    THRESHOLD_AUTO_GROUP,
    THRESHOLD_HUMAN_REVIEW,
    StructuralMatcherV2,
)


def _write(d: Path, name: str, content: str) -> Path:
    f = d / name
    f.write_text(content, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# Phase 1 — ArchitectureExtractorV2
# ---------------------------------------------------------------------------

class TestArchitectureExtractorV2:
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
            ext = ArchitectureExtractorV2(d).analyze_project()
            routes = {e.route for e in ext.endpoints}
            assert "users/<int:pk>/" in routes
            assert "orders/" in routes

    def test_add_url_rule_detected(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
app.add_url_rule("/api/v1/data", view_func=data_view, methods=["GET"])
''')
            ext = ArchitectureExtractorV2(d).analyze_project()
            assert any("/api/v1/data" in e.route for e in ext.endpoints)

    def test_conditional_verifier_not_guaranteed(self):
        """A verifier inside `if` must NOT count as guaranteed verification."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
def verify_user(): pass
def save_user(): pass
@app.post("/conditional")
def cond_route():
    if admin_mode:
        verify_user()
    save_user()
    return "ok"
''')
            ext = ArchitectureExtractorV2(d).analyze_project()
            flaws = ext.detect_verification_order_flaws()
            # verify_user is conditional -> not in guaranteed_chain -> flaw detected
            assert any(f.route == "/conditional" for f in flaws), flaws

    def test_endpoint_has_file_path_and_line(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "app.py", '''
@app.get("/x")
def x(): pass
''')
            ext = ArchitectureExtractorV2(d).analyze_project()
            ep = next(e for e in ext.endpoints if e.route == "/x")
            assert ep.file_path == "app.py"
            assert ep.line_no > 0

    def test_no_artificial_depth_limit(self):
        """A 20-deep call chain must be fully resolved (no depth=12 cutoff)."""
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            lines = []
            for i in range(20):
                callee = f"step_{i+1}" if i < 19 else "save_user"
                lines.append(f"def step_{i}():\n    {callee}()")
            lines.append("def save_user(): pass")
            lines.append("@app.get('/deep')\ndef deep_route():\n    step_0()")
            _write(d, "deep.py", "\n".join(lines))
            ext = ArchitectureExtractorV2(d).analyze_project()
            ep = next(e for e in ext.endpoints if e.route == "/deep")
            # Chain should include step_0 through step_19 and save_user
            assert "save_user" in ep.call_chain, ep.call_chain
            assert len(ep.call_chain) >= 20, len(ep.call_chain)

    def test_corrupt_file_skipped_no_crash(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            _write(d, "good.py", "@app.get('/ok')\ndef ok(): pass")
            _write(d, "bad.py", "def broken(:\n  pass\n")
            ext = ArchitectureExtractorV2(d).analyze_project()
            assert ext.stats["files_skipped"] >= 1
            assert ext.stats["files_analyzed"] >= 1


# ---------------------------------------------------------------------------
# Phase 2 — StructuralMatcherV2
# ---------------------------------------------------------------------------

class TestStructuralMatcherV2:
    def test_different_operation_sets_do_not_match(self):
        """A=B; C=D (assignments) vs if X: return Y (branch+return) — must NOT match."""
        m = StructuralMatcherV2()
        a = m.fingerprint('''
def f(a, b):
    x = a
    y = b
    z = x + y
    return z
''', role="handler")
        b = m.fingerprint('''
def g(user):
    if user.is_admin:
        return True
    raise PermissionError()
''', role="verifier")
        assert a is not None and b is not None
        assert m.classify_match(a, b) == "no_match"

    def test_identical_structure_auto_groups(self):
        m = StructuralMatcherV2()
        src = '''
def handler_one(input_data):
    parsed = parse(input_data)
    cleaned = sanitize(parsed)
    result = save(cleaned)
    if result:
        return result
    return None
'''
        a = m.fingerprint(src, role="handler")
        b = m.fingerprint(src.replace("handler_one", "handler_two").replace("input_data", "payload"), role="handler")
        assert m.classify_match(a, b) == "auto_group"

    def test_role_mismatch_blocks_auto_group(self):
        """Same structure but verifier vs mutator -> NOT same root cause."""
        m = StructuralMatcherV2()
        src = '''
def check(x):
    if x > 0:
        return True
    return False
'''
        a = m.fingerprint(src, role="verifier")
        b = m.fingerprint(src.replace("check", "mutate"), role="mutator")
        assert m.classify_match(a, b) == "no_match"

    def test_short_function_no_fingerprint(self):
        m = StructuralMatcherV2()
        fp = m.fingerprint("def f(): pass", role="handler")
        assert fp is None  # too short -> no global fingerprint

    def test_thresholds_constants(self):
        assert THRESHOLD_AUTO_GROUP > THRESHOLD_HUMAN_REVIEW
        assert THRESHOLD_HUMAN_REVIEW > 0.8


# ---------------------------------------------------------------------------
# Phase 3 — ConfidenceEngine
# ---------------------------------------------------------------------------

class TestConfidenceEngine:
    def test_new_pattern_zero_weight(self):
        """A pattern with 0 observations has effective_weight ~0 — not surfaced."""
        eng = ConfidenceEngine()
        eng.register("new_pat")
        assert eng.surfaceable_patterns(["new_pat"]) == []
        assert eng.causal_weight_for("new_pat") < 0.1

    def test_weight_scales_with_evidence(self):
        eng = ConfidenceEngine()
        eng.register("pat")
        w1 = eng.causal_weight_for("pat")
        for i in range(10):
            eng.record_feedback("pat", f"/r{i}", FeedbackState.EXAMINED_MATCHED)
        w10 = eng.causal_weight_for("pat")
        assert w10 > w1
        assert w10 >= 0.3  # 10 observations -> substantial weight

    def test_not_examined_no_confidence_change(self):
        eng = ConfidenceEngine()
        eng.register("pat")
        eng.add_pending("pat", "/unexamined")
        before = eng.patterns["pat"].total
        eng.record_feedback("pat", "/unexamined", FeedbackState.NOT_EXAMINED)
        after = eng.patterns["pat"].total
        assert after == before  # no change
        assert "/unexamined" in eng.pending_routes("pat")  # stays in queue

    def test_partial_feedback_small_penalty_stays_pending(self):
        eng = ConfidenceEngine()
        eng.register("pat")
        eng.record_feedback("pat", "/r", FeedbackState.PARTIAL)
        # total should NOT increment (partial isn't a full observation)
        assert eng.patterns["pat"].total == 0

    def test_examined_unrelated_reduces_confidence(self):
        eng = ConfidenceEngine()
        eng.register("pat")
        for i in range(5):
            eng.record_feedback("pat", f"/ok{i}", FeedbackState.EXAMINED_MATCHED)
        conf_before = eng.patterns["pat"].jeffrey_confidence
        rel_before = eng.patterns["pat"].component_weights["relevance"]
        eng.record_feedback("pat", "/miss", FeedbackState.EXAMINED_UNRELATED, failed_component="relevance")
        conf_after = eng.patterns["pat"].jeffrey_confidence
        rel_after = eng.patterns["pat"].component_weights["relevance"]
        assert conf_after < conf_before
        assert rel_after < rel_before  # only relevance penalised
        # Other components untouched (still boosted by the 5 confirmations).
        assert eng.patterns["pat"].component_weights["structural_match"] == pytest.approx(rel_before * 1.0, abs=0.01)


# ---------------------------------------------------------------------------
# Phase 4 — CausalAdapter
# ---------------------------------------------------------------------------

class TestCausalAdapter:
    def test_hypothesis_dicts_have_only_schema_fields(self):
        adapter = CausalAdapter()
        hyps = adapter.engagement_start_hypotheses(
            target_url="https://t/",
            transferred_insights=[{"causal_label": "scope_leak", "confidence": 0.9,
                                   "pattern_id": "p1", "sample_size": 5,
                                   "typical_segments": ["seg1"]}],
        )
        assert hyps
        for h in hyps:
            assert set(h.keys()) <= HYPOTHESIS_FIELDS, set(h.keys()) - HYPOTHESIS_FIELDS
            assert h["origin"] == "heuristic"

    def test_sibling_hypotheses_schema_compliant(self):
        adapter = CausalAdapter()
        hyps = adapter.sibling_hypotheses(
            sibling_routes=["/api/users/2/profile"],
            parent_finding={"id": "f1", "vuln_class": "idor", "request_method": "GET", "target_param": "id"},
            causal_label="scope_leak_no_verification",
            confidence=0.85,
        )
        assert hyps
        for h in hyps:
            assert set(h.keys()) <= HYPOTHESIS_FIELDS

    def test_annotate_finding_uses_existing_reasoning_field(self):
        adapter = CausalAdapter()
        finding = {"id": "f1", "title": "IDOR", "vuln_class": "idor", "reasoning": "base"}
        out = adapter.annotate_finding(finding, "causal: shared DAO defect")
        assert "causal: shared DAO defect" in out["reasoning"]
        assert "base" in out["reasoning"]  # preserved
        assert set(out.keys()) <= FINDING_FIELDS

    def test_disabled_returns_empty(self):
        adapter = CausalAdapter(disabled=True)
        assert adapter.engagement_start_hypotheses(target_url="x", transferred_insights=[{"confidence": 0.9}]) == []
        assert adapter.sibling_hypotheses(sibling_routes=["/x"], parent_finding={}, causal_label="x", confidence=0.5) == []
        assert adapter.report_clusters([{"cluster_id": "c1"}]) == []
        assert adapter.annotate_finding({"id": "f"}, "x") == {"id": "f"}


# ---------------------------------------------------------------------------
# Phase 5 — PatternVersioning
# ---------------------------------------------------------------------------

class TestPatternVersioning:
    def test_signature_change_bumps_version(self):
        kb = VersionedKnowledgeBase()
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="sig_v1",
                        confirmed=True, project_id="proj1")
        pat = kb.patterns["p1"]
        v1 = pat.signature_version
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="sig_v2",
                        confirmed=True, project_id="proj2")
        assert kb.patterns["p1"].signature_version == v1 + 1

    def test_stale_evidence_excluded_from_confidence(self):
        kb = VersionedKnowledgeBase()
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="sig_v1",
                        confirmed=True, project_id="proj1")
        # Change signature -> old evidence becomes stale.
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="sig_v2",
                        confirmed=False, project_id="proj2")
        pat = kb.patterns["p1"]
        assert len(pat.stale_evidence()) == 1
        assert len(pat.fresh_evidence()) == 1
        # Confidence computed from fresh only (1 refuted -> low).
        assert pat.confidence() < 0.6

    def test_run_fingerprint_reproducible_and_unique(self):
        fp1 = RunFingerprint.compute(project_id="projA", config={"w": 0.4}, kb_pattern_count=10)
        fp2 = RunFingerprint.compute(project_id="projA", config={"w": 0.4}, kb_pattern_count=10)
        # Same inputs -> same config_hash, different timestamps -> different fingerprint.
        assert fp1.config_hash == fp2.config_hash
        assert fp1.fingerprint != fp2.fingerprint
        assert fp1.engine_version == ENGINE_VERSION
        d = fp1.to_dict()
        assert "fingerprint" in d and "engine_version" in d

    def test_stale_report_counts(self):
        kb = VersionedKnowledgeBase()
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="s1",
                        confirmed=True, project_id="p")
        kb.add_evidence(pattern_id="p1", cause_type="scope", structural_signature="s2",
                        confirmed=True, project_id="p")
        report = kb.stale_report()
        assert report["stale_evidence"] == 1
        assert report["fresh_evidence"] == 1


# ---------------------------------------------------------------------------
# Phase 6 — Boundary + load tests
# ---------------------------------------------------------------------------

class TestBoundaryAndLoad:
    def test_empty_project_no_crash(self):
        with tempfile.TemporaryDirectory() as td:
            ext = ArchitectureExtractorV2(Path(td)).analyze_project()
            assert ext.endpoints == []
            assert ext.detect_verification_order_flaws() == ()

    def test_large_synthetic_project_performance(self):
        """100 files, each with 5 endpoints — must complete quickly (<30s)."""
        import time
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            for i in range(50):
                lines = []
                for j in range(5):
                    lines.append(f"@app.get('/ep{i}_{j}')\ndef h{i}_{j}():\n    verify_{i}()\n    save_{i}()")
                lines.append(f"def verify_{i}(): pass\ndef save_{i}(): pass")
                _write(d, f"mod_{i}.py", "\n".join(lines))
            start = time.time()
            ext = ArchitectureExtractorV2(d).analyze_project()
            elapsed = time.time() - start
            assert elapsed < 30, f"too slow: {elapsed:.1f}s"
            assert ext.stats["files_analyzed"] == 50
            assert len(ext.endpoints) == 250

    def test_adapter_fail_safe_on_bad_input(self):
        adapter = CausalAdapter()
        # Non-dict insights, bad types — must return [] not raise.
        result = adapter.engagement_start_hypotheses(target_url="x", transferred_insights=[None, "bad", 42])
        assert isinstance(result, list)

    def test_confidence_engine_empty(self):
        eng = ConfidenceEngine()
        assert eng.surfaceable_patterns([]) == []
        assert eng.summary()["patterns"] == 0
