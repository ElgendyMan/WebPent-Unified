# tests/test_causal_v2_deep.py
"""Deep-fix Phases 1-4 comprehensive tests.

Covers: architecture_extractor (static analysis), root_cause_analyzer_v2
(structural logic matching), structural_knowledge_base (bayesian confidence
+ per-component refinement), closed_loop_integration (priority merge +
feedback loop).  All tests deterministic, offline, no external deps.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from webpent.causal_reasoning_v2.architecture_extractor import ArchitectureExtractor
from webpent.causal_reasoning_v2.closed_loop_integration import ClosedLoopIntegrator
from webpent.causal_reasoning_v2.root_cause_analyzer_v2 import (
    RootCauseAnalyzerV2,
    StructuralLogicMatcher,
)
from webpent.causal_reasoning_v2.structural_knowledge_base import StructuralKnowledgeBase


# ---------------------------------------------------------------------------
# Phase 1 — ArchitectureExtractor (static analysis from source)
# ---------------------------------------------------------------------------

class TestArchitectureExtractor:
    def _write(self, d: Path, name: str, content: str) -> Path:
        f = d / name
        f.write_text(content, encoding="utf-8")
        return f

    def test_detects_verification_after_mutation(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._write(d, "app.py", '''
from flask import Flask
app = Flask(__name__)

def verify_user():
    return True

def update_data():
    pass

@app.post("/bad")
def bad_route():
    update_data()
    verify_user()
    return "ok"

@app.get("/good")
def good_route():
    verify_user()
    update_data()
    return "ok"
''')
            ext = ArchitectureExtractor(d).analyze_project()
            assert ext.stats["files_analyzed"] == 1
            flaws = ext.detect_verification_order_flaws()
            bad_routes = {f.route for f in flaws}
            assert "/bad" in bad_routes
            assert "/good" not in bad_routes

    def test_detects_no_verification_before_mutate(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._write(d, "app.py", '''
@app.post("/nocheck")
def nocheck_route():
    save_user()
    return "ok"
''')
            ext = ArchitectureExtractor(d).analyze_project()
            flaws = ext.detect_verification_order_flaws()
            types = {f.flaw_type for f in flaws}
            assert "no_verification_before_mutate" in types

    def test_shared_dependencies_between_routes(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._write(d, "app.py", '''
def shared_dao():
    pass

@app.get("/a")
def route_a():
    shared_dao()

@app.get("/b")
def route_b():
    shared_dao()
''')
            ext = ArchitectureExtractor(d).analyze_project()
            shared = ext.shared_dependencies("/a", "/b")
            assert any("dao" in s.lower() for s in shared), shared

    def test_skips_corrupt_file_without_crashing(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._write(d, "good.py", '''
@app.get("/x")
def x(): pass
''')
            self._write(d, "bad.py", "def broken(:\n  pass\n")
            ext = ArchitectureExtractor(d).analyze_project()
            assert ext.stats["files_skipped"] >= 1
            assert ext.stats["files_analyzed"] >= 1

    def test_endpoints_bound_to_handlers(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            self._write(d, "app.py", '''
@app.get("/users/{id}")
def get_user():
    pass
''')
            ext = ArchitectureExtractor(d).analyze_project()
            routes = {e.route for e in ext.endpoints}
            assert "/users/{id}" in routes


# ---------------------------------------------------------------------------
# Phase 2 — StructuralLogicMatcher (match code structure, not names)
# ---------------------------------------------------------------------------

class TestStructuralLogicMatcher:
    def test_identical_structure_different_names_score_1(self):
        matcher = StructuralLogicMatcher()
        a = matcher.fingerprint('''
def handler_a(user_input):
    data = get_input(user_input)
    clean = sanitize(data)
    save(clean)
    return clean
''')
        b = matcher.fingerprint('''
def handler_xyz(request_payload):
    val = receive(request_payload)
    washed = clean(val)
    store(washed)
    return washed
''')
        assert a is not None and b is not None
        assert matcher.similarity(a, b) == pytest.approx(1.0, abs=0.01)

    def test_different_structure_low_score(self):
        matcher = StructuralLogicMatcher()
        a = matcher.fingerprint('''
def f(x):
    if x > 0:
        return x
    return -x
''')
        b = matcher.fingerprint('''
def g(y):
    total = 0
    for i in range(y):
        total += i
    return total
''')
        assert a is not None and b is not None
        assert matcher.similarity(a, b) < 0.7

    def test_root_cause_groups_duplicated_logic(self):
        with tempfile.TemporaryDirectory() as td:
            ext = ArchitectureExtractor(td)
            ana = RootCauseAnalyzerV2(ext)
            src1 = '''
def h1(x):
    d = read(x)
    w = clean(d)
    save(w)
'''
            src2 = '''
def h2(y):
    val = fetch(y)
    washed = sanitize(val)
    store(washed)
'''
            ana.register_handler_source("h1", src1, route="/a")
            ana.register_handler_source("h2", src2, route="/b")
            dups = ana.duplicated_logic_routes()
            assert dups, "identical structure should be detected as duplication"
            # Both routes should appear in the same duplication group.
            routes_in_group = set()
            for routes in dups.values():
                routes_in_group.update(routes)
            assert "/a" in routes_in_group and "/b" in routes_in_group

    def test_analyze_groups_findings_by_shared_dependency(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            (d / "app.py").write_text('''
def shared_verify(): pass
@app.get("/a")
def ra(): shared_verify()
@app.get("/b")
def rb(): shared_verify()
''')
            ext = ArchitectureExtractor(d).analyze_project()
            ana = RootCauseAnalyzerV2(ext)
            findings = [
                {"id": "f1", "route": "/a", "vuln_class": "idor"},
                {"id": "f2", "route": "/b", "vuln_class": "idor"},
            ]
            groups = ana.analyze(findings)
            assert groups
            # Both findings should be in the same group (shared dependency).
            member_ids = set()
            for g in groups:
                member_ids.update(g.member_finding_ids)
            assert {"f1", "f2"} <= member_ids


# ---------------------------------------------------------------------------
# Phase 3 — StructuralKnowledgeBase (bayesian + per-component refinement)
# ---------------------------------------------------------------------------

class TestStructuralKnowledgeBase:
    def test_confidence_rises_with_confirmation(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            pid = kb.add_observation(
                structural_signature="sig_A", cause_type="scope_leak",
                confirmed=True, project_id="p1", description="test",
            )
            c1 = kb.patterns[pid].bayes_confidence
            kb.add_observation(structural_signature="sig_A", cause_type="scope_leak",
                               confirmed=True, project_id="p2")
            c2 = kb.patterns[pid].bayes_confidence
            assert c2 > c1

    def test_refutation_drops_only_failed_component(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            pid = kb.add_observation(
                structural_signature="sig_B", cause_type="sanitization_bypass",
                confirmed=True, project_id="p1", description="t",
            )
            before = dict(kb.patterns[pid].component_weights)
            # Refute, blaming only 'relevance' component.
            kb.add_observation(
                structural_signature="sig_B", cause_type="sanitization_bypass",
                confirmed=False, project_id="p2", failed_component="relevance",
            )
            after = kb.patterns[pid].component_weights
            assert after["relevance"] < before["relevance"]
            # Other components untouched (or only trivially changed on confirm).
            assert after["structural_match"] == before["structural_match"]
            assert after["historical_success"] == before["historical_success"]

    def test_dynamic_threshold_critical_target_stricter(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            # Build a pattern with moderate confidence (~0.67 after 1 confirm).
            pid = kb.add_observation(
                structural_signature="sig_C", cause_type="scope_leak",
                confirmed=True, project_id="p1", route_globs=["/api/*"],
            )
            # Exploratory target (threshold 0.6) should surface it.
            expl = kb.query_for_target(target_profile={"exploratory": True}, top_k=10)
            assert any(p["pattern_id"] == pid for p in expl)
            # Critical target (threshold 0.9) should NOT surface it.
            crit = kb.query_for_target(target_profile={"critical": True}, top_k=10)
            assert not any(p["pattern_id"] == pid for p in crit)

    def test_persistence_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "kb.json"
            kb1 = StructuralKnowledgeBase(path)
            pid = kb1.add_observation(
                structural_signature="sig_D", cause_type="scope_leak",
                confirmed=True, project_id="p1", description="persist test",
            )
            kb2 = StructuralKnowledgeBase(path)
            assert pid in kb2.patterns
            assert kb2.patterns[pid].description == "persist test"

    def test_empty_kb_returns_no_insights(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            assert kb.query_for_target() == []


# ---------------------------------------------------------------------------
# Phase 4 — ClosedLoopIntegrator (priority merge + feedback)
# ---------------------------------------------------------------------------

class TestClosedLoopIntegrator:
    def test_causal_recommendations_added_to_priority_list(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            kb.add_observation(
                structural_signature="sig_E", cause_type="scope_leak",
                confirmed=True, project_id="p1", route_globs=["/api/admin/*"],
                description="t",
            )
            # Add more confirmations to push confidence above default 0.75.
            for i in range(5):
                kb.add_observation(structural_signature="sig_E", cause_type="scope_leak",
                                   confirmed=True, project_id=f"p{i}")
            cli = ClosedLoopIntegrator(knowledge_base=kb)
            cli.set_context("new_proj", {"exploratory": True})
            base = [{"endpoint": "/home", "priority": 0.5}]
            prios = cli.generate_priorities(base)
            # A causal-only candidate /api/admin/* should be added.
            assert any("/api/admin" in p.get("endpoint", "") for p in prios), prios
            # Every entry has causal_contribution field.
            assert all("causal_contribution" in p for p in prios)

    def test_feedback_updates_knowledge_base(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            pid = kb.add_observation(
                structural_signature="sig_F", cause_type="scope_leak",
                confirmed=True, project_id="p1", route_globs=["/api/x/*"],
            )
            for i in range(5):
                kb.add_observation(structural_signature="sig_F", cause_type="scope_leak",
                                   confirmed=True, project_id=f"p{i}")
            cli = ClosedLoopIntegrator(knowledge_base=kb)
            cli.set_context("proj2", {"exploratory": True})
            base: list = []
            prios = cli.generate_priorities(base)
            route = next(p["endpoint"] for p in prios)
            before = kb.patterns[pid].bayes_confidence
            cli.submit_feedback(route, examined=True, finding=None)  # refuted
            after = kb.patterns[pid].bayes_confidence
            assert after < before  # refutation reduced confidence

    def test_disabled_returns_base_unchanged(self):
        cli = ClosedLoopIntegrator(disabled=True)
        base = [{"endpoint": "/a", "priority": 0.8}, {"endpoint": "/b", "priority": 0.2}]
        out = cli.generate_priorities(base)
        assert [p["endpoint"] for p in out] == ["/a", "/b"]
        assert all("causal_contribution" not in p for p in out)

    def test_fail_safe_on_error(self):
        # Pass a knowledge_base that will raise; integrator must return base.
        cli = ClosedLoopIntegrator(knowledge_base=None)  # type: ignore
        cli.kb = None  # force failure path
        base = [{"endpoint": "/a", "priority": 0.5}]
        out = cli.generate_priorities(base)
        assert len(out) == 1 and out[0]["endpoint"] == "/a"

    def test_final_report_summary(self):
        with tempfile.TemporaryDirectory() as td:
            kb = StructuralKnowledgeBase(Path(td) / "kb.json")
            cli = ClosedLoopIntegrator(knowledge_base=kb)
            cli.set_context("p")
            report = cli.final_report()
            assert report["project_id"] == "p"
            assert "confirmation_rate" in report
            assert "knowledge_base_summary" in report
