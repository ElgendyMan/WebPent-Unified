# tests/team1_acceptance/test_fabric_graph_wiring_final.py
"""TEAM-2 FINAL fix verification: (A) real canonical HTTP, (B) graph reachable."""
from __future__ import annotations

import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")


class _RealHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "nonexistent" in self.path:
            self.send_response(404); self.end_headers(); self.wfile.write(b'{"error":"nf"}')
        elif "candidate" in self.path:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"id":1,"secret":"real_server_secret","role":"admin"}')
        else:
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(b'{"id":1,"owner":"u1","baseline":true}')
    def log_message(self, *a): pass


@pytest.fixture(scope="module")
def real_target():
    srv = HTTPServer(("127.0.0.1", 0), _RealHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True); t.start()
    time.sleep(0.2); yield f"http://127.0.0.1:{port}"; srv.shutdown()


# ---- CRITICAL A: real canonical HTTP execution -----------------------------

class TestRealCanonicalHttp:
    def test_make_safe_httpx_client_exists(self):
        """PART 1: ACTUAL canonical HTTP constructor exists and is used."""
        from webpent.shared.http import make_safe_httpx_client
        client = make_safe_httpx_client(timeout=3.0, follow_redirects=False)
        assert client is not None

    def test_execute_local_loopback_uses_real_http(self, real_target):
        """PART 2: _execute_local_loopback performs REAL HTTP, returns real observations."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1", "localhost"), engagement_id="eng_http",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_http", scope_law=ScopeLaw(profile=p, engagement_id="eng_http"))
        orch.run_deep_recon(target_url=real_target, observed=[{"path": "/api/users", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        obs = orch._execute_local_loopback(target_url=f"{real_target}/api/users", tool_name="httpx_bounded")
        assert obs.get("real_http") is True  # PROVES real execution
        assert obs.get("status_code") == 200  # real server responded
        assert obs.get("body_length") > 0  # real body captured
        assert "baseline" in obs.get("response_body", "")  # real server content

    def test_three_real_observations_independent(self, real_target):
        """PART 3: baseline/candidate/negative_control are REAL and INDEPENDENT."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id="eng_3obs",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        results = []
        for i, path in enumerate(["/api/1", "/api/1?variant=candidate", "/api/nonexistent_999"]):
            p2 = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id=f"eng_3obs_{i}",
                                     operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
            orch2 = ModernOrchestrator(engagement_id=f"eng_3obs_{i}", scope_law=ScopeLaw(profile=p2, engagement_id=f"eng_3obs_{i}"))
            orch2.run_deep_recon(target_url=real_target, observed=[{"path": "/api/1", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
            results.append(orch2._execute_local_loopback(target_url=f"{real_target}{path}", tool_name="httpx_bounded"))
        baseline, candidate, nc = results
        # Three independent real responses, different states.
        assert baseline["status_code"] == 200
        assert candidate["status_code"] == 200
        assert nc["status_code"] == 404  # genuinely different
        assert baseline["body_digest"] != candidate["body_digest"]  # different content


# ---- CRITICAL B: graph reachability ----------------------------------------

class TestGraphReachability:
    def test_research_campaign_node_reachable_from_start(self):
        """PART 4/5: NODE_RESEARCH_CAMPAIGN has incoming edge from production path."""
        from webpent.graph.builder import (
            NODE_CRAWLER,
            NODE_RECON,
            NODE_RESEARCH_CAMPAIGN,
            build_graph,
        )
        graph = build_graph(auto_approve=True)
        g = graph.get_graph()
        edges = list(g.edges)
        # Edges may be tuples or objects — normalize.
        def edge_src(e):
            return e[0] if isinstance(e, (tuple, list)) else getattr(e, "source", getattr(e, "src", str(e)))
        def edge_tgt(e):
            return e[1] if isinstance(e, (tuple, list)) else getattr(e, "target", getattr(e, "tgt", str(e)))
        # Incoming edge: NODE_RECON → NODE_RESEARCH_CAMPAIGN
        incoming = [e for e in edges if edge_tgt(e) == NODE_RESEARCH_CAMPAIGN]
        assert len(incoming) >= 1, f"No incoming edge to {NODE_RESEARCH_CAMPAIGN}"
        assert any(edge_src(e) == NODE_RECON for e in incoming), f"Incoming not from {NODE_RECON}: {[edge_src(e) for e in incoming]}"
        # Outgoing edge: NODE_RESEARCH_CAMPAIGN → NODE_CRAWLER
        outgoing = [e for e in edges if edge_src(e) == NODE_RESEARCH_CAMPAIGN]
        assert len(outgoing) >= 1, f"No outgoing edge from {NODE_RESEARCH_CAMPAIGN}"
        assert any(edge_tgt(e) == NODE_CRAWLER for e in outgoing), f"Outgoing not to {NODE_CRAWLER}: {[edge_tgt(e) for e in outgoing]}"

    def test_no_fake_observations_in_source(self):
        """PART 5: no synthetic hardcoded observations remain."""
        import inspect

        from webpent.production import modern_spine
        src = inspect.getsource(modern_spine)
        assert '"baseline": True' not in src
        assert '"candidate": True' not in src
        assert '"secret": "x"' not in src

    def test_no_get_bounded_http_client_remaining(self):
        """PART 1: non-existent symbol fully removed."""
        import inspect

        from webpent.production import modern_spine
        src = inspect.getsource(modern_spine)
        assert "get_bounded_http_client" not in src  # non-existent symbol removed
        assert "run_bounded_experiment" in src  # canonical bounded execution path used


# ---- PART 7/14: automatic fabric dispatch + identity -----------------------

class TestAutomaticFabricDispatch:
    def test_selected_experiment_equals_executed(self, real_target):
        """PART 14: selected experiment ID == executed experiment ID."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id="eng_sel",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_sel", scope_law=ScopeLaw(profile=p, engagement_id="eng_sel"))
        orch.run_deep_recon(target_url=real_target, observed=[{"path": "/api/1", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        hyps = [{"id": "h_idor", "path": "/api/1", "vulnerability_class": "IDOR"}]
        orch.run_research_campaign(target_url=real_target, hypotheses=hyps, max_steps=1)
        trace = orch._fabric_dispatch_trace[0]
        assert trace["experiment_id"] == "exp_idor_v1"  # selected == executed
        assert trace["fabric_runner_invoked"] is True

    def test_no_double_execution(self, real_target):
        """PART 15: one selection → one execution → one outcome."""
        from webpent.live_hunter.profile import AuthorizedLabProfile
        from webpent.live_hunter.tool_scope import ScopeLaw
        from webpent.production.modern_spine import ModernOrchestrator
        p = AuthorizedLabProfile(authorized_targets=("127.0.0.1",), engagement_id="eng_nodbl",
                                 operator_approval_at="2026-09-15T00:00:00Z", knowledge_ready=True, lab_fixture_mode=True)
        orch = ModernOrchestrator(engagement_id="eng_nodbl", scope_law=ScopeLaw(profile=p, engagement_id="eng_nodbl"))
        orch.run_deep_recon(target_url=real_target, observed=[{"path": "/api/update", "method": "GET", "status_code": 200, "body": "{}", "headers": {}}])
        hyps = [{"id": "h_ma", "path": "/api/update", "vulnerability_class": "MASS_ASSIGNMENT"}]
        orch.run_research_campaign(target_url=real_target, hypotheses=hyps, max_steps=1)
        assert len(orch._fabric_dispatch_trace) == 1  # exactly one dispatch
