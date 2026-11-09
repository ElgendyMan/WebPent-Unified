"""Unit tests for the browser-hypothesis bridge (standalone, no heavy deps).

Run:  PYTHONPATH=src python3 -m unittest tests.team1_acceptance.test_browser_hypothesis_bridge
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from webpent.integration.browser_hypothesis_bridge import (  # noqa: E402
    BrowserSurface,
    browser_surface_to_hypotheses,
    hypotheses_from_auth_flow,
    hypotheses_from_forms,
    hypotheses_from_js_secrets,
    hypotheses_from_xhr_endpoints,
)
from webpent.models.findings import VulnClass  # noqa: E402
from webpent.models.hypothesis import HypothesisOrigin  # noqa: E402

TARGET = "http://synthetic-browser.test"


def _surface(**kw):
    base = {"target_url": TARGET, "routes": (), "forms": (), "xhr_endpoints": (), "state_transitions": (), "js_blobs": ()}
    base.update(kw)
    return BrowserSurface(**base)


class TestBrowserHypothesisBridge(unittest.TestCase):
    def test_form_with_user_id_param_generates_idor_hypothesis(self):
        surface = _surface(forms=({"action": "/profile", "method": "GET", "inputs": ({"name": "user_id"},)},))
        hyps = hypotheses_from_forms(surface)
        self.assertTrue(any(h.vuln_class == VulnClass.IDOR for h in hyps))
        self.assertTrue(all(h.origin == HypothesisOrigin.DEEP_RECON for h in hyps))
        self.assertTrue(all("browser_observed:" in (h.origin_detail or "") for h in hyps))

    def test_form_with_search_param_generates_xss_and_sqli(self):
        surface = _surface(forms=({"action": "/search", "method": "GET", "inputs": ({"name": "q"},)},))
        hyps = hypotheses_from_forms(surface)
        classes = {h.vuln_class for h in hyps}
        self.assertIn(VulnClass.XSS, classes)
        self.assertIn(VulnClass.SQLI, classes)

    def test_form_with_url_param_generates_ssrf_and_open_redirect(self):
        surface = _surface(forms=({"action": "/fetch", "method": "POST", "inputs": ({"name": "url"},)},))
        hyps = hypotheses_from_forms(surface)
        classes = {h.vuln_class for h in hyps}
        self.assertIn(VulnClass.SSRF, classes)
        self.assertIn(VulnClass.OPEN_REDIRECT, classes)

    def test_xhr_hidden_endpoint_generates_api_hypothesis(self):
        surface = _surface(xhr_endpoints=({"url": "/api/internal/proxy", "method": "POST", "params": ("target",)},))
        hyps = hypotheses_from_xhr_endpoints(surface)
        self.assertGreaterEqual(len(hyps), 1)
        self.assertTrue(any("xhr_endpoint" in (h.origin_detail or "") for h in hyps))

    def test_xhr_with_id_param_generates_idor(self):
        surface = _surface(xhr_endpoints=({"url": "/api/orders", "method": "GET", "params": ("order_id",)},))
        hyps = hypotheses_from_xhr_endpoints(surface)
        self.assertTrue(any(h.vuln_class == VulnClass.IDOR for h in hyps))

    def test_auth_flow_transition_attaches_principal_and_idor(self):
        surface = _surface(state_transitions=({"from_route": "/login", "to_route": "/dashboard", "requires_auth": True, "principal_alias": "alice"},))
        hyps = hypotheses_from_auth_flow(surface)
        self.assertEqual(len(hyps), 1)
        self.assertEqual(hyps[0].vuln_class, VulnClass.IDOR)
        self.assertIn("alice", hyps[0].statement)

    def test_js_api_key_disclosure_generates_info_disclosure(self):
        surface = _surface(js_blobs=("const config = { api_key: 'sk_live_abcdef0123456789' };",))
        hyps = hypotheses_from_js_secrets(surface)
        self.assertGreaterEqual(len(hyps), 1)
        self.assertTrue(any(h.vuln_class == VulnClass.INFO_DISCLOSURE for h in hyps))
        # secret must be redacted, not raw
        self.assertNotIn("sk_live_abcdef0123456789", hyps[0].statement)

    def test_js_aws_and_password_secrets_detected(self):
        blob = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE; password='hunter2secretpass';"
        surface = _surface(js_blobs=(blob,))
        hyps = hypotheses_from_js_secrets(surface)
        kinds = {h.origin_detail for h in hyps}
        self.assertTrue(any("aws_credential" in k for k in kinds))
        self.assertTrue(any("hardcoded_password" in k for k in kinds))

    def test_path_injection_param_name_rejected_fail_closed(self):
        surface = _surface(forms=({"action": "/x", "method": "GET", "inputs": ({"name": "user/../../etc/passwd"},)},))
        hyps = hypotheses_from_forms(surface)
        self.assertEqual(len(hyps), 0)

    def test_hypothesis_count_is_capped(self):
        many_inputs = tuple({"name": f"user_id_{i}"} for i in range(50))
        surface = _surface(forms=({"action": "/x", "method": "GET", "inputs": many_inputs},))
        hyps = browser_surface_to_hypotheses(surface)
        self.assertLessEqual(len(hyps), 32)

    def test_full_surface_combines_all_four_sources(self):
        surface = BrowserSurface(
            target_url=TARGET,
            routes=("/", "/dashboard"),
            forms=({"action": "/profile", "method": "GET", "inputs": ({"name": "user_id"},)},),
            xhr_endpoints=({"url": "/api/fetch", "method": "POST", "params": ("url",)},),
            state_transitions=({"from_route": "/login", "to_route": "/dashboard", "requires_auth": True, "principal_alias": "bob"},),
            js_blobs=("api_key='abcdef0123456789xyz';",),
        )
        hyps = browser_surface_to_hypotheses(surface)
        classes = {h.vuln_class for h in hyps}
        self.assertIn(VulnClass.IDOR, classes)
        self.assertIn(VulnClass.SSRF, classes)
        self.assertIn(VulnClass.INFO_DISCLOSURE, classes)
        self.assertGreaterEqual(len(hyps), 3)

    def test_dict_input_normalised(self):
        hyps = browser_surface_to_hypotheses({"target_url": TARGET, "forms": [{"action": "/s", "inputs": [{"name": "query"}]}]})
        self.assertGreaterEqual(len(hyps), 1)
        self.assertTrue(any(h.vuln_class in (VulnClass.XSS, VulnClass.SQLI) for h in hyps))


if __name__ == "__main__":
    unittest.main(verbosity=2)
