"""V-2: The Real-Server SSRF Probe — the most security-critical test in the project."""
from __future__ import annotations
import os, socket, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")

def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0)); return s.getsockname()[1]

class CountingHandler(BaseHTTPRequestHandler):
    request_counts: dict = {"origin": 0, "redirect": 0, "destination": 0, "other": 0}
    def log_message(self, fmt, *args): pass
    def do_GET(self):
        if self.path == "/origin":
            CountingHandler.request_counts["origin"] += 1; self._respond(200, "origin-marker-body")
        elif self.path == "/redirect":
            CountingHandler.request_counts["redirect"] += 1
            dest_port = self.server.dest_port
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{dest_port}/destination"); self.end_headers()
        elif self.path == "/destination":
            CountingHandler.request_counts["destination"] += 1; self._respond(200, "destination-contacted")
        else:
            CountingHandler.request_counts["other"] += 1; self._respond(404, "not found")
    def _respond(self, status, body):
        data = body.encode()
        self.send_response(status); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

class DestinationHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_GET(self):
        CountingHandler.request_counts["destination"] += 1; self._respond(200, "DESTINATION CONTACTED — SSRF BYPASS!")
    def _respond(self, status, body):
        data = body.encode()
        self.send_response(status); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

@pytest.fixture()
def ssrf_probe_servers():
    CountingHandler.request_counts = {"origin": 0, "redirect": 0, "destination": 0, "other": 0}
    origin_port = _free_port(); dest_port = _free_port()
    origin_server = ThreadingHTTPServer(("127.0.0.1", origin_port), CountingHandler)
    origin_server.dest_port = dest_port
    dest_server = ThreadingHTTPServer(("127.0.0.1", dest_port), DestinationHandler)
    threading.Thread(target=origin_server.serve_forever, daemon=True).start()
    threading.Thread(target=dest_server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    yield origin_port, dest_port, origin_server, dest_server
    origin_server.shutdown(); dest_server.shutdown()

class TestV2RealServerSSRFProbe:
    def test_redirect_to_out_of_scope_destination_blocked(self, ssrf_probe_servers):
        origin_port, dest_port, _, _ = ssrf_probe_servers
        origin_url = f"http://127.0.0.1:{origin_port}"
        redirect_url = f"http://127.0.0.1:{origin_port}/redirect"
        CountingHandler.request_counts = {"origin": 0, "redirect": 0, "destination": 0, "other": 0}
        from webpent.shared.http import make_safe_httpx_client, SSRFRedirectBlockedError
        from webpent.shared.engagement_scope import set_engagement_target_hosts, clear_engagement_target_hosts
        target_token = set_engagement_target_hosts(origin_url)
        try:
            try:
                with make_safe_httpx_client(timeout=5.0, follow_redirects=False, guard_redirects=True) as client:
                    resp = client.get(redirect_url)
            except (SSRFRedirectBlockedError, Exception): pass
        finally:
            clear_engagement_target_hosts(target_token)
        assert CountingHandler.request_counts["redirect"] >= 1, "V-2 FAIL: origin not hit"
        assert CountingHandler.request_counts["destination"] == 0, f"V-2 FAIL: DESTINATION CONTACTED {CountingHandler.request_counts['destination']} times!"

    def test_origin_hit_exactly_once_for_redirect_request(self, ssrf_probe_servers):
        origin_port, dest_port, _, _ = ssrf_probe_servers
        origin_url = f"http://127.0.0.1:{origin_port}"
        redirect_url = f"http://127.0.0.1:{origin_port}/redirect"
        CountingHandler.request_counts = {"origin": 0, "redirect": 0, "destination": 0, "other": 0}
        from webpent.shared.http import make_safe_httpx_client, SSRFRedirectBlockedError
        from webpent.shared.engagement_scope import set_engagement_target_hosts, clear_engagement_target_hosts
        target_token = set_engagement_target_hosts(origin_url)
        try:
            try:
                with make_safe_httpx_client(timeout=5.0, follow_redirects=False, guard_redirects=True) as client:
                    resp = client.get(redirect_url)
            except SSRFRedirectBlockedError: pass
        finally:
            clear_engagement_target_hosts(target_token)
        assert CountingHandler.request_counts["redirect"] == 1, f"V-2(a) FAIL: origin /redirect hit {CountingHandler.request_counts['redirect']} times"
        assert CountingHandler.request_counts["destination"] == 0, f"V-2(b) FAIL: destination contacted"

    def test_guard_blocks_redirect_to_out_of_scope_hostname(self, ssrf_probe_servers):
        origin_port, dest_port, _, _ = ssrf_probe_servers
        origin_url = f"http://127.0.0.1:{origin_port}"
        redirect_url = f"http://127.0.0.1:{origin_port}/redirect"
        CountingHandler.request_counts = {"origin": 0, "redirect": 0, "destination": 0, "other": 0}
        from webpent.shared.http import make_safe_httpx_client, SSRFRedirectBlockedError
        from webpent.shared.engagement_scope import set_engagement_target_hosts, clear_engagement_target_hosts
        target_token = set_engagement_target_hosts(origin_url)
        try:
            try:
                with make_safe_httpx_client(timeout=5.0, follow_redirects=True, guard_redirects=True) as client:
                    resp = client.get(redirect_url)
            except (SSRFRedirectBlockedError, Exception): pass
        finally:
            clear_engagement_target_hosts(target_token)
        assert CountingHandler.request_counts["destination"] == 0, f"V-2(d) FAIL: destination contacted"
