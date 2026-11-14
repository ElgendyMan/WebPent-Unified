from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from webpent.live_hunter.profile import build_authorized_lab_profile
from webpent.live_hunter.tool_scope import ScopeLaw
from webpent.recon.autonomous_crawler import AutonomousCrawler, CrawlConfig
from webpent.recon.hypothesis_generator import HypothesisGenerator


class _ServiceSurfaceHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            body = b"<html><body>service surface</body></html>"
            status = 200
            content_type = "text/html"
        elif path.startswith(("/workshop/", "/community/")):
            body = json.dumps({"service": path.split("/", 2)[1], "id": 1}).encode()
            status = 200
            content_type = "application/json"
        else:
            body = b"not found"
            status = 404
            content_type = "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        return


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ServiceSurfaceHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _scope():
    return ScopeLaw(
            # DR-007 (TC-2): lab_fixture_mode is REQUIRED for loopback
            # authorization since the GAP-4 fail-closed design; these are
            # genuine lab-fixture tests hitting ephemeral 127.0.0.1 servers.
        profile=build_authorized_lab_profile(
            engagement_id="crapi-surface-test",
            operator_approval_at="2026-10-01T00:00:00Z",
            authorized_targets=("127.0.0.1",),
            lab_fixture_mode=True,
        ),
        engagement_id="crapi-surface-test",
    )


def test_operator_route_seeds_discover_workshop_and_community_services():
    server = _server()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        result = AutonomousCrawler(
            target_url=target,
            scope_law=_scope(),
            engagement_id="crapi-surface-test",
            config=CrawlConfig(
                max_pages=4,
                max_depth=2,
                per_host_min_interval_seconds=0,
                route_seeds=("/workshop/api/shop/orders/all", "/community/api/v2/community/posts/recent"),
            ),
        ).crawl()
        projection = result.as_dict()
        routes = {item["route"] for item in projection["routes"]}
        assert "/workshop/api/shop/orders/all" in routes
        assert "/community/api/v2/community/posts/recent" in routes
        queued = [event for event in projection["events"] if event["event"] == "configured_route_seed_queued"]
        assert len(queued) == 2
    finally:
        server.shutdown()


def test_generic_bola_preserves_observed_order_id_and_derives_negative_control():
    server = _server()
    try:
        target = f"http://127.0.0.1:{server.server_port}/"
        surface = AutonomousCrawler(
            target_url=target,
            scope_law=_scope(),
            engagement_id="crapi-resource-id-test",
            config=CrawlConfig(
                max_pages=4,
                max_depth=2,
                per_host_min_interval_seconds=0,
                route_seeds=("/workshop/api/shop/orders/1",),
            ),
        ).crawl().surface_map
        candidates = HypothesisGenerator(
            max_hypotheses=50,
            principal_count=2,
            principal_ids={"owner": "11", "foreign": "12"},
        ).generate(surface)
        bola = next(item for item in candidates if item["vulnerability_class"] == "BOLA" and "/orders/1" in item["route"])
        requests = bola["requests"]
        assert requests["baseline"]["path"] == "/workshop/api/shop/orders/1"
        assert requests["candidate"]["path"] == "/workshop/api/shop/orders/1"
        assert requests["negative_control"]["path"] == "/workshop/api/shop/orders/2"
        assert bola["metadata"]["owner_value"] == "1"
    finally:
        server.shutdown()
