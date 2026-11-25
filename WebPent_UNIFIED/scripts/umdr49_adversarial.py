#!/usr/bin/env python3
"""UM-DR-49 W3.1 — adversarial robustness on the real-ground window.

An in-process hostile origin: rate limits (429 + Retry-After), tarpits
(delayed bodies), 500 bursts, and DECOY endpoints (error pages that
LOOK exploitable — a fake reflected-XSS page, a fake admin panel). The
engine must: keep FP=0 (no Tool-Confirmed on decoys), degrade to
coverage gaps (never crash), and respect the rate-limit signals.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
os.environ["LLM_ENABLED"] = "false"
os.environ["EMBEDDINGS_OFFLINE"] = "true"
os.environ["DISABLE_RAG"] = "true"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["ENABLE_JS_INTELLIGENCE"] = "true"

STATS = {"requests": 0, "429": 0, "500": 0, "decoy_hits": 0,
         "tarpit_served": 0}
LOCK = threading.Lock()

DECOY_XSS = """<html><body><h1>Search results</h1>
<div>Your query: <b>__Q__</b></div>
<script>document.title='results'</script>
</body></html>"""

DECOY_ADMIN = """<html><body><h1>ADMIN CONSOLE</h1>
<table><tr><td>user</td><td>role</td></tr></table>
<!-- debug: password=hunter2 -->
</body></html>"""


class HostileHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body=b"", headers=None):
        self.send_response(code)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        with LOCK:
            STATS["requests"] += 1
            n = STATS["requests"]
        path = self.path.lower()
        # rate limit after the first 15 requests (the crawl must SEE
        # the decoys first, then survive the throttling)
        if n > 15 and n % 3 == 0:
            with LOCK:
                STATS["429"] += 1
            self._send(429, b"rate limited",
                       {"Retry-After": "1"})
            return
        # 500 burst window (mid-crawl)
        if 30 <= n <= 36:
            with LOCK:
                STATS["500"] += 1
            self._send(500, b"internal error")
            return
        # tarpit: /tarpit holds the socket 3s
        if "/tarpit" in path:
            time.sleep(3.0)
            with LOCK:
                STATS["tarpit_served"] += 1
            self._send(200, b"<html><body>slow page</body></html>")
            return
        # decoy 1: fake reflected XSS
        if "/search" in path:
            with LOCK:
                STATS["decoy_hits"] += 1
            q = ""
            m = re.search(r"[?&]q=([^&]*)", self.path)
            if m:
                q = m.group(1)
            body = DECOY_XSS.replace("__Q__", q).encode()
            self._send(200, body)
            return
        # decoy 2: fake admin panel with a "password" comment
        if "/admin" in path:
            with LOCK:
                STATS["decoy_hits"] += 1
            self._send(200, DECOY_ADMIN.encode())
            return
        if path == "/" or path.startswith("/index"):
            self._send(200, b"<html><body><a href='/search?q=1'>s</a> "
                            b"<a href='/admin'>a</a> "
                            b"<a href='/tarpit'>t</a></body></html>")
            return
        self._send(404, b"not found")


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), HostileHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    from webpent.cli.unified_hunt import run_unified_hunt
    t0 = time.monotonic()
    s = run_unified_hunt(
        url=f"http://127.0.0.1:{port}/", mode="standard",
        authorization="umdr49-owner-approved-local-lab",
        engagement_id=f"umdr49-adversarial-{uuid.uuid4().hex[:6]}",
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True)
    elapsed = time.monotonic() - t0
    server.shutdown()

    findings = s.get("findings_detail") or []
    confirmed = [f for f in findings
                 if f.get("confidence_level") == "Tool-Confirmed"]
    decoy_confirmed = [f for f in confirmed
                       if "/search" in str(f.get("url"))
                       or "/admin" in str(f.get("url"))]
    record = {
        "schema": "umdr49-adversarial/1.0.0",
        "elapsed_s": round(elapsed, 2),
        "hostile_origin": {
            "requests_total": STATS["requests"],
            "rate_limited_429": STATS["429"],
            "error_500_burst": STATS["500"],
            "tarpit_served": STATS["tarpit_served"],
            "decoy_hits": STATS["decoy_hits"],
        },
        "findings_total": s.get("findings_total"),
        "findings_confirmed": len(confirmed),
        "confirmed_on_decoys": len(decoy_confirmed),
        "fp_on_decoys": len(decoy_confirmed),
        "verdict": {
            "fp_zero": len(decoy_confirmed) == 0,
            "no_crash": s is not None,
        },
    }
    out = REPO / "deliverables/umdr49/run_files/adversarial.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1))
    print(json.dumps(record, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
