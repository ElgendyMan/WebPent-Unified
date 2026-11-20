"""Monitoring dashboard — reads the shared nginx/fail2ban logs and serves
per-IP request counts, 403/429 totals, top attackers, WAF trigger rate and
ban events, as JSON at /api/stats and as a small HTML page at /.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

LOG_DIR = Path(sys.argv[1] if len(sys.argv) > 1 else "/logs")


def stats() -> dict:
    out: dict = {"requests_per_ip": {}, "blocked_403": 0, "throttled_429": 0,
                 "top_attackers": [], "waf_triggers": 0, "ban_events": []}
    access = LOG_DIR / "access.log"
    if access.is_file():
        ips: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        for line in access.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            ips[parts[0]] += 1
            statuses[parts[8]] += 1
        out["requests_per_ip"] = dict(ips)
        out["blocked_403"] = statuses.get("403", 0)
        out["throttled_429"] = statuses.get("429", 0)
        out["top_attackers"] = [ip for ip, _ in ips.most_common(5)]
        out["waf_triggers"] = statuses.get("403", 0)
    f2b = LOG_DIR / "fail2ban.log"
    if f2b.is_file():
        out["ban_events"] = [
            line for line in f2b.read_text(errors="replace").splitlines()
            if "Ban" in line
        ]
    return out


DASH_HTML = """<!doctype html><title>Emulator Monitoring</title>
<h1>Emulator Monitoring</h1>
<pre id="data">loading...</pre>
<script>
fetch('/api/stats').then(r => r.json()).then(s => {
  document.getElementById('data').textContent = JSON.stringify(s, null, 2);
});
</script>"""


class DashHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/stats":
            body = json.dumps(stats()).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/":
            body = DASH_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        else:
            self.send_error(404)
            return
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print(f"monitoring: {fmt % args}", flush=True)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 9090), DashHandler).serve_forever()
