"""Synthetic in-scope local target for the P7 reproduction (Dispatch #009-A WP-J).

A small static site with a JSON status endpoint — enough surface for the
governed crawler to map routes, and deliberately unexploitable: the run
must complete WITHOUT any governed AVI decision, which is the exact
shape the lab observed (exit 0, production_trace.complete=false).
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PORT = 8977

INDEX = b"""<!doctype html><html><head><title>Repro Target</title></head>
<body><h1>Local synthetic target</h1>
<a href="/about.html">about</a> <a href="/status">status</a>
</body></html>"""

ABOUT = b"""<!doctype html><html><head><title>About</title></head>
<body><h1>About</h1><p>Static page.</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: object) -> None:  # quiet
        pass

    def _send(self, body: bytes, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self._send(INDEX)
        elif path == "/about.html":
            self._send(ABOUT)
        elif path == "/status":
            self._send(json.dumps({"ok": True, "version": "repro-1.0"}).encode(), "application/json")
        elif path == "/api/items":
            self._send(json.dumps({"items": [{"id": 1, "name": "alpha"}]}).encode(), "application/json")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"target on 127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
