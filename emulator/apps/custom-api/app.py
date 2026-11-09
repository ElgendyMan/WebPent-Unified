"""Custom API — a tiny local training target for the emulator.

Deliberately simple on purpose: it exists so the emulator has a
scenario endpoint we fully control (IDOR demo, reflected search,
health probe). It is local training infrastructure only.
"""

from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer

USERS = {
    "1": {"id": "1", "name": "alice", "role": "admin"},
    "2": {"id": "2", "name": "bob", "role": "user"},
    "3": {"id": "3", "name": "carol", "role": "user"},
}


class ApiHandler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] == "/":
            self._send(200, {"status": "custom-api running"})
        elif self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/api/users":
            self._send(200, {"users": list(USERS.values())})
        elif match := re.fullmatch(r"/api/users/([^/]+)", self.path):
            # IDOR demo: no authorization check, only existence.
            user = USERS.get(match.group(1))
            self._send(200 if user else 404, user or {"error": "not found"})
        elif match := re.fullmatch(r"/api/search\?q=(.*)", self.path):
            # Reflected demo: the query is echoed back.
            self._send(200, {"query": match.group(1), "results": []})
        else:
            self._send(404, {"error": "not found"})

    def log_message(self, fmt: str, *args) -> None:
        print(f"custom-api: {fmt % args}", flush=True)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), ApiHandler).serve_forever()
