"""FINAL VERIFICATION — shared authorized local lab target.

Rich surface for runtime proofs:
  /admin/dashboard      auth-gated (200 with sid cookie, 401 anonymous)
  /user/profile/<id>    IDOR-shaped resource
  /search?q=&user=      parameterized surface (non-keyword hypothesis producer)
  /api/users/<id>       REST path-shape surface (deep recon producer)
  /items/<id>/edit      form + param producer (POST)
Headers record whether the request carried credentials (honesty differential).
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

LAB_STATE = {"requests": 0, "auth_hits": 0, "anon_401": 0, "post_hits": 0, "hosts": set()}


class LabHandler(BaseHTTPRequestHandler):
    def _emit(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _traffic(self, extra=""):
        LAB_STATE["requests"] += 1
        cookie = self.headers.get("Cookie") or ""
        has_sid = "sid=lab-session-operator" in cookie
        if has_sid:
            LAB_STATE["auth_hits"] += 1
        print(f"[traffic] {self.command} {self.path} auth_cookie={has_sid} {extra}")
        return has_sid

    def do_GET(self):
        if self.path.startswith("/admin/dashboard"):
            if self._traffic():
                self._emit(
                    200,
                    "<html><body><h1>Admin Dashboard</h1>"
                    "<a href='/admin/settings'>settings</a>"
                    "<form action='/admin/settings' method='post'>"
                    "<input name='email'><button>save</button></form></body></html>",
                )
            else:
                LAB_STATE["anon_401"] += 1
                self._emit(401, "<html><body>unauthorized</body></html>")
        elif self.path.startswith("/search"):
            self._traffic()
            self._emit(
                200,
                "<html><body><h1>Search results</h1>"
                "<div>query echo: results for your filters</div>"
                "<a href='/api/users/1001'>api users</a></body></html>",
            )
        elif self.path.startswith("/api/users/"):
            self._traffic()
            uid = self.path.rsplit("/", 1)[-1]
            self._emit(
                200,
                f'{{"id": {uid}, "email": "user{uid}@lab.test", "role": "member"}}',
                ctype="application/json",
            )
        elif self.path.startswith("/user/profile/"):
            self._traffic()
            uid = self.path.rsplit("/", 1)[-1]
            self._emit(200, f"<html><body>Profile {uid}: email user{uid}@lab.test</body></html>")
        elif self.path.startswith("/items/"):
            self._traffic()
            self._emit(
                200,
                "<html><body><h1>Item</h1><form action='/items/9/edit' method='post'>"
                "<input name='title'><input name='price'><button>update</button></form>"
                "</body></html>",
            )
        else:
            self._traffic()
            self._emit(
                200,
                "<html><body><h1>Lab Home</h1>"
                "<a href='/user/profile/1001'>profile 1001</a>"
                "<a href='/user/profile/1002'>profile 1002</a>"
                "<a href='/admin/dashboard'>admin</a>"
                "<a href='/search?q=shirt&user=7'>search</a>"
                "<a href='/api/users/1001'>api users</a>"
                "<a href='/items/9/edit'>item edit</a></body></html>",
            )

    def do_POST(self):
        LAB_STATE["post_hits"] += 1
        self._traffic()
        self._emit(200, "<html><body>saved</body></html>")

    def log_message(self, *args):
        pass


def start_lab() -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", 0), LabHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def reset_lab_state():
    for k in ("requests", "auth_hits", "anon_401", "post_hits"):
        LAB_STATE[k] = 0
    LAB_STATE["hosts"] = set()
