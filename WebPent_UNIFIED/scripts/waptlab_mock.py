"""Local, intentionally vulnerable-shaped HTTP fixture for WAPTLab coverage tests.

This fixture is not WAPTLab and is never used as proof of a live WAPTLab result.
It exposes deterministic, non-destructive response markers so WebPent discovery
and evidence plumbing can be exercised when Docker networking is unavailable.
Bind to loopback by default only.
"""

from __future__ import annotations

import argparse
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DEFAULT_STATE = Path("/tmp/webpent-waptlab-mock-state.json")


class MockHandler(BaseHTTPRequestHandler):
    server_version = "WAPTLabMock/1.0 Elasticsearch/1.4.4"
    state: dict[str, object] = {"oob": [], "profile": {}}
    state_path = DEFAULT_STATE
    lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_state(self) -> None:
        self.state_path.write_text(json.dumps(self.state, sort_keys=True), encoding="utf-8")

    def _send(self, status: int, body: str, content_type: str = "text/html") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _json(self, status: int, value: object) -> None:
        self._send(status, json.dumps(value), "application/json")

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(min(length, 2_000_000))

    def _params(self) -> dict[str, str]:
        parsed = urlparse(self.path)
        return {key: values[-1] for key, values in parse_qs(parsed.query).items() if values}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path
        params = self._params()
        if path in {"/", "/dashboard"}:
            host = self.headers.get("Host", "127.0.0.1")
            base_url = f"http://{host}"
            links = [
                "/crm/download/1",
                "/crm/view?path=../waptlab-secret.txt",
                "/v1/crm/download/1",
                "/profile/edit",
                "/user_profile/1",
                f"/swagger_ui?url={base_url}/internal",
                "/oauth/authorize?redirect_uri=//evil.example/return",
                "/debug?trigger=1",
                "/composer.lock.bak",
                "/_oob/mock-token",
            ]
            body = (
                "<html><body><h1>WAPTLab Mock</h1>"
                + "".join(
                    f'<a href="{html.escape(link)}">{html.escape(link)}</a><br>' for link in links
                )
                + '<form method="post" action="/profile"><input name="name"><input name="email">'
            )
            body += '<textarea name="description"></textarea></form>'
            body += '<script src="/js/markdown-editor-0.3.0.js"></script></body></html>'
            self._send(200, body)
            return
        if path == "/sqli/header":
            forwarded = self.headers.get("X-Forwarded-For", "")
            if any(token in forwarded.lower() for token in ("' or ", "union", "sleep(")):
                self._send(200, "MOCK_SQLI_HEADER_MARKER", "text/plain")
            else:
                self._send(200, "ok", "text/plain")
            return
        if path == "/swagger_ui":
            remote = params.get("url") or params.get("configUrl")
            if remote:
                self._json(
                    200,
                    {
                        "status": "fetched",
                        "remote": remote,
                        "preview": "mock-internal-response",
                    },
                )
            else:
                self._send(200, '<script src="/js/swagger-ui.js"></script>')
            return
        if path in {"/crm/download/1", "/v1/crm/download/1"}:
            self._send(200, "id,name\n1,tenant-a-record\n", "text/csv")
            return
        if path == "/crm/view":
            requested = params.get("path", "")
            if ".." in requested or requested.startswith("/etc"):
                self._send(
                    200,
                    f"root:x:0:0:root:/root:/bin/bash\npath={html.escape(requested)}\n",
                    "text/plain",
                )
            else:
                self._send(404, "not found", "text/plain")
            return
        if path == "/dashboard/view-crm/1":
            self._send(200, "<html><body>tenant-a-record</body></html>")
            return
        if path == "/user_profile/1":
            profile = self.state.get("profile", {})
            description = str(profile.get("description", "<p>stored-profile</p>"))
            self._send(
                200,
                f"<html><body><div class=description>{description}</div></body></html>",
            )
            return
        if path == "/profile/edit":
            self._send(
                200,
                '<form method="post" action="/profile"><input name="name"><input '
                'name="email"><textarea name="description"></textarea></form>',
            )
            return
        if path == "/oauth/authorize":
            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri.startswith("//") or redirect_uri.startswith("https://"):
                self.send_response(302)
                self.send_header("Location", redirect_uri)
                self.end_headers()
            else:
                self._send(
                    200,
                    f'<form action="/oauth/authorize" method="post"><input '
                    f'name="redirect_uri" value="{html.escape(redirect_uri)}"></form>',
                )
            return
        if path == "/debug":
            if params.get("trigger"):
                self._send(
                    500,
                    "Whoops! APP_DEBUG=true Traceback: /var/www/html/.env APP_KEY=mock-secret",
                )
            else:
                self._send(200, "ok")
            return
        if path in {"/composer.lock.bak", "/storage/logs/laravel.log", "/.env", "/backup.sql"}:
            self._send(200, "MOCK_BACKUP_DISCLOSURE APP_KEY=redacted\n", "text/plain")
            return
        if path == "/_oob/mock-token":
            self._json(200, {"oob": self.state.get("oob", [])})
            return
        if path == "/health":
            self._json(200, {"status": "ok", "service": "mock"})
            return
        if path == "/internal":
            self._send(200, "MOCK_INTERNAL_SERVICE")
            return
        if path.startswith("/js/"):
            self._send(
                200,
                "/*! markdown-editor 0.3.0 vulnerable fixture */",
                "application/javascript",
            )
            return
        if path == "/es/fetch/elasticsearch:9200/_search":
            self._json(200, {"hits": {"hits": [{"_source": {"tenant": "tenant-a"}}]}})
            return
        self._send(404, "not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        raw = self._body()
        text = raw.decode("utf-8", errors="replace")
        params = parse_qs(text, keep_blank_values=True)
        if path == "/profile/fetch-image":
            image_url = params.get("image_url", [""])[-1]
            self._json(
                200,
                {
                    "status": "fetched",
                    "final_url": image_url,
                    "flag": "MOCK_SSRF_MARKER",
                },
            )
            return
        if path == "/profile":
            with self.lock:
                self.state["profile"] = {
                    key: values[-1] for key, values in params.items() if values
                }
                self._write_state()
            self._json(200, {"status": "saved"})
            return
        if path in {"/training/send-results-email", "/crm/export", "/export-erp"}:
            template_text = "\n".join(value for values in params.values() for value in values)
            if "{{17*23}}" in template_text:
                rendered = "391"
            elif "{{" in template_text or "{!!" in template_text:
                rendered = "MOCK_SSTI_MARKER"
            else:
                rendered = "rendered"
            self._json(
                200,
                {"status": "sent", "rendered": rendered, "body": template_text[:2000]},
            )
            return
        if path in {"/csv", "/crm/save-csv"}:
            marker = (
                "MOCK_SQLI_CSV_MARKER"
                if any(token in text.lower() for token in ("union", "sleep(", "' or "))
                else "queued"
            )
            self._json(200, {"status": "processed", "result": marker})
            return
        if path == "/elasticsearch":
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                payload = {"url": text}
            url = str(payload.get("url", ""))
            self._json(
                400 if ".." in url else 200,
                {"flag": "MOCK_ES_TRAVERSAL_MARKER" if ".." in url else "ok"},
            )
            return
        if path in {"/xml/upload", "/csv/upload"}:
            if "<!ENTITY" in text or "document(" in text or "xsl:copy-of" in text:
                self._json(200, {"status": "processed", "marker": "MOCK_XML_SINK_MARKER"})
            else:
                self._json(200, {"status": "processed"})
            return
        if path == "/oauth/authorize":
            redirect_uri = params.get("redirect_uri", [""])[-1]
            self.send_response(302)
            self.send_header("Location", redirect_uri)
            self.end_headers()
            return
        self._json(404, {"error": "not found"})


def serve(host: str, port: int, state_path: Path) -> None:
    MockHandler.state_path = state_path
    state_path.write_text(json.dumps(MockHandler.state), encoding="utf-8")
    server = ThreadingHTTPServer((host, port), MockHandler)
    print(f"WAPTLab mock listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Loopback-only WAPTLab coverage mock")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args()
    if args.host not in {"127.0.0.1", "localhost", "::1"}:
        parser.error("mock must bind to loopback")
    serve(args.host, args.port, args.state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
