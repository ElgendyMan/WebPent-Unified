"""M1-A (M-1) regression: webpent-cli.sh must not auto-approve the HITL
sandbox gate without a human.

Contract (M1_READINESS_REVIEW §2.1):
  (a) no TTY and no --yes  -> the approve endpoint is NEVER called;
  (b) --yes + WEBPENT_API_TOKEN -> approve called exactly once, WITH the
      Bearer header;
  (c) approve rejected by the API (e.g. 401 with auth enabled) -> the
      script surfaces the failure (non-zero exit, FAIL in output) instead
      of swallowing it.

The mock API never touches any network beyond 127.0.0.1.
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = str(Path(__file__).resolve().parents[1] / "webpent-cli.sh")


class _MockAPI:
    """Stateful mock of the three endpoints the launcher talks to."""

    def __init__(self, approve_status: int = 200) -> None:
        self.approve_calls: list[dict] = []
        self.status_calls = 0
        self.approve_status = approve_status
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code: int, payload: dict) -> None:
                body = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                if self.path == "/api/v1/scans":
                    outer.status_calls = 0
                    self._send(200, {"thread_id": "t-m1a-001"})
                elif self.path == "/api/v1/scans/t-m1a-001/approve":
                    outer.approve_calls.append(
                        {"auth": self.headers.get("Authorization")}
                    )
                    if outer.approve_status == 200:
                        # approved -> the scan may run to completion
                        outer.status_calls = 99
                        self._send(200, {"ok": True})
                    else:
                        self._send(outer.approve_status, {"detail": "denied"})
                else:
                    self._send(404, {"detail": "not found"})

            def do_GET(self):  # noqa: N802
                if self.path == "/api/v1/scans/t-m1a-001/status":
                    outer.status_calls += 1
                    if outer.status_calls >= 3:
                        # eventually finish so the launcher's polling loops
                        # terminate in tests
                        self._send(
                            200,
                            {"status": "completed", "is_paused_at_sandbox": False},
                        )
                    else:
                        self._send(
                            200,
                            {"status": "running", "is_paused_at_sandbox": True},
                        )
                else:
                    self._send(404, {"detail": "not found"})

            def log_message(self, *args):  # silence
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def start(self) -> None:
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _run_script(tmp_path, mock: _MockAPI, *args: str, token: str | None = None):
    env_vars = {"WEBPENT_API_URL": mock.url, "WEBPENT_DB_PATH": str(tmp_path / "db.sqlite")}
    if token is not None:
        env_vars["WEBPENT_API_TOKEN"] = token
    env = {**os.environ, **env_vars}
    return subprocess.run(
        ["bash", SCRIPT, "http://127.0.0.1:9/target", *args],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.DEVNULL,  # NO TTY — the whole point of (a)
        capture_output=True,
        text=True,
        timeout=120,
    )


@pytest.fixture()
def mock_api():
    mock = _MockAPI()
    mock.start()
    yield mock
    mock.stop()


def test_no_tty_no_yes_never_approves(tmp_path, mock_api):
    result = _run_script(tmp_path, mock_api)
    assert mock_api.approve_calls == [], (
        "launcher reached the approve endpoint without a human (--yes/TTY)"
    )
    assert "REFUSED" in result.stdout
    assert result.returncode == 0


def test_yes_flag_approves_once_with_bearer(tmp_path, mock_api):
    result = _run_script(tmp_path, mock_api, "--yes", token="tok-m1a-secret")
    assert len(mock_api.approve_calls) == 1
    assert mock_api.approve_calls[0]["auth"] == "Bearer tok-m1a-secret"
    assert "Sandbox approved" in result.stdout


def test_rejected_approval_surfaces_failure(tmp_path):
    mock = _MockAPI(approve_status=401)
    mock.start()
    try:
        result = _run_script(tmp_path, mock, "--yes", token="tok-m1a-secret")
    finally:
        mock.stop()
    assert len(mock.approve_calls) == 1
    assert result.returncode != 0
    assert "FAIL" in result.stdout and "401" in result.stdout


def test_syntax_clean():
    result = subprocess.run(
        ["bash", "-n", SCRIPT], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stderr
