"""M1-A (H-1) tunnel-exposure rejection tests (2026-11-05).

M0 finding H-1: auth_enabled=False by default + a cloudflared tunnel that
publishes the WHOLE API (not just OOB callbacks) = unauthenticated scan
launch (with auto_approve → HITL bypass) against arbitrary targets. The
preflight bind check is defeated by tunneling a loopback service.

M1-A fix (three layers):
  1. API middleware — while auth is disabled, requests carrying
     proxy/tunnel indicators (X-Forwarded-*, Cf-*) are refused with 401;
     /api/oob/* stays reachable (by-design unauthenticated callbacks with
     token/size/constant-time compensations); direct local requests are
     unaffected.
  2. scripts/start_tunnel.sh — refuses to start when AUTH_ENABLED is not
     true unless I_UNDERSTAND_THIS_IS_INSECURE=1.
  3. docker-compose.dev.yml — published port bound to 127.0.0.1.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.api import app as api_app  # noqa: E402
from webpent.config.settings import Settings  # noqa: E402

REPO = Path(__file__).resolve().parents[1]

STRONG = "x" * 48  # passes length + not a placeholder (M1-A/H-2)


def _auth_on_settings() -> Settings:
    """Valid auth-on Settings (strong secrets — H-2 rejects placeholders)."""
    return Settings(
        auth_enabled=True,
        jwt_secret_key=STRONG,
        audit_secret_key=STRONG,
        celery_payload_key=STRONG,
    )


def _client_with_auth(auth_enabled: bool) -> TestClient:
    api_app._settings = Settings(auth_enabled=auth_enabled)
    return TestClient(api_app.app, raise_server_exceptions=False)


class TestTunnelExposureMiddleware:
    """test_preflight_tunnel_exposure — the M0-named regression."""

    def test_tunneled_scan_request_refused_when_auth_disabled(self):
        client = _client_with_auth(auth_enabled=False)
        response = client.post(
            "/api/v1/scans",
            json={"url": "http://127.0.0.1:5801/", "auto_approve": True},
            headers={"X-Forwarded-Host": "something.trycloudflare.com"},
        )
        assert response.status_code == 401
        assert "authentication disabled" in response.json()["detail"]

    @pytest.mark.parametrize(
        "header",
        [
            {"X-Forwarded-Host": "t.trycloudflare.com"},
            {"X-Forwarded-For": "203.0.113.9"},
            {"Cf-Ray": "8f3a2b"},
            {"Cf-Visitor": '{"scheme":"https"}'},
            {"Cf-Connecting-Ip": "203.0.113.9"},
            {"X-Real-Ip": "203.0.113.9"},
        ],
    )
    def test_each_tunnel_indicator_refused(self, header):
        client = _client_with_auth(auth_enabled=False)
        response = client.get("/api/v1/me", headers=header)
        assert response.status_code == 401

    def test_direct_local_request_unaffected_when_auth_disabled(self):
        """Local dev flow preserved: no proxy headers → passes through the
        middleware (the stub-admin path still applies downstream)."""
        client = _client_with_auth(auth_enabled=False)
        response = client.get("/api/v1/me")
        assert response.status_code != 401 or "proxy" not in response.text

    def test_oob_endpoints_exempt_from_tunnel_rejection(self):
        """OOB callbacks are the tunnel's raison d'être — token-gated, not
        auth-gated. A forwarded OOB request must reach the handler (it
        will fail on token validation, NOT on the tunnel middleware)."""
        client = _client_with_auth(auth_enabled=False)
        response = client.get(
            "/api/oob/00000000-0000-0000-0000-000000000000/not-a-valid-token",
            headers={"X-Forwarded-Host": "t.trycloudflare.com"},
        )
        assert response.status_code != 401

    def test_proxied_request_allowed_when_auth_enabled(self, monkeypatch):
        """Legitimate reverse-proxy deployments with auth on are not
        blocked by this middleware (auth itself decides)."""
        import webpent.api.auth as api_auth

        auth_on = _auth_on_settings()
        # The middleware reads the app module's _settings; the auth
        # dependency (get_current_user) resolves get_settings() live —
        # BOTH must see auth_enabled=True or the stub-admin dev path
        # answers 200 before the auth layer can 401.
        monkeypatch.setattr(api_app, "_settings", auth_on)
        monkeypatch.setattr(api_auth, "get_settings", lambda: auth_on)
        client = TestClient(api_app.app, raise_server_exceptions=False)
        response = client.get(
            "/api/v1/me", headers={"X-Forwarded-Host": "proxy.example.com"}
        )
        # 401 from the AUTH layer (no token) — not from the tunnel guard.
        assert response.status_code == 401
        assert "proxy/tunnel" not in response.text


class TestTunnelScriptGuard:
    """The tunnel script must refuse to start with auth disabled."""

    def _run_script(self, env: dict, env_file: Path | None = None) -> int:
        import subprocess

        cmd = ["bash", str(REPO / "scripts" / "start_tunnel.sh")]
        if env_file is not None:
            cmd.append(str(env_file))
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            env={**env, "PATH": "/usr/bin:/bin"},
        )
        return proc.returncode

    def test_refuses_without_auth(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("AUTH_ENABLED=false\n")
        assert self._run_script({}, env_file) == 1

    def test_refuses_when_env_missing(self):
        assert self._run_script({}) == 1

    def test_insecure_override_acknowledged(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("AUTH_ENABLED=false\n")
        # The override proceeds past the guard (it will then fail later on
        # missing cloudflared — exit code differs from the guard's 1 with
        # the REFUSED banner, which is what we assert on stderr absence).
        import subprocess

        proc = subprocess.run(
            ["bash", str(REPO / "scripts" / "start_tunnel.sh"), str(env_file)],
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "I_UNDERSTAND_THIS_IS_INSECURE": "1",
                "PATH": "/usr/bin:/bin",
            },
        )
        assert "REFUSED: AUTH_ENABLED" not in proc.stderr

    def test_proceeds_with_auth_enabled(self, tmp_path):
        import subprocess

        env_file = tmp_path / ".env"
        env_file.write_text("AUTH_ENABLED=true\n")
        proc = subprocess.run(
            ["bash", str(REPO / "scripts" / "start_tunnel.sh"), str(env_file)],
            capture_output=True,
            text=True,
            timeout=10,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert "REFUSED: AUTH_ENABLED" not in proc.stderr


class TestDevComposeLoopbackBinding:
    def test_dev_compose_publishes_loopback_only(self):
        compose = (REPO / "docker-compose.dev.yml").read_text(encoding="utf-8")
        assert '127.0.0.1:8000:8000' in compose
        assert '"8000:8000"' not in compose
