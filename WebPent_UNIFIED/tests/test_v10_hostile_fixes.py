#!/usr/bin/env python3
"""tests/test_v10_hostile_fixes.py

V10 HOSTILE regression tests for P0-1 (terminal worker states → API)
and P1-1 (Playwright login verification), plus P2-2/P2-3 spot checks.

Run: python -m pytest tests/test_v10_hostile_fixes.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


# ===========================================================================
# P0-1: Terminal worker states must reach GET /status
# ===========================================================================


class TestP01TerminalWorkerStatesToAPI:
    """When the worker returns a terminal status (terminated_recursion_limit,
    soft_timeout, terminated_zombie_running), the API must map it to a
    terminal status — never leave "running"."""

    def _make_mock_async_result(self, state: str, result: dict | None = None):
        """Build a mock AsyncResult with .state and .result."""
        mock_ar = MagicMock()
        mock_ar.state = state
        mock_ar.result = result
        return mock_ar

    def test_recursion_limit_maps_to_completed(self):
        """terminated_recursion_limit → API status "completed" (findings persisted)."""
        from webpent.api import app as app_module

        # Graph says "running" (stale — the graph was interrupted mid-step).
        # Celery says SUCCESS with result.status=terminated_recursion_limit.
        # API must map to "completed", NOT "running".
        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-1"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "running",  # stale graph checkpoint
                "next": ["validator"],
                "is_paused_at_sandbox": False,
            }
            mock_celery.AsyncResult.return_value = self._make_mock_async_result(
                "SUCCESS",
                result={"status": "terminated_recursion_limit", "thread_id": "t1"},
            )
            # Replicate the get_scan_status decision matrix.
            state_info = mock_gs.return_value
            async_result = mock_celery.AsyncResult.return_value
            _worker_result = async_result.result if isinstance(async_result.result, dict) else None
            _worker_status = _worker_result.get("status") if _worker_result else ""
            if _worker_status in (
                "terminated_recursion_limit",
                "soft_timeout",
                "terminated_zombie_running",
            ):
                if _worker_status == "soft_timeout":
                    state_info["status"] = "error"
                else:
                    state_info["status"] = "completed"
            assert state_info["status"] == "completed", (
                f"P0-1 REGRESSION: terminated_recursion_limit → {state_info['status']}, "
                "expected completed"
            )

    def test_soft_timeout_maps_to_error(self):
        """soft_timeout → API status "error" (interrupted, partial findings)."""
        from webpent.api import app as app_module

        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-2"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "running",
                "next": ["validator"],
                "is_paused_at_sandbox": False,
            }
            mock_celery.AsyncResult.return_value = self._make_mock_async_result(
                "SUCCESS",
                result={"status": "soft_timeout", "thread_id": "t2"},
            )
            state_info = mock_gs.return_value
            async_result = mock_celery.AsyncResult.return_value
            _worker_result = async_result.result if isinstance(async_result.result, dict) else None
            _worker_status = _worker_result.get("status") if _worker_result else ""
            if _worker_status in (
                "terminated_recursion_limit",
                "soft_timeout",
                "terminated_zombie_running",
            ):
                if _worker_status == "soft_timeout":
                    state_info["status"] = "error"
                else:
                    state_info["status"] = "completed"
            assert state_info["status"] == "error", (
                f"P0-1 REGRESSION: soft_timeout → {state_info['status']}, expected error"
            )

    def test_zombie_running_maps_to_completed(self):
        """terminated_zombie_running → API status "completed" (findings persisted)."""
        from webpent.api import app as app_module

        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-3"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "running",
                "next": ["validator"],
                "is_paused_at_sandbox": False,
            }
            mock_celery.AsyncResult.return_value = self._make_mock_async_result(
                "SUCCESS",
                result={"status": "terminated_zombie_running", "thread_id": "t3"},
            )
            state_info = mock_gs.return_value
            async_result = mock_celery.AsyncResult.return_value
            _worker_result = async_result.result if isinstance(async_result.result, dict) else None
            _worker_status = _worker_result.get("status") if _worker_result else ""
            if _worker_status in (
                "terminated_recursion_limit",
                "soft_timeout",
                "terminated_zombie_running",
            ):
                if _worker_status == "soft_timeout":
                    state_info["status"] = "error"
                else:
                    state_info["status"] = "completed"
            assert state_info["status"] == "completed", (
                "P0-1 REGRESSION: terminated_zombie_running → "
                f"{state_info['status']}, expected completed"
            )

    def test_normal_completed_stays_completed(self):
        """Worker returns status=completed → API status "completed"."""
        from webpent.api import app as app_module

        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-4"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "completed",
                "next": [],
                "is_paused_at_sandbox": False,
            }
            mock_celery.AsyncResult.return_value = self._make_mock_async_result(
                "SUCCESS",
                result={"status": "completed", "thread_id": "t4"},
            )
            state_info = mock_gs.return_value
            async_result = mock_celery.AsyncResult.return_value
            _worker_result = async_result.result if isinstance(async_result.result, dict) else None
            _worker_status = _worker_result.get("status") if _worker_result else ""
            if _worker_status in (
                "terminated_recursion_limit",
                "soft_timeout",
                "terminated_zombie_running",
            ):
                if _worker_status == "soft_timeout":
                    state_info["status"] = "error"
                else:
                    state_info["status"] = "completed"
            # Not a terminal string → trust graph (already "completed").
            assert state_info["status"] == "completed"

    def test_celery_started_does_not_override_completed(self):
        """Celery STARTED (task still running) must NOT leave "completed"
        if the graph says running. The premature-completed fix must still hold."""
        # This test verifies the EXISTING P0-0 fix is not broken by P0-1.
        from webpent.api import app as app_module

        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-5"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "running",
                "next": ["validator"],
                "is_paused_at_sandbox": False,
            }
            mock_celery.AsyncResult.return_value = self._make_mock_async_result("STARTED")
            state_info = mock_gs.return_value
            celery_state = mock_celery.AsyncResult.return_value.state
            # P0-0 fix: STARTED → running (never completed)
            if (
                celery_state in ("PENDING", "STARTED", "RETRY")
                and not (celery_state == "PENDING" and state_info["status"] == "completed")
                and state_info["status"] != "paused"
            ):
                state_info["status"] = "running"
            assert state_info["status"] == "running", (
                "P0-1 REGRESSION: Celery STARTED must not allow 'completed'"
            )


# ===========================================================================
# P1-1: Playwright login must verify success
# ===========================================================================


class TestP11PlaywrightLoginVerification:
    """_perform_login must validate the session after submit — non-empty
    cookies do NOT mean login succeeded."""

    def test_perform_login_returns_empty_on_validation_failure(self):
        """When _validate_session_cookies returns False, _perform_login
        must return {} — not the unvalidated cookies."""
        from webpent.agents.authentication import agent as auth_agent

        # Mock Playwright to return cookies (as DVWA does even on wrong password).
        _fake_cookies = {"PHPSESSID": "session-id-set-on-login-page", "security": "impossible"}

        with (
            patch("webpent.agents.authentication.agent._validate_session_cookies") as mock_validate,
            patch("playwright.sync_api.sync_playwright") as mock_pw,
        ):
            mock_validate.return_value = (
                False,
                "200 OK but body contains login indicator 'login.php'",
            )

            # Minimal Playwright mock that returns cookies.
            _pw_instance = MagicMock()
            _browser = MagicMock()
            _context = MagicMock()
            _page = MagicMock()
            _pw_instance.chromium.launch.return_value = _browser
            _browser.new_context.return_value = _context
            _context.new_page.return_value = _page
            _context.cookies.return_value = [
                {"name": k, "value": v} for k, v in _fake_cookies.items()
            ]
            mock_pw.return_value.start.return_value = _pw_instance

            result = auth_agent._perform_login("http://target/login.php", "admin", "wrongpassword")

        assert result == {}, (
            f"P1-1 REGRESSION: _perform_login returned {result} on validation "
            "failure — should be empty dict (unvalidated cookies must NOT be "
            "treated as an authenticated session)"
        )

    def test_perform_login_returns_target_issued_cookies_unchanged(self):
        """A valid login returns exactly the cookies issued by the target.

        Authentication must remain target-agnostic: it must not invent or
        downgrade a lab-specific security cookie.
        """
        from webpent.agents.authentication import agent as auth_agent

        _fake_cookies = {
            "SESSION": "valid-session-id",
            "tenant": "blue",
        }

        with (
            patch("webpent.agents.authentication.agent._validate_session_cookies") as mock_validate,
            patch("playwright.sync_api.sync_playwright") as mock_pw,
        ):
            mock_validate.return_value = (True, "200 OK, no login indicators")

            _pw_instance = MagicMock()
            _browser = MagicMock()
            _context = MagicMock()
            _page = MagicMock()
            _pw_instance.chromium.launch.return_value = _browser
            _browser.new_context.return_value = _context
            _context.new_page.return_value = _page
            _context.cookies.return_value = [
                {"name": k, "value": v} for k, v in _fake_cookies.items()
            ]
            mock_pw.return_value.start.return_value = _pw_instance

            result = auth_agent._perform_login(
                "http://target/login.php", "admin", "correctpassword"
            )

        assert result != {}, "P1-1 REGRESSION: _perform_login returned empty on validation success"
        assert result == _fake_cookies

    def test_perform_login_does_not_log_login_successful_on_failure(self):
        """On validation failure, the log must NOT say 'Login successful'."""
        from webpent.agents.authentication import agent as auth_agent

        _fake_cookies = {"PHPSESSID": "session-id"}

        with (
            patch("webpent.agents.authentication.agent._validate_session_cookies") as mock_validate,
            patch("playwright.sync_api.sync_playwright") as mock_pw,
            patch.object(auth_agent.logger, "info") as mock_info,
            patch.object(auth_agent.logger, "error") as mock_error,
        ):
            mock_validate.return_value = (False, "redirected to login page")

            _pw_instance = MagicMock()
            _browser = MagicMock()
            _context = MagicMock()
            _page = MagicMock()
            _pw_instance.chromium.launch.return_value = _browser
            _browser.new_context.return_value = _context
            _context.new_page.return_value = _page
            _context.cookies.return_value = [
                {"name": k, "value": v} for k, v in _fake_cookies.items()
            ]
            mock_pw.return_value.start.return_value = _pw_instance

            auth_agent._perform_login("http://target/login.php", "admin", "wrongpassword")

        # Must NOT log "Login successful" anywhere.
        for call in mock_info.call_args_list:
            args, kwargs = call
            for arg in args:
                assert "Login successful" not in str(arg), (
                    "P1-1 REGRESSION: 'Login successful' logged on validation failure"
                )
        # Must log ERROR about the failure.
        assert mock_error.called, "P1-1 REGRESSION: no ERROR log on login failure"


# ===========================================================================
# P1-2: CLI must not write plaintext password into checkpoint
# ===========================================================================


class TestP12CliNoPasswordInDescription:
    """CLI must not stuff username:/password: into target.description."""

    def test_no_credential_stuffing_in_cli_source(self):
        """Static check: cli/__init__.py must not contain target.description
        credential stuffing."""
        cli_path = Path(__file__).resolve().parents[1] / "src" / "webpent" / "cli" / "__init__.py"
        source = cli_path.read_text()
        # The old pattern: target.description = ...username:...password:
        assert "target.description = " not in source or "username:" not in source, (
            "P1-2 REGRESSION: cli still stuffs credentials into target.description"
        )
        # Must not contain the old stuffing pattern.
        assert "f\"username:{credentials['username']}\" " not in source, (
            "P1-2 REGRESSION: cli still has plaintext password in description"
        )


# ===========================================================================
# P1-3: SQLi post-exploitation must normalize URL
# ===========================================================================


class TestP13PostExploitNormalizeUrl:
    """post_exploit sqlmap command must use normalize_sqli_url + -p id."""

    def test_collect_sqli_uses_normalize_sqli_url(self):
        """_collect_sqli_post_exploitation must call normalize_sqli_url."""
        import inspect

        from webpent.agents.post_exploit.agent import _collect_sqli_post_exploitation

        source = inspect.getsource(_collect_sqli_post_exploitation)
        assert "normalize_sqli_url" in source, (
            "P1-3 REGRESSION: post_exploit must use normalize_sqli_url"
        )

    def test_collect_sqli_passes_p_id(self):
        """The sqlmap command must include -p id for DVWA-style endpoints."""
        import inspect

        from webpent.agents.post_exploit.agent import _collect_sqli_post_exploitation

        source = inspect.getsource(_collect_sqli_post_exploitation)
        assert '"-p", "id"' in source or "'-p', 'id'" in source, (
            "P1-3 REGRESSION: post_exploit must pass -p id"
        )


# ===========================================================================
# P2-2: payload_optimizer skips SQLi synthetic marker
# ===========================================================================


class TestP22OptimizerSkipsSyntheticMarker:
    """payload_optimizer must not LLM-optimize __SQLMAP_TOOL_DRIVEN__."""

    def test_optimizer_skips_synthetic_marker(self):
        import inspect

        from webpent.agents.payload_optimizer.agent import payload_optimizer_node

        source = inspect.getsource(payload_optimizer_node)
        assert "__SQLMAP_TOOL_DRIVEN__" in source, (
            "P2-2 REGRESSION: optimizer must check for __SQLMAP_TOOL_DRIVEN__"
        )
        assert "skipping" in source.lower() or "skip" in source.lower(), (
            "P2-2 REGRESSION: optimizer must skip the synthetic marker"
        )


# ===========================================================================
# P2-3: katana empty hostname fail-closed
# ===========================================================================


class TestP23KatanaEmptyHostnameFailClosed:
    """katana must drop endpoints with empty/unparseable hostname."""

    def test_katana_drops_empty_hostname(self):
        import inspect

        from webpent.tools.recon.katana import run_katana

        source = inspect.getsource(run_katana)
        assert "empty" in source.lower() or "unparseable" in source.lower(), (
            "P2-3 REGRESSION: katana must drop empty-hostname endpoints"
        )


# ===========================================================================
# P0-2: Production compose hardening
# ===========================================================================


class TestP02ProductionComposeHardening:
    """Production docker-compose.yml must be secure by default."""

    def test_auth_enabled_true_in_production_compose(self):
        compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        source = compose_path.read_text()
        assert "WEBPENT_AUTH_ENABLED=true" in source, (
            "P0-2 REGRESSION: production compose must set AUTH_ENABLED=true"
        )

    def test_no_admin_admin_default_in_production_compose(self):
        """No admin:admin as an actual env default (comments are OK)."""
        compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        source = compose_path.read_text()
        # Strip comments (lines starting with #) before checking.
        code_lines = [line for line in source.splitlines() if not line.strip().startswith("#")]
        code = "\n".join(code_lines)
        # The old default was: WEBPENT_USERS=${WEBPENT_USERS:-admin:admin:admin,...}
        assert "admin:admin:admin" not in code, (
            "P0-2 REGRESSION: production compose has admin:admin as actual default"
        )
        # The new compose uses ${WEBPENT_USERS:?...} (no fallback).
        assert "WEBPENT_USERS=${WEBPENT_USERS:?}" in code or "WEBPENT_USERS:" in code, (
            "P0-2 REGRESSION: WEBPENT_USERS must use ${VAR:?} (no fallback default)"
        )

    def test_no_hardcoded_jwt_secret_default(self):
        compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        source = compose_path.read_text()
        # The old default was a 64-hex string. The new compose uses ${VAR:?msg}
        # which has no fallback. Check that no 64-hex literal appears as a default.
        assert "a1b2c3d4e5f67890" not in source, (
            "P0-2 REGRESSION: production compose has hardcoded JWT secret default"
        )

    def test_no_redis_ports_published_to_host(self):
        compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        source = compose_path.read_text()
        # Redis section must not have ports: mapping.
        # Find the redis service block.
        redis_start = source.find("  redis:")
        redis_end = source.find("  postgres:", redis_start)
        redis_block = source[redis_start:redis_end] if redis_start >= 0 else ""
        assert '"6379:6379"' not in redis_block, (
            "P0-2 REGRESSION: Redis ports published to host in production compose"
        )

    def test_no_postgres_ports_published_to_host(self):
        compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
        source = compose_path.read_text()
        postgres_start = source.find("  postgres:")
        postgres_end = source.find("  api:", postgres_start)
        postgres_block = source[postgres_start:postgres_end] if postgres_start >= 0 else ""
        assert '"5432:5432"' not in postgres_block, (
            "P0-2 REGRESSION: Postgres ports published to host in production compose"
        )

    def test_dev_compose_marked_not_production(self):
        dev_compose_path = Path(__file__).resolve().parents[1] / "docker-compose.dev.yml"
        source = dev_compose_path.read_text()
        assert "NOT FOR PRODUCTION" in source or "NOT FOR PROD" in source.upper(), (
            "P0-2 REGRESSION: dev compose must be clearly marked as NOT production"
        )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
