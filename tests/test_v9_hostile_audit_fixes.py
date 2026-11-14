#!/usr/bin/env python3
"""tests/test_v9_hostile_audit_fixes.py — regression tests for bugs found
during a hostile third-party audit of the V9 "hardened-final" patch
set. Each bug below was independently reproduced against the real code
before being patched; these tests lock the fixes in.

1. FIX-5 regression: _get_cached_graph() permanently bound the compiled
   graph to whichever checkpointer was passed on the FIRST call. Every
   real caller opens its checkpointer via a per-request
   `with get_checkpointer() as checkpointer:` block that CLOSES the
   underlying SQLite connection on exit. Every status poll after the
   first therefore raised sqlite3.ProgrammingError: Cannot operate on
   a closed database, silently caught and reported as
   {"status": "error"} for the remaining life of the worker process.
   Fixed by rebinding .checkpointer to the live connection on every
   call (cache hit or not), while still caching the compiled topology.

2. FIX-6 regression: future.result(timeout=5.0) stopped the CALLER
   from waiting on a hung Celery inspect() call, but the enclosing
   `with ThreadPoolExecutor() as executor:` block's implicit
   shutdown(wait=True) on exit re-blocked until the orphaned
   background thread actually finished — negating the 5s cap for
   exactly the "unresponsive worker" case it exists to guard against.
   Fixed with an explicit try/finally: executor.shutdown(wait=False).

3. Re-auth / FIX-10 interaction: has_creds only checked
   credentials.get("username"), never password. V9 FIX-10 scrubs
   credentials["password"] to "" after a successful initial Playwright
   login (so it isn't persisted in the checkpoint DB) but leaves
   username intact. A mid-scan session death after that scrub reached
   the re-login branch with a blank password — wasting a doomed
   Playwright login attempt and reporting a misleading "the login flow
   needs operator attention" message. Fixed by requiring both fields,
   which also makes FIX-10's own comment ("will log a warning and
   skip re-auth") actually true.

Run: python -m pytest tests/test_v9_hostile_audit_fixes.py -v
"""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.validator import agent as validator_agent  # noqa: E402
from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402


# ---------------------------------------------------------------------------
# 1. FIX-5: cached graph must rebind a live checkpointer on every call,
#    not permanently trust the one captured when the cache was first
#    populated.
# ---------------------------------------------------------------------------
class TestFix5CachedGraphCheckpointerRebind:
    def setup_method(self):
        import webpent.api.app as app_mod
        app_mod._GRAPH_CACHE.clear()

    def test_second_request_survives_first_requests_closed_checkpointer(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        import webpent.api.app as app_mod
        from webpent.graph.checkpoints import get_checkpointer

        db_path = str(tmp_path / "sessions.db")
        config = {"configurable": {"thread_id": "test-thread-fix5"}}

        with get_checkpointer(db_path) as cp1:
            g1 = app_mod._get_cached_graph(cp1)
            g1.get_state(config)  # cp1 still open here -- must not raise

        # cp1's connection is now CLOSED: its with-block exited.

        with get_checkpointer(db_path) as cp2:
            g2 = app_mod._get_cached_graph(cp2)
            assert g2 is g1, "compiled topology should be cached/reused, not rebuilt"
            # This exact call raised sqlite3.ProgrammingError before the fix.
            g2.get_state(config)

        # A third request proves it is not a one-off fluke.
        with get_checkpointer(db_path) as cp3:
            g3 = app_mod._get_cached_graph(cp3)
            g3.get_state(config)

    def test_checkpointer_attribute_is_rebound_not_stale(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        import webpent.api.app as app_mod
        from webpent.graph.checkpoints import get_checkpointer

        db_path = str(tmp_path / "sessions2.db")

        with get_checkpointer(db_path) as cp1:
            g1 = app_mod._get_cached_graph(cp1)
            assert g1.checkpointer is cp1

        with get_checkpointer(db_path) as cp2:
            g2 = app_mod._get_cached_graph(cp2)
            assert g2.checkpointer is cp2
            assert g2.checkpointer is not cp1


# ---------------------------------------------------------------------------
# 2. FIX-6: a hung Celery inspect() must not re-block the request on
#    executor teardown.
# ---------------------------------------------------------------------------
class TestFix6CeleryInspectTimeout:
    def test_hanging_celery_inspect_returns_within_timeout_not_full_hang(self):
        import webpent.api.app as app_mod

        fake_user = SimpleNamespace(username="operator", role="operator")

        def _hanging_active():
            time.sleep(20)  # simulates an unresponsive Celery worker
            return {}

        fake_inspector = MagicMock()
        fake_inspector.active = _hanging_active
        fake_celery_app = MagicMock()
        fake_celery_app.control.inspect = MagicMock(return_value=fake_inspector)

        with patch(
            "webpent.api.app._get_graph_status",
            return_value={"status": "running", "next": [], "is_paused_at_sandbox": False},
        ), patch(
            "webpent.workers.pentest_worker.celery_app", fake_celery_app,
        ), patch(
            "webpent.api.scan_registry.get_scan_record",
            return_value={
                "thread_id": "test-thread-fix6",
                "owner_username": "operator",
                "client_id": "test-client",
                "engagement_id": "test-thread-fix6",
                "target_url": "https://target.test",
            },
        ):
            t0 = time.monotonic()
            result = app_mod.get_scan_status("test-thread-fix6", user=fake_user)
            elapsed = time.monotonic() - t0

        assert elapsed < 8.0, (
            f"get_scan_status took {elapsed:.1f}s -- FIX-6 regressed: "
            f"executor.shutdown(wait=False) is not returning control "
            f"within the 5s inspect() timeout ceiling (unpatched: ~20s)."
        )
        assert result.status == "running"


# ---------------------------------------------------------------------------
# 3. has_creds must require BOTH username and password, or a
#    FIX-10-scrubbed password wastes a doomed re-login attempt instead
#    of failing closed to Needs Human Review.
# ---------------------------------------------------------------------------
def _make_sqli_finding() -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title="SQLi at /dvwa/vulnerabilities/sqli/",
        url="http://192.168.40.128/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
        vuln_class=VulnClass.SQLI.value,
        severity="high",
        confidence=Confidence.TENTATIVE.value,
        description="test",
        payload="id=1",
        tool_name="sqlmap",
    )


class _FakeDeadSessionResp:
    status_code = 302
    headers = {"location": "/dvwa/login.php"}
    text = ""
    content = b""


class _FakeProbeClient:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, headers=None):
        return _FakeDeadSessionResp()


_NOT_FALSE_POSITIVE = SimpleNamespace(is_false_positive=False, reason="")

_POSITIVE_SQLMAP_OUTPUT = (
    "sqlmap identified the following injection point(s) with a total of "
    "47 HTTP(s) requests:\n---\nParameter: id (GET)\n"
    "    Type: boolean-based blind\n---\n"
)


class TestHasCredsRequiresPassword:
    def test_scrubbed_password_skips_reauth_instead_of_blank_login_attempt(self):
        """V9 FIX-10 leaves credentials["password"] == "" after a
        successful initial login. Before this fix, has_creds only
        checked username, so this reached _perform_login(url, "admin",
        "") -- a doomed attempt with a misleading failure message.
        After the fix it must fail closed WITHOUT calling
        _perform_login at all, exactly like the no-credentials case.
        """
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}
        credentials = {"username": "admin", "password": ""}  # FIX-10-scrubbed

        with patch(
            "webpent.shared.http.make_safe_httpx_client",
            return_value=_FakeProbeClient(),
        ), patch(
            "webpent.agents.validator.agent.baseline_differential_test",
            return_value=_NOT_FALSE_POSITIVE,
        ), patch(
            "webpent.agents.authentication.agent._perform_login",
        ) as mock_login, patch(
            "webpent.agents.validator.agent.get_tool"
        ) as mock_get_tool:
            tool_entry = MagicMock()
            tool_entry.func = MagicMock()
            mock_get_tool.return_value = tool_entry

            result = validator_agent._validate_with_tool(
                _make_sqli_finding(), "sqli", llm=MagicMock(),
                session_cookies=session_cookies,
                credentials=credentials,
                target_url="http://192.168.40.128/dvwa/",
            )

            assert mock_login.called is False, (
                "has_creds let a blank password through to _perform_login "
                "-- the FIX-10/re-auth interaction bug has regressed."
            )
            assert tool_entry.func.called is False
            assert result.confidence_level == "Needs Human Review"
            assert result.evidence.get("session_dead") is True
            assert result.evidence.get("reauth_attempted") is False

    def test_full_credentials_still_trigger_reauth(self):
        """Sanity check: the added password check must not also break
        the already-working case (real username + real password)."""
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}
        credentials = {"username": "admin", "password": "password"}

        with patch(
            "webpent.shared.http.make_safe_httpx_client",
            return_value=_FakeProbeClient(),
        ), patch(
            "webpent.agents.validator.agent.baseline_differential_test",
            return_value=_NOT_FALSE_POSITIVE,
        ), patch(
            "webpent.agents.authentication.agent._perform_login",
            return_value={"PHPSESSID": "freshcookie", "security": "low"},
        ) as mock_login, patch(
            "webpent.agents.validator.agent.get_tool"
        ) as mock_get_tool, patch(
            "webpent.agents.validator.agent._persist_finding_incrementally",
            return_value=None,
        ), patch(
            "webpent.agents.validator.agent._llm_supervisor_verdict",
            return_value=True,
        ):
            tool_entry = MagicMock()
            tool_entry.func = MagicMock(return_value=_POSITIVE_SQLMAP_OUTPUT)
            mock_get_tool.return_value = tool_entry

            validator_agent._validate_with_tool(
                _make_sqli_finding(), "sqli", llm=MagicMock(),
                session_cookies=session_cookies,
                credentials=credentials,
                target_url="http://192.168.40.128/dvwa/",
            )

            mock_login.assert_called_once_with(
                "http://192.168.40.128/dvwa/", "admin", "password",
            )


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
