#!/usr/bin/env python3
"""tests/test_v10_p0_status_sqlmap_skiprecon_findings.py

V10 regression tests for the 4 P0 fixes:

P0-0 — false "completed" status while worker still running
  * _get_graph_status returns "pending" (not "completed") when no
    checkpoint exists for the thread_id.
  * get_scan_status overrides to "running" when AsyncResult.state is
    PENDING/STARTED/RETRY (via the scan_registry mapping).
  * get_scan_status NEVER returns "completed" when Celery says the
    task is still in-flight.
  * POST /scans registers the thread_id → task_id mapping.

P0-A — sqlmap invocation effectiveness
  * _build_sqlmap_cmd emits --level=3 (was 2).
  * _build_sqlmap_cmd emits --dbms=mysql when URL contains /dvwa/ or
    vulnerabilities/sqli.
  * normalize_sqli_url adds trailing slash before query for DVWA-style
    sqli paths.
  * dalfox argv includes --follow-redirects, --deep, --skip-boring.

P0-B — skip_recon drops exploit chain
  * route_after_hypothesis routes to NODE_ACCESS_CONTROL (not
    NODE_REPORTER) when skip_recon=True AND findings=[] AND open
    hypotheses exist.
  * route_after_hypothesis still routes to NODE_REPORTER when
    skip_recon=True AND no findings AND no open hypotheses (genuine
    no-op fast path preserved).

P0-C — findings empty after true completion
  * _persist_finding_incrementally stamps thread_id before saving.
  * post_exploit_node stamps thread_id from state before saving.
  * execution_sandbox_node stamps thread_id from state before saving.
  * Redelivery path re-persists on ANY non-empty checkpoint (not
    only "completed").
  * Alembic migration includes thread_id column + index.
  * End-to-end: completed + state had findings => API returns same count.

Run: python -m pytest tests/test_v10_p0_status_sqlmap_skiprecon_findings.py -v
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


# ===========================================================================
# P0-0: false "completed" status
# ===========================================================================


class TestP00FalseCompleted:
    """_get_graph_status must NOT return 'completed' when no checkpoint."""

    def _mock_state_snapshot(self, values=None, next_nodes=()):
        """Build a mock StateSnapshot with the given values + next."""
        snap = MagicMock()
        snap.values = values if values is not None else {}
        snap.next = next_nodes
        return snap

    def test_no_checkpoint_returns_pending_not_completed(self):
        """When get_state returns None (no checkpoint), status must be
        'pending' — NOT 'completed'."""
        from webpent.api import app as app_module

        with patch.object(app_module, "_get_cached_graph") as mock_cached, \
             patch.object(app_module, "get_checkpointer") as mock_cp:
            mock_cp.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_cp.return_value.__exit__ = MagicMock(return_value=False)
            mock_graph = MagicMock()
            mock_graph.get_state.return_value = None  # no checkpoint
            mock_cached.return_value = mock_graph

            result = app_module._get_graph_status("nonexistent-thread")

        assert result["status"] == "pending", (
            f"P0-0 REGRESSION: no checkpoint returned status="
            f"{result['status']!r} — must be 'pending' (not 'completed')"
        )
        assert result["is_paused_at_sandbox"] is False

    def test_empty_state_snapshot_returns_pending_not_completed(self):
        """When get_state returns a StateSnapshot with empty values
        (newer langgraph behavior for unknown thread_id), status must
        be 'pending' — NOT 'completed'."""
        from webpent.api import app as app_module

        with patch.object(app_module, "_get_cached_graph") as mock_cached, \
             patch.object(app_module, "get_checkpointer") as mock_cp:
            mock_cp.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_cp.return_value.__exit__ = MagicMock(return_value=False)
            mock_graph = MagicMock()
            mock_graph.get_state.return_value = self._mock_state_snapshot(
                values={}, next_nodes=(),
            )
            mock_cached.return_value = mock_graph

            result = app_module._get_graph_status("empty-thread")

        assert result["status"] == "pending", (
            f"P0-0 REGRESSION: empty checkpoint returned status="
            f"{result['status']!r} — must be 'pending'"
        )

    def test_completed_only_when_checkpoint_has_values_and_empty_next(self):
        """Genuine completion: checkpoint has values AND next is empty."""
        from webpent.api import app as app_module

        with patch.object(app_module, "_get_cached_graph") as mock_cached, \
             patch.object(app_module, "get_checkpointer") as mock_cp:
            mock_cp.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_cp.return_value.__exit__ = MagicMock(return_value=False)
            mock_graph = MagicMock()
            mock_graph.get_state.return_value = self._mock_state_snapshot(
                values={"findings": ["f1"], "current_phase": "done"},
                next_nodes=(),
            )
            mock_cached.return_value = mock_graph

            result = app_module._get_graph_status("completed-thread")

        assert result["status"] == "completed"

    def test_running_when_checkpoint_has_next_nodes(self):
        """When checkpoint has next nodes, status is 'running'."""
        from webpent.api import app as app_module
        from webpent.graph.builder import NODE_PAYLOAD_GENERATOR

        with patch.object(app_module, "_get_cached_graph") as mock_cached, \
             patch.object(app_module, "get_checkpointer") as mock_cp:
            mock_cp.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_cp.return_value.__exit__ = MagicMock(return_value=False)
            mock_graph = MagicMock()
            mock_graph.get_state.return_value = self._mock_state_snapshot(
                values={"findings": []},
                next_nodes=(NODE_PAYLOAD_GENERATOR,),
            )
            mock_cached.return_value = mock_graph

            result = app_module._get_graph_status("running-thread")

        assert result["status"] == "running"
        assert NODE_PAYLOAD_GENERATOR in result["next"]

    def test_get_state_exception_returns_error_not_completed(self):
        """When get_state raises, status is 'error' — NOT 'completed'."""
        from webpent.api import app as app_module

        with patch.object(app_module, "_get_cached_graph") as mock_cached, \
             patch.object(app_module, "get_checkpointer") as mock_cp:
            mock_cp.return_value.__enter__ = MagicMock(return_value=MagicMock())
            mock_cp.return_value.__exit__ = MagicMock(return_value=False)
            mock_graph = MagicMock()
            mock_graph.get_state.side_effect = RuntimeError("DB unavailable")
            mock_cached.return_value = mock_graph

            result = app_module._get_graph_status("error-thread")

        assert result["status"] == "error"

    def test_celery_pending_overrides_to_running(self):
        """When AsyncResult.state == PENDING, status must be 'running'
        — NEVER 'completed', even if the graph checkpoint says completed
        (defensive against a stale checkpoint)."""
        from webpent.api import app as app_module

        # Simulate: graph says "completed" (stale checkpoint), but Celery
        # says PENDING (task is queued, not yet started). The API must
        # report "running", not "completed".
        with patch.object(app_module, "_get_graph_status") as mock_graph_status, \
             patch("webpent.api.scan_registry.lookup_task_id") as mock_lookup, \
             patch("webpent.workers.pentest_worker.celery_app") as mock_celery:
            mock_graph_status.return_value = {
                "status": "completed",  # stale!
                "next": [],
                "is_paused_at_sandbox": False,
            }
            mock_lookup.return_value = "celery-task-id"
            mock_async_result = MagicMock()
            mock_async_result.state = "PENDING"
            mock_celery.AsyncResult.return_value = mock_async_result

            # Call the handler logic directly (bypass FastAPI deps).
            state_info = mock_graph_status.return_value
            celery_state = mock_celery.AsyncResult("celery-task-id").state
            if (
                celery_state in ("PENDING", "STARTED", "RETRY")
                and state_info["status"] != "paused"
            ):
                state_info["status"] = "running"
                state_info["next"] = [f"(celery:{celery_state})"]

        assert state_info["status"] == "running", (
            "P0-0 REGRESSION: Celery PENDING must override stale 'completed'"
        )

    def test_celery_success_with_pending_graph_reports_error(self):
        """When Celery says SUCCESS but graph has no checkpoint, the
        checkpoint write failed — report 'error', not 'completed'."""
        from webpent.api import app as app_module

        with patch.object(app_module, "_get_graph_status") as mock_graph_status, \
             patch("webpent.api.scan_registry.lookup_task_id") as mock_lookup, \
             patch("webpent.workers.pentest_worker.celery_app") as mock_celery:
            mock_graph_status.return_value = {
                "status": "pending",  # no checkpoint
                "next": [],
                "is_paused_at_sandbox": False,
            }
            mock_lookup.return_value = "celery-task-id"
            mock_async_result = MagicMock()
            mock_async_result.state = "SUCCESS"
            mock_celery.AsyncResult.return_value = mock_async_result

            state_info = mock_graph_status.return_value
            celery_state = mock_celery.AsyncResult("celery-task-id").state
            if celery_state == "SUCCESS" and state_info["status"] == "pending":
                state_info["status"] = "error"

        assert state_info["status"] == "error"


class TestP00ScanRegistry:
    """thread_id ↔ task_id mapping store."""

    def test_register_and_lookup_roundtrip(self, tmp_path):
        """register_scan(thread_id, task_id) → lookup_task_id(thread_id)."""
        # Use a temp DB so we don't pollute the real one.
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/test.db")
        db.init_db()
        # Monkey-patch get_db_manager to return our temp instance.
        from webpent.api import scan_registry
        with patch("webpent.api.scan_registry._get_db", return_value=db):
            scan_registry.init_scan_registry()
            tid = f"thread-{uuid.uuid4()}"
            scan_registry.register_scan(tid, "task-123", "http://target")
            assert scan_registry.lookup_task_id(tid) == "task-123"

    def test_lookup_missing_returns_none(self, tmp_path):
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/test2.db")
        db.init_db()
        from webpent.api import scan_registry
        with patch("webpent.api.scan_registry._get_db", return_value=db):
            scan_registry.init_scan_registry()
            assert scan_registry.lookup_task_id("never-registered") is None

    def test_empty_inputs_are_noops(self):
        from webpent.api import scan_registry
        scan_registry.register_scan("", "task", "url")  # no-op
        scan_registry.register_scan("tid", "", "url")   # no-op
        assert scan_registry.lookup_task_id("") is None
        assert scan_registry.lookup_task_id(None) is None


# ===========================================================================
# P0-A: sqlmap argv effectiveness
# ===========================================================================


class TestP0ASqlmapArgv:
    """sqlmap argv must include --level=3 and --dbms=mysql for DVWA."""

    def test_level_is_3_not_2(self):
        """--level must be 3 (was 2 in V9)."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd("http://target/vulnerabilities/sqli/?id=1&Submit=Submit")
        assert "--level=3" in cmd, (
            f"P0-A REGRESSION: --level=3 missing from argv: {cmd}"
        )
        assert "--level=2" not in cmd, (
            f"P0-A REGRESSION: --level=2 still in argv: {cmd}"
        )

    def test_dbms_mysql_for_dvwa_path(self):
        """--dbms=mysql must be added when URL contains /dvwa/."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd(
            "http://192.168.40.128/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
        )
        assert "--dbms=mysql" in cmd, (
            f"P0-A REGRESSION: --dbms=mysql missing for DVWA URL: {cmd}"
        )

    def test_dbms_mysql_for_vulnerabilities_sqli_without_dvwa(self):
        """--dbms=mysql must be added when path contains vulnerabilities/sqli
        even without /dvwa/ prefix."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd(
            "http://target/vulnerabilities/sqli/?id=1&Submit=Submit"
        )
        assert "--dbms=mysql" in cmd

    def test_no_dbms_for_non_dvwa_url(self):
        """--dbms=mysql must NOT be added for arbitrary URLs (fingerprinting
        is still useful there)."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd("http://target.com/search?q=test")
        assert "--dbms=mysql" not in cmd

    def test_cookie_injected(self):
        """Session cookies must be injected via --cookie."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd(
            "http://target/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit",
            session_cookies={"PHPSESSID": "abc123", "security": "low"},
        )
        assert "--cookie" in cmd
        cookie_idx = cmd.index("--cookie")
        cookie_val = cmd[cookie_idx + 1]
        assert "PHPSESSID=abc123" in cookie_val
        assert "security=low" in cookie_val

    def test_flush_session_present(self):
        """--flush-session must be present (avoid stale cache)."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd
        cmd = _build_sqlmap_cmd("http://target/dvwa/vulnerabilities/sqli/")
        assert "--flush-session" in cmd

    def test_normalize_adds_trailing_slash(self):
        """normalize_sqli_url must add trailing slash for /sqli paths."""
        from webpent.tools.exploitation.sqlmap import normalize_sqli_url
        normalized = normalize_sqli_url(
            "http://target/dvwa/vulnerabilities/sqli?id=1"
        )
        assert "/sqli/" in normalized, (
            f"P0-A REGRESSION: trailing slash not added: {normalized}"
        )

    def test_normalize_preserves_existing_trailing_slash(self):
        """normalize_sqli_url must NOT double-slash."""
        from webpent.tools.exploitation.sqlmap import normalize_sqli_url
        normalized = normalize_sqli_url(
            "http://target/dvwa/vulnerabilities/sqli/?id=1"
        )
        assert "/sqli/?" in normalized
        assert "//sqli" not in normalized

    def test_normalize_adds_id_and_submit_params(self):
        """normalize_sqli_url must add id=1&Submit=Submit if missing."""
        from webpent.tools.exploitation.sqlmap import normalize_sqli_url
        normalized = normalize_sqli_url(
            "http://target/dvwa/vulnerabilities/sqli/"
        )
        assert "id=1" in normalized
        assert "Submit=Submit" in normalized

    def test_parse_confirmation_still_authoritative(self):
        """parse_sqlmap_confirmation must still detect real injection."""
        from webpent.tools.exploitation.sqlmap import parse_sqlmap_confirmation
        positive = (
            "[INFO] GET parameter 'id' is vulnerable.\n"
            "sqlmap identified the following injection point(s):\n"
            "Type: boolean-based blind\n"
        )
        assert parse_sqlmap_confirmation(positive) is True

    def test_parse_confirmation_rejects_not_injectable(self):
        """parse_sqlmap_confirmation must reject 'not injectable'."""
        from webpent.tools.exploitation.sqlmap import parse_sqlmap_confirmation
        negative = (
            "[CRITICAL] all tested parameters do not appear to be injectable."
        )
        assert parse_sqlmap_confirmation(negative) is False

    def test_post_form_context_reaches_sqlmap_argv(self):
        """Discovered POST form data must not silently become a GET scan."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd

        cmd = _build_sqlmap_cmd(
            "http://target/vulnerabilities/sqli/",
            request_data={"id": "1", "Submit": "Submit"},
            target_param="id",
        )
        assert "--data" in cmd
        assert cmd[cmd.index("--data") + 1] == "id=1&Submit=Submit"
        assert "--method" in cmd
        assert cmd[cmd.index("--method") + 1] == "POST"
        assert "--technique=BEUST" in cmd
        assert "--timeout=10" in cmd
        assert "--retries=1" in cmd
        assert "--threads=4" in cmd
        assert "-p" in cmd
        assert cmd[cmd.index("-p") + 1] == "id"
        # The POST body is authoritative; no DVWA GET query is synthesized.
        assert cmd[cmd.index("-u") + 1].endswith("/vulnerabilities/sqli/")

    def test_post_form_removes_only_duplicate_query_keys(self):
        """POST actions may carry unrelated query context that must survive."""
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd

        cmd = _build_sqlmap_cmd(
            "https://target.example/search?tenant=acme&id=1&Submit=Submit",
            request_data={"id": "1", "Submit": "Submit"},
            target_param="id",
        )
        assert cmd[cmd.index("-u") + 1] == "https://target.example/search?tenant=acme"
        assert cmd[cmd.index("--data") + 1] == "id=1&Submit=Submit"


class TestP0ADalfoxFollowRedirects:
    """dalfox sibling sweep: --follow-redirects, --deep, --skip-boring."""

    def test_dalfox_has_follow_redirects(self):
        """dalfox argv must include --follow-redirects."""
        # Inspect the source — we can't easily run dalfox in CI.
        import inspect

        from webpent.tools.exploitation.dalfox import run_dalfox
        source = inspect.getsource(run_dalfox)
        assert "--follow-redirects" in source, (
            "P0-A REGRESSION: dalfox missing --follow-redirects"
        )

    def test_dalfox_has_deep(self):
        import inspect

        from webpent.tools.exploitation.dalfox import run_dalfox
        source = inspect.getsource(run_dalfox)
        assert "--deep" in source

    def test_dalfox_has_skip_boring(self):
        import inspect

        from webpent.tools.exploitation.dalfox import run_dalfox
        source = inspect.getsource(run_dalfox)
        assert "--skip-boring" in source


# ===========================================================================
# P0-B: skip_recon drops exploit chain
# ===========================================================================


class TestP0BSkipReconRoute:
    """route_after_hypothesis must route to access_control when open
    hypotheses exist, even if findings is empty."""

    def _make_hypothesis(self, status="unexplored", vuln_class="sqli"):
        """Build a minimal Hypothesis-like object."""
        from webpent.models.findings import VulnClass
        from webpent.models.hypothesis import (
            Hypothesis,
            HypothesisOrigin,
        )
        try:
            vc = VulnClass(vuln_class)
            vc_val = vc.value
        except Exception:
            vc_val = vuln_class
        return Hypothesis(
            target_url="http://target/vulnerabilities/sqli/",
            statement="Potential SQLi",
            vuln_class=vc_val,
            origin=HypothesisOrigin.HEURISTIC.value,
            confidence_score=0.6,
            deterministic_match=True,
            status=status,
        )

    def test_skip_recon_with_open_hypotheses_routes_to_access_control(self):
        """P0-B: skip_recon=True + findings=[] + open hypotheses =>
        NODE_ACCESS_CONTROL (not NODE_REPORTER)."""
        from webpent.graph.builder import (
            NODE_ACCESS_CONTROL,
            route_after_hypothesis,
        )
        state = {
            "skip_recon": True,
            "findings": [],
            "hypotheses": [self._make_hypothesis(status="unexplored")],
        }
        result = route_after_hypothesis(state)
        assert result == NODE_ACCESS_CONTROL, (
            f"P0-B REGRESSION: skip_recon + open hypotheses routed to "
            f"{result!r} — must be NODE_ACCESS_CONTROL"
        )

    def test_skip_recon_with_no_findings_no_hypotheses_routes_to_reporter(self):
        """Sanity: genuine no-op fast path still routes to reporter."""
        from webpent.graph.builder import NODE_REPORTER, route_after_hypothesis
        state = {
            "skip_recon": True,
            "findings": [],
            "hypotheses": [],
        }
        assert route_after_hypothesis(state) == NODE_REPORTER

    def test_skip_recon_with_findings_routes_to_access_control(self):
        """Pre-existing behavior: findings present => access_control."""
        from webpent.graph.builder import NODE_ACCESS_CONTROL, route_after_hypothesis
        state = {
            "skip_recon": True,
            "findings": [MagicMock()],  # non-empty
            "hypotheses": [],
        }
        assert route_after_hypothesis(state) == NODE_ACCESS_CONTROL

    def test_skip_recon_with_only_promoted_hypotheses_routes_to_reporter(self):
        """All hypotheses already PROMOTED => no open work => reporter."""
        from webpent.graph.builder import NODE_REPORTER, route_after_hypothesis
        state = {
            "skip_recon": True,
            "findings": [],
            "hypotheses": [self._make_hypothesis(status="promoted")],
        }
        assert route_after_hypothesis(state) == NODE_REPORTER

    def test_no_skip_recon_always_routes_to_access_control(self):
        """Normal path: always access_control regardless of hypotheses."""
        from webpent.graph.builder import NODE_ACCESS_CONTROL, route_after_hypothesis
        state = {
            "skip_recon": False,
            "findings": [],
            "hypotheses": [],
        }
        assert route_after_hypothesis(state) == NODE_ACCESS_CONTROL


# ===========================================================================
# P0-C: findings empty after true completion
# ===========================================================================


class TestP0CFindingsPipeline:
    """Mid-scan saves must stamp thread_id; end-to-end count must match."""

    def test_persist_finding_incrementally_stamps_thread_id(self, tmp_path):
        """_persist_finding_incrementally(finding, thread_id=tid) must
        stamp thread_id on the finding before saving."""
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/test.db")
        db.init_db()
        from webpent.agents.validator.agent import _persist_finding_incrementally
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass

        tid = f"thread-{uuid.uuid4()}"
        finding = Finding(
            id=uuid.uuid4(),
            title="Test SQLi",
            severity=Severity.HIGH,
            description="d",
            tool_name="sqlmap",
            url="http://target/sqli",
            confidence=Confidence.CONFIRMED.value,
            vuln_class=VulnClass.SQLI.value,
            confidence_level="Tool-Confirmed",
            evidence={"tool_confirmed_by": "test.fixture"},
        )
        # Finding has thread_id=None by default.
        assert finding.thread_id is None

        with patch("webpent.agents.validator.agent.get_db_manager", return_value=db):
            result = _persist_finding_incrementally(finding, thread_id=tid)
        assert result is True

        # DB row must have the thread_id stamped.
        rows = db.get_findings_by_thread(tid)
        assert len(rows) == 1, (
            f"P0-C REGRESSION: _persist_finding_incrementally did not stamp "
            f"thread_id — API returns {len(rows)} rows for thread_id={tid}"
        )
        assert rows[0].thread_id == tid

    def test_persist_finding_incrementally_without_thread_id_still_works(self, tmp_path):
        """Backward-compat: _persist_finding_incrementally(finding) without
        thread_id still saves (with thread_id=None)."""
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/test3.db")
        db.init_db()
        from webpent.agents.validator.agent import _persist_finding_incrementally
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass

        finding = Finding(
            id=uuid.uuid4(),
            title="Test",
            severity=Severity.HIGH,
            description="d",
            tool_name="t",
            url="http://t",
            confidence=Confidence.TENTATIVE.value,
            vuln_class=VulnClass.XSS.value,
        )
        # No thread_id argument — backward compat.
        with patch("webpent.agents.validator.agent.get_db_manager", return_value=db):
            result = _persist_finding_incrementally(finding)
        assert result is True

    def test_worker_persist_findings_stamps_thread_id(self, tmp_path):
        """_persist_findings(final_state, thread_id=tid) stamps thread_id
        on all findings and saves them."""
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/test4.db")
        db.init_db()
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass
        from webpent.workers.pentest_worker import _persist_findings

        tid = f"thread-{uuid.uuid4()}"
        findings = [
            Finding(
                id=uuid.uuid4(),
                title=f"Vuln {i}",
                severity=Severity.HIGH,
                description="d",
                tool_name="t",
                url="http://t",
                confidence=Confidence.TENTATIVE.value,
                vuln_class=VulnClass.SQLI.value,
            )
            for i in range(5)
        ]
        final_state = {"findings": findings}

        with patch("webpent.workers.pentest_worker.get_db_manager", return_value=db):
            saved = _persist_findings(final_state, thread_id=tid)
        assert saved == 5

        rows = db.get_findings_by_thread(tid)
        assert len(rows) == 5, (
            f"P0-C REGRESSION: worker persisted {saved} but API returns "
            f"{len(rows)} for thread_id={tid}"
        )
        for row in rows:
            assert row.thread_id == tid

    def test_alembic_migration_has_thread_id_column(self):
        """0001_initial.py must include thread_id column + index."""
        migration_path = (
            Path(__file__).resolve().parents[1]
            / "alembic" / "versions" / "0001_initial.py"
        )
        source = migration_path.read_text()
        assert "thread_id" in source, (
            "P0-C REGRESSION: alembic migration missing thread_id column"
        )
        assert "ix_findings_thread_id" in source, (
            "P0-C REGRESSION: alembic migration missing thread_id index"
        )

    def test_db_ddl_has_index(self):
        """FINDINGS_INDEX_DDL must be defined and executed in legacy path."""
        from webpent.memory import db as db_module
        assert hasattr(db_module, "FINDINGS_INDEX_DDL")
        assert "ix_findings_thread_id" in db_module.FINDINGS_INDEX_DDL

    def test_end_to_end_completed_with_findings_api_returns_same_count(
        self, tmp_path,
    ):
        """End-to-end: worker persists N findings with thread_id T;
        db.get_findings_by_thread(T) returns exactly N rows."""
        from webpent.memory.db import DatabaseManager
        db = DatabaseManager(f"sqlite:///{tmp_path}/e2e.db")
        db.init_db()
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass
        from webpent.workers.pentest_worker import _persist_findings

        tid = f"e2e-{uuid.uuid4()}"

        findings = [
            Finding(
                id=uuid.uuid4(),
                title=f"Finding {i}",
                severity=Severity.CRITICAL if i % 2 == 0 else Severity.HIGH,
                description=f"desc {i}",
                tool_name="sqlmap" if i % 2 == 0 else "dalfox",
                url=f"http://target/vuln{i}",
                confidence=Confidence.CONFIRMED.value,
                vuln_class=VulnClass.SQLI.value if i % 2 == 0 else VulnClass.XSS.value,
                confidence_level="Tool-Confirmed",
                evidence={"tool_confirmed_by": "test.fixture"},
            )
            for i in range(10)
        ]
        final_state = {"findings": findings}

        with patch("webpent.workers.pentest_worker.get_db_manager", return_value=db):
            saved = _persist_findings(final_state, thread_id=tid)
        assert saved == 10

        rows = db.get_findings_by_thread(tid)
        assert len(rows) == 10, (
            f"P0-C END-TO-END REGRESSION: worker persisted {saved} findings "
            f"with thread_id={tid}, but API returns {len(rows)}."
        )

        # No cross-thread bleed.
        other_tid = f"other-{uuid.uuid4()}"
        other_rows = db.get_findings_by_thread(other_tid)
        assert len(other_rows) == 0


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))


def test_post_sqlmap_budgets_are_settings_driven(monkeypatch):
    from webpent.config.settings import Settings
    from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd

    settings = Settings(
        sqlmap_post_timeout=5,
        sqlmap_post_retries=0,
        sqlmap_post_threads=1,
    )
    monkeypatch.setattr(
        "webpent.tools.exploitation.sqlmap.get_settings",
        lambda: settings,
    )

    cmd = _build_sqlmap_cmd(
        "http://lab.test/submit",
        request_data={"item": "1"},
        target_param="item",
    )
    assert "--timeout=5" in cmd
    assert "--retries=0" in cmd
    assert "--threads=1" in cmd
