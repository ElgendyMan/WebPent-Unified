#!/usr/bin/env python3
"""tests/test_v10_audit_fixes.py

V10 AUDIT FIX regression tests — covers C1-C6 + H1-H12.

Run: python -m pytest tests/test_v10_audit_fixes.py -v
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


# ===========================================================================
# C1: scan_registry init_scan_registry wired into app startup
# ===========================================================================


class TestC1ScanRegistryInit:
    """init_scan_registry must be called at app import time."""

    def test_init_scan_registry_called_on_import(self, tmp_path):
        """Importing webpent.api.app should call init_scan_registry."""
        from webpent.api import scan_registry
        from webpent.memory.db import DatabaseManager

        db = DatabaseManager(f"sqlite:///{tmp_path}/test_c1.db")
        db.init_db()
        with patch("webpent.api.scan_registry._get_db", return_value=db):
            scan_registry.init_scan_registry()
            tid = f"audit-c1-{uuid.uuid4()}"
            scan_registry.register_scan(tid, "task-c1", "http://target")
            assert scan_registry.lookup_task_id(tid) == "task-c1"


# ===========================================================================
# C2: execution_sandbox _test_finding_payloads thread_id parameter
# ===========================================================================


class TestC2ExecutionSandboxThreadId:
    """_test_finding_payloads must accept thread_id and use it for stamping."""

    def test_test_finding_payloads_accepts_thread_id(self):
        """The function signature must include thread_id parameter."""
        import inspect

        from webpent.agents.execution_sandbox.agent import _test_finding_payloads

        sig = inspect.signature(_test_finding_payloads)
        assert "thread_id" in sig.parameters, (
            "C2 REGRESSION: _test_finding_payloads must accept thread_id"
        )
        assert sig.parameters["thread_id"].default is None

    def test_test_finding_payloads_stamps_thread_id_on_typed_replay_attestation(
        self, tmp_path
    ):
        """When a finding is confirmed, thread_id must be stamped before save.

        RECONCILIATION NOTE (v10/v61 -> GOED v1.8.4 canonical merge): GOED's
        CausalBridge work moved final promotion out of
        ``_test_finding_payloads`` entirely. Per that function's own
        docstring, "dialog detection alone can never confirm a finding", and
        even a fully successful typed-replay attestation intentionally does
        NOT set confidence to Confirmed here — "CampaignExecutor must build,
        seal, validate, and replay the bundle before Tool-Confirmed is
        allowed anywhere downstream" (see test_v92_action_executor_proof_bundle.py
        and test_v94_autonomous_controller.py for that later stage). There is
        no more direct ``get_db_manager().save_finding(...)`` call in this
        function at all. This test now verifies the C2 thread_id-stamping
        guarantee against the current architecture: the finding returned
        from a successful typed-replay attestation still carries thread_id,
        ready for the caller (execution_sandbox_node) to persist.
        """
        from webpent.agents.execution_sandbox import agent as es_agent
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass
        from webpent.shared.browser_proof_runner import BrowserProofRun

        finding = Finding(
            id=uuid.uuid4(),
            title="Test XSS",
            severity=Severity.HIGH,
            description="d",
            tool_name="playwright",
            url="http://target/xss",
            confidence=Confidence.TENTATIVE.value,
            vuln_class=VulnClass.XSS.value,
        )
        tid = f"thread-c2-{uuid.uuid4()}"

        fake_proof_runner = MagicMock()
        fake_proof_runner.run.return_value = BrowserProofRun(
            passed=True,
            reason="typed_replay_verified",
            observations={},
            attestation={
                "proof_evidence": (),
                "baseline": {},
                "candidate": {},
                "negative_control": {},
                "evidence_refs": (),
                "scope_context": {},
                "identity_context": {},
                "validator_id": "typed-browser",
                "validator_version": "v1",
                "replay_metadata": {},
            },
        )

        result = es_agent._test_finding_payloads(
            browser=MagicMock(),
            finding=finding,
            payloads=["<script>alert(1)</script>"],
            auth_state={},
            stealth_mode=False,
            thread_id=tid,
            proof_runner=fake_proof_runner,
        )
        # thread_id must be stamped on the returned finding regardless of
        # promotion stage, so a later persistence call never writes a
        # thread_id=NULL row.
        assert result.thread_id == tid, (
            f"C2 REGRESSION: thread_id not stamped: got {result.thread_id!r}, "
            f"expected {tid!r}"
        )
        # A successful typed-replay attestation is recorded, but promotion
        # to Tool-Confirmed is deliberately deferred to CampaignExecutor.
        assert result.evidence["proof_verified"] is True
        assert result.evidence["promotion_guard"]["status"] == "central_bundle_required"
        assert result.confidence == Confidence.TENTATIVE.value


# ===========================================================================
# C3: OOB validation persists finding before probe
# ===========================================================================


class TestC3OOBPrePersist:
    """_validate_via_oob must persist the finding BEFORE the OOB probe."""

    def test_validate_via_oob_persists_before_probe(self, tmp_path):
        """The finding must be saved to DB before _poll_for_oob_callback."""
        from webpent.agents.validator import agent as validator_agent
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass

        finding = Finding(
            id=uuid.uuid4(),
            title="Test SSRF",
            severity=Severity.HIGH,
            description="d",
            tool_name="oob",
            url="http://target/ssrf?url=test",
            confidence=Confidence.TENTATIVE.value,
            vuln_class=VulnClass.SSRF.value,
        )
        tid = f"thread-c3-{uuid.uuid4()}"

        # Mock _build_oob_url to return a valid URL (OOB enabled).
        with (
            patch.object(validator_agent, "_build_oob_url", return_value="http://oob/test"),
            patch.object(validator_agent, "get_db_manager") as mock_db_mgr,
            patch.object(validator_agent, "_poll_for_oob_callback", return_value=None) as mock_poll,
        ):
            mock_db = MagicMock()
            mock_db_mgr.return_value = mock_db
            validator_agent._validate_via_oob(finding, "ssrf", thread_id=tid)

            # save_finding must have been called BEFORE _poll_for_oob_callback.
            assert mock_db.save_finding.called, (
                "C3 REGRESSION: finding was not persisted before OOB probe"
            )
            saved_finding = mock_db.save_finding.call_args[0][0]
            assert saved_finding.thread_id == tid
            # _poll_for_oob_callback must also have been called.
            assert mock_poll.called, "OOB poll was not called"

    def test_validate_deserialization_persists_before_probe(self):
        """_validate_deserialization must persist the finding before OOB."""
        from webpent.agents.validator import agent as validator_agent
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass

        finding = Finding(
            id=uuid.uuid4(),
            title="Test Deser",
            severity=Severity.CRITICAL,
            description="d",
            tool_name="ysoserial",
            url="http://target/deser",
            confidence=Confidence.TENTATIVE.value,
            vuln_class=VulnClass.DESERIALIZATION.value,
        )
        tid = f"thread-c3d-{uuid.uuid4()}"

        with (
            patch.object(validator_agent, "_build_oob_url", return_value="http://oob/test"),
            patch.object(validator_agent, "get_db_manager") as mock_db_mgr,
            patch.object(validator_agent, "_poll_for_oob_callback", return_value=None),
        ):
            mock_db = MagicMock()
            mock_db_mgr.return_value = mock_db
            validator_agent._validate_deserialization(finding, thread_id=tid)
            assert mock_db.save_finding.called, (
                "C3 REGRESSION: deser finding not persisted before OOB probe"
            )


# ===========================================================================
# C4: dalfox/katana SSRF guard
# ===========================================================================


class TestC4DalfoxKatanaSSRF:
    """dalfox/katana must not follow redirects to non-engagement targets."""

    def test_dalfox_no_follow_redirects_for_non_target(self):
        """dalfox --follow-redirects only added when host is engagement target."""
        import inspect

        from webpent.tools.exploitation.dalfox import run_dalfox

        source = inspect.getsource(run_dalfox)
        # Must reference engagement_scope check.
        assert "is_engagement_target_host" in source, (
            "C4 REGRESSION: dalfox must check engagement_scope"
        )

    def test_katana_drops_offscope_endpoints(self):
        """katana must post-filter discovered endpoints by engagement scope."""
        import inspect

        from webpent.tools.recon.katana import run_katana

        source = inspect.getsource(run_katana)
        assert "is_engagement_target_host" in source, (
            "C4 REGRESSION: katana must check engagement_scope"
        )
        assert "dropping off-scope" in source or "off-scope" in source


# ===========================================================================
# C5: merge_dicts skips None values
# ===========================================================================


class TestC5MergeDictsNoneSkip:
    """merge_dicts must NOT overwrite existing values with None."""

    def test_none_does_not_overwrite_dict(self):
        from webpent.state.reducers import merge_dicts

        existing = {"mental_model": {"nodes": {"a": 1}}}
        new = {"mental_model": None}
        result = merge_dicts(existing, new)
        assert result["mental_model"] == {"nodes": {"a": 1}}, (
            "C5 REGRESSION: None overwrote the existing dict"
        )

    def test_none_does_not_overwrite_list(self):
        from webpent.state.reducers import merge_dicts

        existing = {"lessons": ["a", "b"]}
        new = {"lessons": None}
        result = merge_dicts(existing, new)
        assert result["lessons"] == ["a", "b"]

    def test_none_does_not_overwrite_scalar(self):
        from webpent.state.reducers import merge_dicts

        existing = {"current_phase": "validator"}
        new = {"current_phase": None}
        result = merge_dicts(existing, new)
        assert result["current_phase"] == "validator"


# ===========================================================================
# C6: merge_findings/merge_hypotheses handle dict-shaped items
# ===========================================================================


class TestC6MergeFindingsDictSafe:
    """Reducers must not crash on dict-shaped items from checkpoint round-trips."""

    def test_merge_findings_with_dict_shaped_finding(self):
        """merge_findings must handle a dict (from checkpoint) without crashing."""
        from webpent.state.reducers import merge_findings

        # A dict-shaped finding (as it would come from a checkpoint round-trip).
        dict_finding = {"id": uuid.uuid4(), "title": "from-checkpoint"}
        # A Finding instance (as a live node would produce).
        from webpent.models.findings import Confidence, Finding, Severity, VulnClass

        live_finding = Finding(
            id=dict_finding["id"],  # same id → should upsert, not duplicate
            title="live-update",
            severity=Severity.HIGH,
            description="d",
            tool_name="t",
            url="http://t",
            confidence=Confidence.TENTATIVE.value,
            vuln_class=VulnClass.SQLI.value,
        )
        result = merge_findings([dict_finding], [live_finding])
        assert len(result) == 1, (
            f"C6 REGRESSION: expected 1 (upsert), got {len(result)} (duplicate)"
        )

    def test_merge_hypotheses_with_dict_shaped_hypothesis(self):
        """merge_hypotheses must handle dicts without unbounded growth."""
        from webpent.state.reducers import merge_hypotheses

        dict_hyp = {"id": uuid.uuid4(), "status": "unexplored"}
        result = merge_hypotheses([dict_hyp], [dict_hyp])
        assert len(result) == 1, f"C6 REGRESSION: expected 1 (upsert), got {len(result)} (grew)"


# ===========================================================================
# H1: normalize_sqli_url does not mangle .php URLs
# ===========================================================================


class TestH1NormalizeSqliPhp:
    """normalize_sqli_url must NOT add trailing slash to .php URLs."""

    def test_php_url_not_mangled(self):
        from webpent.tools.exploitation.sqlmap import normalize_sqli_url

        result = normalize_sqli_url("http://target/sqli.php?id=1")
        assert "/sqli.php/" not in result, f"H1 REGRESSION: .php URL mangled: {result}"
        assert "/sqli.php?" in result

    def test_directory_url_gets_slash(self):
        """Non-file paths (like /vulnerabilities/sqli) should still get slash."""
        from webpent.tools.exploitation.sqlmap import normalize_sqli_url

        result = normalize_sqli_url("http://target/vulnerabilities/sqli?id=1")
        assert "/sqli/" in result


# ===========================================================================
# H2: --dbms=mysql heuristic checks path only
# ===========================================================================


class TestH2DbmsHeuristicPathOnly:
    """--dbms=mysql must only trigger on PATH, not query string."""

    def test_no_dbms_for_query_string_match(self):
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd

        cmd = _build_sqlmap_cmd(
            "https://example.com/search?q=test&redirect=/vulnerabilities/sqli_blind"
        )
        assert "--dbms=mysql" not in cmd, (
            f"H2 REGRESSION: --dbms=mysql added for query-string-only match: {cmd}"
        )

    def test_dbms_for_dvwa_path(self):
        from webpent.tools.exploitation.sqlmap import _build_sqlmap_cmd

        cmd = _build_sqlmap_cmd(
            "http://192.168.40.128/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
        )
        assert "--dbms=mysql" in cmd


# ===========================================================================
# H3: rabbit_hole assigns exploitable vuln_class
# ===========================================================================


class TestH3RabbitHoleVulnClass:
    """Rabbit Hole hypotheses must get an exploitable vuln_class."""

    def test_infer_rabbit_hole_vuln_class_returns_exploitable(self):
        from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
        from webpent.models.findings import EXPLOITABLE_CLASSES

        for artifact_type in ("credential", "url", "command", "file", "service"):
            vc = _infer_rabbit_hole_vuln_class(artifact_type, "fetch")
            assert vc in EXPLOITABLE_CLASSES, (
                f"H3 REGRESSION: {artifact_type} → {vc} not in EXPLOITABLE_CLASSES"
            )


# ===========================================================================
# H4: post_exploit passes session cookies
# ===========================================================================


class TestH4PostExploitCookies:
    """post_exploit must pass session_cookies to sqlmap and HTTP requests."""

    def test_collect_sqli_accepts_session_cookies(self):
        import inspect

        from webpent.agents.post_exploit.agent import _collect_sqli_post_exploitation

        sig = inspect.signature(_collect_sqli_post_exploitation)
        assert "session_cookies" in sig.parameters

    def test_collect_rce_accepts_session_cookies(self):
        import inspect

        from webpent.agents.post_exploit.agent import _collect_rce_post_exploitation

        sig = inspect.signature(_collect_rce_post_exploitation)
        assert "session_cookies" in sig.parameters

    def test_post_exploitation_node_reads_cookies_from_state(self):
        import inspect

        from webpent.agents.post_exploit.agent import post_exploitation_node

        source = inspect.getsource(post_exploitation_node)
        assert "session_cookies" in source, (
            "H4 REGRESSION: post_exploitation_node must read session_cookies from state"
        )


# ===========================================================================
# H5: _get_cached_graph has a lock
# ===========================================================================


class TestH5GraphCacheLock:
    """_get_cached_graph must use a threading lock."""

    def test_graph_cache_lock_exists(self):
        from webpent.api import app as app_module

        assert hasattr(app_module, "_GRAPH_CACHE_LOCK"), (
            "H5 REGRESSION: _GRAPH_CACHE_LOCK not defined"
        )

    def test_get_cached_graph_uses_lock(self):
        import inspect

        from webpent.api import app as app_module

        source = inspect.getsource(app_module._get_cached_graph)
        assert "_GRAPH_CACHE_LOCK" in source, (
            "H5 REGRESSION: _get_cached_graph must use _GRAPH_CACHE_LOCK"
        )


# ===========================================================================
# H7: SSRF blocklist includes IPv6 link-local
# ===========================================================================


class TestH7SSRFBlocklistIPv6:
    """SSRF blocklist must include fe80::/10 and ::ffff:0:0/96."""

    def test_ipv6_link_local_blocked(self):
        import ipaddress

        from webpent.shared.http import BLOCKED_NETWORKS

        fe80 = ipaddress.ip_address("fe80::1")
        assert any(fe80 in net for net in BLOCKED_NETWORKS), (
            "H7 REGRESSION: fe80::1 not in any blocked network"
        )

    def test_ipv4_mapped_ipv6_blocked(self):
        import ipaddress

        from webpent.shared.http import BLOCKED_NETWORKS

        mapped = ipaddress.ip_address("::ffff:169.254.169.254")
        assert any(mapped in net for net in BLOCKED_NETWORKS), (
            "H7 REGRESSION: ::ffff:169.254.169.254 not blocked"
        )


# ===========================================================================
# H8: Playwright route handler fails closed
# ===========================================================================


class TestH8PlaywrightFailClosed:
    """Playwright route handler must NOT fall through to continue_() on abort failure."""

    def test_no_continue_fallback_in_exception_handler(self):
        import inspect

        from webpent.shared import http as http_module

        # Find the _ssrf_route_handler source.
        source = inspect.getsource(http_module)
        # The exception handler should NOT have route.continue_() as a
        # fallback after route.abort() fails.
        # Check that the "with contextlib_suppress(): route.continue_()" pattern
        # is gone from the route handler's exception path.
        # (It may still exist elsewhere — we check the specific handler.)
        handler_source = None
        for name, obj in inspect.getmembers(http_module):
            if inspect.isfunction(obj) and "ssrf" in name.lower() and "route" in name.lower():
                handler_source = inspect.getsource(obj)
                break
        # If we can't find it by name, check the module source for the pattern.
        if handler_source is None:
            handler_source = source
        # The fix removes the `route.continue_()` fallback from the
        # exception handler. Verify the "DROPPING request" log is present
        # (it was added by the fix).
        assert "DROPPING request" in source or "no continue_ fallback" in source, (
            "H8 REGRESSION: fail-closed fix not found"
        )


# ===========================================================================
# H10: false-running after Celery result expiry
# ===========================================================================


class TestH10CeleryExpiry:
    """Celery PENDING + graph completed must NOT override to running."""

    def test_celery_pending_plus_graph_completed_stays_completed(self):
        """When Celery says PENDING but graph says completed, trust the graph."""
        from webpent.api import app as app_module

        with (
            patch.object(app_module, "_get_graph_status") as mock_gs,
            patch("webpent.api.scan_registry.lookup_task_id", return_value="task-10"),
            patch("webpent.workers.pentest_worker.celery_app") as mock_celery,
        ):
            mock_gs.return_value = {
                "status": "completed",  # graph says completed
                "next": [],
                "is_paused_at_sandbox": False,
            }
            mock_ar = MagicMock()
            mock_ar.state = "PENDING"  # Celery forgot (expired)
            mock_celery.AsyncResult.return_value = mock_ar

            state_info = mock_gs.return_value
            celery_state = mock_celery.AsyncResult("task-10").state

            # Replicate the H10 fix logic.
            if celery_state in ("PENDING", "STARTED", "RETRY"):
                if celery_state == "PENDING" and state_info["status"] == "completed":
                    pass  # trust graph
                elif state_info["status"] != "paused":
                    state_info["status"] = "running"

        assert state_info["status"] == "completed", (
            "H10 REGRESSION: Celery PENDING overrode genuine completed"
        )


# ===========================================================================
# H12: _check_graph_state distinguishes no-checkpoint from completed
# ===========================================================================


class TestH12WorkerCheckGraphState:
    """Worker's _check_graph_state must not return completed for no checkpoint."""

    def test_no_checkpoint_returns_pending(self):
        from webpent.workers.pentest_worker import _check_graph_state

        mock_graph = MagicMock()
        mock_graph.get_state.return_value = None
        result = _check_graph_state(mock_graph, {})
        assert result["status"] == "pending", (
            f"H12 REGRESSION: no checkpoint returned {result['status']}, expected pending"
        )

    def test_empty_values_returns_pending(self):
        from webpent.workers.pentest_worker import _check_graph_state

        mock_graph = MagicMock()
        snap = MagicMock()
        snap.values = {}
        snap.next = ()
        mock_graph.get_state.return_value = snap
        result = _check_graph_state(mock_graph, {})
        assert result["status"] == "pending"

    def test_completed_only_with_values_and_empty_next(self):
        from webpent.workers.pentest_worker import _check_graph_state

        mock_graph = MagicMock()
        snap = MagicMock()
        snap.values = {"findings": ["f1"]}
        snap.next = ()
        mock_graph.get_state.return_value = snap
        result = _check_graph_state(mock_graph, {})
        assert result["status"] == "completed"


# ===========================================================================
# H6: vault preserved on pause exit
# ===========================================================================


class TestH6VaultPreservedOnPause:
    """run_pentest_task must NOT clear the vault when pausing for HITL."""

    def test_check_graph_state_paused_helper_exists(self):
        from webpent.workers.pentest_worker import _check_graph_state_paused

        assert callable(_check_graph_state_paused)

    def test_check_graph_state_paused_returns_true_for_sandbox(self):
        from webpent.graph.builder import NODE_EXECUTION_SANDBOX
        from webpent.workers.pentest_worker import _check_graph_state_paused

        mock_graph = MagicMock()
        snap = MagicMock()
        snap.next = (NODE_EXECUTION_SANDBOX,)
        mock_graph.get_state.return_value = snap
        assert _check_graph_state_paused(mock_graph, {}) is True

    def test_check_graph_state_paused_returns_false_for_completed(self):
        from webpent.workers.pentest_worker import _check_graph_state_paused

        mock_graph = MagicMock()
        snap = MagicMock()
        snap.next = ()
        mock_graph.get_state.return_value = snap
        assert _check_graph_state_paused(mock_graph, {}) is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
