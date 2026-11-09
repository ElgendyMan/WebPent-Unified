#!/usr/bin/env python3
"""tests/test_v10_p0_reauth_vault_and_emergency_persist.py

V10 regression tests for the two P0 fixes:

P0-1 — emergency persist must not rely on locals().get("graph")
  * _emergency_persist_findings(None, None, ...) returns 0 and logs
    an explicit SKIPPED message (not a silent 0).
  * The 4 call sites in run_pentest_task / resume_pentest_task pass
    the graph/config variables explicitly (verified by static
    inspection — grep returns zero locals().get(...) outside
    comments).

P0-2 Option A — sealed reauth vault unblocks mid-scan re-auth after
  FIX-10 has scrubbed the password from state.
  * vault roundtrip: seal -> unseal -> clear.
  * vault empty cases: empty thread_id, empty password, missing key.
  * validator dead-session branch: when state password is "" but
    the vault has a sealed secret, re-auth runs and succeeds.
  * validator dead-session branch: when both state and vault are
    empty, the finding gets evidence["reauth_unavailable"]=True +
    Needs Human Review (fail-loud, not silent).

Run: python -m pytest tests/test_v10_p0_reauth_vault_and_emergency_persist.py -v
"""
from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.validator import agent as validator_agent  # noqa: E402
from webpent.auth.reauth_vault import (  # noqa: E402
    clear_reauth_secret,
    seal_reauth_secret,
    unseal_reauth_secret,
)
from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402

# --------------------------------------------------------------------------
# P0-1: _emergency_persist_findings None-safety
# --------------------------------------------------------------------------


class TestP01EmergencyPersistNoneSafe:
    """graph=None / config=None must log an explicit SKIPPED, not silent 0."""

    def test_none_graph_returns_zero_and_logs_skipped(self, caplog):
        from webpent.workers.pentest_worker import _emergency_persist_findings
        with caplog.at_level(logging.WARNING, logger="webpent.workers.pentest_worker"):
            result = _emergency_persist_findings(
                None, None,
                context="run_pentest_task[Exception]",
                thread_id="t-test",
            )
        assert result == 0
        # The skip must be VISIBLE in the logs — not a silent 0.
        assert any(
            "SKIPPED" in r.getMessage() and "graph or config is None" in r.getMessage()
            for r in caplog.records
        ), f"expected SKIPPED log; got {[r.getMessage() for r in caplog.records]}"

    def test_none_config_with_built_graph_returns_zero_and_logs_skipped(self, caplog):
        from webpent.workers.pentest_worker import _emergency_persist_findings
        # graph is not None but config IS None — still a skip.
        with caplog.at_level(logging.WARNING, logger="webpent.workers.pentest_worker"):
            result = _emergency_persist_findings(
                object(), None,
                context="resume_pentest_task[Exception]",
                thread_id="t-test",
            )
        assert result == 0
        assert any(
            "SKIPPED" in r.getMessage() for r in caplog.records
        )

    def test_no_locals_get_in_worker_outside_comments(self):
        """Static check: zero locals().get(...) calls in executable code.

        Uses ``ast`` to extract Call nodes only — docstrings and comments
        are excluded automatically by the AST parse.
        """
        import ast
        worker_path = (
            Path(__file__).resolve().parents[1]
            / "src" / "webpent" / "workers" / "pentest_worker.py"
        )
        source = worker_path.read_text()
        tree = ast.parse(source)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Match locals().get(...) — Call where func is an
                # Attribute (.get) whose value is a Call to Name('locals').
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "get"
                    and isinstance(func.value, ast.Call)
                    and isinstance(func.value.func, ast.Name)
                    and func.value.func.id == "locals"
                ):
                    violations.append(
                        f"line {node.lineno}: locals().get(...) call"
                    )
        assert not violations, (
            "P0-1 violation: pentest_worker.py still calls locals().get() "
            "in executable code: " + "; ".join(violations)
        )


# --------------------------------------------------------------------------
# P0-2: reauth vault roundtrip + empty cases
# --------------------------------------------------------------------------


class TestP02VaultRoundtrip:
    def test_seal_unseal_clear_roundtrip(self):
        tid = "t-roundtrip"
        try:
            seal_reauth_secret(tid, "s3cret")
            assert unseal_reauth_secret(tid) == "s3cret"
        finally:
            clear_reauth_secret(tid)
        assert unseal_reauth_secret(tid) is None

    def test_seal_noop_on_empty_thread_id(self):
        seal_reauth_secret("", "s3cret")
        assert unseal_reauth_secret("") is None

    def test_seal_noop_on_empty_password(self):
        tid = "t-empty-pw"
        try:
            seal_reauth_secret(tid, "")
            assert unseal_reauth_secret(tid) is None
        finally:
            clear_reauth_secret(tid)

    def test_unseal_missing_key_returns_none(self):
        assert unseal_reauth_secret("nonexistent-thread") is None

    def test_clear_missing_key_is_silent_noop(self):
        # Must not raise.
        clear_reauth_secret("never-sealed")

    def test_reseal_overwrites(self):
        tid = "t-reseal"
        try:
            seal_reauth_secret(tid, "first")
            seal_reauth_secret(tid, "second")
            assert unseal_reauth_secret(tid) == "second"
        finally:
            clear_reauth_secret(tid)


# --------------------------------------------------------------------------
# P0-2: validator dead-session path uses the vault
# --------------------------------------------------------------------------


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

POSITIVE_SQLMAP_OUTPUT = (
    "[15:41:05] [INFO] GET parameter 'id' is vulnerable. Do you want to "
    "keep testing the others (if any)? [y/N] N\n"
    "sqlmap identified the following injection point(s) with a total of "
    "47 HTTP(s) requests:\n"
    "---\n"
    "Parameter: id (GET)\n"
    "    Type: boolean-based blind\n"
    "---\n"
)


class TestP02ValidatorVaultReauth:
    """Dead session + scrubbed state password + vault has secret -> re-auth succeeds."""

    def test_vault_secret_unblocks_reauth_after_fix10_scrub(self):
        """State password is "" (FIX-10 scrubbed) but vault has the secret.

        Validator must look up the vault, re-login, and run the tool once
        with fresh cookies — same end-state as the existing "credentials
        present in state" success path.
        """
        tid = "t-vault-success"
        # State credentials: username present, password SCRUBBED (FIX-10).
        credentials = {"username": "admin", "password": ""}
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}

        try:
            seal_reauth_secret(tid, "real-password")
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
                tool_entry.func = MagicMock(return_value=POSITIVE_SQLMAP_OUTPUT)
                mock_get_tool.return_value = tool_entry

                result = validator_agent._validate_with_tool(
                    _make_sqli_finding(), "sqli", llm=MagicMock(),
                    session_cookies=session_cookies,
                    credentials=credentials,
                    target_url="http://192.168.40.128/dvwa/",
                    thread_id=tid,
                )

                # Re-login was attempted with the VAULT password, not the
                # empty state password.
                mock_login.assert_called_once_with(
                    "http://192.168.40.128/dvwa/", "admin", "real-password",
                )
                # Tool ran once with the fresh cookies.
                tool_entry.func.assert_called_once()
                assert tool_entry.func.call_args.kwargs["session_cookies"] == {
                    "PHPSESSID": "freshcookie", "security": "low",
                }
                # Finding is Tool-Confirmed, with reauth_source=vault.
                assert result.confidence == Confidence.CONFIRMED.value
                assert result.confidence_level == "Tool-Confirmed"
                assert result.evidence.get("session_reauth") is True
                assert result.evidence.get("reauth_source") == "vault"
        finally:
            clear_reauth_secret(tid)

    def test_vault_empty_and_state_scrubbed_yields_reauth_unavailable(self):
        """State password scrubbed (FIX-10) AND vault empty (worker restart).

        Validator must NOT silently fail. It must:
          * log ERROR with "re-auth UNAVAILABLE"
          * mark finding Needs Human Review
          * set evidence["reauth_unavailable"]=True
          * set evidence["reauth_attempted"]=False
          * NOT call _perform_login (no doomed login attempt)
          * NOT call the tool (no false-negative run with dead cookies)
        """
        tid = "t-vault-empty"
        credentials = {"username": "admin", "password": ""}  # FIX-10 scrub
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}

        # Vault is NOT sealed for this tid.
        assert unseal_reauth_secret(tid) is None

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
                thread_id=tid,
            )

            # No re-login attempted (vault empty, state scrubbed).
            assert mock_login.called is False
            # No tool invocation (would produce false negatives with dead cookies).
            assert tool_entry.func.called is False
            # Fail-loud signals.
            assert result.confidence_level == "Needs Human Review"
            assert result.evidence.get("session_dead") is True
            assert result.evidence.get("reauth_attempted") is False
            assert result.evidence.get("reauth_unavailable") is True
            assert result.evidence.get("reauth_source") == "none"

    def test_state_password_takes_precedence_over_vault(self):
        """If state still has a password (e.g. login failed, no scrub),
        it takes precedence over the vault. reauth_source=state.
        """
        tid = "t-state-precedence"
        credentials = {"username": "admin", "password": "state-pw"}
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}

        try:
            seal_reauth_secret(tid, "vault-pw-should-not-be-used")
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
                tool_entry.func = MagicMock(return_value=POSITIVE_SQLMAP_OUTPUT)
                mock_get_tool.return_value = tool_entry

                result = validator_agent._validate_with_tool(
                    _make_sqli_finding(), "sqli", llm=MagicMock(),
                    session_cookies=session_cookies,
                    credentials=credentials,
                    target_url="http://192.168.40.128/dvwa/",
                    thread_id=tid,
                )

                mock_login.assert_called_once_with(
                    "http://192.168.40.128/dvwa/", "admin", "state-pw",
                )
                assert result.evidence.get("reauth_source") == "state"
        finally:
            clear_reauth_secret(tid)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
