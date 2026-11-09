#!/usr/bin/env python3
"""tests/test_v9_p0_hotfix_sqlmap_reauth.py — V9 P0 hostile-review hotfix regression tests.

Locks in two fixes found during a hostile review of the "P0-A sqlmap /
session" patch:

1. P0-A: ``validator._deterministic_check("sqli", ...)`` used to
   duplicate an unguarded keyword list that false-positived on
   sqlmap's own NEGATIVE result message ("all tested parameters do
   NOT appear to be injectable") because that sentence contains the
   substring "injectable". Combined with the sqli fast-path that
   skips the LLM supervisor when det_confirmed=True, this
   auto-confirmed SQLi findings on NON-vulnerable targets with zero
   human/LLM check. Fixed by deleting the duplicate keyword list and
   delegating to ``tools.exploitation.sqlmap.parse_sqlmap_confirmation``
   (the negative-guarded parser) as the single source of truth.

2. P0-B: a dead session (302 -> login.php) mid-scan always fell back
   to "Needs Human Review", even when operator credentials were
   available in state and an automated re-login could have fixed it.
   Fixed with an in-validator retry: one re-login attempt via the
   existing Playwright login helper, then ONE (not two) tool
   invocation with the refreshed cookies. No credentials -> unchanged
   fail-closed behavior.

Run: python -m pytest tests/test_v9_p0_hotfix_sqlmap_reauth.py -v
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.validator import agent as validator_agent  # noqa: E402
from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402

NEGATIVE_SQLMAP_OUTPUT = (
    "[15:41:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n"
    "[15:41:10] [WARNING] GET parameter 'id' does not seem to be injectable\n"
    "[15:41:10] [CRITICAL] all tested parameters do not appear to be "
    "injectable. Try to increase values for '--level'/'--risk' options "
    "if you wish to perform more tests."
)

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


class TestP0ASqlmapDeterministicCheck:
    """A negative sqlmap scan must never be treated as confirmed."""

    def test_negative_output_is_not_confirmed(self):
        assert validator_agent._deterministic_check("sqli", NEGATIVE_SQLMAP_OUTPUT) is False

    def test_positive_output_is_still_confirmed(self):
        assert validator_agent._deterministic_check("sqli", POSITIVE_SQLMAP_OUTPUT) is True

    def test_xss_path_is_unaffected(self):
        dalfox_positive = "[V] Triggered XSS Payload (GET): localhost:8080"
        assert validator_agent._deterministic_check("xss", dalfox_positive) is True

    def test_sqli_no_longer_has_a_duplicate_unguarded_keyword_list(self):
        # The whole point of the fix: "sqli" must not exist in the bare
        # keyword dict anymore -- sqli goes through the guarded parser.
        assert "sqli" not in validator_agent._DETERMINISTIC_SUCCESS_KEYWORDS


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


class TestP0BReauthRetry:
    """Dead session + credentials -> exactly one re-login + one tool call."""

    def test_relogin_success_runs_tool_once_with_fresh_cookies(self):
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
            tool_entry.func = MagicMock(return_value=POSITIVE_SQLMAP_OUTPUT)
            mock_get_tool.return_value = tool_entry

            result = validator_agent._validate_with_tool(
                _make_sqli_finding(), "sqli", llm=MagicMock(),
                session_cookies=session_cookies,
                credentials=credentials,
                target_url="http://192.168.40.128/dvwa/",
            )

            mock_login.assert_called_once_with(
                "http://192.168.40.128/dvwa/", "admin", "password",
            )
            # Exactly ONE tool invocation, using the FRESH cookies.
            tool_entry.func.assert_called_once()
            assert tool_entry.func.call_args.kwargs["session_cookies"] == {
                "PHPSESSID": "freshcookie", "security": "low",
            }
            assert result.confidence == Confidence.CONFIRMED.value
            assert result.confidence_level == "Tool-Confirmed"
            assert result.evidence.get("session_reauth") is True
            # The caller's dict object was mutated in place so it
            # propagates to validator_node's state update.
            assert session_cookies == {"PHPSESSID": "freshcookie", "security": "low"}

    def test_no_credentials_stays_fail_closed(self):
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}

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
                credentials=None,
                target_url="http://192.168.40.128/dvwa/",
            )

            assert mock_login.called is False
            assert tool_entry.func.called is False
            assert result.confidence_level == "Needs Human Review"
            assert result.evidence.get("session_dead") is True
            assert result.evidence.get("reauth_attempted") is False

    def test_relogin_failure_stays_fail_closed(self):
        session_cookies = {"PHPSESSID": "deadbeef", "security": "low"}
        credentials = {"username": "admin", "password": "wrong"}

        with patch(
            "webpent.shared.http.make_safe_httpx_client",
            return_value=_FakeProbeClient(),
        ), patch(
            "webpent.agents.validator.agent.baseline_differential_test",
            return_value=_NOT_FALSE_POSITIVE,
        ), patch(
            "webpent.agents.authentication.agent._perform_login",
            return_value={},
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

            mock_login.assert_called_once()
            assert tool_entry.func.called is False
            assert result.confidence_level == "Needs Human Review"
            assert result.evidence.get("reauth_attempted") is True
            assert result.evidence.get("reauth_succeeded") is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
