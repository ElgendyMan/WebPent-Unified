#!/usr/bin/env python3
"""tests/test_v9_round2_wiring_fixes.py — Round-2 residual-audit regression tests.

Locks in the fixes made during the round-2 hostile wiring audit:

1. payload_generator_node now only generates browser-injection payload
   strings (and seeds ``payloads_to_test``) for XSS findings, since
   execution_sandbox_node is the only consumer of that state field.
   sqli/csrf/ssrf/rce/deserialization findings previously got a wasted
   LLM payload-generation call every pass (and every optimizer retry)
   for payloads nothing downstream ever reads.
   Also: the first generated candidate is now written to
   ``finding.payload`` so Stage 0 (differential/baseline testing) in
   the validator can actually run for XSS, instead of the field
   staying ``None`` forever.

2. execution_sandbox_node:
   a. clears the module-level ``_LAST_LOGIN_COOKIES`` cache on entry,
      closing a cross-engagement/cross-invocation session-cookie leak
      (the cache was previously only ever cleared on a fresh
      successful login, never on entry).
   b. defensively skips any non-XSS finding in the per-finding
      payload-test loop, protecting resumed engagements whose
      checkpointed state predates fix (1) above.

3. validator._validate_with_tool's Stage 0 (differential/baseline
   false-positive) check now logs explicitly when it is skipped due
   to a missing ``finding.payload``, instead of silently falling
   through with no log line.

4. reporter_node no longer crashes uncaught (the graph's LAST node)
   if legacy Markdown composition/save fails or the output directory
   is unavailable; it degrades gracefully instead.

Run: python -m pytest tests/test_v9_round2_wiring_fixes.py -v
"""
from __future__ import annotations

import sys
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.execution_sandbox import agent as sandbox_agent  # noqa: E402
from webpent.agents.payload_generator import agent as payload_gen_agent  # noqa: E402
from webpent.agents.reporter import agent as reporter_agent  # noqa: E402
from webpent.agents.validator import agent as validator_agent  # noqa: E402
from webpent.models.findings import Confidence, Finding, VulnClass  # noqa: E402
from webpent.models.targets import Target  # noqa: E402

_NOT_FALSE_POSITIVE = SimpleNamespace(is_false_positive=False, reason="")


def _make_finding(vuln_class: str, *, severity: str = "high") -> Finding:
    return Finding(
        id=uuid.uuid4(),
        title=f"{vuln_class} finding",
        url="http://192.168.40.128/dvwa/vulnerabilities/x/?id=1",
        vuln_class=vuln_class,
        severity=severity,
        confidence=Confidence.TENTATIVE.value,
        confidence_level="Pending",
        description="test",
        tool_name="dynamic_prioritization",
    )


# ---------------------------------------------------------------------------
# 1. payload_generator_node: XSS-only payload-string generation
# ---------------------------------------------------------------------------
class TestPayloadGeneratorClassGating:
    """payloads_to_test is seeded for XSS (a real LLM-generated payload
    string, consumed by execution_sandbox_node) and for sqli (a
    synthetic, non-executable marker — see V9 FIX-4 below), but not for
    other tool/OOB-driven vuln classes (csrf, ssrf, rce, ...).

    V9 FIX-4 UPDATE: sqli findings now get a synthetic
    "__SQLMAP_TOOL_DRIVEN__" marker written to both
    payloads_to_test[fid] and finding.payload. This is NOT a real
    exploit candidate — sqlmap does its own internal payload discovery
    and never consumes it. Its only purpose is making sqli findings
    satisfy route_after_validator's `fid in payloads_to_test` gate, so
    a sqli finding that fails to confirm on the first validator pass is
    retry-eligible instead of being permanently excluded. This is safe
    ONLY because validator._validate_with_tool's Stage 0 differential
    test now unconditionally skips sqli regardless of finding.payload
    (see tests/test_hostile_audit_v9_fixes.py::TestStage0SqliExclusion)
    — without that companion fix, this marker would get diffed against
    a baseline URL and produce false "Needs Human Review" downgrades
    before sqlmap ever ran."""

    def _run(self, findings: list[Finding]):
        state = {"findings": findings}
        with patch(
            "webpent.agents.payload_generator.agent.get_llm",
            return_value=MagicMock(),
        ), patch(
            "webpent.agents.payload_generator.agent._generate_payloads_for_finding",
            return_value=(["<script>alert(1)</script>", "p2", "p3"], "canary-token-123"),
        ) as mock_generate:
            result = payload_gen_agent.payload_generator_node(state)
        return result, mock_generate

    def test_xss_and_sqli_get_payloads_to_test_entry_csrf_does_not(self):
        xss = _make_finding(VulnClass.XSS.value)
        sqli = _make_finding(VulnClass.SQLI.value)
        csrf = _make_finding(VulnClass.CSRF.value)
        result, _ = self._run([xss, sqli, csrf])

        assert str(xss.id) in result["payloads_to_test"]
        assert result["payloads_to_test"][str(xss.id)] == [
            "<script>alert(1)</script>", "p2", "p3",
        ]
        # V9 FIX-4: sqli gets the synthetic tool-driven marker, not a
        # real payload string — see class docstring.
        assert str(sqli.id) in result["payloads_to_test"]
        assert result["payloads_to_test"][str(sqli.id)] == ["__SQLMAP_TOOL_DRIVEN__"]
        # csrf has no tool-driven marker mechanism — stays absent.
        assert str(csrf.id) not in result["payloads_to_test"]

    def test_generate_payloads_llm_call_only_made_for_xss(self):
        xss = _make_finding(VulnClass.XSS.value)
        sqli = _make_finding(VulnClass.SQLI.value)
        rce = _make_finding(VulnClass.RCE.value)
        _, mock_generate = self._run([xss, sqli, rce])

        # The whole point of the fix: no wasted LLM payload-generation
        # calls for tool/OOB-driven vuln classes.
        mock_generate.assert_called_once()
        assert mock_generate.call_args.args[0].id == xss.id

    def test_xss_finding_gets_payload_and_canary_set(self):
        xss = _make_finding(VulnClass.XSS.value)
        result, _ = self._run([xss])

        updated = next(f for f in result["findings"] if f.id == xss.id)
        assert updated.payload == "<script>alert(1)</script>"
        assert updated.canary_token == "canary-token-123"

    def test_sqli_finding_gets_synthetic_marker_not_llm_payload(self):
        sqli = _make_finding(VulnClass.SQLI.value)
        result, _ = self._run([sqli])

        updated = next(f for f in result["findings"] if f.id == sqli.id)
        # V9 FIX-4: synthetic marker, not None (pre-FIX-4 contract) and
        # not a real LLM-generated payload string either — sqlmap does
        # its own internal discovery and never reads finding.payload.
        assert updated.payload == "__SQLMAP_TOOL_DRIVEN__"
        assert updated.canary_token is None
        # Finding is NOT dropped from state — still present for the
        # validator's sqlmap-based confirmation path.
        assert len(result["findings"]) == 1


# ---------------------------------------------------------------------------
# 2. execution_sandbox_node: defense-in-depth fixes
# ---------------------------------------------------------------------------
class TestExecutionSandboxDefenseInDepth:
    def test_stale_login_cookies_cleared_on_entry(self):
        sandbox_agent._LAST_LOGIN_COOKIES.clear()
        sandbox_agent._LAST_LOGIN_COOKIES.update(
            {"PHPSESSID": "leaked-from-prior-engagement"}
        )
        state = {
            "target": Target(url="http://192.168.40.128/dvwa/"),
            "findings": [],
            "payloads_to_test": {},
            "playwright_enabled": False,  # short-circuits before browser launch
        }

        sandbox_agent.execution_sandbox_node(state)

        assert sandbox_agent._LAST_LOGIN_COOKIES == {}

    def test_non_xss_finding_never_reaches_browser_test(self):
        xss = _make_finding(VulnClass.XSS.value)
        sqli = _make_finding(VulnClass.SQLI.value)
        state = {
            "target": Target(url="http://192.168.40.128/dvwa/"),
            "findings": [xss, sqli],
            # Simulates a resumed pre-fix checkpoint: BOTH findings
            # have stale payloads_to_test entries.
            "payloads_to_test": {
                str(xss.id): ["<script>1</script>"],
                str(sqli.id): ["' OR '1'='1"],
            },
            "playwright_enabled": True,
            "credentials": {},
        }

        with patch(
            "webpent.agents.execution_sandbox.agent._try_launch_browser",
            return_value=(MagicMock(), MagicMock()),
        ), patch(
            "webpent.agents.execution_sandbox.agent._test_finding_payloads",
        ) as mock_test:
            mock_test.return_value = xss.model_copy()
            sandbox_agent.execution_sandbox_node(state)

        # Only the XSS finding may be browser-tested, regardless of
        # what stale entries payloads_to_test contains.
        mock_test.assert_called_once()
        assert mock_test.call_args.args[1].id == xss.id


# ---------------------------------------------------------------------------
# 3. validator Stage 0: explicit skip logging
# ---------------------------------------------------------------------------
class TestStage0ExplicitSkipLogging:
    def test_missing_payload_logs_explicit_skip_and_still_reaches_stage1(self, caplog):
        finding = _make_finding(VulnClass.SQLI.value)
        assert finding.payload is None  # precondition for this test

        with patch(
            "webpent.agents.validator.agent.get_tool"
        ) as mock_get_tool, patch(
            "webpent.agents.validator.agent._persist_finding_incrementally",
            return_value=True,
        ), patch(
            "webpent.agents.validator.agent._llm_supervisor_verdict",
            return_value=False,
        ):
            tool_entry = MagicMock()
            tool_entry.func = MagicMock(return_value="sqlmap did not confirm anything")
            mock_get_tool.return_value = tool_entry

            with caplog.at_level("INFO"):
                validator_agent._validate_with_tool(
                    finding, "sqli", llm=MagicMock(),
                )

            # Stage 1 still ran (tool called) even though Stage 0 was
            # skipped -- Stage 0's absence must not block confirmation.
            tool_entry.func.assert_called_once()

        assert any(
            "Stage 0" in rec.message and "SKIPPED" in rec.message
            for rec in caplog.records
        ), "Expected an explicit Stage-0-skipped log line, found none."


# ---------------------------------------------------------------------------
# 4. reporter_node: crash resilience
# ---------------------------------------------------------------------------
class TestReporterCrashResilience:
    def _base_state(self):
        return {
            "target": Target(url="http://192.168.40.128/dvwa/"),
            "findings": [],
            "hypotheses": [],
            "executive_summary": "Pre-computed summary.",
            "risk_score": "Low",
            "decision_log": [],
        }

    def test_markdown_failure_does_not_crash_and_export_still_attempted(self, tmp_path):
        with patch(
            "webpent.agents.reporter.agent.get_settings"
        ) as mock_settings, patch(
            "webpent.agents.reporter.agent._compose_markdown",
            side_effect=RuntimeError("boom: malformed finding field"),
        ), patch(
            "webpent.reporter.export.export_all_formats",
            return_value={"json": tmp_path / "r.json", "html": tmp_path / "r.html", "pdf": None},
        ) as mock_export:
            mock_settings.return_value.ensure_output_dir.return_value = tmp_path

            # Must not raise.
            result = reporter_agent.reporter_node(self._base_state())

        assert result["current_phase"] == "reporting"
        # The JSON/HTML/PDF export must still be attempted even though
        # Markdown composition failed -- it does not depend on markdown.
        mock_export.assert_called_once()

    def test_output_dir_failure_returns_clean_degraded_result(self):
        with patch(
            "webpent.agents.reporter.agent.get_settings"
        ) as mock_settings, patch(
            "webpent.reporter.export.export_all_formats"
        ) as mock_export:
            mock_settings.return_value.ensure_output_dir.side_effect = OSError(
                "Permission denied: /mnt/user-data/outputs"
            )

            # Must not raise.
            result = reporter_agent.reporter_node(self._base_state())

        assert result["current_phase"] == "reporting"
        assert "output directory" in result["messages"][0].content
        # No point attempting an export that needs the same directory.
        mock_export.assert_not_called()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
