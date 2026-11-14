"""U-8 cheap-yields full-chain tests (XSS / SQLi / SSRF).

Restored after the workspace reset. 6 tests covering the AVI validator
``cheap-yields`` path for the three "cheap" full-chain vulnerability
families — the ones whose differential is observable in a single
candidate-vs-baseline-vs-control request triple without an external
tool (sqlmap, dalfox, …).

Two tests per family:
  * the positive cheap-yield: validator CONFIRMS on a clean differential.
  * the negative cheap-yield: validator REFUTES on the encoded / clean
    control (no false positive).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.production.validators import (  # noqa: E402
    ValidationOutcome,
    validate_ssrf,
    validate_sqli,
    validate_xss,
)


def _ev(status: int, body: str = "", *, headers: dict | None = None,
        structured: dict | None = None, payload: str | None = None) -> dict:
    ev = {"status_code": status, "response_body": body, "headers": headers or {}}
    if structured:
        ev["structured_fields"] = structured
    if payload is not None:
        ev["payload"] = payload
    return ev


# ---------------------------------------------------------------------------
# XSS — cheap yields (2 tests)
# ---------------------------------------------------------------------------
class TestXssCheapYields:
    PAYLOAD = "<script>document.title='webpent_xss_probe'</script>"

    def test_xss_confirms_on_unencoded_reflection(self):
        """Cheap-yield positive: executable payload reflected unencoded in
        candidate only — CONFIRMED with OBSERVED_DIFFERENTIAL evidence.
        """
        b = _ev(200, "<html>normal page</html>")
        c = _ev(200, f"<html>{self.PAYLOAD}</html>", headers={"Content-Type": "text/html"},
                payload=self.PAYLOAD)
        nc = _ev(200, "<html>control page</html>")
        result = validate_xss(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.CONFIRMED
        assert "unencoded payload reflected" in result.discriminating_signal

    def test_xss_refutes_when_payload_is_html_encoded(self):
        """Cheap-yield negative: HTML-encoded reflection → REFUTED on
        ``output_encoding_enforced`` (no false positive).
        """
        encoded = (self.PAYLOAD.replace("&", "&amp;").replace("<", "&lt;")
                   .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;"))
        b = _ev(200, "<html>normal page</html>")
        c = _ev(200, f"<html>{encoded}</html>", headers={"Content-Type": "text/html"},
                payload=self.PAYLOAD)
        nc = _ev(200, "<html>control page</html>")
        result = validate_xss(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.REFUTED
        assert result.refutation_path == "output_encoding_enforced"


# ---------------------------------------------------------------------------
# SQLi — cheap yields (2 tests)
# ---------------------------------------------------------------------------
class TestSqliCheapYields:
    SQL_PAYLOAD = "' OR '1'='1"

    def test_sqli_confirms_on_error_differential(self):
        """Cheap-yield positive: candidate leaks a SQL error signature
        absent from baseline and control → CONFIRMED.
        """
        b = _ev(200, '{"products":[]}')
        c = _ev(500, "Syntax error near 'OR' at line 1 -- sqlstate[42000]",
                payload=self.SQL_PAYLOAD)
        nc = _ev(200, '{"products":[]}', payload="'")
        result = validate_sqli(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.CONFIRMED

    def test_sqli_refutes_when_control_also_errors(self):
        """Cheap-yield negative: when the negative control itself produces
        a SQL error (control not clean), the candidate cannot be
        confirmed → REFUTED.
        """
        b = _ev(200, '{"products":[]}')
        c = _ev(500, "sqlstate[42000] syntax error near 'OR'",
                payload=self.SQL_PAYLOAD)
        nc = _ev(500, "sqlstate[42000] syntax error near ''",
                 payload="'")
        result = validate_sqli(baseline=b, candidate=c, negative_control=nc)
        # Either REFUTED or INCONCLUSIVE — never CONFIRMED when control
        # is dirty.
        assert result.outcome != ValidationOutcome.CONFIRMED

    # -- U-8 SQLi timing branch (C1(c) TC-2): response_time_ms plumbing ----

    def test_sqli_confirms_on_timing_differential(self):
        """U-8 timing path: candidate delayed >= 1000ms over baseline AND
        >= 2x the control gap → CONFIRMED via OBSERVED_DIFFERENTIAL
        (time-based blind SQLi).
        """
        b = _ev(200, '{"products":[]}')
        b["response_time_ms"] = 50.0
        c = _ev(200, '{"products":[]}', payload="' AND SLEEP(1.5)--")
        c["response_time_ms"] = 1500.0
        nc = _ev(200, '{"products":[]}', payload="'")
        nc["response_time_ms"] = 60.0
        result = validate_sqli(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.CONFIRMED
        assert result.details["baseline_ms"] == 50.0
        assert result.details["candidate_ms"] == 1500.0
        assert result.details["control_ms"] == 60.0

    def test_sqli_refutes_when_timing_gap_is_control_noise(self):
        """Timing differential within control noise (control gap >= 2x the
        candidate delay minus baseline) is NOT evidence → REFUTED.
        """
        b = _ev(200, '{"products":[]}')
        b["response_time_ms"] = 50.0
        c = _ev(200, '{"products":[]}', payload="' AND SLEEP(1.5)--")
        c["response_time_ms"] = 1500.0
        nc = _ev(200, '{"products":[]}', payload="'")
        nc["response_time_ms"] = 800.0  # control gap 750ms -> threshold 1500
        result = validate_sqli(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome != ValidationOutcome.CONFIRMED

    def test_sqli_timing_requires_all_three_observations(self):
        """A broken evidence path (control missing response_time_ms) can
        NEVER confirm via timing — the branch is skipped entirely
        (fail-closed, no half-plumbed evidence).
        """
        b = _ev(200, '{"products":[]}')
        b["response_time_ms"] = 50.0
        c = _ev(200, '{"products":[]}', payload="' AND SLEEP(1.5)--")
        c["response_time_ms"] = 1500.0
        nc = _ev(200, '{"products":[]}', payload="'")  # no response_time_ms
        result = validate_sqli(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome != ValidationOutcome.CONFIRMED
        assert result.details.get("candidate_ms") is None

    def test_execute_real_request_plumbs_response_time_ms(self):
        """C1(c) plumbing: the spine's real-HTTP path returns
        ``response_time_ms`` on every authorized observation (U-8
        instrumentation restored) — measured against a real loopback
        HTTP target.
        """
        from tests.lab.idor_lab_target import start_lab_server
        from tests.team1_acceptance.test_sprint_i2_e2e_walking_skeleton import (
            _make_orchestrator,
        )

        server, base_url = start_lab_server(vulnerable=False)
        try:
            # Register engagement target hosts the same way the E2E fixture does.
            from webpent.shared.engagement_scope import (
                clear_engagement_target_hosts,
                set_engagement_target_hosts,
            )
            tok = set_engagement_target_hosts("127.0.0.1", "localhost")
            try:
                orch = _make_orchestrator(f"u8-timing-{int(time.time() * 1000)}")
                obs = orch.execute_real_request(
                    method="GET", target_url=f"{base_url}/api/invoices/me",
                    hypothesis_id="u8_timing_plumb",
                )
            finally:
                clear_engagement_target_hosts(tok)
            assert obs.get("authorized") is True, obs
            assert obs.get("real_http") is True
            assert obs.get("failed") is not True
            rt = obs.get("response_time_ms")
            assert isinstance(rt, float) and rt >= 0.0, f"response_time_ms missing/bad: {rt!r}"
            assert obs.get("status_code") == 401  # unauthenticated probe still times
        finally:
            server.should_exit = True


# ---------------------------------------------------------------------------
# SSRF — cheap yields (2 tests)
# ---------------------------------------------------------------------------
class TestSsrfCheapYields:
    def test_ssrf_confirms_on_cloud_metadata_differential(self):
        """Cheap-yield positive: candidate fetches 169.254.169.254 and
        leaks ≥2 internal indicators absent from baseline and control →
        CONFIRMED.
        """
        b = _ev(200, '{"ok":true,"data":"public"}')
        c = _ev(200, '{"metadata":{"iam":"role-arn"},"internal-ip":"10.0.0.42",'
                     '"host":"169.254.169.254"}')
        nc = _ev(400, '{"error":"invalid scheme rejected"}')
        result = validate_ssrf(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.CONFIRMED

    def test_ssrf_refutes_when_no_differential(self):
        """Cheap-yield negative: candidate == baseline → no differential →
        REFUTED on ``url_validation_enforced``.
        """
        b = _ev(200, '{"ok":true,"data":"public"}')
        c = _ev(200, '{"ok":true,"data":"public"}')
        nc = _ev(400, '{"error":"invalid scheme rejected"}')
        result = validate_ssrf(baseline=b, candidate=c, negative_control=nc)
        assert result.outcome == ValidationOutcome.REFUTED
        assert result.refutation_path == "url_validation_enforced"
