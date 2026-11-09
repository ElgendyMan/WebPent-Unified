# tests/team1_acceptance/test_behavioral_validator_refactor.py
"""BEHAVIORAL VALIDATOR REFACTOR — generic pattern matching tests.

Sprint deliverable: validators no longer depend on Juice Shop response formats
(JSON field names like 'basket'/'email', hard-coded 'html' content-type gate,
target-specific error strings).  These unit tests exercise the refactored
validators with SYNTHETIC responses in arbitrary formats (HTML, plain text,
XML, non-Juice-Shop JSON) — no HTTP, no target application needed.

Covers:
  PART 2 — generic helpers: responses_similar, marker_reflected,
           response_differs, has_error_signature
  PART 3 — refactored validators: IDOR/BOLA, XSS, SSRF, Open Redirect,
           Info Disclosure (plus Mass Assignment / Auth Bypass regression)
  PART 4.1 — unit tests with synthetic responses
  PART 4.2 — Juice Shop regression (JSON format still confirms)
  PART 4.3 — WebGoat generalization (HTML/plain-text responses now confirm)
"""
from __future__ import annotations

import pytest

from webpent.production.validators import (
    VALIDATORS,
    EvidenceQuality,
    ValidationOutcome,
    has_error_signature,
    marker_reflected,
    response_differs,
    responses_similar,
    validate_auth_bypass,
    validate_idor,
    validate_info_disclosure,
    validate_mass_assignment,
    validate_open_redirect,
    validate_ssrf,
    validate_xss,
)


def _ev(status, body="", headers=None, **extra):
    ev = {"status_code": status, "response_body": body, "headers": headers or {}}
    ev.update(extra)
    return ev


# ============================================================================
# PART 2 — Generic comparison helpers (pure logic, no format assumptions)
# ============================================================================

class TestResponsesSimilar:
    def test_identical_responses_are_similar(self):
        a = _ev(200, '{"id":1,"data":"abc"}')
        assert responses_similar(a, a) is True

    def test_same_status_size_and_overlap_is_similar(self):
        # Same resource, only a dynamic timestamp differs — should be "similar".
        a = _ev(200, "<html><body>Account 12345 balance 500.00 ts=2026-01-01T00:00:00</body></html>")
        b = _ev(200, "<html><body>Account 12345 balance 500.00 ts=2026-01-02T11:22:33</body></html>")
        assert responses_similar(a, b) is True

    def test_different_status_is_not_similar(self):
        assert responses_similar(_ev(200, "ok"), _ev(403, "ok")) is False

    def test_size_beyond_tolerance_is_not_similar(self):
        small = _ev(200, "short body")
        large = _ev(200, "x" * 500)
        assert responses_similar(small, large) is False

    def test_different_content_is_not_similar(self):
        # Two different resources (different account data) — must NOT be similar.
        owner = _ev(200, "<html>owner statement 42</html>")
        foreign = _ev(200, "<html>foreign statement 7</html>")
        assert responses_similar(owner, foreign) is False

    def test_plain_text_responses_similar(self):
        # No JSON, no HTML — pure behavioral comparison must still work.
        a = _ev(200, "User profile: name=JohnDoe email=john@example.com id=42")
        b = _ev(200, "User profile: name=JohnDoe email=john@example.com id=42 sid=ab")
        assert responses_similar(a, b) is True


class TestMarkerReflected:
    MARKER = "webpent_xss_9f8e7d"

    def test_raw_marker_reflected(self):
        assert marker_reflected(self.MARKER, _ev(200, f"<p>hello {self.MARKER}</p>")) is True

    def test_marker_accepts_raw_body_string(self):
        assert marker_reflected(self.MARKER, f"text {self.MARKER} more") is True

    def test_html_encoded_only_is_not_reflected(self):
        encoded = self.MARKER.replace("<", "&lt;").replace(">", "&gt;")
        # marker has no < > so encoded == raw here; use a payload with brackets.
        payload = "<script>alert(1)</script>"
        encoded_body = payload.replace("<", "&lt;").replace(">", "&gt;")
        assert marker_reflected(payload, _ev(200, encoded_body)) is False

    def test_url_encoded_only_is_not_reflected(self):
        payload = "<script>x</script>"
        encoded = payload.replace("<", "%3C").replace(">", "%3E")
        assert marker_reflected(payload, _ev(200, encoded)) is False

    def test_marker_absent_is_not_reflected(self):
        assert marker_reflected(self.MARKER, _ev(200, "no marker here")) is False

    def test_empty_marker_is_not_reflected(self):
        assert marker_reflected("", _ev(200, "anything")) is False

    def test_raw_and_encoded_both_present_still_reflected(self):
        payload = "<script>z</script>"
        encoded = payload.replace("<", "&lt;").replace(">", "&gt;")
        body = f"raw {payload} and encoded {encoded}"
        assert marker_reflected(payload, _ev(200, body)) is True


class TestResponseDiffers:
    def test_different_status_differs(self):
        assert response_differs(_ev(200, "x"), _ev(404, "x")) is True

    def test_identical_do_not_differ(self):
        a = _ev(200, "same body")
        assert response_differs(a, a) is False

    def test_large_size_diff_differs(self):
        assert response_differs(_ev(200, "tiny"), _ev(200, "y" * 400)) is True


class TestHasErrorSignature:
    def test_4xx_is_error(self):
        is_err, matches = has_error_signature(_ev(403, ""))
        assert is_err is True

    def test_5xx_is_error(self):
        is_err, _ = has_error_signature(_ev(500, "boom"))
        assert is_err is True

    def test_error_text_pattern(self):
        is_err, matches = has_error_signature(_ev(200, "An error occurred: invalid input"))
        assert is_err is True
        assert len(matches) >= 1

    def test_clean_200_is_not_error(self):
        is_err, matches = has_error_signature(_ev(200, '{"ok":true,"data":[1,2,3]}'))
        assert is_err is False
        assert matches == ()


# ============================================================================
# PART 3.1 / 3.2 — IDOR / BOLA refactored (generic, works on any format)
# ============================================================================

class TestIDORGeneralization:
    """WebGoat-style targets: HTML / plain-text responses, no Juice Shop fields."""

    def test_webgoat_html_idor_confirmed(self):
        # Baseline (owner) and candidate (foreign) both return the SAME account
        # page as HTML, differing only by a per-request nonce.  Control 404.
        owner = _ev(200, "<html><h1>Account #1001</h1><p>Balance: $250.00</p><span nonce='a1b2c3'></span></html>")
        foreign = _ev(200, "<html><h1>Account #1001</h1><p>Balance: $250.00</p><span nonce='d4e5f6'></span></html>")
        control = _ev(404, "<html><h1>Not Found</h1></html>")
        r = validate_idor(baseline=owner, candidate=foreign, negative_control=control)
        assert r.outcome == ValidationOutcome.CONFIRMED, r.discriminating_signal
        assert r.is_confirmation_grade()

    def test_webgoat_plain_text_idor_confirmed(self):
        # Entirely non-HTML, non-JSON format — behavioral only.
        owner = _ev(200, "RECORD id=777 owner=acme balance=1200.50 ref=ABC-1")
        foreign = _ev(200, "RECORD id=777 owner=acme balance=1200.50 ref=XYZ-9")
        control = _ev(403, "ERROR: record not found or access denied")
        r = validate_idor(baseline=owner, candidate=foreign, negative_control=control)
        assert r.outcome == ValidationOutcome.CONFIRMED, r.discriminating_signal

    def test_bola_alias_uses_same_generic_validator(self):
        owner = _ev(200, "<xml><obj><id>55</id><name>doc.pdf</name></obj></xml>")
        foreign = _ev(200, "<xml><obj><id>55</id><name>doc.pdf</name></obj><ts>1</ts></xml>")
        control = _ev(404, "<xml><error>missing</error></xml>")
        r = validate_idor(baseline=owner, candidate=foreign, negative_control=control)
        assert r.outcome == ValidationOutcome.CONFIRMED
        # BOLA registry entry dispatches to the same generic validator.
        assert VALIDATORS["BOLA"] is VALIDATORS["IDOR"]

    def test_different_resource_still_inconclusive(self):
        owner = _ev(200, "<html>Account #1001 balance 250</html>")
        foreign = _ev(200, "<html>Account #2002 balance 999</html>")
        control = _ev(404, "<html>not found</html>")
        r = validate_idor(baseline=owner, candidate=foreign, negative_control=control)
        assert r.outcome == ValidationOutcome.INCONCLUSIVE

    def test_juice_shop_json_regression_still_confirmed(self):
        """PART 4.2 — Juice Shop format must still confirm (no regression)."""
        r = validate_idor(
            baseline=_ev(200, '{"id":1,"basketId":3,"email":"a@test.com"}'),
            candidate=_ev(200, '{"id":1,"basketId":3,"email":"a@test.com"}'),
            negative_control=_ev(404, '{"error":"Not found"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_refuted_when_foreign_denied(self):
        r = validate_idor(
            baseline=_ev(200, "ok data"),
            candidate=_ev(403, "forbidden"),
            negative_control=_ev(404, "nf"),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ============================================================================
# PART 3.3 — XSS refactored (marker_reflected, no hard HTML content-type gate)
# ============================================================================

class TestXSSGeneralization:
    PAYLOAD = "<script>webpent_xss_9f8e7d()</script>"

    def test_xss_reflected_in_plain_text_confirmed(self):
        # Reflected in a text/plain response — old validator required 'html' in
        # content-type and would return INCONCLUSIVE here.
        r = validate_xss(
            baseline=_ev(200, "search results: none"),
            candidate=_ev(200, f"results for: {self.PAYLOAD}", {"content-type": "text/plain; charset=utf-8"}, payload=self.PAYLOAD),
            negative_control=_ev(200, "results for: "),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED, r.discriminating_signal

    def test_xss_encoded_only_refuted(self):
        encoded = self.PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
        r = validate_xss(
            baseline=_ev(200, "q="),
            candidate=_ev(200, f"q={encoded}", {"content-type": "text/html"}, payload=self.PAYLOAD),
            negative_control=_ev(200, "q="),
        )
        assert r.outcome == ValidationOutcome.REFUTED

    def test_xss_marker_in_control_inconclusive(self):
        r = validate_xss(
            baseline=_ev(200, f"echo {self.PAYLOAD}"),
            candidate=_ev(200, f"echo {self.PAYLOAD}", payload=self.PAYLOAD),
            negative_control=_ev(200, f"echo {self.PAYLOAD}"),
        )
        assert r.outcome != ValidationOutcome.CONFIRMED

    def test_xss_binary_content_type_inconclusive(self):
        r = validate_xss(
            baseline=_ev(200, ""),
            candidate=_ev(200, self.PAYLOAD, {"content-type": "image/png"}, payload=self.PAYLOAD),
            negative_control=_ev(200, ""),
        )
        assert r.outcome == ValidationOutcome.INCONCLUSIVE


# ============================================================================
# PART 3.4 — SSRF refactored (generic internal-indicator differential)
# ============================================================================

class TestSSRFGeneralization:
    def test_single_strong_internal_ip_confirms(self):
        # Old validator required >=2 indicator classes AND control status in
        # (400,403,404).  Generic path accepts one strong indicator.
        r = validate_ssrf(
            baseline=_ev(200, '{"fetched":"https://api.example.com/data"}'),
            candidate=_ev(200, '{"fetched":"http://10.0.0.5/internal-api/users"}'),
            negative_control=_ev(400, "invalid url scheme"),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED, r.discriminating_signal

    def test_no_differential_refuted(self):
        r = validate_ssrf(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"ok":true}'),
            negative_control=_ev(400, "bad"),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ============================================================================
# PART 3.5 — Open Redirect (already behavioral; regression check)
# ============================================================================

class TestOpenRedirectRegression:
    def test_external_redirect_confirmed(self):
        r = validate_open_redirect(
            baseline=_ev(302, "", {"location": "https://trusted.com/home"}),
            candidate=_ev(302, "", {"location": "https://evil.com/steal"}),
            negative_control=_ev(200, "", {}),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_trusted_redirect_refuted(self):
        r = validate_open_redirect(
            baseline=_ev(302, "", {"location": "https://trusted.com"}),
            candidate=_ev(302, "", {"location": "https://trusted.com/dash"}),
            negative_control=_ev(200, "", {}),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ============================================================================
# PART 3.6 — Info Disclosure refactored (generic error-signature indicator)
# ============================================================================

class TestInfoDisclosureGeneralization:
    def test_verbose_500_error_confirms(self):
        # A 500 with a stack-trace-like error body now counts as a disclosure
        # indicator class even without the old hard-coded path strings.
        r = validate_info_disclosure(
            baseline=_ev(200, '{"public":"data"}'),
            candidate=_ev(500, "Internal Server Error. Exception in thread main: NullPointerException at com.example.App.handle (App.java:42). Stack trace: ..."),
            negative_control=_ev(200, '{"ok":true}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED, r.discriminating_signal

    def test_version_only_still_refuted(self):
        r = validate_info_disclosure(
            baseline=_ev(200, '{"ok":true}'),
            candidate=_ev(200, '{"version":"12.4.1"}'),
            negative_control=_ev(200, '{"ok":true}'),
        )
        assert r.outcome == ValidationOutcome.REFUTED


# ============================================================================
# Regression: Mass Assignment + Auth Bypass still behave
# ============================================================================

class TestOtherValidatorsRegression:
    def test_mass_assignment_still_confirms(self):
        r = validate_mass_assignment(
            baseline=_ev(200, '{"role":"user"}'),
            candidate=_ev(200, '{"role":"admin","is_admin":true}'),
            negative_control=_ev(200, '{"role":"user"}'),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED

    def test_auth_bypass_still_confirms(self):
        r = validate_auth_bypass(
            baseline=_ev(401, "unauthorized"),
            candidate=_ev(200, "welcome admin"),
            negative_control=_ev(403, "forbidden"),
        )
        assert r.outcome == ValidationOutcome.CONFIRMED


# ============================================================================
# Security non-regression: no validator confirms without a real differential
# ============================================================================

class TestNoFakeConfirmation:
    def test_all_same_evidence_never_confirms(self):
        for fam, vf in VALIDATORS.items():
            if fam == "BOLA":
                continue
            r = vf(baseline=_ev(200, "same"), candidate=_ev(200, "same"), negative_control=_ev(200, "same"))
            assert r.outcome != ValidationOutcome.CONFIRMED, f"{fam} confirmed without differential"

    def test_missing_evidence_fails_closed(self):
        with pytest.raises(Exception):
            validate_idor(baseline=None, candidate=_ev(200), negative_control=_ev(404))
