#!/usr/bin/env python3
"""tests/test_v10_p1_rca_followup.py — V10 P0+P1 (RCA follow-up) regression tests.

Covers the structural fixes from the hostile RCA follow-up:

P0-1: VulnClass enum expansion (idor, auth_bypass, mass_assignment,
      request_smuggling, brute_force, captcha, weak_session, csp,
      javascript, cryptography, api_issue) + "Not Scanned"
      confidence_level.
P0-2: access_control/api_testing no longer silently swallow
      ValidationError on Finding construction.
P0-3: Open Redirect path classification + ?redirect=http://
      priority over SSRF misroute.
P0-4: Explicit "Not Scanned" finding emitted when no detector
      covers the seed URL.
P1-5: api_testing urljoin fix (preserves /dvwa/ prefix).
P2:   deterministic_match bypasses EXPLOITABLE_CLASSES gate so
      structural validators can run.

Run: python -m pytest tests/test_v10_p1_rca_followup.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure src/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.hypothesis_analyzer.agent import (  # noqa: E402
    _analyze_url_for_hypotheses,
    _classify_by_url_path,
)
from webpent.models.findings import (  # noqa: E402
    EXPLOITABLE_CLASSES,
    Finding,
    Severity,
    VulnClass,
)
from webpent.models.hypothesis import Hypothesis  # noqa: E402
from webpent.shared.prioritization import (  # noqa: E402
    PrioritizationAction,
    promote_hypothesis_to_finding,
    recommend_action,
)

# ---------------------------------------------------------------------------
# P0-1: VulnClass enum accepts all new members + idor
# ---------------------------------------------------------------------------

class TestVulnClassEnumExpansion:
    """Every new vuln_class must be representable in Finding without ValidationError."""

    @pytest.mark.parametrize(
        "vuln_class",
        [
            VulnClass.IDOR.value,
            VulnClass.AUTH_BYPASS.value,
            VulnClass.MASS_ASSIGNMENT.value,
            VulnClass.REQUEST_SMUGGLING.value,
            VulnClass.BRUTE_FORCE.value,
            VulnClass.CAPTCHA.value,
            VulnClass.WEAK_SESSION.value,
            VulnClass.CSP.value,
            VulnClass.JAVASCRIPT.value,
            VulnClass.CRYPTOGRAPHY.value,
            VulnClass.API_ISSUE.value,
            VulnClass.RACE_CONDITION.value,
        ],
    )
    def test_finding_construction_succeeds(self, vuln_class):
        """Finding(vuln_class=...) must not raise ValidationError."""
        f = Finding(
            title=f"Test {vuln_class}",
            severity=Severity.MEDIUM,
            description=f"Test finding for {vuln_class}",
            tool_name="test",
            url="http://target/test",
            vuln_class=vuln_class,
        )
        assert f.vuln_class == vuln_class

    def test_not_scanned_confidence_level_accepted(self):
        """V10 P0-4: 'Not Scanned' must be a valid confidence_level."""
        f = Finding(
            title="Not Scanned test",
            severity=Severity.INFO,
            description="test",
            tool_name="test",
            url="http://target/test",
            vuln_class=VulnClass.UNKNOWN.value,
            confidence_level="Not Scanned",
        )
        assert f.confidence_level == "Not Scanned"

    def test_idor_finding_construction(self):
        """V10 P0-1: idor must be a real enum member, not a raw string."""
        f = Finding(
            title="IDOR test",
            severity=Severity.HIGH,
            description="test",
            tool_name="access_control_mapper",
            url="http://target/api/users/123",
            vuln_class=VulnClass.IDOR.value,
        )
        assert f.vuln_class == "idor"

    def test_mass_assignment_finding_construction(self):
        """V10 P0-1: mass_assignment must be a real enum member."""
        f = Finding(
            title="Mass assignment test",
            severity=Severity.HIGH,
            description="test",
            tool_name="api_testing_agent",
            url="http://target/api/v1/user",
            vuln_class=VulnClass.MASS_ASSIGNMENT.value,
        )
        assert f.vuln_class == "mass_assignment"

    def test_request_smuggling_finding_construction(self):
        """V10 P0-1: request_smuggling must be a real enum member."""
        f = Finding(
            title="Request smuggling test",
            severity=Severity.CRITICAL,
            description="test",
            tool_name="request_smuggling_detector",
            url="http://target/",
            vuln_class=VulnClass.REQUEST_SMUGGLING.value,
        )
        assert f.vuln_class == "request_smuggling"


# ---------------------------------------------------------------------------
# P0-3: Open Redirect path + ?redirect=http:// classification
# ---------------------------------------------------------------------------

class TestOpenRedirectClassification:
    """V10 P0-3: open_redirect path + param heuristics."""

    def test_bare_open_redirect_path_classified(self):
        """skip_recon=true + /dvwa/vulnerabilities/open_redirect/ → OPEN_REDIRECT."""
        result = _classify_by_url_path(
            "http://192.168.40.128/dvwa/vulnerabilities/open_redirect/"
        )
        assert result is not None
        assert result[0] == VulnClass.OPEN_REDIRECT.value

    def test_open_redirect_with_redirect_param_classified_as_open_redirect(self):
        """?redirect=http://google.com on open_redirect surface → OPEN_REDIRECT, not SSRF."""
        hypotheses = _analyze_url_for_hypotheses(
            "http://192.168.40.128/dvwa/vulnerabilities/open_redirect/?redirect=http://google.com"
        )
        vuln_classes = [h[0] for h in hypotheses]
        assert VulnClass.OPEN_REDIRECT.value in vuln_classes
        # SSRF should NOT be emitted for a redirect param on an
        # open_redirect surface.
        assert VulnClass.SSRF.value not in vuln_classes

    def test_url_param_on_non_open_redirect_surface_still_ssrf(self):
        """?url=http://... on a non-open-redirect surface → SSRF (classic)."""
        hypotheses = _analyze_url_for_hypotheses(
            "http://192.168.40.128/dvwa/api/fetch?url=http://internal-host/"
        )
        vuln_classes = [h[0] for h in hypotheses]
        assert VulnClass.SSRF.value in vuln_classes

    def test_redirect_param_on_non_open_redirect_surface_is_open_redirect(self):
        """?redirect=http://... on a non-open-redirect surface → OPEN_REDIRECT."""
        hypotheses = _analyze_url_for_hypotheses(
            "http://192.168.40.128/dvwa/login?redirect=http://evil.com"
        )
        vuln_classes = [h[0] for h in hypotheses]
        assert VulnClass.OPEN_REDIRECT.value in vuln_classes
        assert VulnClass.SSRF.value not in vuln_classes


# ---------------------------------------------------------------------------
# P0-3: New DVWA path patterns
# ---------------------------------------------------------------------------

class TestNewPathPatterns:
    """All 8 new DVWA path segments must classify correctly."""

    @pytest.mark.parametrize(
        "path,expected_class",
        [
            ("/dvwa/vulnerabilities/csp/", "csp"),
            ("/dvwa/vulnerabilities/weak_id/", "weak_session"),
            ("/dvwa/vulnerabilities/javascript/", "javascript"),
            ("/dvwa/vulnerabilities/captcha/", "captcha"),
            ("/dvwa/vulnerabilities/cryptography/", "cryptography"),
            ("/dvwa/vulnerabilities/brute/", "brute_force"),
            ("/dvwa/vulnerabilities/authorisation/", "auth_bypass"),
            ("/dvwa/vulnerabilities/authorization/", "auth_bypass"),
            ("/dvwa/vulnerabilities/auth_bypass/", "auth_bypass"),
            ("/dvwa/vulnerabilities/api/", "api_issue"),
        ],
    )
    def test_path_classification(self, path, expected_class):
        url = f"http://192.168.40.128{path}"
        result = _classify_by_url_path(url)
        assert result is not None, f"{path} did not classify"
        assert result[0] == expected_class, f"{path} -> {result[0]}, expected {expected_class}"

    def test_api_segment_safe_no_false_positive(self):
        """'api' must be a standalone segment — /rapid/ must not match."""
        result = _classify_by_url_path("http://target/rapid/")
        assert result is None or result[0] != VulnClass.API_ISSUE.value

    def test_csp_segment_safe_no_false_positive(self):
        """'csp' must be a standalone segment — /csrf/ must not match csp."""
        # csrf classifies as csrf, NOT csp.
        result = _classify_by_url_path("http://target/dvwa/vulnerabilities/csrf/")
        assert result is not None
        assert result[0] == VulnClass.CSRF.value
        assert result[0] != VulnClass.CSP.value


# ---------------------------------------------------------------------------
# P1-5: api_testing urljoin fix
# ---------------------------------------------------------------------------

class TestApiTestingUrlJoinFix:
    """V10 P1-5, superseded by TEAM-1 (2026-10, Section-8 DVWA-decoupling).

    The private ``_resolve_url()`` these tests originally covered always
    preserved the DVWA ``/dvwa/`` prefix and NEVER tried plain host-root
    resolution — correct for DVWA, silently wrong for any real target with
    no app-level path prefix (see webpent.shared.url_resolution's module
    docstring for the full rationale). It was replaced by
    ``resolve_url_candidates()``, which returns BOTH the standard
    host-root URL and the DVWA-style app-root-preserving URL so the
    caller can probe both instead of assuming one. These tests are
    updated to the new return shape (a list of candidates) rather than
    deleted, so the original DVWA-prefix-preservation guarantee stays
    covered — it's not gone, just no longer the ONLY candidate produced.
    """

    def test_resolve_url_candidates_preserves_dvwa_prefix(self):
        from webpent.shared.url_resolution import resolve_url_candidates
        base = "http://192.168.40.128/dvwa/vulnerabilities/api/"
        results = resolve_url_candidates(base, "/graphql")
        assert any(r.endswith("/dvwa/graphql") for r in results), (
            f"/dvwa/ prefix candidate missing: {results}"
        )

    def test_resolve_url_candidates_also_offers_host_root(self):
        """Unlike the old DVWA-only helper, a real non-DVWA target (no app
        prefix) must also get a plain host-root candidate, or a target
        shaped like a flat API would silently never be probed correctly.
        """
        from webpent.shared.url_resolution import resolve_url_candidates
        base = "http://192.168.40.128/dvwa/vulnerabilities/api/"
        results = resolve_url_candidates(base, "/graphql")
        assert "http://192.168.40.128/graphql" in results

    def test_resolve_url_candidates_absolute_url_unchanged(self):
        from webpent.shared.url_resolution import resolve_url_candidates
        results = resolve_url_candidates(
            "http://target/dvwa/api/",
            "http://other-host/path",
        )
        assert results == ["http://other-host/path"]


# ---------------------------------------------------------------------------
# P0-2: access_control Finding construction (no silent swallow)
# ---------------------------------------------------------------------------

class TestAccessControlFindingConstruction:
    """V10 P0-1/P0-2: IDOR finding construction must succeed."""

    def test_create_idor_finding_uses_legal_enum(self):
        from webpent.agents.access_control.agent import _create_idor_finding
        f = _create_idor_finding(
            "http://target/api/users/123",
            200,
            500,
            "without any authentication",
        )
        assert f.vuln_class == VulnClass.IDOR.value
        assert f.confidence_level == "AI-Assessed"


# ---------------------------------------------------------------------------
# P2: deterministic_match bypasses EXPLOITABLE_CLASSES gate
# ---------------------------------------------------------------------------

class TestDeterministicBypassesExploitabilityGate:
    """V10 P2: structural classes (CSP etc.) must be promotable with deterministic_match."""

    @pytest.mark.parametrize(
        "vuln_class",
        [
            VulnClass.CSP.value,
            VulnClass.WEAK_SESSION.value,
            VulnClass.JAVASCRIPT.value,
            VulnClass.AUTH_BYPASS.value,
            VulnClass.API_ISSUE.value,
            VulnClass.CRYPTOGRAPHY.value,
            VulnClass.CAPTCHA.value,
            VulnClass.BRUTE_FORCE.value,
        ],
    )
    def test_deterministic_match_promotes_non_exploitable_class(self, vuln_class):
        """A deterministic_match=True hypothesis for a structural class must be promoted."""
        h = Hypothesis(
            target_url=f"http://target/dvwa/vulnerabilities/{vuln_class}/",
            statement=f"Potential {vuln_class.upper()} at test URL",
            vuln_class=vuln_class,
            confidence_score=0.6,
            deterministic_match=True,
        )
        state = {"findings": [], "mental_model": {}}

        # recommend_action must return PROMOTE.
        action, score, rule = recommend_action(h, state, rabbit_hole_available=False)
        assert action == PrioritizationAction.PROMOTE, (
            f"{vuln_class}: action={action}, expected PROMOTE. rule={rule}"
        )

        # promote_hypothesis_to_finding must NOT return None (which the
        # EXPLOITABLE_CLASSES gate would cause without the bypass).
        finding = promote_hypothesis_to_finding(h, state)
        assert finding is not None, f"{vuln_class}: promote returned None"
        assert finding.vuln_class == vuln_class

    def test_non_deterministic_non_exploitable_class_still_blocked(self):
        """Control: without deterministic_match, structural classes are still blocked."""
        h = Hypothesis(
            target_url="http://target/dvwa/vulnerabilities/csp/",
            statement="Potential CSP at test URL",
            vuln_class=VulnClass.CSP.value,
            confidence_score=0.6,
            deterministic_match=False,
        )
        state = {"findings": [], "mental_model": {}}
        finding = promote_hypothesis_to_finding(h, state)
        # Should be blocked by EXPLOITABLE_CLASSES gate.
        assert finding is None

    def test_new_structural_classes_not_in_exploitable_classes(self):
        """Structural classes must NOT be in EXPLOITABLE_CLASSES (no payload injection)."""
        structural = {
            VulnClass.CSP.value,
            VulnClass.WEAK_SESSION.value,
            VulnClass.JAVASCRIPT.value,
            VulnClass.AUTH_BYPASS.value,
            VulnClass.API_ISSUE.value,
            VulnClass.CRYPTOGRAPHY.value,
            VulnClass.CAPTCHA.value,
            VulnClass.BRUTE_FORCE.value,
            VulnClass.IDOR.value,
            VulnClass.MASS_ASSIGNMENT.value,
            VulnClass.REQUEST_SMUGGLING.value,
            VulnClass.RACE_CONDITION.value,
        }
        for vc in structural:
            assert vc not in EXPLOITABLE_CLASSES, (
                f"{vc} should NOT be in EXPLOITABLE_CLASSES — it is structural, "
                f"not payload-injection exploitable"
            )


# ---------------------------------------------------------------------------
# P0-4: Not Scanned finding emission (integration-level)
# ---------------------------------------------------------------------------

class TestNotScannedEmission:
    """V10 P0-4: hypothesis_node emits Not Scanned for unknown paths.

    This tests the classification logic only — the full hypothesis_node
    requires a LangGraph state with Target etc., which is heavy to set
    up in a unit test. The integration is covered by the operator's
    verification curls.
    """

    def test_unknown_path_returns_none_from_classifier(self):
        """An unknown path must return None from _classify_by_url_path."""
        result = _classify_by_url_path("http://target/some/random/page/")
        assert result is None

    def test_known_path_returns_classification(self):
        """A known path must return a non-None classification."""
        result = _classify_by_url_path("http://target/dvwa/vulnerabilities/brute/")
        assert result is not None
        assert result[0] == VulnClass.BRUTE_FORCE.value
