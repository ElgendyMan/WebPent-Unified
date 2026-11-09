#!/usr/bin/env python3
"""tests/test_v9_fix2_path_promotion.py — V9 P0 Fix 2 regression tests.

Covers the two things the hostile audit found broken:

1. ``_classify_by_url_path`` — correctness on the operator's URL table,
   plus the narrowed "fi" pattern (V9 P0 Fix 2-C) so it no longer
   false-positives on paths that merely contain "fi" as a substring
   (config.php, profile.php, notification.php, ...).

2. The promotion gate — ``recommend_action`` must PROMOTE a
   deterministic path-classified hypothesis even though its score
   (~0.28-0.42 under current Mental Model / cost defaults) never
   clears the probabilistic ``PROMOTION_THRESHOLD`` of 0.5. This is
   the actual regression: Fix 2's classifier worked from day one, but
   without this bypass the resulting hypothesis was silently DEFERRED
   forever and sqlmap/dalfox never ran.

Run: python -m pytest tests/test_v9_fix2_path_promotion.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Ensure src/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.agents.hypothesis_analyzer.agent import _classify_by_url_path  # noqa: E402
from webpent.models.hypothesis import Hypothesis  # noqa: E402
from webpent.shared.prioritization import (  # noqa: E402
    PrioritizationAction,
    promote_hypothesis_to_finding,
    recommend_action,
)


class TestClassifyByUrlPath:
    """Operator's audit table, verbatim, plus the 'fi' false-positive fix."""

    @pytest.mark.parametrize(
        "url,expected_class",
        [
            ("http://192.168.40.128/dvwa/vulnerabilities/sqli/", "sqli"),
            ("http://192.168.40.128/dvwa/vulnerabilities/sqli_blind/", "sqli"),
            ("http://192.168.40.128/dvwa/vulnerabilities/xss_r/", "xss"),
            ("http://192.168.40.128/dvwa/vulnerabilities/xss_s/", "xss"),
            ("http://192.168.40.128/dvwa/login.php", None),
            ("http://192.168.40.128/dvwa/", None),
        ],
    )
    def test_operator_table(self, url, expected_class):
        result = _classify_by_url_path(url)
        got = result[0] if result else None
        assert got == expected_class, f"{url} -> {got!r}, expected {expected_class!r}"

    def test_fi_requires_path_segment_not_substring(self):
        """V9 P0 Fix 2-C: 'fi' must not match inside other words."""
        false_positives = [
            "http://target/dvwa/config.php",
            "http://target/dvwa/profile.php",
            "http://target/notifications",
            "http://target/verify-account",
        ]
        for url in false_positives:
            result = _classify_by_url_path(url)
            assert result is None, f"{url} incorrectly classified as {result}"

        # The real DVWA LFI page must still match.
        result = _classify_by_url_path("http://target/dvwa/vulnerabilities/fi/")
        assert result is not None and result[0] == "lfi"


class TestDeterministicPromotionBypass:
    """V9 P0 Fix 2-B: deterministic_match must bypass the score gate."""

    def _make_hypothesis(self, *, deterministic_match: bool, vuln_class: str = "sqli",
                          confidence_score: float = 0.6) -> Hypothesis:
        return Hypothesis(
            target_url="http://192.168.40.128/dvwa/vulnerabilities/sqli/",
            statement=f"Potential {vuln_class.upper()} at test URL",
            vuln_class=vuln_class,
            confidence_score=confidence_score,
            deterministic_match=deterministic_match,
        )

    def test_deterministic_hypothesis_is_promoted_despite_low_score(self):
        h = self._make_hypothesis(deterministic_match=True)
        state = {"findings": [], "mental_model": {}}
        action, score, rule = recommend_action(h, state, rabbit_hole_available=False)

        assert score < 0.5, (
            "test assumption violated: score formula changed and now "
            "clears 0.5 on its own — this test needs to be re-derived"
        )
        assert action == PrioritizationAction.PROMOTE
        assert "deterministic" in rule.lower()

    def test_non_deterministic_hypothesis_at_same_score_still_defers(self):
        """Control: the global probabilistic threshold must be untouched."""
        h = self._make_hypothesis(deterministic_match=False)
        state = {"findings": [], "mental_model": {}}
        action, score, _ = recommend_action(h, state, rabbit_hole_available=False)

        assert score < 0.5
        assert action != PrioritizationAction.PROMOTE

    def test_promoted_finding_has_correct_vuln_class_for_validator_dispatch(self):
        h = self._make_hypothesis(deterministic_match=True, vuln_class="sqli")
        state = {"findings": [], "mental_model": {}}
        recommend_action(h, state, rabbit_hole_available=False)
        finding = promote_hypothesis_to_finding(h, state)

        assert finding is not None
        assert finding.vuln_class == "sqli"
        assert finding.hypothesis_id == h.id
