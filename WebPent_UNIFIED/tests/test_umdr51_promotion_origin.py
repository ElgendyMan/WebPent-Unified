"""UM-DR-51 P3 regression tests — the promoted finding keeps the real origin.

Root cause this pins: promote_confirmed_finding stamped relative/absent
candidate endpoints with the synthetic ``family-validated-target.local``
host, losing the real campaign origin — every anchor-attributed battery
measurement (TP by declared anchor path) then counted real confirmations
as FP (measured: recall 1.0 -> 0.0, fp 0 -> 3-6 per family, inherited
from the window-50 W2 closure moving promotions through this seam).
"""
from __future__ import annotations

from webpent.agents.validator.family_checks import (
    FamilyValidationResult,
    FamilyVerdict,
)
from webpent.families.promotion import promote_confirmed_finding


def _confirmed(scenario: str = "sc_origin_regression") -> FamilyValidationResult:
    return FamilyValidationResult(
        verdict=FamilyVerdict.CONFIRMED,
        vuln_class="idor_bola",
        scenario_id=scenario,
        rationale="origin regression pin",
        evidence_refs=("e1",),
        proof_bundle_spec={},
    )


def test_origin_url_resolves_relative_endpoint() -> None:
    from webpent.families.base import FamilyCandidate

    finding = promote_confirmed_finding(
        _confirmed(),
        candidate=FamilyCandidate(
            candidate_id="c1", family="business_logic",
            vuln_class="idor_bola", scenario_id="sc1",
            affected_endpoint="/api/Feedbacks", hypothesis="h1",
        ),
        origin_url="http://127.0.0.1:40287",
        verification=None,
    )
    assert finding is not None
    assert finding.url == "http://127.0.0.1:40287/api/Feedbacks"
    # verification=None keeps it an explicit Pending candidate (fail-closed)
    assert finding.confidence_level == "Pending"


def test_origin_url_with_method_prefix_and_path() -> None:
    from webpent.families.base import FamilyCandidate

    finding = promote_confirmed_finding(
        _confirmed("sc_method_prefix"),
        candidate=FamilyCandidate(
            candidate_id="c2", family="business_logic",
            vuln_class="idor_bola", scenario_id="sc2",
            affected_endpoint="GET /workflows/1", hypothesis="h2",
        ),
        origin_url="http://127.0.0.1:40287/",
    )
    assert finding is not None
    assert finding.url == "http://127.0.0.1:40287/workflows/1"


def test_origin_url_fills_absent_endpoint() -> None:
    finding = promote_confirmed_finding(
        _confirmed("sc_absent"), candidate=None,
        origin_url="http://127.0.0.1:40287",
    )
    assert finding is not None
    assert finding.url == "http://127.0.0.1:40287/"


def test_without_origin_the_synthetic_host_stays_explicit() -> None:
    """No origin supplied: the synthetic host remains EXPLICITLY synthetic
    (never a silent wrong-origin claim) — the pre-fix behavior for callers
    that genuinely have no origin, now documented and pinned."""
    finding = promote_confirmed_finding(
        _confirmed("sc_no_origin"), candidate=None,
    )
    assert finding is not None
    assert finding.url == "https://family-validated-target.local/"


def test_absolute_candidate_endpoint_wins() -> None:
    from webpent.families.base import FamilyCandidate

    finding = promote_confirmed_finding(
        _confirmed("sc_absolute"),
        candidate=FamilyCandidate(
            candidate_id="c3", family="business_logic",
            vuln_class="idor_bola", scenario_id="sc3",
            affected_endpoint="http://real-target.example/api/x",
            hypothesis="h3",
        ),
        origin_url="http://127.0.0.1:40287",
    )
    assert finding is not None
    assert finding.url == "http://real-target.example/api/x"
