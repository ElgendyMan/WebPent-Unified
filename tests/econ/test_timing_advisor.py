"""U-ECON-5 — TimingAdvisor tests (NC-ECON-1 charter, exact test names)."""

from __future__ import annotations

from pathlib import Path

from webpent.econ.market_kb import MarketKB
from webpent.econ.roi_optimizer import Finding, FindingValuation
from webpent.econ.timing_advisor import (
    COLLECT_MORE,
    DEFER,
    HOLD,
    IMPROVE_FIRST,
    REPORT_NOW,
    REPORT_SOON,
    TimingAdvisor,
    TimingContext,
)

REPO = Path(__file__).resolve().parents[2]
SEED_CONFIG = REPO / "config" / "econ" / "programs.yaml"
PARAMS = REPO / "config" / "econ" / "roi_params.yaml"
NOW = 1_800_000_000.0


def _advisor() -> TimingAdvisor:
    return TimingAdvisor(
        MarketKB(SEED_CONFIG, payout_curves_path=REPO / "config" / "econ" / "payout_curves.yaml"),
        params_path=PARAMS,
    )


def _valuation(ev: float = 500.0) -> FindingValuation:
    return FindingValuation(
        finding_id="F-1",
        ev_usd=ev,
        ev_range=(ev * 0.5, ev * 1.5),
        recommendation="submit" if ev >= 100 else "improve_first",
        components={},
        rationale="test",
    )


def _finding() -> Finding:
    return Finding("F-1", "ATO", "high", "example-corp")


def _ctx(**kw) -> TimingContext:
    return TimingContext(now=NOW, **kw)


def test_report_now_when_deadline_imminent_and_strong():
    advisor = _advisor()
    # deadline 24h away, strong EV, PoC ready, 3 evidence points
    ctx = _ctx(deadline_ts=NOW + 24 * 3600, poc_ready=True, evidence_points=3)
    d = advisor.decide(_finding(), _valuation(ev=500.0), ctx)
    assert d.action == REPORT_NOW
    assert d.deadline == ctx.deadline_ts
    assert d.prerequisites == []
    # same but deadline far away -> no urgency
    ctx_far = _ctx(deadline_ts=NOW + 30 * 86400, poc_ready=True, evidence_points=3)
    assert advisor.decide(_finding(), _valuation(ev=500.0), ctx_far).action == REPORT_SOON


def test_report_soon_for_complete_finding():
    advisor = _advisor()
    # complete, strong, no deadline, responsive program, low dup
    d = advisor.decide(
        Finding("F-1", "ATO", "high", "example-bank"),
        _valuation(ev=500.0),
        _ctx(poc_ready=True, evidence_points=3),
    )
    assert d.action == REPORT_SOON
    assert d.confidence == 0.9
    assert d.prerequisites == []


def test_improve_first_when_poc_weak():
    advisor = _advisor()
    d = advisor.decide(
        _finding(), _valuation(ev=500.0), _ctx(poc_ready=False, evidence_points=3)
    )
    assert d.action == IMPROVE_FIRST
    assert any("PoC" in p for p in d.prerequisites)
    # thin evidence also lands here with a matching prerequisite
    d2 = advisor.decide(
        _finding(), _valuation(ev=500.0), _ctx(poc_ready=True, evidence_points=1)
    )
    assert d2.action == IMPROVE_FIRST
    assert any("evidence" in p for p in d2.prerequisites)


def test_collect_more_when_evidence_thin():
    advisor = _advisor()
    # EV below the submit threshold (100) but positive, 1 evidence point
    d = advisor.decide(_finding(), _valuation(ev=40.0), _ctx(evidence_points=1))
    assert d.action == COLLECT_MORE
    assert d.prerequisites and "2 more evidence points" in d.prerequisites[0]
    assert d.confidence == 0.7


def test_hold_when_dup_risk_high():
    advisor = _advisor()
    # example-social: dup_rate 0.55 > hold threshold 0.5; complete finding
    d = advisor.decide(
        Finding("F-1", "ATO", "high", "example-social"),
        _valuation(ev=500.0),
        _ctx(poc_ready=True, evidence_points=3),
    )
    assert d.action == HOLD
    assert "dup risk" in d.rationale
    # slow program path: example-gov-portal p90 60 days > 30
    d2 = advisor.decide(
        Finding("F-2", "ATO", "high", "example-gov-portal"),
        _valuation(ev=500.0),
        _ctx(poc_ready=True, evidence_points=3),
    )
    assert d2.action == HOLD
    assert "p90 response" in d2.rationale


def test_defer_when_deadline_passed():
    advisor = _advisor()
    d = advisor.decide(
        _finding(),
        _valuation(ev=500.0),
        _ctx(deadline_ts=NOW - 3600, poc_ready=True, evidence_points=3),
    )
    assert d.action == DEFER
    assert "deadline" in d.rationale.lower()
    assert d.prerequisites == []
