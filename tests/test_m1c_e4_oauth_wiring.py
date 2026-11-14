"""M1-C (UM-DR-12) regression: E-4 OAuth dead-field wiring.

M1_READINESS_REVIEW §4, E-4: the OAuth analyzer's composite precondition
(``oauth_flow_present``) had no writer — the pre-M1-B analyzer fabricated
it from the open_redirect class, and M1-B (ب1) correctly demoted that to
an unverified marker. The data, however, EXISTS: the recon auth detector
(``recon/auth_detector.py``) emits real OAuth observations.

Contract:
  * an OAuth auth signal (AuthSignal-like or dict) from recon verifies
    ``oauth_flow_present`` — the CHAIN-002 scenario becomes APPLICABLE
    (not speculative) when its feeder finding + real OAuth observation
    exist;
  * WITHOUT the signal the M1-B contract is unchanged: the condition
    stays unverified and the candidate stays SPECULATIVE with the
    ``unverified_precondition:oauth_flow_present`` marker;
  * non-OAuth signals (basic, session, garbage shapes) never verify it.
"""
from __future__ import annotations

from dataclasses import dataclass

from webpent.chained_exploits.analyzer import PreconditionGraphBuilder


@dataclass
class _AuthSignal:
    """AuthSignal-shaped minimal stand-in (mirrors recon/auth_detector)."""

    auth_type: str
    confidence: float = 0.8


def _open_redirect_finding() -> dict:
    return {
        "vuln_class": "open_redirect",
        "evidence": {"tool_confirmed_by": "test.fixture"},
    }


def _analyze(auth_signals=None):
    return PreconditionGraphBuilder().analyze(
        [_open_redirect_finding()],
        target_id="t1",
        engagement_id="e1",
        auth_signals=auth_signals,
    )


def _applicable_candidates(analysis):
    return [
        c
        for c in analysis.candidates
        if c.scenario_id == "CHAIN-002-open-redirect-oauth-state-theft"
        and not any(
            ref.startswith("unverified_precondition:") for ref in c.evidence_refs
        )
    ]


def _speculative_candidates(analysis):
    return [
        c
        for c in analysis.candidates
        if c.scenario_id == "CHAIN-002-open-redirect-oauth-state-theft"
        and "unverified_precondition:oauth_flow_present" in c.evidence_refs
    ]


def test_oauth_signal_verifies_precondition():
    analysis = _analyze([_AuthSignal(auth_type="oauth", confidence=0.8)])
    applicable = _applicable_candidates(analysis)
    assert applicable, (
        "E-4 REGRESSION: a real recon OAuth observation must verify "
        "oauth_flow_present and make CHAIN-002 applicable."
    )
    assert not _speculative_candidates(analysis)


def test_oauth2_variant_signal_verifies_precondition():
    analysis = _analyze([_AuthSignal(auth_type="oauth2")])
    assert _applicable_candidates(analysis)


def test_dict_shaped_oauth_signal_verifies_precondition():
    analysis = _analyze([{"auth_type": "oauth", "confidence": 0.9}])
    assert _applicable_candidates(analysis)


def test_no_signal_keeps_m1b_speculative_contract():
    analysis = _analyze(None)
    speculative = _speculative_candidates(analysis)
    assert speculative, "M1-B contract: no observation → SPECULATIVE with marker"
    assert not _applicable_candidates(analysis)


def test_non_oauth_signals_never_verify():
    for signal in (
        _AuthSignal(auth_type="basic"),
        _AuthSignal(auth_type="session_cookie"),
        {"auth_type": "form"},
        "garbage",
        None,
    ):
        analysis = _analyze([signal])
        assert not _applicable_candidates(analysis), (
            f"E-4 REGRESSION: signal {signal!r} must not verify oauth_flow_present"
        )
        assert _speculative_candidates(analysis)
