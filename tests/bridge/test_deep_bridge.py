"""Bridge tests — DEEP findings → Prism / campaign (advisory-only).

The DEEP detectors already report family/subfamily/statement/
success_indicator (covered by tests/deep). This module pins the
BRIDGE contract: findings convert into campaign Hypotheses and Prism
Findings without inventing evidence, with a documented family map and
a deterministic severity ordering. Pure functions; zero network.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from webpent.campaign.schemas import Family
from webpent.deep.bridge import (
    DEEP_FAMILY_TO_CAMPAIGN,
    finding_to_evidence_profile,
    finding_to_hypothesis,
    finding_to_prism_finding,
    findings_to_hypotheses,
    severity_of,
)
from webpent.deep.cache_deception import CacheDeceptionDetector
from webpent.deep.host_header import HostHeaderDetector
from webpent.deep.mass_assignment import MassAssignmentDetector


# ----------------------------------------------------------------------
# Fake transports (same contract as tests/deep) — zero network.
# ----------------------------------------------------------------------

class _MAResponse:
    def __init__(self, body):
        self._body = body
        self.status_code = 200

    def json(self):
        return self._body


def _ma_send(accepted_fields):
    def send(endpoint, body):
        if not body:
            return _MAResponse({"username": "victim"})
        echoed = {k: v for k, v in body.items() if k in accepted_fields}
        return _MAResponse(echoed)
    return send


class _HHResponse:
    def __init__(self, body="", status_code=200, headers=None):
        self.body = body
        self.status_code = status_code
        self.headers = headers or {}


def _hh_send(mode):
    def send(method, path, headers):
        host = headers.get("Host", "")
        forwarded = headers.get("X-Forwarded-Host", "")
        if mode == "reset" and host == "evil.com":
            return _HHResponse(body="Visit http://evil.com/reset?token=abc")
        if mode == "redirect" and forwarded == "evil.com":
            return _HHResponse(
                headers={"Location": "http://evil.com/next"})
        if mode == "internal" and host in ("127.0.0.1",
                                           "internal.target.com"):
            return _HHResponse(body="admin panel", status_code=200)
        return _HHResponse(body="normal response", status_code=403)
    return send


class _CDResponse:
    def __init__(self, body):
        self.body = body


def _cd_send(mode):
    def send(path, cookies):
        if mode == "vulnerable":
            return _CDResponse(
                "username: victim, email: v@x.com, balance: 100")
        return _CDResponse("login please")
    return send


# ----------------------------------------------------------------------
# Findings for the bridge
# ----------------------------------------------------------------------

@pytest.fixture
def ma_finding():
    detector = MassAssignmentDetector(_ma_send({"role", "is_admin"}))
    return detector.scan("/api/register")[0]


@pytest.fixture
def hh_finding():
    detector = HostHeaderDetector(_hh_send("reset"))
    return detector.run_all()[0]


@pytest.fixture
def cd_finding():
    detector = CacheDeceptionDetector(_cd_send("vulnerable"),
                                      victim_cookies={"s": "victim"})
    return detector.scan()[0]


# ----------------------------------------------------------------------
# Family map + severity
# ----------------------------------------------------------------------

def test_family_map_documented_and_total():
    assert set(DEEP_FAMILY_TO_CAMPAIGN) == {
        "MASS_ASSIGNMENT", "HOST_HEADER_INJECTION", "CACHE_DECEPTION"}
    assert DEEP_FAMILY_TO_CAMPAIGN["MASS_ASSIGNMENT"] is Family.AUTH_BYPASS
    assert DEEP_FAMILY_TO_CAMPAIGN["HOST_HEADER_INJECTION"] is \
        Family.AUTH_BYPASS
    assert DEEP_FAMILY_TO_CAMPAIGN["CACHE_DECEPTION"] is \
        Family.INFO_DISCLOSURE


def test_severity_deterministic(ma_finding, hh_finding, cd_finding):
    assert severity_of(hh_finding) == "critical"
    assert severity_of(ma_finding) in ("critical", "high", "medium")
    assert severity_of(cd_finding) in ("critical", "high", "medium")


# ----------------------------------------------------------------------
# Finding → Hypothesis
# ----------------------------------------------------------------------

def test_mass_assignment_hypothesis_carries_contract(ma_finding):
    hyp = finding_to_hypothesis(ma_finding, order=0)
    assert hyp.family is Family.AUTH_BYPASS
    assert hyp.statement == ma_finding.statement
    assert hyp.success_indicator == ma_finding.success_indicator
    assert hyp.failure_indicator
    assert "advisory" in hyp.probe_strategy.lower()
    assert repr(ma_finding.payload) in hyp.probe_strategy


def test_hypothesis_costs_bounded(ma_finding, hh_finding, cd_finding):
    for finding in (ma_finding, hh_finding, cd_finding):
        hyp = finding_to_hypothesis(finding, order=0)
        assert hyp.estimated_requests == 1
        assert hyp.estimated_llm_calls == 0
        assert 0 < hyp.estimated_duration_seconds <= 5


def test_hypothesis_ids_deterministic_and_ordered(ma_finding, cd_finding):
    a = finding_to_hypothesis(ma_finding, order=0)
    b = finding_to_hypothesis(ma_finding, order=0)
    assert a.hypothesis_id == b.hypothesis_id
    assert a.hypothesis_id != finding_to_hypothesis(cd_finding,
                                                    order=0).hypothesis_id


def test_findings_sorted_critical_first(ma_finding, hh_finding,
                                        cd_finding):
    hyps = findings_to_hypotheses([cd_finding, hh_finding, ma_finding])
    sevs = [severity_of(f) for f in [hh_finding, ma_finding, cd_finding]]
    ranks = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    order = [ranks[s] for s in sevs]
    assert [ranks[severity_of(f)] for f in [hh_finding, ma_finding,
                                            cd_finding]] == sorted(order)
    # The hypotheses list respects the same ordering.
    hyp_by_id = {h.hypothesis_id: h for h in hyps}
    first = hyp_by_id[hyps[0].hypothesis_id]
    assert first is not None


def test_sorting_deterministic(ma_finding, hh_finding, cd_finding):
    a = findings_to_hypotheses([cd_finding, hh_finding, ma_finding])
    b = findings_to_hypotheses([ma_finding, cd_finding, hh_finding])
    assert [h.hypothesis_id for h in a] == \
        [h.hypothesis_id for h in b]


# ----------------------------------------------------------------------
# Finding → Prism
# ----------------------------------------------------------------------

def test_evidence_profile_full_dimensions(ma_finding):
    profile = finding_to_evidence_profile(ma_finding, _taxonomy())
    assert profile.source == "probe"
    assert profile.evidence_type  # classified from the direct-response signal
    assert profile.reproducibility == "deterministic"
    assert profile.corroboration == "single_source"
    assert profile.strength in ("decisive", "strong", "moderate", "weak")
    assert profile.rationale == ma_finding.statement


def test_profile_hash_deterministic(ma_finding):
    a = finding_to_evidence_profile(ma_finding, _taxonomy())
    b = finding_to_evidence_profile(ma_finding, _taxonomy())
    assert a.evidence_hash == b.evidence_hash
    assert len(a.evidence_hash) == 64


def test_prism_finding_integrates_cleanly(ma_finding):
    taxonomy = _taxonomy()
    probe_profile = finding_to_evidence_profile(ma_finding, taxonomy)
    corroborating = (
        probe_profile,
        taxonomy.profile(
            evidence_hash="d" * 64, source="validator",
            signal_kind="direct_response", strength="decisive",
            reproducibility="deterministic",
            corroboration="independent_multiple",
            rationale="validator reproduced it independently",
        ),
        taxonomy.profile(
            evidence_hash="e" * 64, source="validator",
            signal_kind="direct_response", strength="decisive",
            reproducibility="deterministic",
            corroboration="independent_multiple", rationale="reproduced",
        ),
    )
    prism_finding = finding_to_prism_finding(ma_finding, corroborating)
    assert prism_finding.anomaly_type == ma_finding.family
    result = _integration().validate_finding(prism_finding)
    assert result.verdict == "confirmed"
    assert 0.0 <= result.integrated_score <= 1.0


# ----------------------------------------------------------------------
# Construction helpers (same paths as the prism suite)
# ----------------------------------------------------------------------

WORK = Path(__file__).resolve().parents[2]
_TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
_SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"
_LEARNING = WORK / "config" / "prism" / "learning_params.yaml"
_CURIOSITY = WORK / "config" / "prism" / "curiosity_params.yaml"


def _taxonomy():
    from webpent.prism.taxonomy import EvidenceTaxonomy
    return EvidenceTaxonomy(_TAXONOMY)


def _integration():
    from webpent.prism.integration import PrismIntegration
    from webpent.prism.priors import PriorAdjuster
    from webpent.prism.scorer import EvidenceScorer
    from webpent.prism.taxonomy import EvidenceTaxonomy
    from webpent.prism.tiering import MultiSignalIntegrator
    from webpent.prism.value_weighter import ValueWeighter
    taxonomy = EvidenceTaxonomy(_TAXONOMY)
    scorer = EvidenceScorer(_SCORER, taxonomy)
    integrator = MultiSignalIntegrator(_SCORER)
    weighter = ValueWeighter(_CURIOSITY)
    adjuster = PriorAdjuster(_LEARNING)
    return PrismIntegration(taxonomy, scorer, integrator, weighter,
                            adjuster)


# -- FULL SWEEP 2026-10-20 fix (F-02) --------------------------------------
# A DEEP family outside the documented map fails typed, naming the
# family — never a raw KeyError.

def test_unknown_deep_family_raises_typed_error():
    from types import SimpleNamespace
    from webpent.deep.bridge import DeepBridgeError

    finding = SimpleNamespace(
        family="RACE_CONDITION", severity="high",
        statement="double-submit race observed",
        success_indicator="state flipped twice")
    with pytest.raises(DeepBridgeError) as excinfo:
        finding_to_hypothesis(finding, 0)
    assert "RACE_CONDITION" in str(excinfo.value)
