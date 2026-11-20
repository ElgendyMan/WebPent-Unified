"""v89 PRISM — U-PRISM-3 (scorer) and U-PRISM-4 (multi-signal integrator) tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.prism.errors import PrismLawError
from webpent.prism.scorer import EvidenceScorer, ScoreResult
from webpent.prism.taxonomy import (
    EvidenceProfile,
    EvidenceTaxonomy,
)
from webpent.prism.tiering import MultiSignalIntegrator

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"


@pytest.fixture()
def taxonomy() -> EvidenceTaxonomy:
    return EvidenceTaxonomy(TAXONOMY)


@pytest.fixture()
def scorer(taxonomy: EvidenceTaxonomy) -> EvidenceScorer:
    return EvidenceScorer(SCORER, taxonomy)


@pytest.fixture()
def integrator() -> MultiSignalIntegrator:
    return MultiSignalIntegrator(SCORER)


def _profile(
    source: str = "validator",
    signal_kind: str = "direct_response",
    strength: str = "strong",
    reproducibility: str = "deterministic",
    corroboration: str = "independent_multiple",
    evidence_hash: str = "a" * 64,
    rationale: str = "payload echoed back",
) -> EvidenceProfile:
    return EvidenceTaxonomy(TAXONOMY).profile(
        evidence_hash=evidence_hash,
        source=source,
        signal_kind=signal_kind,
        strength=strength,
        reproducibility=reproducibility,
        corroboration=corroboration,
        rationale=rationale,
    )


def _scored(**kwargs) -> tuple[EvidenceProfile, ScoreResult]:
    profile = _profile(**kwargs)
    return profile, EvidenceScorer(SCORER, EvidenceTaxonomy(TAXONOMY)).score(
        profile
    )


# -- U-PRISM-3: scorer ---------------------------------------------------------

def test_score_direct_decisive_is_tier_a(scorer: EvidenceScorer) -> None:
    result = scorer.score(
        _profile(strength="decisive", corroboration="independent_multiple")
    )
    # validator weight 0.9 × 1.0 × 1.0 × 1.0 + 0.05 bonus = 0.95
    assert result.score >= 0.90
    assert result.tier == "A"
    assert "prioritize" in result.recommendation


def test_score_components_transparent(scorer: EvidenceScorer) -> None:
    result = scorer.score(_profile())
    for key in ("base_weight", "strength", "reproducibility", "corroboration",
                "type_bonus", "noise_penalty"):
        assert key in result.components
    assert result.formula
    assert result.rationale == "payload echoed back"


def test_score_formula_matches_components(scorer: EvidenceScorer) -> None:
    result = scorer.score(_profile(source="probe", strength="moderate",
                                   reproducibility="repeatable",
                                   corroboration="single_source"))
    c = result.components
    expected = min(1.0, max(0.0, (
        c["base_weight"] * c["strength"] * c["reproducibility"]
        * c["corroboration"] + c["type_bonus"] + c["noise_penalty"]
    )))
    assert abs(result.score - expected) < 1e-9


def test_score_clamped_at_one(scorer: EvidenceScorer) -> None:
    result = scorer.score(
        _profile(source="validator", strength="decisive",
                 corroboration="independent_multiple")
    )
    assert result.score <= 1.0


def test_score_clamped_at_zero(scorer: EvidenceScorer) -> None:
    result = scorer.score(
        _profile(source="ledger", strength="negligible",
                 reproducibility="unreproducible",
                 corroboration="uncorroborated")
    )
    assert result.score == 0.0
    assert result.tier == "F"


def test_tier_boundaries(scorer: EvidenceScorer) -> None:
    assert scorer.tier_for(0.90) == "A"
    assert scorer.tier_for(0.8999) == "B"
    assert scorer.tier_for(0.75) == "B"
    assert scorer.tier_for(0.7499) == "C"
    assert scorer.tier_for(0.55) == "C"
    assert scorer.tier_for(0.35) == "D"
    assert scorer.tier_for(0.3499) == "F"


def test_noise_penalty_applied(scorer: EvidenceScorer) -> None:
    clean = scorer.score(
        _profile(reproducibility="deterministic",
                 corroboration="independent_multiple")
    )
    noisy = scorer.score(
        _profile(reproducibility="unreproducible",
                 corroboration="uncorroborated")
    )
    assert noisy.score < clean.score
    assert noisy.components["noise_penalty"] < 0


def test_recommendation_present_for_every_tier(scorer: EvidenceScorer) -> None:
    seen_tiers: set[str] = set()
    for source in ("probe", "validator", "ledger", "crawler", "operator"):
        for strength in ("decisive", "strong", "moderate", "weak",
                         "negligible"):
            for reproducibility in ("deterministic", "unreproducible"):
                result = scorer.score(
                    _profile(source=source, strength=strength,
                             reproducibility=reproducibility)
                )
                seen_tiers.add(result.tier)
                # the recommendation always matches the tier config
                assert result.recommendation
                assert result.tier == scorer.tier_for(result.score)
    # the sweep reaches every tier, so every recommendation is exercised
    assert seen_tiers == {"A", "B", "C", "D", "F"}


def test_deterministic_same_profile_same_score(scorer: EvidenceScorer) -> None:
    first = scorer.score(_profile())
    second = scorer.score(_profile())
    assert first.to_dict() == second.to_dict()


def test_scorer_missing_config_is_law_error(taxonomy: EvidenceTaxonomy,
                                            tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        EvidenceScorer(tmp_path / "missing.yaml", taxonomy)


def test_scorer_rejects_missing_source_weight(taxonomy: EvidenceTaxonomy,
                                              tmp_path: Path) -> None:
    broken = tmp_path / "broken_scorer.yaml"
    lines = SCORER.read_text(encoding="utf-8").splitlines()
    dropped = [ln for ln in lines if ln.strip() != "ledger: 0.3"]
    broken.write_text("\n".join(dropped), encoding="utf-8")
    with pytest.raises(PrismLawError):
        EvidenceScorer(broken, taxonomy)


# -- U-PRISM-4: multi-signal integrator -----------------------------------------

def test_integrator_empty_signals_raise(integrator: MultiSignalIntegrator) -> None:
    with pytest.raises(PrismLawError):
        integrator.integrate([])


def test_single_signal_coherence(integrator: MultiSignalIntegrator) -> None:
    result = integrator.integrate([_scored()])
    assert result.coherence == 0.4
    assert result.signal_count == 1


def test_two_same_type_coherence(integrator: MultiSignalIntegrator) -> None:
    signals = [
        _scored(evidence_hash="a" * 64),
        _scored(evidence_hash="b" * 64),
    ]
    result = integrator.integrate(signals)
    assert result.coherence == 0.7


def test_three_same_type_coherence(integrator: MultiSignalIntegrator) -> None:
    signals = [
        _scored(evidence_hash="a" * 64),
        _scored(evidence_hash="b" * 64),
        _scored(evidence_hash="c" * 64),
    ]
    result = integrator.integrate(signals)
    assert result.coherence == 1.0


def test_corroboration_bonus_independent_multiple(
    integrator: MultiSignalIntegrator,
) -> None:
    result = integrator.integrate([_scored()])
    assert result.corroboration_bonus == 0.15


def test_corroboration_bonus_corroborated(
    integrator: MultiSignalIntegrator,
) -> None:
    result = integrator.integrate(
        [_scored(corroboration="corroborated")]
    )
    assert result.corroboration_bonus == 0.08


def test_corroboration_bonus_never_stacks(
    integrator: MultiSignalIntegrator,
) -> None:
    signals = [
        _scored(corroboration="independent_multiple"),
        _scored(corroboration="corroborated", evidence_hash="b" * 64),
    ]
    result = integrator.integrate(signals)
    assert result.corroboration_bonus == 0.15


def test_conflict_penalty_applied(integrator: MultiSignalIntegrator) -> None:
    signals = [
        _scored(evidence_hash="a" * 64),
        _scored(signal_kind="header_anomaly", source="crawler",
                strength="strong", evidence_hash="b" * 64),
    ]
    result = integrator.integrate(signals)
    assert result.conflict_penalty > 0
    assert result.conflicts
    assert result.conflicts[0]["resolution"].startswith("higher-scored")


def test_conflict_resolved_deterministically(
    integrator: MultiSignalIntegrator,
) -> None:
    strong_active = _scored(evidence_hash="a" * 64)
    weak_anomaly = _scored(signal_kind="header_anomaly", source="crawler",
                           strength="weak", evidence_hash="b" * 64)
    forward = integrator.integrate([strong_active, weak_anomaly])
    backward = integrator.integrate([weak_anomaly, strong_active])
    assert forward.to_dict() == backward.to_dict()
    assert forward.conflicts[0]["winner"] == strong_active[1].evidence_hash


def test_integrated_score_clamped(integrator: MultiSignalIntegrator) -> None:
    signals = [
        _scored(evidence_hash=f"{c}" * 64)
        for c in "abcde"
    ]
    result = integrator.integrate(signals)
    assert 0.0 <= result.integrated_score <= 1.0


def test_verdict_confirmed_requires_active_signal(
    integrator: MultiSignalIntegrator,
) -> None:
    # three coherent decisive inference signals score high but are never
    # "confirmed": no direct/side-effect signal backs them
    inference_signals = [
        _scored(signal_kind="inference", source="validator",
                strength="decisive", corroboration="independent_multiple",
                evidence_hash=f"{c}" * 64)
        for c in "abc"
    ]
    result = integrator.integrate(inference_signals)
    assert result.integrated_score >= 0.90
    assert result.verdict != "confirmed"
    # the same strength with direct evidence is confirmed
    active_signals = [
        _scored(strength="decisive", corroboration="independent_multiple",
                evidence_hash=f"{c}" * 64)
        for c in "abc"
    ]
    active = integrator.integrate(active_signals)
    assert active.verdict == "confirmed"


def test_integration_is_advisory(integrator: MultiSignalIntegrator) -> None:
    result = integrator.integrate([_scored()])
    assert result.mode == "advisory-only (PRISM-L-2)"


def test_integrator_missing_config_is_law_error(tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        MultiSignalIntegrator(tmp_path / "missing.yaml")
