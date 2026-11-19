"""v89 PRISM — U-PRISM-5 (ledger), U-PRISM-6 (patterns), U-PRISM-7 (priors) tests."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.prism.errors import PrismLawError
from webpent.prism.ledger import SCHEMA_VERSION, CampaignLedger
from webpent.prism.patterns import PATTERN_TYPES, Pattern, PatternExtractor
from webpent.prism.priors import PriorAdjuster
from webpent.prism.scorer import EvidenceScorer
from webpent.prism.taxonomy import EvidenceTaxonomy

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
SCORER = WORK / "config" / "prism" / "scorer_weights.yaml"
LEARNING = WORK / "config" / "prism" / "learning_params.yaml"

NOW = datetime(2026, 10, 18, 12, 0, 0, tzinfo=timezone.utc)


def _profile_and_score(evidence_hash: str = "a" * 64):
    taxonomy = EvidenceTaxonomy(TAXONOMY)
    scorer = EvidenceScorer(SCORER, taxonomy)
    profile = taxonomy.profile(
        evidence_hash=evidence_hash, source="probe",
        signal_kind="direct_response", strength="strong",
        reproducibility="deterministic",
        corroboration="independent_multiple", rationale="payload echoed",
    )
    return profile, scorer.score(profile)


# -- U-PRISM-5: ledger -----------------------------------------------------------

def test_schema_versioned(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "download" / "prism" / "ledger.db")
    try:
        row = ledger._conn.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        assert int(row["version"]) == SCHEMA_VERSION
    finally:
        ledger.close()


def test_campaign_target_hashed_not_plaintext(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    ledger = CampaignLedger(db_path)
    try:
        campaign_id = ledger.open_campaign("secret-target.example", "proj")
        assert campaign_id
        blob = db_path.read_bytes()
        assert b"secret-target.example" not in blob
    finally:
        ledger.close()


def test_record_evidence_roundtrip(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        profile, score = _profile_and_score()
        evidence_id = ledger.record_evidence(campaign_id, profile, score)
        data = ledger.export(campaign_id)
        assert data["evidence"][0]["evidence_id"] == evidence_id
        assert data["evidence"][0]["source"] == "probe"
        assert data["evidence"][0]["tier"] == score.tier
    finally:
        ledger.close()


def test_record_outcome(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        profile, score = _profile_and_score()
        evidence_id = ledger.record_evidence(campaign_id, profile, score)
        outcome_id = ledger.record_outcome(
            campaign_id, evidence_id, "confirmed", notes="validated"
        )
        data = ledger.export(campaign_id)
        assert data["outcomes"][0]["outcome_id"] == outcome_id
        assert data["outcomes"][0]["result"] == "confirmed"
    finally:
        ledger.close()


def test_record_outcome_rejects_invalid_result(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        profile, score = _profile_and_score()
        evidence_id = ledger.record_evidence(campaign_id, profile, score)
        with pytest.raises(PrismLawError):
            ledger.record_outcome(campaign_id, evidence_id, "kind-of-true")
    finally:
        ledger.close()


def test_record_adjustment_requires_reason(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        with pytest.raises(PrismLawError):
            ledger.record_adjustment(campaign_id, "pat-1", 0.1, "", 0.9)
        adjustment_id = ledger.record_adjustment(
            campaign_id, "pat-1", 0.1, "5/6 confirmed outcomes", 0.9
        )
        assert adjustment_id
    finally:
        ledger.close()


def test_unknown_campaign_raises(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        with pytest.raises(PrismLawError):
            ledger.export("nope")
    finally:
        ledger.close()


def test_export_json_roundtrip_and_no_pii(tmp_path: Path) -> None:
    ledger = CampaignLedger(tmp_path / "ledger.db")
    try:
        campaign_id = ledger.open_campaign("target.example", "proj")
        profile, score = _profile_and_score()
        evidence_id = ledger.record_evidence(campaign_id, profile, score)
        ledger.record_outcome(
            campaign_id, evidence_id, "refuted",
            notes="contact bob.hidden@example.net for details",
        )
        text = ledger.export_json(campaign_id)
        assert "bob.hidden@example.net" not in text
        data = json.loads(text)
        assert data["schema_version"] == SCHEMA_VERSION
    finally:
        ledger.close()


def test_newer_schema_rejected(tmp_path: Path) -> None:
    db_path = tmp_path / "ledger.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(_make_newer_schema())
    conn.commit()
    conn.close()
    with pytest.raises(PrismLawError):
        CampaignLedger(db_path)


def _make_newer_schema() -> str:
    from webpent.prism.ledger import _SCHEMA
    return _SCHEMA.replace(
        "INSERT INTO schema_version", "INSERT INTO schema_version"
    ) + (
        "\nDELETE FROM schema_version;"
        "\nINSERT INTO schema_version (version) VALUES (99);"
    )


# -- U-PRISM-6: pattern extractor --------------------------------------------------

def _records(n: int, technique: str = "sqli_union", outcome: str = "confirmed",
             **extra) -> list[dict]:
    return [
        {"technique": technique, "signal_kind": "direct_response",
         "stack": "nginx", "family": "sqli", "archetype": "fintech_api",
         "outcome": outcome, **extra}
        for _ in range(n)
    ]


def test_extract_requires_min_samples(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    assert extractor.extract(_records(4), NOW) == []
    patterns = extractor.extract(_records(5), NOW)
    assert len(patterns) == len(PATTERN_TYPES)


def test_extract_five_pattern_types(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    patterns = extractor.extract(_records(6), NOW)
    assert sorted(p.pattern_type for p in patterns) == sorted(PATTERN_TYPES)


def test_pattern_id_deterministic(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    first = extractor.extract(_records(6), NOW)
    second = extractor.extract(_records(6), NOW)
    assert [p.pattern_id for p in first] == [p.pattern_id for p in second]


def test_dedupe_keeps_freshest(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    first = extractor.extract(_records(6), NOW)
    updated = [extractor.update(p, "confirmed", NOW) for p in first]
    merged = extractor.dedupe([*first, *updated])
    assert len(merged) == len(first)
    by_id = {p.pattern_id: p for p in merged}
    for old in first:
        assert by_id[old.pattern_id].samples == old.samples + 1


def test_update_increments_samples_and_rate(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    pattern = extractor.extract(_records(5, outcome="refuted"), NOW)[0]
    assert pattern.success_rate == 0.0
    updated = extractor.update(pattern, "confirmed", NOW)
    assert updated.samples == 6
    assert updated.successes == 1
    assert abs(updated.success_rate - 1 / 6) < 1e-9


def test_update_rejects_unknown_outcome(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    pattern = extractor.extract(_records(5), NOW)[0]
    with pytest.raises(PrismLawError):
        extractor.update(pattern, "probably", NOW)


def test_prune_stale(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    patterns = extractor.extract(_records(6), NOW)
    later = datetime(2027, 3, 1, tzinfo=timezone.utc)  # > 90 days later
    assert extractor.prune(patterns, later) == []
    fresh = extractor.prune(patterns, NOW)
    assert len(fresh) == len(patterns)


def test_prune_under_sampled(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    patterns = extractor.extract(_records(6), NOW)
    shrunk = [p for p in patterns if p.samples < extractor.min_samples]
    assert extractor.prune(patterns, NOW) == patterns
    assert extractor.prune(shrunk, NOW) == []


def test_confidence_monotonic_and_in_range(tmp_path: Path) -> None:
    extractor = PatternExtractor(LEARNING)
    patterns = extractor.extract(_records(5), NOW)
    for pattern in patterns:
        assert 0.0 <= pattern.confidence <= 1.0
        bigger = extractor.update(pattern, "confirmed", NOW)
        assert bigger.confidence > pattern.confidence


def test_extractor_missing_config_is_law_error(tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        PatternExtractor(tmp_path / "missing.yaml")


# -- U-PRISM-7: prior adjuster -------------------------------------------------------

def _pattern(samples: int = 20, successes: int = 16,
             pattern_type: str = "technique_effectiveness",
             key: str = "sqli_union") -> Pattern:
    from webpent.prism.patterns import _confidence
    return Pattern(
        pattern_id="pat" * 4, pattern_type=pattern_type, key=key,
        samples=samples, successes=successes,
        success_rate=successes / samples,
        confidence=_confidence(samples),
        updated_at=NOW.isoformat(),
        reason=f"{successes}/{samples} confirmed outcomes",
    )


def test_adjustment_within_cap() -> None:
    adjuster = PriorAdjuster(LEARNING)
    result = adjuster.adjust(
        0.5, _pattern(), {"technique": "sqli_union"}
    )
    assert abs(result.delta) <= adjuster.adjustment_cap
    assert 0.0 <= result.adjusted <= 1.0


def test_adjustment_capped_at_020() -> None:
    adjuster = PriorAdjuster(LEARNING)
    # success_rate 1.0 vs baseline 0.1: raw delta far beyond the cap
    result = adjuster.adjust(0.1, _pattern(samples=20, successes=20),
                             {"technique": "sqli_union"})
    assert abs(result.delta) <= adjuster.adjustment_cap + 1e-12
    assert abs(result.delta - adjuster.adjustment_cap) < 1e-9


def test_low_confidence_rejected() -> None:
    adjuster = PriorAdjuster(LEARNING)
    weak = _pattern(samples=4, successes=0)
    assert weak.confidence < 0.6
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, weak, {"technique": "sqli_union"})


def test_reason_mandatory() -> None:
    adjuster = PriorAdjuster(LEARNING)
    silent = _pattern()
    object.__setattr__(silent, "reason", "")
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, silent, {"technique": "sqli_union"})


def test_context_mismatch_rejected() -> None:
    adjuster = PriorAdjuster(LEARNING)
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, _pattern(), {"technique": "other_technique"})
    with pytest.raises(PrismLawError):
        adjuster.adjust(0.5, _pattern(), {})


def test_negative_delta_allowed() -> None:
    adjuster = PriorAdjuster(LEARNING)
    result = adjuster.adjust(
        0.9, _pattern(samples=20, successes=4), {"technique": "sqli_union"}
    )
    assert result.delta < 0
    assert result.adjusted < result.baseline


def test_adjustment_deterministic() -> None:
    adjuster = PriorAdjuster(LEARNING)
    first = adjuster.adjust(0.5, _pattern(), {"technique": "sqli_union"})
    second = adjuster.adjust(0.5, _pattern(), {"technique": "sqli_union"})
    assert first.to_dict() == second.to_dict()


def test_adjustment_is_advisory() -> None:
    adjuster = PriorAdjuster(LEARNING)
    result = adjuster.adjust(0.5, _pattern(), {"technique": "sqli_union"})
    assert result.mode == "advisory-only (PRISM-L-2)"
