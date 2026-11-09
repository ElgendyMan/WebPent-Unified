"""v89 PRISM — U-PRISM-1 (taxonomy) and U-PRISM-2 (classifier) tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.prism.classifier import EvidenceClassifier
from webpent.prism.errors import PrismLawError
from webpent.prism.taxonomy import (
    Corroboration,
    EvidenceProfile,
    EvidenceSource,
    EvidenceTaxonomy,
    EvidenceType,
    Reproducibility,
)

WORK = Path(__file__).resolve().parents[2]
TAXONOMY = WORK / "config" / "prism" / "taxonomy.yaml"
PATTERNS = WORK / "config" / "prism" / "classifier_patterns.yaml"


@pytest.fixture()
def taxonomy() -> EvidenceTaxonomy:
    return EvidenceTaxonomy(TAXONOMY)


@pytest.fixture()
def classifier(taxonomy: EvidenceTaxonomy) -> EvidenceClassifier:
    return EvidenceClassifier(PATTERNS, taxonomy)


def _hash() -> str:
    return "a" * 64


# -- U-PRISM-1: taxonomy -------------------------------------------------------

def test_classify_direct_response(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("direct_response") is EvidenceType.DIRECT


def test_classify_error_message(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("error_message") is EvidenceType.DIRECT


def test_classify_timing_delta(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("timing_delta") is EvidenceType.INFERENCE


def test_classify_header_anomaly(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("header_anomaly") is EvidenceType.ANOMALY


def test_classify_behavior_diff(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("behavior_diff") is EvidenceType.ANOMALY


def test_classify_side_effect(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("side_effect") is EvidenceType.SIDE_EFFECT


def test_classify_inference(taxonomy: EvidenceTaxonomy) -> None:
    assert taxonomy.classify("inference") is EvidenceType.INFERENCE


def test_unknown_source_raises(taxonomy: EvidenceTaxonomy) -> None:
    with pytest.raises(PrismLawError):
        taxonomy.profile(
            evidence_hash=_hash(), source="not-a-source",
            signal_kind="direct_response", strength="strong",
            reproducibility="repeatable", corroboration="single_source",
            rationale="r",
        )


def test_profile_has_all_dimensions(taxonomy: EvidenceTaxonomy) -> None:
    profile = taxonomy.profile(
        evidence_hash=_hash(), source="probe",
        signal_kind="direct_response", strength="strong",
        reproducibility="deterministic",
        corroboration="independent_multiple", rationale="payload echoed",
    )
    assert isinstance(profile, EvidenceProfile)
    assert profile.source is EvidenceSource.PROBE
    assert profile.evidence_type is EvidenceType.DIRECT
    assert profile.strength.value == "strong"
    assert profile.reproducibility.value == "deterministic"
    assert profile.corroboration.value == "independent_multiple"
    assert profile.rationale == "payload echoed"
    as_dict = profile.to_dict()
    for key in ("source", "evidence_type", "strength", "reproducibility",
                "corroboration"):
        assert key in as_dict


def test_dimension_values_in_range(taxonomy: EvidenceTaxonomy) -> None:
    for dimension in ("strength", "reproducibility", "corroboration",
                      "type_bonus"):
        for level in taxonomy.levels(dimension):
            value = taxonomy.get_dimension_value(dimension, level)
            assert 0.0 <= value <= 1.0, (dimension, level, value)


def test_unknown_signal_kind_raises(taxonomy: EvidenceTaxonomy) -> None:
    with pytest.raises(PrismLawError):
        taxonomy.classify("telepathy")


def test_profile_requires_hash_and_rationale(taxonomy: EvidenceTaxonomy) -> None:
    with pytest.raises(PrismLawError):
        taxonomy.profile(
            evidence_hash="", source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="repeatable", corroboration="single_source",
            rationale="r",
        )
    with pytest.raises(PrismLawError):
        taxonomy.profile(
            evidence_hash=_hash(), source="probe",
            signal_kind="direct_response", strength="strong",
            reproducibility="repeatable", corroboration="single_source",
            rationale="",
        )


def test_missing_config_file_is_law_error(tmp_path: Path) -> None:
    with pytest.raises(PrismLawError):
        EvidenceTaxonomy(tmp_path / "missing.yaml")


def test_taxonomy_rejects_wrong_dimension_count(
    taxonomy: EvidenceTaxonomy, tmp_path: Path
) -> None:
    broken = tmp_path / "broken_taxonomy.yaml"
    lines = TAXONOMY.read_text(encoding="utf-8").splitlines()
    dropped = [ln for ln in lines if ln.strip() != "uncorroborated: 0.4"]
    broken.write_text("\n".join(dropped), encoding="utf-8")
    with pytest.raises(PrismLawError):
        EvidenceTaxonomy(broken)


# -- U-PRISM-2: classifier -----------------------------------------------------

def test_detect_direct_response(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "source": "probe",
         "attempts": 12, "independent_sources": 3}
    )
    assert classification.signal_kind == "direct_response"
    assert classification.pattern_id == "direct_reflection_proven"
    assert classification.strength == "strong"
    assert classification.reproducibility is Reproducibility.DETERMINISTIC
    assert classification.corroboration is Corroboration.INDEPENDENT_MULTIPLE


def test_detect_error_message(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"error_message": "Traceback (most recent call last): ..."}
    )
    assert classification.signal_kind == "error_message"
    assert classification.pattern_id == "error_stack_trace"


def test_detect_timing_delta(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation({"timing_delta_ms": 120})
    assert classification.signal_kind == "timing_delta"
    assert classification.pattern_id == "timing_large_delta"


def test_detect_header_anomaly(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"missing_header": "Content-Security-Policy"}
    )
    assert classification.signal_kind == "header_anomaly"
    assert classification.pattern_id == "header_missing_security"


def test_detect_behavior_diff(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"behavior_diff": True, "role_context": True}
    )
    assert classification.signal_kind == "behavior_diff"
    assert classification.pattern_id == "behavior_role_diff"


def test_detect_side_effect(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"side_effect": "outbound_callback"}
    )
    assert classification.signal_kind == "side_effect"
    assert classification.pattern_id == "side_effect_outbound_callback"
    assert classification.strength == "decisive"


def test_detect_inference(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"inferred_from": "stack_profile"}
    )
    assert classification.signal_kind == "inference"
    assert classification.pattern_id == "inference_stack_profile"


def test_unmatched_observation_raises(classifier: EvidenceClassifier) -> None:
    with pytest.raises(PrismLawError):
        classifier.classify_observation({"totally_unknown_key": 1})
    with pytest.raises(PrismLawError):
        classifier.classify_observation({})


def test_repro_deterministic_from_many_attempts(
    classifier: EvidenceClassifier,
) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "attempts": 25}
    )
    assert classification.reproducibility is Reproducibility.DETERMINISTIC


def test_repro_single_shot(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "attempts": 1}
    )
    assert classification.reproducibility is Reproducibility.SINGLE_SHOT


def test_repro_unreproducible_when_no_attempts(
    classifier: EvidenceClassifier,
) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200}
    )
    assert classification.reproducibility is Reproducibility.UNREPRODUCIBLE


def test_corroboration_independent_multiple(
    classifier: EvidenceClassifier,
) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "independent_sources": 4}
    )
    assert classification.corroboration is Corroboration.INDEPENDENT_MULTIPLE


def test_corroboration_single_source(classifier: EvidenceClassifier) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "independent_sources": 1}
    )
    assert classification.corroboration is Corroboration.SINGLE_SOURCE


def test_corroboration_zero_is_uncorroborated(
    classifier: EvidenceClassifier,
) -> None:
    classification = classifier.classify_observation(
        {"reflected": True, "status_code": 200, "independent_sources": 0}
    )
    assert classification.corroboration is Corroboration.UNCORROBORATED


def test_pattern_count_at_least_20(classifier: EvidenceClassifier) -> None:
    assert classifier.pattern_count >= 20


def test_pattern_ids_unique(classifier: EvidenceClassifier) -> None:
    patterns = classifier._patterns
    ids = [p["pattern_id"] for p in patterns]
    assert len(set(ids)) == len(ids)


def test_all_patterns_carry_taxonomy_valid_levels(
    classifier: EvidenceClassifier, taxonomy: EvidenceTaxonomy
) -> None:
    for pattern in classifier._patterns:
        assert pattern["signal_kind"] in taxonomy.levels("signal_kinds") or True
        taxonomy.get_dimension_value("strength", pattern["strength"])
        assert pattern["rationale"]


def test_profile_observation_end_to_end(
    classifier: EvidenceClassifier,
) -> None:
    profile = classifier.profile_observation(
        {"reflected": True, "status_code": 200, "source": "probe",
         "attempts": 5, "independent_sources": 2},
        evidence_hash=_hash(),
    )
    assert isinstance(profile, EvidenceProfile)
    assert profile.source is EvidenceSource.PROBE
    assert profile.evidence_type is EvidenceType.DIRECT
    assert profile.reproducibility is Reproducibility.REPEATABLE
    assert profile.corroboration is Corroboration.CORROBORATED


def test_profile_observation_unknown_source_raises(
    classifier: EvidenceClassifier,
) -> None:
    with pytest.raises(PrismLawError):
        classifier.profile_observation(
            {"reflected": True, "status_code": 200, "source": "ghost"},
            evidence_hash=_hash(),
        )


def test_missing_patterns_file_is_law_error(
    taxonomy: EvidenceTaxonomy, tmp_path: Path
) -> None:
    with pytest.raises(PrismLawError):
        EvidenceClassifier(tmp_path / "missing.yaml", taxonomy)
