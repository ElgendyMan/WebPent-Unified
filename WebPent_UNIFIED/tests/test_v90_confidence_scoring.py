from __future__ import annotations

from webpent.shared.confidence import EvidenceType, compute_confidence_score


def test_confidence_without_structured_signals_preserves_base_formula() -> None:
    assert compute_confidence_score(evidence_type=EvidenceType.HEURISTIC) == 0.30
    assert compute_confidence_score(evidence_type=EvidenceType.TOOL_CONFIRMED) == 0.85


def test_structured_positive_evidence_increases_score() -> None:
    base = compute_confidence_score(evidence_type=EvidenceType.HEURISTIC)
    enriched = compute_confidence_score(
        evidence_type=EvidenceType.HEURISTIC,
        evidence_signals={
            "source_quality": 1.0,
            "reproducibility": 1.0,
            "identity_certainty": 1.0,
            "oracle_strength": 1.0,
            "negative_control": True,
            "deterministic_match": True,
            "validator_status": "validated",
        },
    )

    assert enriched > base
    assert 0.0 <= enriched <= 1.0


def test_contradictory_or_failed_control_reduces_score() -> None:
    base = compute_confidence_score(evidence_type=EvidenceType.LLM_ASSESSED)
    weakened = compute_confidence_score(
        evidence_type=EvidenceType.LLM_ASSESSED,
        evidence_signals={
            "negative_control": False,
            "contradictory_evidence": 1.0,
            "validator_status": "rejected",
        },
    )

    assert weakened < base
    assert 0.0 <= weakened <= 1.0
