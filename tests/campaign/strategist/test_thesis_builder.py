"""U-CAMPAIGN-1 — ThesisBuilder (10 tests).

The thesis is the ONLY entry point to a campaign: no thesis, no
campaign, no requests. Every claim traces to evidence; derivation is
deterministic (no LLM); validation fails closed below the confidence
floor.
"""
from __future__ import annotations

import pytest

from webpent.campaign.errors import (
    InsufficientDataError,
    ThesisValidationError,
)
from webpent.campaign.schemas import Family, TargetThesis, ThesisEvidence
from webpent.campaign.strategist.thesis_builder import ThesisBuilder


def test_build_from_full_inputs(oracle_full, patterns_fintech, econ_a):
    """Happy path — all inputs present."""
    builder = ThesisBuilder()
    thesis = builder.build("target-1", oracle_full, patterns_fintech, econ_a)

    assert thesis.target_id == "target-1"
    assert thesis.confidence >= 0.5
    assert len(thesis.evidence) >= 3
    assert len(thesis.likely_vuln_families) >= 1
    assert "fintech" in thesis.statement.lower() or "node" in thesis.statement.lower()


def test_build_insufficient_evidence_raises(oracle_minimal, econ_c):
    """No patterns, no leaks → only 1 evidence piece → raises."""
    builder = ThesisBuilder()
    with pytest.raises(InsufficientDataError):
        builder.build("target-1", oracle_minimal, [], econ_c)


def test_confidence_computed_correctly(oracle_full, patterns_strong, econ_a):
    """More evidence + strong pattern → higher confidence."""
    builder = ThesisBuilder()
    thesis = builder.build("t1", oracle_full, patterns_strong, econ_a)

    # Strong pattern (0.9) + multiple evidence sources should be > 0.6
    assert thesis.confidence > 0.6


def test_families_deterministic(oracle_full, patterns_fintech, econ_a):
    """Same inputs → same families."""
    builder = ThesisBuilder()
    t1 = builder.build("t1", oracle_full, patterns_fintech, econ_a)
    t2 = builder.build("t1", oracle_full, patterns_fintech, econ_a)

    assert t1.likely_vuln_families == t2.likely_vuln_families


def test_families_no_overlap(oracle_full, patterns_fintech, econ_a):
    """A family can't be both likely and unlikely."""
    builder = ThesisBuilder()
    thesis = builder.build("t1", oracle_full, patterns_fintech, econ_a)

    likely_set = {f for f, _ in thesis.likely_vuln_families}
    unlikely_set = {f for f, _ in thesis.unlikely_vuln_families}

    assert likely_set & unlikely_set == set()


def test_likely_families_sum_leq_one(oracle_full, patterns_fintech, econ_a):
    """Normalized probabilities."""
    builder = ThesisBuilder()
    thesis = builder.build("t1", oracle_full, patterns_fintech, econ_a)

    total = sum(p for _, p in thesis.likely_vuln_families)
    assert total <= 1.0


def test_refine_creates_new_version(oracle_full, patterns_fintech, econ_a):
    """Refining should create version+1, preserving old."""
    builder = ThesisBuilder()
    v1 = builder.build("t1", oracle_full, patterns_fintech, econ_a)

    new_ev = ThesisEvidence(
        evidence_id="ev-new",
        source="oracle",
        source_ref="extra",
        claim="new evidence found",
        weight=0.8,
    )
    v2 = builder.refine(v1, [new_ev])

    assert v2.version == v1.version + 1
    assert v2.supersedes == v1.thesis_id
    assert len(v2.evidence) == len(v1.evidence) + 1


def test_validate_catches_low_confidence(oracle_minimal):
    """Below MIN_CONFIDENCE_TO_PROCEED → validation fails."""
    builder = ThesisBuilder()
    thesis = TargetThesis.create(
        target_id="t1", statement="x", confidence=0.2,
        likely_vuln_families=[], unlikely_vuln_families=[],
        crown_jewels=["data"], likely_entry_points=[],
        evidence=[ThesisEvidence("e1", "oracle", "x", "claim", 0.2)],
        reasoning="short",
    )

    with pytest.raises(ThesisValidationError):
        builder.validate(thesis)


def test_tech_stack_boost_families(oracle_node_full, econ_b):
    """Node.js tech stack should boost BOLA and SQLI."""
    builder = ThesisBuilder()
    thesis = builder.build("t1", oracle_node_full, [], econ_b)

    likely_families = {f for f, _ in thesis.likely_vuln_families}
    # Either BOLA or SQLI should be present
    assert Family.BOLA in likely_families or Family.SQLI in likely_families


def test_leaked_signals_boost_auth_bypass(oracle_with_leaks, econ_b):
    """Leaked credentials should boost AUTH_BYPASS."""
    builder = ThesisBuilder()
    thesis = builder.build("t1", oracle_with_leaks, [], econ_b)

    likely_families = {f for f, _ in thesis.likely_vuln_families}
    assert Family.AUTH_BYPASS in likely_families
