"""U-JC-4: the Evidence Weigher — transparent, deterministic weighting."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from webpent.jc.contracts import SOURCE_RELIABILITY, Evidence
from webpent.jc.weigher import (
    CORROBORATION_BONUS,
    HALF_LIFE_DAYS,
    EvidenceWeigher,
    recency_factor,
    specificity_factor,
)

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

KINDS = ("signal", "metric", "lesson", "prior")


def ev(kind="signal", content="c", source="lab-01", observed=NOW,
       confidence=0.8, specificity=0.8):
    return Evidence(kind=kind, content=content, source=source,
                    observed_at=observed, confidence=confidence,
                    specificity=specificity)


# --------------------------------------------------------- source table
@pytest.mark.parametrize("kind", KINDS)
def test_source_reliability_table(kind):
    weighted = EvidenceWeigher(now=NOW).weigh(ev(kind=kind))
    assert weighted.components["source_reliability"] == SOURCE_RELIABILITY[kind]


def test_unknown_kind_uses_lowest_reliability():
    weighted = EvidenceWeigher(now=NOW).weigh(ev(kind="gossip"))
    assert (weighted.components["source_reliability"]
            == SOURCE_RELIABILITY["unknown"])


# -------------------------------------------------------------- recency
def test_recency_half_life_is_30_days():
    assert recency_factor(NOW - timedelta(days=HALF_LIFE_DAYS), NOW
                          ) == pytest.approx(0.5)


def test_recency_fresh_evidence_is_one():
    assert recency_factor(NOW, NOW) == pytest.approx(1.0)


def test_recency_floored_at_half():
    assert recency_factor(NOW - timedelta(days=365), NOW) == 0.5


def test_recency_never_punishes_future_stamp():
    assert recency_factor(NOW + timedelta(days=1), NOW) == pytest.approx(1.0)


# ---------------------------------------------------------- specificity
def test_specificity_formula_bounds():
    assert specificity_factor(0.0) == pytest.approx(0.4)
    assert specificity_factor(1.0) == pytest.approx(1.0)
    assert specificity_factor(0.5) == pytest.approx(0.7)


def test_specificity_clamps_out_of_range():
    assert specificity_factor(-2.0) == pytest.approx(0.4)
    assert specificity_factor(9.0) == pytest.approx(1.0)


# -------------------------------------------------------- corroboration
def test_corroboration_bonus_for_two_sources():
    weighted = EvidenceWeigher(now=NOW).weigh_all([
        ev(source="scanner-1"), ev(source="scanner-2"),
    ])
    assert weighted[0].components["corroboration_factor"] == CORROBORATION_BONUS
    assert weighted[1].components["corroboration_factor"] == CORROBORATION_BONUS


def test_no_bonus_for_same_source():
    weighted = EvidenceWeigher(now=NOW).weigh_all([
        ev(source="scanner-1"), ev(source="scanner-1"),
    ])
    assert weighted[0].components["corroboration_factor"] == 1.0


def test_bonus_applies_only_to_matching_kind_and_content():
    weighted = EvidenceWeigher(now=NOW).weigh_all([
        ev(kind="signal", content="x", source="s1"),
        ev(kind="metric", content="x", source="s2"),
    ])
    assert weighted[0].components["corroboration_factor"] == 1.0


def test_order_independent():
    a = EvidenceWeigher(now=NOW).weigh_all([
        ev(source="s1"), ev(source="s2"), ev(kind="lesson", content="z"),
    ])
    b = EvidenceWeigher(now=NOW).weigh_all([
        ev(kind="lesson", content="z"), ev(source="s2"), ev(source="s1"),
    ])
    assert [w.weight for w in a] == [w.weight for w in reversed(b)]


# --------------------------------------------------------- transparency
def test_weight_formula_composition():
    item = ev(kind="lesson", observed=NOW - timedelta(days=30), specificity=0.5)
    weighted = EvidenceWeigher(now=NOW).weigh(item)
    expected = (0.7 * 0.5 * 0.7 * 1.0)
    assert weighted.weight == pytest.approx(expected)


def test_components_breakdown_complete():
    weighted = EvidenceWeigher(now=NOW).weigh(ev())
    assert set(weighted.components) == {
        "source_reliability", "recency_factor", "specificity_factor",
        "corroboration_factor",
    }
    assert weighted.rationale
    assert "reliability" in weighted.rationale


def test_weighing_is_deterministic():
    item = ev(observed=NOW - timedelta(days=7))
    a = EvidenceWeigher(now=NOW).weigh(item)
    b = EvidenceWeigher(now=NOW).weigh(item)
    assert a.weight == b.weight and a.rationale == b.rationale
