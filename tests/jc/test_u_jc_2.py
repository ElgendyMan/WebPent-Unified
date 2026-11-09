"""U-JC-2: the seven advocates — every voice heard, abstention allowed (JC-L-4)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from webpent.jc.advocates import (
    AdapterAdvocate,
    EconomistAdvocate,
    HistorianAdvocate,
    ObserverAdvocate,
    ResilientAdvocate,
    StrategistAdvocate,
    TacticianAdvocate,
    all_advocate_ids,
    build_default_advocates,
)

NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=timezone.utc)

ALL = (
    TacticianAdvocate,
    ObserverAdvocate,
    AdapterAdvocate,
    HistorianAdvocate,
    StrategistAdvocate,
    ResilientAdvocate,
    EconomistAdvocate,
)

SAMPLE_CONTEXTS = {
    "tactician": {
        "ev_schedule": [
            {"target_id": "attack-lane", "ev_per_hour": 5.0},
            {"target_id": "crawl-lane", "ev_per_hour": 1.0},
        ],
        "target_id": "lab-01",
    },
    "observer": {
        "signals": [{"endpoint": "/admin", "description": "200 OK", "confidence": 0.9}],
        "target_id": "lab-01",
    },
    "adapter": {
        "ev_per_hour_now": {"main": 2.0},
        "ev_per_hour_week_ago": {"main": 10.0},
        "target_id": "lab-01",
    },
    "historian": {
        "lessons": [{"lesson_id": "L1", "content": "sqlmap worked", "confidence": 0.8}],
        "target_id": "lab-01",
    },
    "strategist": {"payload_hints": ["sqli-generic"], "target_id": "lab-01"},
    "resilient": {
        "blocked_paths": [{"lane": "/wp-login", "fallback": "hydra"}],
        "target_id": "lab-01",
    },
    "economist": {
        "findings_value": [{"finding_id": "F1", "value_usd": 40}],
        "target_id": "lab-01",
    },
}


# ------------------------------------------------------- conformance sweep
@pytest.mark.parametrize("advocate_cls", ALL,
                         ids=[cls.__name__.lower() for cls in ALL])
def test_advocate_abstains_without_context(advocate_cls):
    assert advocate_cls().argue({}, now=NOW) is None


@pytest.mark.parametrize("advocate_cls", ALL,
                         ids=[cls.__name__.lower() for cls in ALL])
def test_advocate_argues_when_context_present(advocate_cls):
    advocate = advocate_cls()
    argument = advocate.argue(dict(SAMPLE_CONTEXTS[advocate.id]), now=NOW)
    assert argument is not None
    assert argument.advocate_id == advocate.id
    assert argument.claim
    assert argument.reasoning
    assert argument.alternatives
    assert 0.0 <= argument.confidence <= 1.0
    assert argument.evidence


@pytest.mark.parametrize("advocate_cls", ALL,
                         ids=[cls.__name__.lower() for cls in ALL])
def test_advocate_is_deterministic(advocate_cls):
    advocate = advocate_cls()
    context = dict(SAMPLE_CONTEXTS[advocate.id])
    first = advocate.argue(dict(context), now=NOW)
    second = advocate_cls().argue(dict(context), now=NOW)
    assert first is not None and second is not None
    assert first.claim == second.claim
    assert first.confidence == second.confidence


def test_all_advocate_ids_matches_default_build():
    built = build_default_advocates()
    assert [a.id for a in built] == list(all_advocate_ids())
    assert len(built) == 7


# ------------------------------------------------------------ per-advocate
def test_tactician_picks_highest_ev():
    argument = TacticianAdvocate().argue(SAMPLE_CONTEXTS["tactician"], now=NOW)
    assert argument is not None
    assert "attack-lane" in argument.claim


def test_tactician_ev_not_clamped():
    argument = TacticianAdvocate().argue(
        {"ev_schedule": [{"target_id": "big", "ev_per_hour": 88.0}]}, now=NOW
    )
    assert argument is not None
    assert "88.00" in argument.claim


def test_adapter_fires_on_collapse():
    argument = AdapterAdvocate().argue(SAMPLE_CONTEXTS["adapter"], now=NOW)
    assert argument is not None
    assert "stop working lane main" in argument.claim


def test_adapter_abstains_on_stable_lane():
    assert AdapterAdvocate().argue(
        {"ev_per_hour_now": {"main": 9.0}, "ev_per_hour_week_ago": {"main": 10.0}},
        now=NOW,
    ) is None


def test_economist_prefers_high_value():
    argument = EconomistAdvocate().argue(
        {"findings_value": [{"finding_id": "F1", "value_usd": 120}]}, now=NOW
    )
    assert argument is not None
    assert "submit" in argument.claim


def test_economist_wants_park_on_low_value():
    argument = EconomistAdvocate().argue(
        {"findings_value": [{"finding_id": "F1", "value_usd": 0.2}]}, now=NOW
    )
    assert argument is not None
    assert "park" in argument.claim


def test_observer_reports_signals():
    argument = ObserverAdvocate().argue(SAMPLE_CONTEXTS["observer"], now=NOW)
    assert argument is not None
    assert "/admin" in argument.claim


def test_historian_uses_lessons():
    argument = HistorianAdvocate().argue(SAMPLE_CONTEXTS["historian"], now=NOW)
    assert argument is not None
    assert "L1" in argument.claim


def test_strategist_recommends_payload():
    argument = StrategistAdvocate().argue(SAMPLE_CONTEXTS["strategist"], now=NOW)
    assert argument is not None
    assert "sqli-generic" in argument.claim


def test_resilient_maps_blocked_paths():
    argument = ResilientAdvocate().argue(SAMPLE_CONTEXTS["resilient"], now=NOW)
    assert argument is not None
    assert "blocks" in argument.claim.lower()
    assert "hydra" in argument.claim


def test_evidence_timestamps_are_injected_not_clocked():
    argument = HistorianAdvocate().argue(SAMPLE_CONTEXTS["historian"], now=NOW)
    assert argument is not None
    assert {e.observed_at for e in argument.evidence} == {NOW}


def test_confidence_is_clamped():
    argument = EconomistAdvocate().argue(SAMPLE_CONTEXTS["economist"], now=NOW)
    assert argument is not None
    assert 0.0 <= argument.confidence <= 1.0
