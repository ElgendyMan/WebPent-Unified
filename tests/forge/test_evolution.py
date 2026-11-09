"""U-FORGE-14 — The Evolution Engine (red tests).

Adjust payload ranking from real outcomes: success boosts the payload
and its similar siblings (factor 0.5), failure decreases it, a WAF
failure marks the payload WAF-susceptible, and a heavily failing
payload gets candidate variants generated for testing (never stored
as proven). Zero network.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from forge.conftest import PAYLOADSALLTHETHINGS_MD
from webpent.forge.encoding_engine import EncodedVariant
from webpent.forge.evolution import EvolutionEngine
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.ingester import MultiSourceIngester
from webpent.forge.outcome_tracker import PayloadOutcome, OutcomeTracker

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=timezone.utc)


def _outcome(payload_id, success=True, failure_reason=None,
             context=None, sent_at=NOW):
    return PayloadOutcome(
        outcome_id="", payload_id=payload_id, target_id="t-1",
        family="SQLI", context=context, sent_at=sent_at, success=success,
        evidence={"status": 200} if success else {"status": 403},
        failure_reason=failure_reason, phase_id="ph", campaign_id="c")


@pytest.fixture
def corpus():
    indexer = PayloadIndexer()
    ingester = MultiSourceIngester(indexer)
    ingester.ingest("payloadsallthethings",
                    content=PAYLOADSALLTHETHINGS_MD, dry_run=False)
    return indexer


@pytest.fixture
def rig(corpus):
    tracker = OutcomeTracker(corpus)
    engine = EvolutionEngine(corpus, tracker)
    return corpus, tracker, engine


def test_success_boosts_rate(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(
        p.payload_id for p in corpus.list_all())[0]
    before = engine.success_rate(payload_id)
    engine.update_after_outcome(_outcome(payload_id, success=True))
    assert engine.success_rate(payload_id) > before


def test_failure_decreases_rate(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(
        p.payload_id for p in corpus.list_all())[0]
    engine.update_after_outcome(_outcome(payload_id, success=True))
    before = engine.success_rate(payload_id)
    assert before > 0
    engine.update_after_outcome(_outcome(payload_id, success=False))
    assert engine.success_rate(payload_id) < before


def test_similar_payloads_boosted_by_half(rig, corpus):
    tracker = OutcomeTracker(corpus)
    engine = EvolutionEngine(corpus, tracker)
    by_sub = {}
    for p in corpus.list_all():
        by_sub.setdefault((p.family.value, p.subfamily),
                          []).append(p.payload_id)
    group = next(ids for ids in by_sub.values() if len(ids) >= 2)
    group.sort()
    a, b = group[0], group[1]
    before_a = engine.success_rate(a)
    before_b = engine.success_rate(b)
    engine.update_after_outcome(_outcome(a, success=True))
    gain_a = engine.success_rate(a) - before_a
    gain_b = engine.success_rate(b) - before_b
    # Both moved, and the sibling moved by half the lead payload's gain.
    assert gain_b > 0
    assert gain_b == pytest.approx(gain_a * 0.5)


def test_waf_failure_marks_susceptible(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    engine.update_after_outcome(_outcome(
        payload_id, success=False, failure_reason="blocked by WAF"))
    assert engine.waf_susceptible(payload_id) is True


def test_non_waf_failure_no_mark(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    engine.update_after_outcome(_outcome(
        payload_id, success=False, failure_reason="patched endpoint"))
    assert engine.waf_susceptible(payload_id) is False


def test_context_boost_recorded(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    engine.update_after_outcome(_outcome(
        payload_id, success=True, context={"param_context": ["json"]}))
    assert engine.context_boost(payload_id, "json") > 0


def test_rate_clamped_to_unit_interval(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    for _ in range(30):
        engine.update_after_outcome(_outcome(payload_id, success=True))
    rate = engine.success_rate(payload_id)
    assert 0.0 <= rate <= 1.0


def test_unknown_payload_neutral(rig):
    corpus, tracker, engine = rig
    assert engine.success_rate("nope") == 0.0
    assert engine.waf_susceptible("nope") is False
    assert engine.context_boost("nope", "json") == 0.0


def test_candidates_generated_on_high_failure(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    for i in range(6):
        tracker.record(_outcome(payload_id, success=False,
                                failure_reason="blocked",
                                sent_at=NOW.replace(minute=i)))
    candidates = engine.generate_new_variants(payload_id)
    assert candidates
    assert all(c.needs_testing for c in candidates)


def test_no_candidates_on_healthy_payload(rig):
    corpus, tracker, engine = rig
    payload_id = sorted(p.payload_id for p in corpus.list_all())[0]
    for _ in range(6):
        tracker.record(_outcome(payload_id, success=True))
    assert engine.generate_new_variants(payload_id) == []
