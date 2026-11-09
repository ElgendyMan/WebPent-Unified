"""U-FORGE-15 — The Cross-Target Transfer (red tests).

Knowledge moves only between SIMILAR targets (spec threshold 0.7),
carries only payloads that actually SUCCEEDED on the source target,
and always lands weaker than direct success (factor =
similarity * 0.7). Zero network: everything runs on the in-memory
corpus.
"""
from __future__ import annotations

import pytest

from webpent.forge.cross_target import (
    SIMILARITY_THRESHOLD,
    TargetProfile,
    compute_similarity,
    CrossTargetTransfer,
)
from webpent.forge.outcome_tracker import OutcomeTracker, PayloadOutcome
from webpent.forge.schemas import Family, NormalizedPayload
from webpent.forge.indexer import PayloadIndexer

from datetime import datetime, timezone


def _payload(pid: str, family: Family = Family.SQLI) -> NormalizedPayload:
    return NormalizedPayload(payload_id=pid, family=family,
                             subfamily="", raw=f"{pid}-raw",
                             quality_score=0.5)


def _outcome(pid: str, target: str, success: bool) -> PayloadOutcome:
    return PayloadOutcome(
        outcome_id=f"out-{pid}-{target}-{success}",
        payload_id=pid, target_id=target, family="SQLI",
        context=None, sent_at=datetime.now(timezone.utc),
        success=success, evidence={} if success else {},
        failure_reason=None if success else "blocked")


_SIM_A = TargetProfile(target_id="alpha",
                       tech_stack=("php", "mysql"),
                       waf=("cloudflare",), contexts=("json",))
_SIM_B = TargetProfile(target_id="beta",
                       tech_stack=("php", "python", "mysql"),
                       waf=("cloudflare",), contexts=("json",))
_FAR_C = TargetProfile(target_id="gamma",
                       tech_stack=(".net", "iis"),
                       waf=("f5",), contexts=("xml",))


@pytest.fixture
def rig():
    indexer = PayloadIndexer()
    for pid in ("p-good-1", "p-good-2", "p-fail"):
        indexer.store_payload(_payload(pid))
    tracker = OutcomeTracker(indexer)
    tracker.record(_outcome("p-good-1", "alpha", True))
    tracker.record(_outcome("p-good-2", "alpha", True))
    tracker.record(_outcome("p-fail", "alpha", False))
    transfer = CrossTargetTransfer(indexer)
    transfer.set_profile(_SIM_A)
    transfer.set_profile(_SIM_B)
    transfer.set_profile(_FAR_C)
    return indexer, tracker, transfer


def test_similarity_corpus_documented():
    assert SIMILARITY_THRESHOLD == 0.7
    assert compute_similarity(_SIM_A, _SIM_A) == 1.0
    assert compute_similarity(_SIM_A, _FAR_C) == 0.0
    assert 0.7 <= compute_similarity(_SIM_A, _SIM_B) < 1.0


def test_transfer_below_threshold_is_noop(rig):
    indexer, tracker, transfer = rig
    result = transfer.transfer("alpha", "gamma")
    assert result is None or result.transferred == []
    assert transfer.boost_for("p-good-1", "gamma") == 0.0


def test_transfer_above_threshold_moves_successful(rig):
    indexer, tracker, transfer = rig
    result = transfer.transfer("alpha", "beta")
    assert result is not None
    moved = {pid for pid, _ in result.transferred}
    assert {"p-good-1", "p-good-2"} <= moved
    assert transfer.boost_for("p-good-1", "beta") > 0.0


def test_failed_payloads_never_transfer(rig):
    indexer, tracker, transfer = rig
    result = transfer.transfer("alpha", "beta")
    moved = {pid for pid, _ in result.transferred}
    assert "p-fail" not in moved
    assert transfer.boost_for("p-fail", "beta") == 0.0


def test_boost_factor_is_similarity_times_seven_tenths(rig):
    indexer, tracker, transfer = rig
    result = transfer.transfer("alpha", "beta")
    sim = compute_similarity(_SIM_A, _SIM_B)
    for pid, factor in result.transferred:
        assert factor == pytest.approx(sim * 0.7)
        assert transfer.boost_for(pid, "beta") == \
            pytest.approx(sim * 0.7)


def test_boost_is_weaker_than_direct_success(rig):
    indexer, tracker, transfer = rig
    result = transfer.transfer("alpha", "beta")
    for _, factor in result.transferred:
        assert factor < 1.0
        assert factor <= 0.7


def test_boost_changes_ranking(rig):
    indexer, tracker, transfer = rig
    indexer.store_payload(_payload("p-untried"))
    transfer.transfer("alpha", "beta")
    scores = {
        pid: indexer.get_payload(pid).quality_score
             + transfer.boost_for(pid, "beta")
        for pid in ("p-good-1", "p-untried")
    }
    assert scores["p-good-1"] > scores["p-untried"]


def test_transfer_is_idempotent(rig):
    indexer, tracker, transfer = rig
    first = transfer.transfer("alpha", "beta")
    second = transfer.transfer("alpha", "beta")
    assert [(p, round(f, 6)) for p, f in first.transferred] == \
        [(p, round(f, 6)) for p, f in second.transferred]
