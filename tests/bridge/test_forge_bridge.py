"""Bridge tests — FORGE corpus → campaign probe strategies.

The bridge is pure: it converts ranked corpus hits into an
advisory-only probe strategy string, with the attribution and license
of every payload carried on its line (FORGE-L-7
ATTRIBUTION_IS_SACRED). Zero network, zero mutation.
"""
from __future__ import annotations

import pytest

from forge.conftest import PAYLOADSALLTHETHINGS_MD
from webpent.forge.bridge import probe_strategy, ranked_for
from webpent.forge.ingester import MultiSourceIngester
from webpent.forge.indexer import PayloadIndexer
from webpent.forge.query_engine import PayloadQueryEngine
from webpent.forge.schemas import Family, TargetContext


@pytest.fixture
def engine():
    indexer = PayloadIndexer()
    ingester = MultiSourceIngester(indexer)
    ingester.ingest("payloadsallthethings", content=PAYLOADSALLTHETHINGS_MD,
                    dry_run=False)
    return PayloadQueryEngine(indexer=indexer)


def _context():
    return TargetContext(
        tech_stack=[], waf_detected=[], endpoints=[], parameters=[],
        response_content_type="", param_context=[])


def test_ranks_by_score_order(engine):
    ranked = ranked_for(engine, Family.SQLI, _context(), limit=5)
    scores = [s.score for s in ranked]
    assert scores == sorted(scores, reverse=True)
    assert ranked


def test_attribution_on_every_line(engine):
    strategy = probe_strategy(
        ranked_for(engine, Family.SQLI, _context(), limit=5))
    assert strategy
    assert "payloadsallthethings" in strategy
    assert "MIT" in strategy


def test_limit_enforced(engine):
    ranked = ranked_for(engine, Family.SQLI, _context(), limit=2)
    assert len(ranked) <= 2
    lines = [ln for ln in probe_strategy(ranked).splitlines()
             if ln.strip().startswith(("1.", "2.", "3."))]
    assert len(lines) == len(ranked)


def test_deterministic(engine):
    a = probe_strategy(ranked_for(engine, Family.SQLI, _context(), limit=3))
    b = probe_strategy(ranked_for(engine, Family.SQLI, _context(), limit=3))
    assert a == b


def test_empty_corpus_yields_empty_strategy():
    indexer = PayloadIndexer()
    strategy = probe_strategy(
        ranked_for(PayloadQueryEngine(indexer=indexer), Family.SQLI,
                   _context(), limit=3))
    assert strategy == ""


def test_advisory_marker_present(engine):
    strategy = probe_strategy(
        ranked_for(engine, Family.SQLI, _context(), limit=3))
    assert "advisory" in strategy.lower()
