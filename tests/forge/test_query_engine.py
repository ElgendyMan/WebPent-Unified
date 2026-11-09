"""U-FORGE-6 — The Query Engine (12 tests per spec).

Ranking formula is the spec's published arithmetic:
    score = context_match*0.4 + quality*0.3 + success_rate*0.2
          + novelty*0.1
Every score carries its transparent breakdown (FORGE-L-7
ATTRIBUTION_IS_SACRED / L-9 determinism).
"""
from __future__ import annotations

import time

import pytest

from webpent.forge.indexer import PayloadIndexer
from webpent.forge.normalizer import Normalizer
from webpent.forge.query_engine import PayloadQueryEngine
from webpent.forge.schemas import Family, PayloadAttribution, TargetContext


def make_attribution(source="payloadsallthethings", trust=0.95):
    return PayloadAttribution(
        payload_id="pending",
        original_source=source,
        original_url="https://example/src",
        original_author="author",
        license="MIT",
        license_url="https://example/license",
        source_trust=trust,
    )


def seed(indexer: PayloadIndexer, raw: str, family: Family | None = None,
         quality=0.9, novelty=0.5, polyglot=False,
         tech=(), waf=(), context=(), chains_with=()):
    normalizer = Normalizer()
    payload = normalizer.normalize(raw, make_attribution(), family=family)
    # Direct curator-level control for ranking tests (the frozen
    # dataclass is adjusted through its storage contract, exactly as
    # the indexer round-trip would rebuild it).
    object.__setattr__(payload, "quality_score", quality)
    object.__setattr__(payload, "novelty_score", novelty)
    object.__setattr__(payload, "is_polyglot", polyglot)
    object.__setattr__(payload, "target_tech", tuple(tech))
    object.__setattr__(payload, "target_waf", tuple(waf))
    object.__setattr__(payload, "target_context", tuple(context))
    object.__setattr__(payload, "chains_with", tuple(chains_with))
    indexer.store_payload(payload)
    return payload


@pytest.fixture
def setup():
    indexer = PayloadIndexer()
    mysql_union = seed(indexer, "' UNION SELECT NULL--", quality=0.9,
                       novelty=0.6, tech=("mysql",), context=("query",))
    mysql_sleep = seed(indexer, "SLEEP(5)", quality=0.8, novelty=0.7,
                       tech=("mysql",), context=("query",))
    xss = seed(indexer, "<script>alert(1)</script>", quality=0.7,
               novelty=0.4)
    waf_bypass = seed(indexer, "1/*!50000UNION*/ SELECT NULL--",
                      quality=0.95, novelty=0.9, tech=("mysql",),
                      waf=("cloudflare",), context=("query",))
    polyglot = seed(indexer, '"><svg onload=alert(1)>', quality=0.95,
                    novelty=0.8, polyglot=True,
                    context=("html", "javascript"))
    # Outcomes: mysql_union succeeded once of two attempts (L-5).
    indexer.store_outcome(payload_id=mysql_union.payload_id, target_id="t1",
                          success=True, evidence="rows leaked")
    indexer.store_outcome(payload_id=mysql_union.payload_id, target_id="t2",
                          success=False, evidence="blocked")
    engine = PayloadQueryEngine(indexer=indexer)
    return engine, indexer, {
        "mysql_union": mysql_union, "mysql_sleep": mysql_sleep,
        "xss": xss, "waf_bypass": waf_bypass, "polyglot": polyglot,
    }


def test_find_by_family(setup):
    engine, _, seeded = setup
    results = engine.find(Family.SQLI, _generic_context())
    ids = {r.payload.payload_id for r in results}
    assert seeded["mysql_union"].payload_id in ids
    assert seeded["mysql_sleep"].payload_id in ids
    assert seeded["xss"].payload_id not in ids


def test_find_by_tech_match(setup):
    engine, _, seeded = setup
    context = TargetContext(
        tech_stack=["mysql"], waf_detected=[], endpoints=[], parameters=[],
        response_content_type="application/json", param_context=["query"])
    results = engine.find(Family.SQLI, context)
    top = results[0].payload.payload_id
    # A mysql-targeting payload outranks one without tech affinity.
    assert top in (seeded["mysql_union"].payload_id,
                   seeded["mysql_sleep"].payload_id)


def test_find_by_waf_bypass(setup):
    engine, _, seeded = setup
    context = TargetContext(
        tech_stack=["mysql"], waf_detected=["cloudflare"], endpoints=[],
        parameters=[], response_content_type="application/json",
        param_context=["query"])
    results = engine.find(Family.SQLI, context)
    assert results[0].payload.payload_id == seeded["waf_bypass"].payload_id


def test_find_by_context(setup):
    engine, _, _ = setup
    json_context = TargetContext(
        tech_stack=[], waf_detected=[], endpoints=[], parameters=[],
        response_content_type="application/json", param_context=["json"])
    results = engine.find(Family.SQLI, json_context)
    assert results, "context-scoped find should still rank the family"


def test_ranking_deterministic(setup):
    engine, _, _ = setup
    a = engine.find(Family.SQLI, _generic_context())
    b = engine.find(Family.SQLI, _generic_context())
    assert [(r.payload.payload_id, r.score) for r in a] == \
        [(r.payload.payload_id, r.score) for r in b]


def test_limit_enforced(setup):
    engine, _, _ = setup
    results = engine.find(Family.SQLI, _generic_context(), limit=2)
    assert len(results) == 2


def test_min_quality_enforced(setup):
    engine, _, _ = setup
    results = engine.find(Family.SQLI, _generic_context(), min_quality=0.85)
    assert all(r.payload.quality_score >= 0.85 for r in results)
    assert results


def test_polyglots_found(setup):
    engine, _, seeded = setup
    results = engine.find_polyglots(["html", "javascript"])
    ids = {r.payload.payload_id for r in results}
    assert seeded["polyglot"].payload_id in ids
    assert all(r.payload.is_polyglot for r in results)


def test_chained_found(setup):
    engine, indexer, seeded = setup
    base = seeded["mysql_union"]
    follower = seed(indexer, "' UNION SELECT NULL,user(),3-- -")
    object.__setattr__(follower, "chains_with", [base.payload_id])
    indexer.store_payload(follower)
    results = engine.find_chained(base.payload_id)
    assert follower.payload_id in {r.payload.payload_id for r in results}


def test_no_results_when_no_match(setup):
    engine, _, _ = setup
    results = engine.find(Family.XXE, _generic_context())
    assert results == []


def test_breakdown_transparent(setup):
    engine, _, _ = setup
    results = engine.find(Family.SQLI, _generic_context())
    top = results[0]
    assert set(top.breakdown) == {
        "context_match", "quality", "success_rate", "novelty"}
    expected = (top.breakdown["context_match"] * 0.4
                + top.breakdown["quality"] * 0.3
                + top.breakdown["success_rate"] * 0.2
                + top.breakdown["novelty"] * 0.1)
    assert top.score == pytest.approx(expected, abs=1e-6)


def test_performance_under_100ms(setup):
    engine, indexer, _ = setup
    for i in range(200):
        seed(indexer, f"' OR {i}=1-- -")
    start = time.perf_counter()
    engine.find(Family.SQLI, _generic_context())
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 100.0, f"find took {elapsed_ms:.1f}ms"


def _generic_context():
    return TargetContext(
        tech_stack=["mysql"], waf_detected=[], endpoints=[], parameters=[],
        response_content_type="application/json", param_context=["query"])
