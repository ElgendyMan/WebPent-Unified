"""UM-DR-40 RC-5 — generation-time semantic fingerprint dedup.

The 39 register's RC-5: hypothesis dedup was fragmented — per-batch
(url, vuln_class) TEXTUAL comparison while the reducer upserts by
fresh random UUIDs, so the same content re-entered the pool across
passes. The acceptance: a deterministic fingerprint (uuid5) at
GENERATION time, and a dedup test across TWO hypothesis_node passes.

The implementation (production/hypothesis_dedup.py, wired at the
builder registration boundary): the registered node is the
dedup-wrapped generator, so every emitted hypothesis carries the
deterministic uuid5 of its content fingerprint. These tests pin the
fingerprint, the wrapper, and the cross-pass reducer behavior.
"""
from __future__ import annotations

import sys

REPO = __file__.rsplit("/tests/", 1)[0]
sys.path.insert(0, f"{REPO}/src")

from webpent.agents.hypothesis_analyzer.agent import (  # noqa: E402
    hypothesis_node,
)
from webpent.models.hypothesis import Hypothesis  # noqa: E402
from webpent.production.hypothesis_dedup import (  # noqa: E402
    deduplicated_hypothesis_node,
    deterministic_hypothesis_id,
    hypothesis_content_fingerprint,
)
from webpent.state.reducers import merge_hypotheses  # noqa: E402


def _hypothesis(**overrides):
    kwargs = dict(
        target_url="http://127.0.0.1:9000/invoices/33",
        statement="Potential IDOR at /invoices/33",
        vuln_class="idor",
        origin="heuristic",
    )
    kwargs.update(overrides)
    return Hypothesis(**kwargs)


def _state() -> dict:
    from types import SimpleNamespace

    from webpent.models.targets import Target

    return {
        "target": Target(
            url="http://127.0.0.1:9000/app/index.php?page=foo"),
        "base_url": "http://127.0.0.1:9000",
        "endpoints": [
            "http://127.0.0.1:9000/app/index.php?page=foo",
            "http://127.0.0.1:9000/app/invoices.php?id=33",
        ],
        "crawled_data": {"forms": []},
        "skip_recon": False,
        "declared_origins": SimpleNamespace(
            url="http://127.0.0.1:9000"),
    }


def test_fingerprint_is_deterministic_and_normalizing() -> None:
    """Same content (any producer, any casing/trailing slash) → same
    fingerprint; a security-relevant difference → different."""
    fp = hypothesis_content_fingerprint(
        "http://127.0.0.1:9000/invoices/33", "idor")
    assert fp == hypothesis_content_fingerprint(
        "HTTP://127.0.0.1:9000/invoices/33/", "IDOR")
    assert fp != hypothesis_content_fingerprint(
        "http://127.0.0.1:9000/invoices/33", "sqli")
    assert fp != hypothesis_content_fingerprint(
        "http://127.0.0.1:9000/other", "idor")
    assert deterministic_hypothesis_id(fp) == (
        deterministic_hypothesis_id(fp))


def test_wrapper_retags_emitted_ids() -> None:
    """The registered node replaces the generator's random uuid4 ids
    with deterministic content ids (generation-time fingerprint)."""
    bare = hypothesis_node(_state())
    wrapped = deduplicated_hypothesis_node(_state())

    bare_ids = {h.id for h in bare["hypotheses"]}
    wrapped_ids = {h.id for h in wrapped["hypotheses"]}
    # the wrapped pass emits ONLY deterministic ids…
    assert wrapped_ids == {
        deterministic_hypothesis_id(
            hypothesis_content_fingerprint(h.target_url, h.vuln_class))
        for h in wrapped["hypotheses"]}
    # …which are NOT the random ones the bare generator produced
    assert not (wrapped_ids & bare_ids)
    # the update content (count, targets, classes) is unchanged
    assert len(wrapped_ids) == len(bare_ids)
    assert {(h.target_url, h.vuln_class) for h in wrapped["hypotheses"]} \
        == {(h.target_url, h.vuln_class) for h in bare["hypotheses"]}


def test_reducer_absorbs_cross_pass_duplicates() -> None:
    """Two identical generation passes land in one pool entry: the
    upsert-by-id reducer absorbs the re-entry."""
    pass_one = [_hypothesis(), _hypothesis(vuln_class="sqli")]
    pass_two = [_hypothesis(), _hypothesis(vuln_class="sqli")]
    for pool in (pass_one, pass_two):
        for h in pool:
            h.id = deterministic_hypothesis_id(
                hypothesis_content_fingerprint(
                    h.target_url, h.vuln_class))
    merged = merge_hypotheses(list(pass_one), list(pass_two))
    assert len(merged) == 2
    assert len({h.id for h in merged}) == 2


def test_dedup_across_two_registered_node_passes() -> None:
    """The RC-5 acceptance test: run the REGISTERED (wrapped) node
    TWICE on the same state; both passes agree per item and the
    union through merge_hypotheses contains each (target_url,
    vuln_class) exactly once — cross-pass content duplicates cannot
    re-enter the pool."""
    first = deduplicated_hypothesis_node(_state())
    second = deduplicated_hypothesis_node(_state())
    first_pool = first["hypotheses"]
    second_pool = second["hypotheses"]
    assert first_pool, "the node must produce hypotheses from endpoints"

    # deterministic ids: both passes agree per item
    assert {h.id for h in first_pool} == {h.id for h in second_pool}

    # the reducer absorbs the cross-pass re-entry: no content growth
    merged = merge_hypotheses(list(first_pool), list(second_pool))
    pairs = [(h.target_url, h.vuln_class) for h in merged]
    assert len(merged) == len(first_pool)
    assert len(set(pairs)) == len(pairs), (
        f"cross-pass content duplicates survived: {sorted(pairs)}")
