"""UM-DR-40 RC-6/RC-7 — the decision-ledger measurement contracts.

RC-7 acceptance: the coverage ledger gains the ranked runner-up
slice. RC-6 acceptance: per-batch gain computed from the before/
after information state (which hypotheses the batch distinguished),
recorded in the decision log — adapted INTO the strategist, not a
parallel orchestrator.

The unit contracts pin the pure functions; the integration contracts
run the ACTUAL strategist node (the thawed frozen file) and assert
that a real decision batch produces coverage entries with the
alternatives slice and a measured-gain decision-log entry.
"""
from __future__ import annotations

import sys

REPO = __file__.rsplit("/tests/", 1)[0]
sys.path.insert(0, f"{REPO}/src")

from webpent.production.decision_ledger import (  # noqa: E402
    ALTERNATIVES_SLICE_SIZE,
    information_gain_snapshot,
    ranked_alternatives,
)

try:
    import webpent.agents.strategist.agent as strategist_mod  # noqa: E402
except ImportError:  # pragma: no cover
    strategist_mod = None


def _cand(hyp_id: str, score: float):
    """A minimal ranked candidate (the strategist uses full
    Hypothesis objects; the unit tests only need id + score)."""
    class _H:
        id = hyp_id
    return _H(), score


def test_ranked_alternatives_bounded_topk_with_scores() -> None:
    """The runner-up slice: ranked order, scores rounded, bounded to
    k, never including the chosen hypothesis."""
    ranked = [_cand(f"h{i}", 0.9 - i * 0.1) for i in range(8)]
    chosen = ranked[0][0]
    alt = ranked_alternatives(ranked, exclude_id=chosen.id)
    assert len(alt) == ALTERNATIVES_SLICE_SIZE == 5
    assert [a["hypothesis_id"] for a in alt] == [
        "h1", "h2", "h3", "h4", "h5"]
    assert [a["rank"] for a in alt] == [1, 2, 3, 4, 5]
    assert alt[0]["score"] == 0.8
    # the chosen hypothesis is never its own alternative
    assert all(a["hypothesis_id"] != chosen.id for a in alt)


def test_ranked_alternatives_empty_without_ids() -> None:
    """Candidates without ids are skipped — nothing is invented."""
    ranked = [(object(), 0.9), _cand("ok", 0.5)]
    alt = ranked_alternatives(ranked)
    assert [a["hypothesis_id"] for a in alt] == ["ok"]


def test_information_gain_snapshot_measures_the_difference() -> None:
    """RC-6: distinguished = ids resolved out of the pool by THIS
    batch; pool_delta is the size change; preconditions are carried
    through when the caller has a real channel."""
    snap = information_gain_snapshot(
        ["a", "b", "c", "d"], ["a", "d", "new"],
        resolved_preconditions=["auth_state=unknown"],
    )
    assert snap["distinguished"] == ["b", "c"]
    assert snap["distinguished_count"] == 2
    assert snap["pool_before"] == 4
    assert snap["pool_after"] == 3
    assert snap["pool_delta"] == -1
    assert snap["added"] == ["new"]
    assert snap["resolved_preconditions"] == ["auth_state=unknown"]


def test_information_gain_empty_batch_yields_zero() -> None:
    """No resolution — no invented gain."""
    snap = information_gain_snapshot(["a", "b"], ["a", "b"])
    assert snap["distinguished"] == []
    assert snap["distinguished_count"] == 0
    assert snap["pool_delta"] == 0


def test_strategist_available_for_integration() -> None:
    """The integration contract needs the strategist module; it is
    importable (the thawed file compiles and loads)."""
    assert strategist_mod is not None


def test_strategist_records_alternatives_and_measured_gain() -> None:
    """The integration acceptance: a real strategist pass over a
    pool produces (1) coverage entries carrying the ranked runner-up
    slice, and (2) a measured-gain decision-log entry whose
    distinguished ids match the ids this batch resolved out of the
    pool (promoted/abandoned)."""
    from webpent.models.hypothesis import Hypothesis
    from webpent.models.targets import Target

    def _hypo(target_id: str) -> Hypothesis:
        return Hypothesis(
            target_url=f"http://127.0.0.1:9100/{target_id}",
            statement=f"Potential test surface {target_id}",
            vuln_class="xss",
            origin="heuristic",
        )

    hypotheses = [_hypo("a"), _hypo("b"), _hypo("c")]
    state = {
        "target": Target(url="http://127.0.0.1:9100/"),
        "base_url": "http://127.0.0.1:9100",
        "hypotheses": hypotheses,
        "crawled_data": {},
        "scan_progress": 0,
    }
    # capture the pool's actual ids (Hypothesis generates its own
    # uuid — the assertion must use the pool's real identity)
    pool_ids = {str(h.id) for h in hypotheses}
    result = strategist_mod.strategist_node(state)

    # RC-7: coverage entries carry the bounded alternatives slice
    ledger = result.get("coverage_ledger") or {}
    assert ledger, "the strategist must record coverage entries"
    # the ledger envelope carries summary fields; the per-candidate
    # entries live under "entries"
    candidate_entries = ledger.get("entries") or {}
    assert candidate_entries, (
        "the strategist must record per-candidate coverage entries")
    slices = [v.get("alternatives_considered") for v in
              candidate_entries.values()]
    assert all(isinstance(s, list) for s in slices), slices
    nonempty = [s for s in slices if s]
    assert nonempty, "at least one entry must list its alternatives"
    for s in nonempty:
        assert len(s) <= 5
        assert all({"hypothesis_id", "score", "rank"} <= set(a)
                   for a in s)
        assert all(a["rank"] >= 1 for a in s)

    # RC-6: the decision log carries the measured batch gain
    log = result.get("decision_log") or []
    gain_entries = [e for e in log
                    if e.get("rule_fired")
                    == "umdr40_rc6_measured_information_gain"]
    assert len(gain_entries) == 1, log
    gain = gain_entries[0]["metadata"]["information_gain"]
    assert gain["pool_before"] == 3
    # distinguished = the ids resolved out of the pool by the batch
    after_ids = {str(h.id) for h in result.get("hypotheses", [])}
    expected = sorted(pool_ids - after_ids)
    assert gain["distinguished"] == expected
    assert gain["distinguished_count"] == len(expected)
    assert gain["pool_after"] == len(after_ids)
    # every recorded alternative must reference a real pool id
    for entry in candidate_entries.values():
        for alt in entry.get("alternatives_considered") or []:
            assert alt["hypothesis_id"] in pool_ids
    # the gain entry persists through the memory decision log path
    # like every other entry (same vocabulary, logged with metadata)
    assert gain_entries[0]["decision_type"] == "prioritization"
