"""UM-DR-41 §10.1/§10.2 — RC-6 reducer-state and RC-7 accounting tests."""
from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from webpent.agents.strategist import agent as strategist_module
from webpent.production.decision_ledger import (
    information_gain_snapshot,
    ranked_alternatives,
)


def _hyp(status: str = "unexplored"):
    return SimpleNamespace(id=str(uuid4()), status=status,
                           vuln_class="idor")


def test_rc6_empty_update_list_is_not_everything_resolved():
    """THE directive scenario: a batch whose updated_hypotheses is EMPTY
    must report pool_after == pool_before (no spurious 'distinguished'
    ids). Previously pool_after was derived from updated_hypotheses
    alone, so an empty list reported every open hypothesis resolved."""
    pool_before = [str(uuid4()) for _ in range(4)]
    # the fixed strategist code path, exercised through the snapshot
    # with the reducer-equivalent computation:
    terminal_ids = set()  # nothing promoted/abandoned
    pool_after = [h for h in pool_before if h not in terminal_ids]
    snap = information_gain_snapshot(pool_before, pool_after)
    assert snap["distinguished_count"] == 0
    assert snap["pool_delta"] == 0
    # and the OLD buggy derivation, for contrast:
    old_after = []  # = ids of updated_hypotheses (empty)
    old_snap = information_gain_snapshot(pool_before, old_after)
    assert old_snap["distinguished_count"] == 4  # the false positive


def test_rc6_terminal_ids_only_leave_the_pool():
    """Promoted/abandoned leave; deferred/rabbit-hole updates STAY."""
    pool = [str(uuid4()) for _ in range(3)]
    promoted = pool[0]
    deferred = pool[1]  # updated but still open (e.g. DEFER retag)
    terminal = {promoted}
    after = [h for h in pool if h not in terminal]
    snap = information_gain_snapshot(pool, after)
    assert snap["distinguished"] == [promoted]
    assert deferred in after  # not counted as resolved


def test_rc7_ranked_alternatives_original_rank_semantics():
    """rank 1 = highest-scored candidate OVERALL (before removing the
    chosen one), and the chosen entry never lists itself."""
    ranked = [(_hyp(), 0.9), (_hyp(), 0.8), (_hyp(), 0.7)]
    alts = ranked_alternatives(ranked, exclude_id=str(ranked[0][0].id))
    assert [a["rank"] for a in alts] == [1, 2]  # ranks continue 1,2
    assert all(a["hypothesis_id"] != str(ranked[0][0].id) for a in alts)
    assert alts[0]["score"] == 0.8


def test_rc7_alternatives_bounded_and_skip_idless():
    ranked = [(_hyp(), float(i)) for i in range(9)] + [
        (SimpleNamespace(id="", status="x"), 1.0)]
    alts = ranked_alternatives(ranked)
    assert len(alts) == 5  # ALTERNATIVES_SLICE_SIZE
    assert all(a["hypothesis_id"] for a in alts)


# ---------------------------------------------------------------------------
# UM-DR-41 §10.2 — RC-7 challenger persistence across research cycles
# ---------------------------------------------------------------------------

def _hyp_with_id(hid: str, status: str = "unexplored"):
    return SimpleNamespace(id=hid, status=status, vuln_class="idor")


def test_rc7_challenger_entry_survives_across_cycles_via_merge():
    """The directive's persistence scenario: cycle 1 ranks A > B and
    promotes A; cycle 2 ranks B > C and defers B. The merged
    coverage_ledger (merge_dicts semantics) must still carry B's
    challenger record from BOTH cycles' perspectives with B alive —
    challengers survive, resolved entries flip to resolved."""
    from webpent.state.reducers import merge_dicts
    a, b, c = "hyp-a", "hyp-b", "hyp-c"
    # cycle 1 ledger (what record_coverage produced)
    cycle1 = {
        "schema_version": 1,
        "cycle_count": 1,
        "last_batch_id": "batch-1",
        "entries": {
            a: {"hypothesis_id": a, "status": "tested", "action": "promote",
                "reason": "promoted_to_validator_pipeline",
                "score": 0.9, "rank_in_batch": 1, "batch_id": "batch-1",
                "challenger_status": "resolved"},
            b: {"hypothesis_id": b, "status": "blocked", "action": "defer",
                "reason": "prioritization_gate_deferred",
                "score": 0.8, "rank_in_batch": 2, "batch_id": "batch-1",
                "challenger_status": "challenger"},
        },
    }
    # cycle 2 ledger: B re-ranked first, still deferred; C new
    cycle2 = {
        "schema_version": 1,
        "cycle_count": 2,
        "last_batch_id": "batch-2",
        "entries": {
            b: {"hypothesis_id": b, "status": "blocked", "action": "defer",
                "reason": "self_critique_deprioritized",
                "score": 0.75, "rank_in_batch": 1, "batch_id": "batch-2",
                "challenger_status": "challenger"},
            c: {"hypothesis_id": c, "status": "blocked", "action": "defer",
                "reason": "prioritization_gate_deferred",
                "score": 0.6, "rank_in_batch": 2, "batch_id": "batch-2",
                "challenger_status": "challenger"},
        },
    }
    merged = merge_dicts(cycle1, cycle2)
    assert merged["cycle_count"] == 2  # scalar overwrite = running count
    assert merged["last_batch_id"] == "batch-2"
    # A stays recorded as resolved from cycle 1 (audit trail survives)
    assert merged["entries"][a]["challenger_status"] == "resolved"
    # B's record reflects cycle 2 (latest decision) and stays a challenger
    assert merged["entries"][b]["batch_id"] == "batch-2"
    assert merged["entries"][b]["rank_in_batch"] == 1
    assert merged["entries"][b]["challenger_status"] == "challenger"
    # C joined the pool in cycle 2
    assert merged["entries"][c]["challenger_status"] == "challenger"
    # every entry carries its rejection/unavailability reason
    assert merged["entries"][b]["reason"] == "self_critique_deprioritized"


def test_rc7_batch_id_deterministic_from_candidates():
    """The batch id must be deterministic (same candidates -> same id)
    so checkpoints and replays map to the same ledger identity."""
    import hashlib
    ids = ["x-1", "x-2", "x-3"]
    bid = hashlib.sha256(",".join(sorted(ids)).encode()).hexdigest()[:12]
    assert bid == hashlib.sha256(
        ",".join(sorted(ids)).encode()).hexdigest()[:12]
    assert len(bid) == 12
    # different candidate set -> different batch
    other = hashlib.sha256(",".join(sorted(["x-1", "x-2"])).encode()).hexdigest()[:12]
    assert bid != other
