"""UM-DR-38.1 Phase 5 — confirmation-chain integrity regression tests.

The published UM-DR-38 records carried a contradiction: the funnel
reported ``replay_verified = 0`` while the instrumentation showed two
``passed = true`` verification events. These tests pin the fixed
measurement contract:

* events join on finding_id — never by summing independent counters;
* a guard confirmation WITHOUT a sealed bundle never completes a
  finding's chain;
* a sealed bundle WITHOUT a replay never completes the chain;
* a replay event joined to a DIFFERENT finding does not complete that
  finding;
* duplicate instrumentation events never double-count;
* missing ids are NOT_MATERIALIZED — never converted to 0;
* a successful full chain yields a consistent measurement.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from confirmation_chain import (  # noqa: E402
    NOT_MATERIALIZED,
    build_confirmation_chain,
    guard_without_bundle_is_not_confirmed,
)


def _finding(fid: str, bundle: str | None = "proof_bundle_1") -> dict:
    return {"id": fid, "vuln_class": "auth_bypass",
            "url": f"http://127.0.0.1:1/api/invoices/{fid}",
            "evidence_bundle_id": bundle}


def _verify(fid: str, passed: bool = True) -> dict:
    return {"finding_id": fid, "passed": passed,
            "reason": "verified_replay" if passed else "replay_failed"}


def test_guard_without_bundle_never_completes_the_chain() -> None:
    chain = build_confirmation_chain(
        [_finding("f-1", bundle=None)],
        [], [{"verdict": "CONFIRMED"}])
    assert chain["events"][0]["chain_status"] == "incomplete"
    assert chain["events"][0]["proof_bundle_sealed"] is False
    assert guard_without_bundle_is_not_confirmed(chain) is True


def test_bundle_without_replay_never_completes_the_chain() -> None:
    chain = build_confirmation_chain(
        [_finding("f-1")], [], [{"verdict": "CONFIRMED"}])
    assert chain["events"][0]["chain_status"] == "incomplete"
    assert chain["events"][0]["replay_passed"] is None


def test_replay_for_a_different_finding_does_not_complete_the_chain() -> None:
    chain = build_confirmation_chain(
        [_finding("f-1")], [_verify("f-OTHER")], [])
    event = chain["events"][0]
    assert event["chain_status"] == "incomplete"
    assert event["replay_passed"] is None
    assert event["replay_events"] == 0
    assert chain["counts"]["replay_verified"] == 0
    # the orphan replay surfaces as a divergence flag, never silent
    assert chain["ids"]["orphan_replay_ids"] == ["f-OTHER"]
    assert chain["invariants"]["replay_ids_subset_of_promoted_ids"] is False
    assert chain["invariants_all_true"] is False


def test_duplicate_events_never_double_count() -> None:
    chain = build_confirmation_chain(
        [_finding("f-1"), _finding("f-1")],          # duplicate result
        [_verify("f-1"), _verify("f-1"), _verify("f-1")],  # dup replays
        [{"verdict": "CONFIRMED"}] * 5)
    assert chain["counts"]["promoted"] == 1
    assert chain["counts"]["replay_verified"] == 1
    assert chain["counts"]["causal_guard_confirmed"] == 5  # events count
    assert chain["ids"]["replay_verified_ids"] == ["f-1"]


def test_missing_ids_are_not_materialized_never_zero() -> None:
    chain = build_confirmation_chain(
        [{"vuln_class": "auth_bypass", "id": None}],
        [], [])
    assert chain["events"][0]["chain_status"] == NOT_MATERIALIZED
    assert chain["events"][0]["finding_id"] is None
    assert chain["ids"]["causal_guard_confirmed_ids"] is None
    assert chain["ids"]["causal_guard_confirmed_ids_reason"], (
        "the missing guard-id correlation must carry its reason — "
        "the authority interface exposes no finding identity")


def test_successful_full_chain_is_consistent() -> None:
    chain = build_confirmation_chain(
        [_finding("f-1", bundle="proof_bundle_1"),
         _finding("f-2", bundle="proof_bundle_2")],
        [_verify("f-1"), _verify("f-2")],
        [{"verdict": "CONFIRMED"}, {"verdict": "CONFIRMED"}],
        eligible_candidates=9)
    assert chain["counts"] == {
        "causal_guard_confirmed": 2, "proof_bundle_valid": 2,
        "replay_verified": 2, "promoted": 2}
    assert chain["invariants"]["replay_verified_le_proof_bundle_valid"]
    assert chain["invariants"][
        "proof_bundle_valid_le_causal_guard_confirmed"]
    assert chain["invariants"][
        "causal_guard_confirmed_le_eligible_candidates"] is True
    assert chain["invariants"]["replay_ids_subset_of_promoted_ids"]
    assert chain["invariants_all_true"] is True
    assert all(e["chain_status"] == "complete"
               for e in chain["events"])


def test_published_contradiction_now_measured_consistently() -> None:
    """The UM-DR-38 published record: funnel replay_verified=0 while
    two instrumentation verifications passed. The chain view measures
    replay from the finding_id-joined instrumentation events (source-
    labeled) — the funnel keeps its graph-state definition, and the
    disagreement between sources is EXPLAINED, not hidden."""
    chain = build_confirmation_chain(
        [_finding("f-1", bundle="proof_bundle_1"),
         _finding("f-2", bundle="proof_bundle_2")],
        [_verify("f-1"), _verify("f-2")],
        [{"verdict": "CONFIRMED"}, {"verdict": "CONFIRMED"}])
    # the funnel (graph state) said 0; the instrumentation joins say 2
    assert chain["counts"]["replay_verified"] == 2
    assert "graph state" in chain["source_of_truth"]["funnel_stages"]
    assert "finding_id-bound" in chain["source_of_truth"]["verifications"]
