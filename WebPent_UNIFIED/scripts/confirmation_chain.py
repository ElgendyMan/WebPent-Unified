#!/usr/bin/env python3
"""UM-DR-38.1 Phase 5 — the confirmation-chain measurement view.

The published UM-DR-38 records carried a contradiction: the discovery
funnel reported ``replay_verified = 0`` while the instrumentation
``verifications`` showed two ``passed = true`` events for the same run.
Root cause (diagnosed, not papered over): the funnel derives its
metrics from the AUTHORITATIVE GRAPH STATE channels, and the graph
state for these findings does not carry a replay flag — replays happen
in the promotion path, measured by the ``counted_verify``
instrumentation. Two legitimate measurement sources were presented as
one number.

This module builds ONE documented, per-finding measurement view:

* every event is joined on ``finding_id`` — never by summing
  independent counters;
* duplicate instrumentation events are de-duplicated by id (a repeated
  event never double-counts a finding);
* the CausalGuard authority interface
  (``adjudicate_with_causal_guard(baseline, candidate, negative_control,
  *, vulnerability_class, ...)``) receives an evidence TRIPLE and
  exposes NO finding identity, so guard confirmation is measured at
  count level and its per-finding ID set is recorded as
  ``NOT_MATERIALIZED`` with the reason — never invented;
* missing evidence is ``null`` / ``NOT_MATERIALIZED`` — missing is
  never converted to ``0``;
* the funnel's stage definitions are NOT changed; its metrics stay
  labeled as graph-state-derived, and the chain invariants are checked
  across BOTH sources explicitly.
"""
from __future__ import annotations

NOT_MATERIALIZED = "NOT_MATERIALIZED"
GUARD_CONFIRMED_VERDICT = "CONFIRMED"
CHAIN_SCHEMA = "umdr38-1-confirmation-chain/v1"


def build_confirmation_chain(
    confirmed_detail: list[dict] | None,
    verifications: list[dict] | None,
    guard_calls: list[dict] | None,
    *,
    eligible_candidates: int | None = None,
) -> dict:
    """Join the confirmation chain per finding.

    ``confirmed_detail`` — the run summary's confirmed findings (id,
    vuln_class, url, evidence_bundle_id): the authoritative RESULT
    artifacts. ``verifications`` — counted_verify events (finding_id,
    passed, ...). ``guard_calls`` — counted_adjudicate events (verdict,
    ...). ``eligible_candidates`` — the funnel's candidate count from
    the authoritative graph state, for the count-level guard invariant.
    """
    confirmed_detail = confirmed_detail or []
    verifications = verifications or []
    guard_calls = guard_calls or []

    # ID sets are SETS: duplicate events never double-count a finding
    confirmed_ids = {
        f["id"] for f in confirmed_detail
        if isinstance(f, dict) and f.get("id")}
    bundle_ids = {
        f["evidence_bundle_id"] for f in confirmed_detail
        if isinstance(f, dict) and f.get("evidence_bundle_id")}
    replay_ids = {
        v["finding_id"] for v in verifications
        if isinstance(v, dict) and v.get("passed")
        and v.get("finding_id")}

    events = []
    for finding in confirmed_detail:
        if not isinstance(finding, dict):
            continue
        fid = finding.get("id")
        if not fid:
            events.append({
                "finding_id": None,
                "chain_status": NOT_MATERIALIZED,
                "reason": "confirmed result artifact carries no finding id",
                "causal_guard_verdict": NOT_MATERIALIZED,
                "proof_bundle_id": finding.get("evidence_bundle_id"),
                "proof_bundle_sealed": bool(
                    finding.get("evidence_bundle_id")),
                "replay_passed": None,
                "promotion_status": NOT_MATERIALIZED,
            })
            continue
        matches = [v for v in verifications
                   if isinstance(v, dict)
                   and v.get("finding_id") == fid]
        bundle_id = finding.get("evidence_bundle_id") or None
        events.append({
            "finding_id": fid,
            "vuln_class": finding.get("vuln_class"),
            "classification_evidence": finding.get(
                "classification_evidence"),
            "url": finding.get("url"),
            "chain_status": (
                "complete"
                if bundle_id and matches
                and any(v.get("passed") for v in matches)
                else "incomplete"),
            # the authority interface exposes no finding identity: the
            # per-finding guard verdict is NOT_MATERIALIZED, honestly
            "causal_guard_verdict": NOT_MATERIALIZED,
            "proof_bundle_id": bundle_id,
            "proof_bundle_sealed": bool(bundle_id),
            "replay_passed": (
                any(v.get("passed") for v in matches)
                if matches else None),
            "replay_events": len(matches),
            "promotion_status": (
                "promoted" if fid in confirmed_ids else NOT_MATERIALIZED),
        })

    guard_confirmed_count = sum(
        1 for g in guard_calls
        if isinstance(g, dict)
        and g.get("verdict") == GUARD_CONFIRMED_VERDICT)

    # replay_verified counts ONLY promoted findings with a passing
    # replay (the finding_id join); a replay event bound to a finding
    # outside the promoted set is an ORPHAN — instrumentation/state
    # divergence, surfaced explicitly, never silently counted
    orphan_replay_ids = replay_ids - confirmed_ids
    replay_verified_ids = replay_ids & confirmed_ids
    counts = {
        "causal_guard_confirmed": guard_confirmed_count,
        "proof_bundle_valid": len(bundle_ids),
        "replay_verified": len(replay_verified_ids),
        "promoted": len(confirmed_ids),
    }
    invariants = {
        # replay_verified <= proof_bundle_valid (by promoted-id subset:
        # a replay-passed finding must be a promoted finding carrying a
        # sealed bundle — the only bundle registry that exists)
        "replay_verified_le_proof_bundle_valid": (
            len(replay_verified_ids) <= len(bundle_ids)),
        "proof_bundle_valid_le_causal_guard_confirmed": (
            len(bundle_ids) <= guard_confirmed_count),
        "causal_guard_confirmed_le_eligible_candidates": (
            (guard_confirmed_count <= eligible_candidates)
            if isinstance(eligible_candidates, int) else None),
        # every replay-passed id IS a promoted finding id (the join);
        # orphan replays make this False — a divergence flag, never a
        # silent correction
        "replay_ids_subset_of_promoted_ids": (
            replay_ids <= confirmed_ids),
        "promoted_ids_all_sealed_bundles": (
            all(f.get("evidence_bundle_id") for f in confirmed_detail
                if isinstance(f, dict) and f.get("id"))),
        "duplicates_deduped_by_id": True,
    }
    return {
        "schema": CHAIN_SCHEMA,
        "source_of_truth": {
            "confirmed_detail": "run summary result artifacts "
                                "(authoritative)",
            "verifications": "counted_verify instrumentation "
                             "(finding_id-bound)",
            "guard_verdicts": "counted_adjudicate instrumentation "
                              "(count-level: the authority interface "
                              "exposes no finding identity)",
            "funnel_stages": "build_discovery_funnel over the "
                             "authoritative final graph state "
                             "(UNCHANGED definitions)",
        },
        "events": events,
        "counts": counts,
        "ids": {
            "causal_guard_confirmed_ids": None,
            "causal_guard_confirmed_ids_reason": (
                "NOT_MATERIALIZED — adjudicate_with_causal_guard "
                "receives an evidence triple (baseline, candidate, "
                "negative_control) with no finding identity; correlating "
                "verdicts to finding ids would require inventing ids"),
            "proof_bundle_valid_ids": sorted(bundle_ids),
            "replay_verified_ids": sorted(replay_verified_ids),
            "orphan_replay_ids": sorted(orphan_replay_ids),
            "promoted_ids": sorted(confirmed_ids),
        },
        "invariants": invariants,
        "invariants_all_true": all(
            v is True for k, v in invariants.items()
            if k != "causal_guard_confirmed_le_eligible_candidates")
            and invariants["causal_guard_confirmed_le_eligible_candidates"]
            is not False
            and not orphan_replay_ids,
    }


def guard_without_bundle_is_not_confirmed(chain: dict) -> bool:
    """A guard confirmation with no sealed bundle never becomes a
    confirmed finding (regression pin §5.5)."""
    for event in chain["events"]:
        if (event.get("proof_bundle_sealed") is not True
                and event.get("chain_status") == "complete"):
            return False
    return True
