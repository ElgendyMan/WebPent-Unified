"""TEAM-2 PHASE 5 — Reproducibility: run the same campaign config twice on
fresh targets + orchestrators and compare LOGICAL outcomes per decision:
validator outcome, promotion decision, identity binding, replay status,
gate status. Timestamps / UUIDs / HMAC stamps / seal digests are excluded by
design. Expected: identical logical outcome across runs.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from team2_common import T2_TARGETS, run_t2_target_campaign, save_json, utc  # noqa: E402
from team2_phase4_campaign import outcome_signature  # noqa: E402


def run_all_targets(run_tag: str) -> list[dict]:
    decisions = []
    for spec in T2_TARGETS:
        camp = run_t2_target_campaign(spec, run_tag=run_tag, max_decisions=25)
        for d in camp["decisions"]:
            d["run_tag"] = run_tag
        decisions.extend(camp["decisions"])
    return decisions


def sig_key(d: dict) -> tuple:
    return (d.get("target_id"), d.get("decision"), d.get("hypothesis_id"))


def main() -> dict:
    ev = {"phase": "PHASE_5_REPRODUCIBILITY", "captured_at": utc()}

    runs = {}
    for tag in ("reproA", "reproB"):
        decs = run_all_targets(tag)
        runs[tag] = {sig_key(d): outcome_signature(d) for d in decs}
        ev[f"{tag}_decisions"] = len(decs)

    a, b = runs["reproA"], runs["reproB"]
    ev["same_decision_keys"] = set(a) == set(b)

    mismatches = []
    for k in sorted(set(a) & set(b)):
        sa, sb = a[k], b[k]
        diff = {f: (sa.get(f), sb.get(f)) for f in sa
                if json.dumps(sa.get(f), sort_keys=True, default=str)
                != json.dumps(sb.get(f), sort_keys=True, default=str)}
        if diff:
            mismatches.append({"decision_key": list(k), "fields": diff})
    ev["signatures_compared"] = len(set(a) & set(b))
    ev["mismatch_count"] = len(mismatches)
    ev["mismatches"] = mismatches[:20]

    # Campaign-level aggregates
    def agg(sigs):
        return {
            "promoted": sum(1 for s in sigs.values() if s["promotion_decision"] == "PROMOTED"),
            "rejected": sum(1 for s in sigs.values() if s["promotion_decision"] == "REJECTED"),
            "identity_bound": sum(1 for s in sigs.values() if s["identity_bound"]),
            "replay_verified": sum(1 for s in sigs.values() if s["replay_verified"]),
            "validator_outcomes": {
                k: sum(1 for s in sigs.values() if s["validator_outcome"] == k)
                for k in ("CONFIRMED", "REFUTED", "INCONCLUSIVE")},
        }
    ev["runA_aggregate"] = agg(a)
    ev["runB_aggregate"] = agg(b)
    ev["aggregates_identical"] = ev["runA_aggregate"] == ev["runB_aggregate"]

    # Cross-check against the PHASE 4 run (third independent execution)
    try:
        p4 = json.load(open(os.path.join(
            "/home/z/my-project/download/TEAM2_AVI_V1_2_VALIDATION",
            "team2_phase4_campaign_run1.json")))
        p4_by_key = {}
        target_of = {}
        for dec in p4["decisions"]:
            target_of.setdefault(dec.get("hypothesis_id"), dec.get("target_id"))
        for dec in p4["decisions"]:
            k = (dec.get("target_id"), dec.get("decision"), dec.get("hypothesis_id"))
            p4_by_key[k] = dec
        p4_sigs = {k: outcome_signature(v) for k, v in p4_by_key.items()}
        cross = 0
        for k in sorted(set(p4_sigs) & set(a)):
            if json.dumps(p4_sigs[k], sort_keys=True, default=str) != json.dumps(a[k], sort_keys=True, default=str):
                cross += 1
        ev["phase4_crosscheck_compared"] = len(set(p4_sigs) & set(a))
        ev["phase4_crosscheck_mismatches"] = cross
    except Exception as exc:
        ev["phase4_crosscheck_error"] = str(exc)[:200]

    ev["expected"] = "same logical outcome across runs (timestamps/uuids/hmac excluded)"
    ev["result"] = ("PASS" if (ev["same_decision_keys"] and ev["mismatch_count"] == 0
                               and ev["aggregates_identical"]
                               and ev.get("phase4_crosscheck_mismatches") == 0)
                    else "FAIL")
    path = save_json("team2_phase5_reproducibility.json", ev)
    print(json.dumps({k: ev.get(k) for k in (
        "same_decision_keys", "signatures_compared", "mismatch_count",
        "runA_aggregate", "runB_aggregate", "aggregates_identical",
        "phase4_crosscheck_compared", "phase4_crosscheck_mismatches",
        "result", "saved")}, indent=1))
    return ev


if __name__ == "__main__":
    main()
