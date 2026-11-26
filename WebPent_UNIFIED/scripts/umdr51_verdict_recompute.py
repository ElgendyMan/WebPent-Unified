#!/usr/bin/env python3
"""UM-DR-51 P1: recompute the G5 verdict from the existing run records."""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "deliverables/umdr51/run_files"
recs = []
for arm in ("off", "on"):
    for n in (1, 2, 3):
        recs.append(json.loads((OUT / f"brain_{arm}_run{n}.json").read_text()))

off = [r for r in recs if r["brain"] == "OFF"]
on = [r for r in recs if r["brain"] == "ON"]
w6_a = json.loads((OUT / "brain_on_run4.json").read_text())
w6_b = json.loads((OUT / "brain_on_run5.json").read_text())

verdict = json.loads(
    (REPO / "deliverables/umdr51/PHASE1_BRAIN_DELTA.json").read_text())


def stats(runs):
    import statistics as st
    return {
        "runs": len(runs),
        "findings_total_mean": round(st.mean(r["findings_total"] for r in runs), 3),
        "findings_confirmed_mean": round(st.mean(r["findings_confirmed"] for r in runs), 3),
        "hypotheses_total_mean": round(st.mean(r["hypotheses_total"] for r in runs), 3),
        "hypotheses_confirmed_mean": round(st.mean(r["hypotheses_confirmed"] for r in runs), 3),
        "elapsed_s_mean": round(st.mean(r["elapsed_s"] for r in runs), 3),
        "rank_fingerprints": [r["rank_fingerprint_sha256"] for r in runs],
        "deterministic_within_arm": len({r["rank_fingerprint_sha256"] for r in runs}) == 1,
        "hypotheses_totals": [r["hypotheses_total"] for r in runs],
        "governor_requests_last_minute": [
            r["governor_snapshot"]["requests_last_minute"] for r in runs],
    }


off_stats, on_stats = stats(off), stats(on)
off_fps = set(off_stats["rank_fingerprints"])
on_fps = set(on_stats["rank_fingerprints"])
ceiling_clean = all(
    r["governor_snapshot"]["requests_last_minute"]
    < r["governor_snapshot"]["requests_per_minute"] for r in recs)
hyps_delta = round(on_stats["hypotheses_total_mean"] - off_stats["hypotheses_total_mean"], 3)
rank_changed = bool(on_fps - off_fps)
counts_changed = round(
    on_stats["findings_total_mean"] - off_stats["findings_total_mean"], 3) != 0
pool_changed = hyps_delta != 0

verdict["off_stats"] = off_stats
verdict["on_stats"] = on_stats
verdict["decision_delta"] = {
    "off_fingerprints": sorted(off_fps),
    "on_fingerprints": sorted(on_fps),
    "on_rank_changed_vs_off": rank_changed,
    "hypotheses_total_delta": hyps_delta,
    "off_hypotheses_totals": off_stats["hypotheses_totals"],
    "on_hypotheses_totals": on_stats["hypotheses_totals"],
    "findings_confirmed_delta": round(
        on_stats["findings_confirmed_mean"] - off_stats["findings_confirmed_mean"], 3),
    "findings_total_delta": round(
        on_stats["findings_total_mean"] - off_stats["findings_total_mean"], 3),
    "elapsed_delta_s": round(
        on_stats["elapsed_s_mean"] - off_stats["elapsed_s_mean"], 3),
    "rate_ceiling_never_hit": ceiling_clean,
}
verdict["gate_g5"] = {
    "question": "does the brain change REAL research decisions OFF/ON, "
                "measured on the field, without touching "
                "scope/execution/confirmation authority?",
    "rank_order_changed": rank_changed,
    "outcome_counts_changed": counts_changed,
    "hypothesis_pool_changed": pool_changed,
    "hypotheses_total_delta": hyps_delta,
    "arms_deterministic": (
        off_stats["deterministic_within_arm"]
        and on_stats["deterministic_within_arm"]),
    "rate_ceiling_clean": ceiling_clean,
    "status": (
        "VERIFIED" if (rank_changed or counts_changed) and ceiling_clean
        else "PARTIALLY VERIFIED — the brain measurably changes the "
             "research pool (+2 injected W4/W5 hypotheses per campaign, "
             "deterministic 3/3 runs, unexplored at campaign end) but not "
             "the top-24 rank order or the promoted outcomes on this "
             "target shape in standard mode"
        if pool_changed and ceiling_clean
        else "FAILED — no measured decision delta"),
}
verdict["w6_chain"]["status"] = (
    "INTEGRATED, NOT E2E-VERIFIED — the memory persists (revision "
    "1->2) and is consulted at campaign start, but the lesson "
    "extraction emits zero lessons on this campaign shape "
    "(lesson_summaries stays empty), so no measurable cross-campaign "
    "decision change yet")

(REPO / "deliverables/umdr51/PHASE1_BRAIN_DELTA.json").write_text(
    json.dumps(verdict, indent=2) + "\n")
print(json.dumps(verdict["gate_g5"], indent=1))
print("w6:", verdict["w6_chain"]["status"])
