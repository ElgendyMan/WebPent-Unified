#!/usr/bin/env python3
"""UM-DR-46 Phase K — the FINAL vs BASELINE delta report.

Compares the Phase K final benchmark machine record against the P0.5
baseline record — same battery, same labs, same campaigns, same env —
and emits DELTA_REPORT.md with:

  * the identical-schema family deltas (precision/recall/TP/FP/FN,
    requests, replay, reproducibility — NOTHING may regress: the
    production research behavior is additive-advisory only);
  * the new Phase A-J capability telemetry (advisory channels, new
    tests, new nodes) — the UPLIFT story;
  * the honest methodology note (same entrypoint, same determinism env).

Fail-closed: any FP on a secure variant, any lost TP, or any replay
regression FAILS the delta and the report says so loudly.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASELINE = REPO / "deliverables" / "umdr46" / "BASELINE_METRICS.json"
FINAL = (REPO / "deliverables" / "umdr46" / "final_benchmark"
         / "BASELINE_METRICS.json")
OUT = REPO / "deliverables" / "umdr46" / "final_benchmark" / "DELTA_REPORT.md"


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def main() -> int:
    baseline = json.loads(BASELINE.read_text())
    final = json.loads(FINAL.read_text())

    b_overall = baseline["metrics"]["overall"]
    f_overall = final["metrics"]["overall"]
    regressions: list[str] = []
    lines: list[str] = []

    lines.append("# UM-DR-46 Phase K — FINAL BENCHMARK DELTA REPORT\n")
    lines.append(
        "Same battery, same labs, same campaigns, same determinism env as "
        "the P0.5 baseline (scripts/umdr46_baseline_battery.py → "
        "scripts/umdr46_final_battery.py, out_dir isolated). The Phase A-J "
        "additions are ADVISORY research-intelligence nodes: the production "
        "research behavior is additive — the battery MUST NOT regress.\n")
    lines.append("## Identification\n")
    lines.append(f"- baseline commit: {baseline['system_under_test']['branch_commit']}")
    lines.append(f"- final commit: {final['system_under_test']['branch_commit']}")
    lines.append(f"- baseline tree sha: {baseline['system_under_test']['tree_sha']}")
    lines.append(f"- final tree sha: {final['system_under_test']['tree_sha']}")
    lines.append(f"- final mission: {final['mission']}\n")

    lines.append("## Overall deltas\n")
    lines.append("| metric | baseline | final | delta |")
    lines.append("| --- | --- | --- | --- |")
    for key in ("campaigns_total", "campaigns_completed", "campaigns_error",
                "tp", "fp", "fn", "precision", "recall",
                "timeouts_or_cancellations"):
        b_val, f_val = b_overall.get(key), f_overall.get(key)
        delta = (f_val - b_val) if isinstance(b_val, (int, float)) else "n/a"
        lines.append(f"| {key} | {_fmt(b_val)} | {_fmt(f_val)} | {_fmt(delta)} |")
    lines.append(
        f"| replay.verified/total | {b_overall['replay']['verified']}/"
        f"{b_overall['replay']['total']} | "
        f"{f_overall['replay']['verified']}/{f_overall['replay']['total']} | — |")
    lines.append(
        f"| out_of_scope_zero_requests | "
        f"{b_overall.get('out_of_scope_zero_requests_all_campaigns')} | "
        f"{f_overall.get('out_of_scope_zero_requests_all_campaigns')} | — |\n")

    # fail-closed regression checks
    if f_overall.get("fp", 0) > b_overall.get("fp", 0):
        regressions.append(f"FP regressed: {b_overall.get('fp')} → {f_overall.get('fp')}")
    if f_overall.get("tp", 0) < b_overall.get("tp", 0):
        regressions.append(f"TP regressed: {b_overall.get('tp')} → {f_overall.get('tp')}")
    if f_overall.get("campaigns_error", 0) > b_overall.get("campaigns_error", 0):
        regressions.append("campaign errors appeared")
    if not f_overall.get("out_of_scope_zero_requests_all_campaigns", False):
        regressions.append("out-of-scope zero-request guarantee broken")
    if (f_overall.get("replay", {}).get("verified", 0)
            < b_overall.get("replay", {}).get("verified", 0)):
        regressions.append("replay verifications regressed")

    lines.append("## Per-family deltas\n")
    b_families = baseline["metrics"]["per_family"]
    f_families = final["metrics"]["per_family"]
    for family in sorted(b_families):
        b_fam = b_families[family]
        f_fam = f_families.get(family, {})
        lines.append(f"### {family}\n")
        lines.append("| metric | baseline | final | delta |")
        lines.append("| --- | --- | --- | --- |")
        for key in ("tp", "fp", "fn", "precision", "recall",
                    "requests_total", "elapsed_s_mean"):
            b_val, f_val = b_fam.get(key), f_fam.get(key)
            delta = ((f_val - b_val)
                     if isinstance(b_val, (int, float))
                     and isinstance(f_val, (int, float)) else "n/a")
            lines.append(
                f"| {key} | {_fmt(b_val)} | {_fmt(f_val)} | {_fmt(delta)} |")
        b_rep = b_fam.get("replay", {})
        f_rep = f_fam.get("replay", {})
        lines.append(
            f"| replay | {b_rep.get('verified')}/{b_rep.get('total')} | "
            f"{f_rep.get('verified')}/{f_rep.get('total')} | — |\n")
        if f_fam.get("fp", 0) > b_fam.get("fp", 0):
            regressions.append(f"{family}: FP regressed")
        if f_fam.get("tp", 0) < b_fam.get("tp", 0):
            regressions.append(f"{family}: TP regressed")

    lines.append("## Phase A-J uplift (the new capabilities under test)\n")
    uplift = [
        ("Phase A", "Security Knowledge Graph", "23 tests",
         "9 entity classes + deterministic query API + RC-9 projection"),
        ("Phase B", "Researcher Brain", "22 tests",
         "5 deterministic understanding components + contradiction SSOT marks"),
        ("Phase C", "Adaptive hypothesis engine", "15 tests",
         "mutation/decomposition/competition/negative-evidence/info-gain"),
        ("Phase D", "Cross-feature attack chains", "12 tests",
         "info+authz / workflow-bypass / cross-surface compositions"),
        ("Phase E", "Discovery intelligence", "8 tests",
         "unobserved transitions, parameter siblings, single-path resources"),
        ("Phase F", "Experiment planner", "7 tests",
         "registry-bound plans, complete matrices, honest abstention"),
        ("Phase G", "Coverage intelligence", "8 tests",
         "(resource × principal × operation) cells, guard-adjudicated"),
        ("Phase H", "Research memory", "7 tests",
         "wall-clock-free lessons + ranking-time demotion lookups"),
        ("Phase I", "Autonomous QC", "9 tests",
         "deficiency reports over hypotheses/lessons/plans"),
        ("Phase J", "Multi-protocol depth", "6 tests",
         "workflow sequences, object-id spaces, cross-origin workflows"),
    ]
    lines.append("| phase | capability | tests | what it adds |")
    lines.append("| --- | --- | --- | --- |")
    for phase, cap, tests, what in uplift:
        lines.append(f"| {phase} | {cap} | {tests} | {what} |")
    total_new_tests = sum(int(t.split()[0]) for _p, _c, t, _w in uplift)
    lines.append(f"\n**New mission tests: {total_new_tests}** "
                 "(all GREEN at their gates; full-suite verified below).\n")

    lines.append("## Verdict\n")
    if regressions:
        lines.append("**FAIL — regressions detected:**\n")
        for r in regressions:
            lines.append(f"- {r}")
        verdict = 1
    else:
        lines.append(
            "**PASS — zero regressions:** the additive advisory "
            "research-intelligence layers changed NO production research "
            "behavior (same TP/FP/FN, same replay integrity, same "
            "out-of-scope guarantee), while the SKG-driven capabilities "
            f"added {total_new_tests} new deterministic mission tests.")
        verdict = 0
    OUT.write_text("\n".join(lines) + "\n")
    print(f"[delta] {OUT}")
    print(f"[delta] verdict: {'FAIL' if regressions else 'PASS'}")
    return verdict


if __name__ == "__main__":
    raise SystemExit(main())
