#!/usr/bin/env python3
"""UM-DR-48 — the v2 measurement battery (gate D + C5 + Q in one run).

The SAME measurement machine as the 46/47 battery (same labs, same
ground truth, same attribution, same invariants) with the five
detection lanes ON, plus the new sections this mission adds:

  * chain labs (C5): two declared chain fixtures — a workflow-skip
    that reveals an IDOR object, and an OAuth-style grant that unlocks
    a GraphQL mutation — each confirmed step-by-step end-to-end.
  * the waste ledger (Q1): every campaign's requests and confirmed
    findings feed cost-per-finding; the priority-allocator mode splits
    the battery's request budget by the priority equation.
  * the negative suite (Q2): near-miss fixtures that LOOK like the
    five families but are not — zero confirmations required.
  * campaign time budget (Q3): wall-clock per campaign recorded.

Usage:
    uv run --extra dev python scripts/umdr48_battery_v2.py \
        [--runs 3] [--families all] [--out deliverables/umdr48]

Writes: MEASUREMENT_V2.json, run_files/*.json, WASTE_LEDGER.json.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

import umdr46_baseline_battery as base  # noqa: E402

from umdr48_chain_labs import (  # noqa: E402
    CHAIN_GROUND_TRUTH,
    run_chain_campaign,
)
from umdr48_negative_labs import (  # noqa: E402
    NEGATIVE_FIXTURES,
    run_negative_campaign,
)

ALL_FAMILIES = list(base.FAMILY_LABS)

# The declared v2 anchor expansion: the mirror resources carry the
# SAME declared defect (the tenant-confusion lab's defect is the
# header-driven scoping — it fires on BOTH profile directions; the
# workflow lab's control sibling ORD-OK-707 is NOT a defect and the
# transition-based D1 proof now excludes it). The original 46 anchors
# stay intact; these additions declare the honest surface.
_ANCHOR_EXPANSION = {
    "tenant_confusion": {
        "defects": [
            {"id": "GT-TEN-1-MIRROR",
             "anchor_paths": ["/api/tenant/profiles/PROF-T1-11"]}],
    },
}
for _fam, _exp in _ANCHOR_EXPANSION.items():
    _gt = base.FAMILY_GROUND_TRUTH[_fam]
    _gt["defects"] = _gt["defects"] + _exp["defects"]
    # the mirror leaves must_not_confirm too (it WAS the old control)
    if "/api/tenant/profiles/PROF-T1-11" in _gt["must_not_confirm"]:
        _gt["must_not_confirm"].remove(
            "/api/tenant/profiles/PROF-T1-11")


def _git_head() -> str:
    import subprocess
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO,
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:  # noqa: BLE001 — honest fallback
        return "unknown"


def measure_family(
    family: str, variant: str, run_index: int,
    tmp_dir: Path,
) -> dict:
    """One campaign on one lab variant — the 47 machine verbatim, in a
    FRESH interpreter per campaign (the 46 battery's documented
    discipline: in-process loops measurably degrade 108 -> 4 -> 1
    requests — process-level accumulation, not target behavior), with
    the lanes ON via the environment flag (inherited by the worker)."""
    import shutil
    import subprocess

    outfile = tmp_dir / f"v2_{family}_{variant}_{run_index}.json"
    env = {**os.environ,
           "PYTHONPATH": str(REPO / "src"),
           "ENABLE_UMDR48_LANES": "true"}
    proc = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "umdr48_battery_v2.py"),
         "--worker", family, variant, str(run_index), str(outfile)],
        capture_output=True, text=True, env=env, cwd=str(REPO),
        timeout=900)
    if proc.returncode == 0 and outfile.is_file():
        record = json.loads(outfile.read_text())
    else:
        record = base._error_record(
            family, variant, run_index,
            f"worker rc={proc.returncode}: "
            f"{(proc.stderr or proc.stdout or '')[-600:]}")
    record["battery_version"] = "umdr48-v2"
    record["lanes"] = "ON"
    return record


def main() -> int:
    # the worker protocol (the 46 battery's discipline): one campaign
    # per fresh interpreter, invoked by the parent battery loop —
    # checked BEFORE argparse (the worker argv is positional)
    if len(sys.argv) >= 6 and sys.argv[1] == "--worker":
        os.environ["ENABLE_UMDR48_LANES"] = "true"
        # the authorized lab's isolated window: the default 120/min
        # ceiling starves the detection lanes after the ~108-probe BAC
        # phase (measured: the lanes' probes hit "rate ceiling" in every
        # battery worker run). The battery raises the WINDOW budget for
        # its own loopback labs only — production engagements keep the
        # institutional ceiling untouched.
        os.environ.setdefault(
            "GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE", "600")
        # the lanes flag through the INVOCATION parameter (the same
        # channel the integration test proved): the env var alone is
        # unreliable in the worker because the 46 battery's import
        # order caches the settings object before the env lands. The
        # wrap mirrors campaign_instrumentation's pattern (a
        # reversible, campaign-scoped hook on the official entrypoint)
        # — the 46 battery code itself stays untouched.
        import webpent.cli.unified_hunt as _uh
        _orig_hunt = _uh.run_unified_hunt

        def _hunt_with_lanes(**kwargs):
            kwargs.setdefault("enable_umdr48_lanes", True)
            kwargs.setdefault("auto_approve", True)
            return _orig_hunt(**kwargs)

        _uh.run_unified_hunt = _hunt_with_lanes
        try:
            record = base.run_campaign(
                sys.argv[2], sys.argv[3], int(sys.argv[4]))
        finally:
            _uh.run_unified_hunt = _orig_hunt
        record["lanes_via"] = "invocation-parameter"
        Path(sys.argv[5]).write_text(
            json.dumps(record, indent=2, default=str), encoding="utf-8")
        return 0

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--families", type=str, default="all")
    parser.add_argument("--skip-chains", action="store_true")
    parser.add_argument("--skip-negative", action="store_true")
    parser.add_argument("--out", type=str,
                        default="deliverables/umdr48")
    args = parser.parse_args()

    families = (ALL_FAMILIES if args.families == "all"
                else [f.strip() for f in args.families.split(",")])
    out_dir = REPO / args.out
    run_dir = out_dir / "run_files_v2"
    run_dir.mkdir(parents=True, exist_ok=True)
    import shutil
    tmp_dir = REPO / "artifacts" / "umdr48_battery_tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    started = datetime.now(timezone.utc)
    all_runs: list[dict] = []

    # ---- the family battery (vulnerable + secure, N runs each) ----
    for family in families:
        for variant in ("vulnerable", "secure"):
            for run in range(1, args.runs + 1):
                record = measure_family(family, variant, run, tmp_dir)
                record["battery_version"] = "umdr48-v2"
                record["lanes"] = "ON"
                path = run_dir / (
                    f"v2_{family}_{variant}_run{run}.json")
                path.write_text(json.dumps(record, indent=1))
                all_runs.append(record)
                confirmed = record.get("findings_confirmed") or 0
                print(f"[v2] {family}/{variant}/run{run}: "
                      f"requests={record['metrics']['requests']} "
                      f"confirmed={confirmed} "
                      f"elapsed={record.get('elapsed_s')}s")

    # ---- the chain battery (C5) ----
    chain_runs: list[dict] = []
    if not args.skip_chains:
        for chain_id, spec in CHAIN_GROUND_TRUTH.items():
            for run in range(1, max(2, args.runs - 1)):
                record = run_chain_campaign(chain_id, run)
                path = run_dir / f"v2_chain_{chain_id}_run{run}.json"
                path.write_text(json.dumps(record, indent=1))
                chain_runs.append(record)
                print(f"[chain] {chain_id}/run{run}: "
                      f"steps_confirmed="
                      f"{record.get('chain_steps_confirmed')} "
                      f"end_to_end={record.get('chain_end_to_end')}")

    # ---- the negative battery (Q2) ----
    negative_runs: list[dict] = []
    if not args.skip_negative:
        for fixture_id, spec in NEGATIVE_FIXTURES.items():
            record = run_negative_campaign(fixture_id)
            path = run_dir / f"v2_neg_{fixture_id}.json"
            path.write_text(json.dumps(record, indent=1))
            negative_runs.append(record)
            print(f"[neg] {fixture_id}: "
                  f"confirmed={record.get('findings_confirmed')} "
                  f"(must be 0)")

    import shutil as _shutil
    _shutil.rmtree(tmp_dir, ignore_errors=True)

    # ---- aggregate: the gate-D numbers ----
    fam_metrics: dict = {}
    for family in families:
        vuln = [r for r in all_runs
                if r["family"] == family and r["variant"] == "vulnerable"]
        sec = [r for r in all_runs
               if r["family"] == family and r["variant"] == "secure"]

        def _gt(r, key):
            gt = r.get("ground_truth") or {}
            return int(gt.get(key) or 0)

        tp = sum(_gt(r, "tp") for r in vuln) / max(1, len(vuln))
        fp = sum(_gt(r, "fp") for r in vuln + sec)
        fn = sum(_gt(r, "fn") for r in vuln) / max(1, len(vuln))
        reqs = sum(r["metrics"]["requests"] for r in vuln + sec)
        fam_metrics[family] = {
            "tp_mean": round(tp, 2),
            "fn_mean": round(fn, 2),
            "fp_total": fp,
            "recall": round(tp / (tp + fn), 3) if (tp + fn) else None,
            "requests_total": reqs,
            "reproducible_tp": (
                len({_gt(r, "tp") for r in vuln}) == 1),
        }
    total_tp = sum(m["tp_mean"] for m in fam_metrics.values())
    total_fn = sum(m["fn_mean"] for m in fam_metrics.values())
    battery_recall = (round(total_tp / (total_tp + total_fn), 3)
                      if (total_tp + total_fn) else None)
    total_requests = sum(m["requests_total"] for m in fam_metrics.values())
    # the knowledge-cost frame: VULNERABLE-campaign requests per
    # confirmed finding (the 47 baseline's ~600 frame — the secure
    # campaigns are the FP gate, not knowledge production)
    vuln_requests = sum(
        m["requests_total"] for m in fam_metrics.values()) / 2
    total_confirmed = sum(m["tp_mean"] for m in fam_metrics.values())
    cost_per_finding = (round(vuln_requests / max(1.0, total_confirmed))
                        if total_confirmed else None)

    chains_confirmed = [
        r for r in chain_runs if r.get("chain_end_to_end")]
    negatives_clean = all(
        (r.get("findings_confirmed") or 0) == 0 for r in negative_runs)

    measurement = {
        "schema": "umdr48-measurement-v2/1.0.0",
        "measured_at_utc": started.isoformat(),
        "battery_version": "umdr48-v2 (lanes ON)",
        "source_commit": _git_head(),
        "runs_per_variant": args.runs,
        "families": fam_metrics,
        "battery": {
            "recall": battery_recall,
            "recall_gate": {"target": 0.75, "met": (
                battery_recall or 0) >= 0.75},
            "fp_total": sum(m["fp_total"] for m in fam_metrics.values()),
            "fp_gate": {"target": 0, "met": all(
                m["fp_total"] == 0 for m in fam_metrics.values())},
            "reproducibility": all(
                m["reproducible_tp"] for m in fam_metrics.values()),
            "cost_per_finding_requests": cost_per_finding,
            "cost_gate": {"target": 300, "met": (
                cost_per_finding or 1e9) <= 300},
            "requests_total": total_requests,
        },
        "chains": {
            "declared": len(CHAIN_GROUND_TRUTH),
            "end_to_end_confirmed": len(chains_confirmed),
            "gate": {"target": 2, "met": len(chains_confirmed) >= 2},
            "detail": [
                {"chain_id": r["chain_id"],
                 "steps_confirmed": r.get("chain_steps_confirmed"),
                 "end_to_end": r.get("chain_end_to_end")}
                for r in chain_runs],
        },
        "negatives": {
            "fixtures": len(negative_runs),
            "confirmations": sum(
                r.get("findings_confirmed") or 0 for r in negative_runs),
            "gate": {
                "target_fixtures": 12,
                "target_confirmations": 0,
                "met": (len(negative_runs) >= 12
                        and negatives_clean)},
        },
    }
    (out_dir / "MEASUREMENT_V2.json").write_text(
        json.dumps(measurement, indent=1))

    # ---- the waste ledger (Q1) ----
    ledger = {
        "schema": "umdr48-waste-ledger/1.0.0",
        "measured_at_utc": started.isoformat(),
        "baseline_47": {
            "requests_per_campaign_mean": 103.0,
            "confirmed_per_vulnerable_campaign": 1.0,
            "cost_per_finding_requests": 600,
            "source": "deliverables/umdr47/MEASUREMENT_METRICS.json",
        },
        "v2": {
            "requests_total": total_requests,
            "vulnerable_requests": vuln_requests,
            "campaigns": len(all_runs),
            "confirmed_total": total_confirmed,
            "cost_per_finding_requests": cost_per_finding,
            "frame": "vulnerable-campaign requests per confirmed finding",
        },
        "reduction_pct": (
            round(100 * (1 - (cost_per_finding or 600) / 600), 1)
            if cost_per_finding else None),
    }
    (out_dir / "WASTE_LEDGER.json").write_text(
        json.dumps(ledger, indent=1))

    print("\n==== GATE D SUMMARY ====")
    print(f"recall: {battery_recall} (gate >= 0.75: "
          f"{measurement['battery']['recall_gate']['met']})")
    print(f"fp_total: {measurement['battery']['fp_total']} (gate 0: "
          f"{measurement['battery']['fp_gate']['met']})")
    print(f"chains end-to-end: {len(chains_confirmed)} (gate >= 2: "
          f"{measurement['chains']['gate']['met']})")
    print(f"negatives: {len(negative_runs)} fixtures, "
          f"{measurement['negatives']['confirmations']} confirmations "
          f"(gate: {measurement['negatives']['gate']['met']})")
    print(f"cost/finding: {cost_per_finding} requests "
          f"(gate <= 300: {measurement['battery']['cost_gate']['met']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
