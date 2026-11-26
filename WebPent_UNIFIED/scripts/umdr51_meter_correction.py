#!/usr/bin/env python3
"""UM-DR-51 Phase 4 — the meter corrections (the owner's word, literal).

Corrections computed FROM THE RAW 36 family-campaign files of window
48 (deliverables/umdr48/run_files_v2 — 6 families x 2 variants x 3
runs), never from derived summaries:

1. cost/finding recomputed with DECLARED denominators, no
   safe/vulnerable mixing (each variant class its own line), no
   total-over-average division (one aggregate over the declared 36
   runs with every denominator spelled out), reconciled against the
   48 Waste Ledger.
2. recall 1.0 corrected: the number on the ORIGINAL anchors is the
   primary line; the expanded mirrors (the tenant_confusion anchor
   expansion) are a SEPARATE line. Changing the truth after seeing
   results and then scoring the same run = independence violation —
   this script never re-scores; it separates what was measured on
   which declared truth.
3. emits the ground-truth fingerprint (the integrity anchor the
   GT-integrity test pins — see tests/test_umdr51_gt_integrity.py).
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "src"))

import umdr46_baseline_battery as base  # noqa: E402

# THE INDEPENDENCE SNAPSHOP (owner's word, literal): umdr48_battery_v2
# MUTATES base.FAMILY_GROUND_TRUTH AT IMPORT TIME (injects the mirror
# defect GT-TEN-1-MIRROR into the defect list). This script measured
# that live: the original-anchor recall computed against the
# pre-import truth and the fn loop running against the post-import
# truth produced a phantom fn=1 on the same runs. "Changing the truth
# after seeing the results and then counting the same run" is exactly
# the independence violation the correction exists to expose — so the
# ORIGINAL truth is snapshotted verbatim BEFORE any battery import,
# and every original-line number below is computed against this
# snapshot only.
ORIGINAL_GT: dict[str, dict] = {
    fam: {
        "defects": [
            {"id": d["id"], "anchor_paths": list(d["anchor_paths"])}
            for d in gt["defects"]
        ],
        "must_not_confirm": sorted(gt["must_not_confirm"]),
    }
    for fam, gt in base.FAMILY_GROUND_TRUTH.items()
}

RAW = REPO / "deliverables/umdr48/run_files_v2"

# the ORIGINAL anchor sets (pre-expansion, the 46 baseline truth —
# from the SNAPSHOT, never from the live GT the battery mutates)
ORIGINAL_ANCHORS = {
    fam: sorted({a for d in gt["defects"] for a in d["anchor_paths"]})
    for fam, gt in ORIGINAL_GT.items()
}
ORIGINAL_MUST_NOT = {
    fam: set(gt["must_not_confirm"]) for fam, gt in ORIGINAL_GT.items()
}
# the EXPANDED mirrors (window 48's declared _ANCHOR_EXPANSION —
# tenant_confusion's header-driven scoping fires on BOTH profile
# directions: the mirror resource PROF-T1-11). Kept as the SEPARATE
# line, never merged into the original-anchor recall. Declared in the
# battery BEFORE the runs — but NOTE: the battery ALSO injects this
# defect into the shared GT at import time (the live-measured
# independence hazard documented above); the snapshot above pins the
# original line against exactly that.
def _load_declared_mirrors() -> dict[str, list[str]]:
    try:
        import umdr48_battery_v2 as battery_v2
        out: dict[str, list[str]] = {}
        for fam, exp in (battery_v2._ANCHOR_EXPANSION or {}).items():
            anchors = [
                a for d in exp.get("defects", [])
                for a in d.get("anchor_paths", [])
                if a not in {x for dd in ORIGINAL_GT.get(fam, {})
                             .get("defects", [])
                             for x in dd["anchor_paths"]}
            ]
            if anchors:
                out[fam] = sorted(anchors)
        return out
    except Exception:
        return {}


EXPANDED_MIRRORS = _load_declared_mirrors()


def gt_fingerprint() -> str:
    """The canonical fingerprint of the ORIGINAL declared ground truth.

    Computed against the snapshot (pre-battery-import) truth: importing
    the battery mutates the live GT (the measured independence hazard),
    so the integrity anchor must be the unmutated original. Any later
    GT modification (an anchor added, a defect renamed) changes this —
    the GT-integrity test fails on exactly that divergence.
    """
    blob = json.dumps(
        {fam: {
            "defects": [sorted(d["anchor_paths"]) for d in gt["defects"]],
            "must_not": sorted(gt["must_not_confirm"]),
        } for fam, gt in sorted(ORIGINAL_GT.items())},
        sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode()).hexdigest()


def _normalize(url: str, origin: str) -> str:
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
    except ValueError:
        return url
    path = u.path or "/"
    return path


def main() -> int:
    files = sorted(RAW.glob("v2_*_run*.json"))
    family_files = [f for f in files if "_vulnerable_" in f.name or "_secure_" in f.name]
    assert len(family_files) == 36, (
        f"expected the 36 raw family campaigns, found {len(family_files)}")

    per_family: dict[str, dict] = {}
    totals = {"vuln_requests": 0, "secure_requests": 0,
              "vuln_runs": 0, "secure_runs": 0}
    for fam in base.FAMILY_GROUND_TRUTH:
        per_family[fam] = {
            "vuln_requests": 0, "secure_requests": 0,
            "vuln_confirmed": 0, "secure_confirmed": 0,
            "vuln_tp_original": 0, "vuln_tp_mirror": 0,
            "vuln_fp": 0, "vuln_fn_original": 0, "vuln_fn_mirror": 0,
            "runs": 0,
        }
    for path in family_files:
        rec = json.loads(path.read_text())
        fam = rec["family"]
        variant = rec["variant"]
        reqs = len(rec.get("lab_requests") or [])
        confirmed = rec.get("confirmed_attribution") or []
        m = per_family[fam]
        m["runs"] += 1
        if variant == "vulnerable":
            totals["vuln_requests"] += reqs
            totals["vuln_runs"] += 1
            m["vuln_requests"] += reqs
            m["vuln_confirmed"] += len(confirmed)
            for a in confirmed:
                p = _normalize(a.get("url") or "", rec.get("lab_origin") or "")
                if p in ORIGINAL_ANCHORS[fam]:
                    m["vuln_tp_original"] += 1
                elif p in EXPANDED_MIRRORS.get(fam, []):
                    m["vuln_tp_mirror"] += 1
                else:
                    m["vuln_fp"] += 1
                # the ORIGINAL-TRUTH line: per the snapshot's
                # must_not_confirm, a mirror-path confirmation is an
                # FP on the original line (the mirror is a defect only
                # on the battery's declared-expansion line)
                if p in ORIGINAL_MUST_NOT[fam]:
                    m["vuln_fp_on_original_truth"] = m.get(
                        "vuln_fp_on_original_truth", 0) + 1
        else:
            totals["secure_requests"] += reqs
            totals["secure_runs"] += 1
            m["secure_requests"] += reqs
            m["secure_confirmed"] += len(confirmed)

    # FN counts per the DECLARED defect lists, per line (original vs
    # mirror): a defect counts found only if one of its anchors was
    # confirmed as a TP (original or mirror) across the 3 vulnerable
    # runs — against the SNAPSHOT truth (never the battery-mutated GT)
    for fam, m in per_family.items():
        gt = ORIGINAL_GT[fam]
        confirmed_paths: set[str] = set()
        for path in family_files:
            rec = json.loads(path.read_text())
            if rec["family"] != fam or rec["variant"] != "vulnerable":
                continue
            for a in rec.get("confirmed_attribution") or []:
                confirmed_paths.add(_normalize(
                    a.get("url") or "", rec.get("lab_origin") or ""))
        m["vuln_fn_original"] = sum(
            1 for d in gt["defects"]
            if not any(a in confirmed_paths for a in d["anchor_paths"]
                       if a in ORIGINAL_ANCHORS[fam]))
        mirror_set = set(EXPANDED_MIRRORS.get(fam, []))
        if mirror_set:
            m["vuln_fn_mirror"] = sum(
                1 for d in gt["defects"]
                if any(a in mirror_set for a in d["anchor_paths"])
                and not any(a in confirmed_paths for a in d["anchor_paths"]))
        else:
            m["vuln_fn_mirror"] = 0

    # the corrected cost lines (each denominator spelled out)
    tp_total_original = sum(m["vuln_tp_original"] for m in per_family.values())
    tp_total_mirror = sum(m["vuln_tp_mirror"] for m in per_family.values())
    cost_lines = {
        "vulnerable_runs_only": {
            "requests": totals["vuln_requests"],
            "runs": totals["vuln_runs"],
            "confirmed_findings": sum(
                m["vuln_confirmed"] for m in per_family.values()),
            "cost_per_finding": round(
                totals["vuln_requests"] / max(1, sum(
                    m["vuln_confirmed"] for m in per_family.values())), 1),
            "denominator_note": "36 raw family campaigns of window 48: "
                                "this line = the 18 VULNERABLE runs only "
                                "(requests summed, confirmations summed — "
                                "a total over a total, never an average of "
                                "averages)",
        },
        "secure_runs_only": {
            "requests": totals["secure_requests"],
            "runs": totals["secure_runs"],
            "confirmed_findings": sum(
                m["secure_confirmed"] for m in per_family.values()),
            "note": "the 18 SECURE runs: their cost is the negative-control "
                    "cost (findings must stay 0 — never mixed into the "
                    "detection ratio)",
        },
        "all_36_runs_declared": {
            "requests": totals["vuln_requests"] + totals["secure_requests"],
            "runs": 36,
            "confirmed_findings_vulnerable": sum(
                m["vuln_confirmed"] for m in per_family.values()),
            "cost_per_finding_if_full_battery_counted": round(
                (totals["vuln_requests"] + totals["secure_requests"])
                / max(1, sum(m["vuln_confirmed"]
                             for m in per_family.values())), 1),
            "denominator_note": "the FULL battery cost per confirmed "
                                "finding (detection + negative controls "
                                "together) — declared as its own line, "
                                "never silently merged with the "
                                "vulnerable-only number",
        },
    }

    recall_lines = {}
    for fam, m in per_family.items():
        orig_tp, orig_fn = m["vuln_tp_original"], m["vuln_fn_original"]
        line = {
            "original_anchors": ORIGINAL_ANCHORS[fam],
            "original_line": {
                "tp": orig_tp, "fn": orig_fn,
                "recall": round(orig_tp / (orig_tp + orig_fn), 3)
                if (orig_tp + orig_fn) else None,
                "fp_on_original_truth": m.get(
                    "vuln_fp_on_original_truth", 0),
                "fp_on_original_truth_note": (
                    "confirmations on the mirror path are FP per the "
                    "ORIGINAL GT's must_not_confirm — the same "
                    "confirmations are TP only on the battery's "
                    "declared-expansion SEPARATE line"),
            },
        }
        mirrors = EXPANDED_MIRRORS.get(fam) or []
        if mirrors:
            mir_tp = m["vuln_tp_mirror"]
            mir_fn = m["vuln_fn_mirror"]
            line["expanded_mirrors_separate_line"] = {
                "anchors": mirrors,
                "tp": mir_tp, "fn": mir_fn,
                "recall": round(mir_tp / (mir_tp + mir_fn), 3)
                if (mir_tp + mir_fn) else None,
                "independence_note": "the mirror line is scored against the "
                                     "EXPANSION declared BEFORE the runs — "
                                     "never re-scored after seeing results",
            }
        recall_lines[fam] = line

    # reconcile with the 48 Waste Ledger (per family) — the ledger's
    # denominator is ONE representative run; the raw 36 are 3 runs per
    # family per variant. Apples-to-apples: ledger_confirmed x 3 runs
    # vs the raw vulnerable-variant confirmations (the raw records 2x
    # per family: vulnerable + secure).
    ledger = json.loads(
        (REPO / "deliverables/umdr48/WASTE_LEDGER.json").read_text())
    reconciliation = {}
    for fam, m in per_family.items():
        led = (ledger.get("after_v2", {}).get("per_family") or {}).get(fam)
        if led:
            raw_per_run = m["vuln_confirmed"] / 3.0
            reconciliation[fam] = {
                "ledger_confirmed_per_run": led.get("confirmed"),
                "raw36_confirmed_per_vuln_run": round(raw_per_run, 3),
                "raw36_confirmed_total_vuln_runs": m["vuln_confirmed"],
                "denominator_note": (
                    "ledger = ONE representative run; raw36 = 3 runs "
                    "x 2 variants — compared per-run (apples to apples)"),
                "agrees": abs(
                    float(led.get("confirmed") or 0) - raw_per_run) < 0.34,
            }

    out = {
        "schema": "umdr51-meter-correction/1.0.0",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source": "the 36 raw family campaign files of window 48 "
                  "(deliverables/umdr48/run_files_v2), never summaries",
        "ground_truth_fingerprint_sha256": gt_fingerprint(),
        "cost_lines": cost_lines,
        "recall_original_vs_mirrors": recall_lines,
        "waste_ledger_reconciliation": reconciliation,
        "the_48_claim_vs_correction": {
            "claimed": "233 requests/finding",
            "corrected_vulnerable_only": cost_lines["vulnerable_runs_only"][
                "cost_per_finding"],
            "corrected_full_battery": cost_lines["all_36_runs_declared"][
                "cost_per_finding_if_full_battery_counted"],
        },
    }
    dest = REPO / "deliverables/umdr51/METER_CORRECTION.json"
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print("gt_fingerprint:", out["ground_truth_fingerprint_sha256"][:16])
    print("cost (vulnerable-only):",
          out["cost_lines"]["vulnerable_runs_only"]["cost_per_finding"],
          "| (full battery):",
          out["cost_lines"]["all_36_runs_declared"][
              "cost_per_finding_if_full_battery_counted"])
    for fam, line in recall_lines.items():
        o = line["original_line"]
        sep = line.get("expanded_mirrors_separate_line")
        print(f"{fam}: original tp={o['tp']} fn={o['fn']} "
              f"recall={o['recall']}"
              + (f" | mirrors tp={sep['tp']} fn={sep['fn']} "
                 f"recall={sep['recall']}" if sep else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
