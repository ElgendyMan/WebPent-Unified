#!/usr/bin/env python3
"""blind_v3 REPLICA measurement runner (UM-DR-25, 2026-11-06).

Boots the same-spec replica target (benchmarks/blind_v3_replica/), runs
the two deterministic producers over the full 120-case manifest, scores
against ground truth, and writes the report:

  mode_a  — the recorded 3-GET methodology (guarded_causal_evaluate
            over baseline/candidate/control). This is the reproduction
            of the methodology that measured recall 0.137 on the
            ORIGINAL blind server; on the replica it establishes the
            replica-corpus baseline.

  mode_a2 — the stateful prober (production/stateful_probe.py): the
            same read-only phase plus bounded stateful discovery for
            the manifest's requires_state_transition cases.

HONESTY: the report is labeled replica_corpus=True and explicitly
records that (a) the original blind server is absent from the repo, (b)
the recorded blind baseline stands as-is, and (c) production_qualified
still requires operator-deployed holdout corpora. The prober reads the
MANIFEST only; ground truth is read HERE, after both runs (the scorer's
privilege, mirroring the original blind_v3 discipline).

Usage: python scripts/run_blind_v3_replica_measurement.py
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.cqa_v2 import guarded_causal_evaluate  # noqa: E402
from webpent.production.stateful_probe import (  # noqa: E402
    StatefulCaseProber,
    make_observation,
)

PORT = 9221
MANIFEST = ROOT / "benchmarks" / "blind_v3" / "manifest.json"
GROUND_TRUTH = ROOT / "benchmarks" / "blind_v3" / "ground_truth.json"
REPLICA = ROOT / "benchmarks" / "blind_v3_replica" / "replica_target.py"
REPORTS = ROOT / "reports" / "qualification"


def start_replica() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(REPLICA)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=os.environ.copy(), start_new_session=True,
    )
    for _ in range(150):
        try:
            httpx.get(f"http://127.0.0.1:{PORT}/", timeout=0.2)
            return proc
        except Exception:
            time.sleep(0.1)
    return proc


def stop_replica(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def classify(per_case: dict, gt: dict) -> dict:
    tp = fp = fn = tn = 0
    by_family: dict[str, dict[str, int]] = {}
    for cid, rec in per_case.items():
        truth = gt.get(cid, {}).get("expected_label") == "vulnerable"
        flagged = rec.get("verdict") == "CONFIRMED"
        fam = gt.get(cid, {}).get("case_family", "unknown")
        m = by_family.setdefault(fam, {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "total": 0})
        m["total"] += 1
        if flagged and truth:
            tp += 1; m["tp"] += 1
        elif flagged and not truth:
            fp += 1; m["fp"] += 1
        elif not flagged and truth:
            fn += 1; m["fn"] += 1
        else:
            tn += 1; m["tn"] += 1
    recall = tp / max(tp + fn, 1)
    precision = tp / max(tp + fp, 1)
    for m in by_family.values():
        v = m["tp"] + m["fn"]
        m["recall"] = round(m["tp"] / v, 4) if v else 0.0
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "recall": round(recall, 4), "precision": round(precision, 4),
        "by_family": by_family,
    }


def main() -> int:
    manifest = json.loads(MANIFEST.read_text())
    cases = manifest["cases"]

    proc = start_replica()
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{PORT}"
    client = httpx.Client(timeout=10, base_url=base_url)

    mode_a: dict[str, dict] = {}
    mode_a2: dict[str, dict] = {}
    total_requests_a2 = 0

    try:
        for case in cases:
            cid = case["case_id"]
            # --- mode_a: the recorded 3-GET methodology ---
            try:
                rb = client.get(case["baseline"], headers={"X-Actor": "attacker"})
                rc = client.get(case["candidate"], headers={"X-Actor": "attacker"})
                rctl = client.get(case["control"], headers={"X-Actor": "attacker"})
                result = guarded_causal_evaluate(
                    make_observation(rb, case["baseline"], base_url),
                    make_observation(rc, case["candidate"], base_url),
                    make_observation(rctl, case["control"], base_url),
                )
                mode_a[cid] = {
                    "verdict": result.verdict.value,
                    "confidence": float(result.confidence),
                }
            except Exception as exc:  # honest not-flagged
                mode_a[cid] = {"verdict": "ERROR",
                               "error": f"{type(exc).__name__}: {exc}"}

            # --- mode_a2: the stateful prober (fresh server state per
            #     case is impossible mid-run; the prober's transitions
            #     are per-case ids so state never crosses cases) ---
            prober = StatefulCaseProber(client, base_url=base_url)
            outcome = prober.probe(case)
            mode_a2[cid] = outcome.to_dict()
            total_requests_a2 += outcome.requests_issued
    finally:
        client.close()
        stop_replica(proc)

    # ---- scoring (ground truth read HERE, after both runs) ----------
    gt = json.loads(GROUND_TRUTH.read_text())
    metrics_a = classify(mode_a, gt)
    metrics_a2 = classify(mode_a2, gt)

    report = {
        "benchmark": "blind_v3_replica",
        "replica_corpus": True,
        "honesty_note": (
            "The original blind_v3 target is absent from the repo; this is "
            "a same-spec replica measurement. The recorded blind baseline "
            "(reports/goed_v1_8_4/differential_v184.json: recall 0.137 / "
            "precision 0.6667) stands as-is and is NOT replaced. The "
            "production_qualified label still requires operator-deployed "
            "holdout corpora per the M11 ladder."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": len(cases),
        "mode_a_read_only": {
            "note": "the recorded methodology reproduced on the replica",
            "metrics": metrics_a,
        },
        "mode_a2_stateful_prober": {
            "note": "deterministic stateful discovery (UM-DR-25), "
                    "guarded_causal_evaluate remains the only confirmation "
                    "authority",
            "metrics": metrics_a2,
            "total_requests": total_requests_a2,
            "avg_requests_per_case": round(total_requests_a2 / len(cases), 2),
        },
        "delta": {
            "recall_gain": round(metrics_a2["recall"] - metrics_a["recall"], 4),
            "precision_delta": round(metrics_a2["precision"] - metrics_a["precision"], 4),
        },
        "per_case": {"mode_a": mode_a, "mode_a2": mode_a2},
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = REPORTS / f"blind_v3_replica_{stamp}.json"
    out.write_text(json.dumps(report, indent=2))

    print(f"mode_a  (read-only):  recall={metrics_a['recall']:.4f} "
          f"precision={metrics_a['precision']:.4f} "
          f"(tp={metrics_a['tp']} fp={metrics_a['fp']} fn={metrics_a['fn']} "
          f"tn={metrics_a['tn']})")
    print(f"mode_a2 (stateful):   recall={metrics_a2['recall']:.4f} "
          f"precision={metrics_a2['precision']:.4f} "
          f"(tp={metrics_a2['tp']} fp={metrics_a2['fp']} fn={metrics_a2['fn']} "
          f"tn={metrics_a2['tn']})")
    print(f"delta: recall {report['delta']['recall_gain']:+.4f}, "
          f"precision {report['delta']['precision_delta']:+.4f}")
    print(f"avg requests/case (mode_a2): {report['mode_a2_stateful_prober']['avg_requests_per_case']}")
    print(f"report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
