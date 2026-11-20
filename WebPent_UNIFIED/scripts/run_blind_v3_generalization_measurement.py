#!/usr/bin/env python3
"""blind_v3 GENERALIZATION measurement runner (UM-DR-27, 2026-11-07).

Boots the generalization fixture (benchmarks/blind_v3_replica/
generalization_target.py — same committed ground-truth spec, UNGUESSABLE
token routes, a root route index as the only discovery surface) and runs
THREE deterministic producers over the full 120-case manifest:

  mode_a  — the recorded 3-GET methodology (guarded_causal_evaluate over
            baseline/candidate/control). Control: the methodology that
            measured recall 0.137 on the ORIGINAL blind server.

  mode_a2 — the stateful prober with the LEGACY name grammar (UM-DR-25
            behavior, no transition_source). Control: the grammar that
            matches the replica's naming but NOT this fixture's tokens —
            the honest demonstration that grammar-guessing does not
            generalize.

  mode_a3 — the stateful prober with an OBSERVED-SURFACE source
            (production/transition_sources.py): candidates derived from
            the fixture's root route index (fetched ONCE, counted as
            discovery cost), scoped by the resource-id convention,
            confirmed only by guarded_causal_evaluate. This is the
            grammar-free generalization measurement.

HONESTY: the report is labeled replica_corpus=True + generalization=True
and records that (a) this fixture was authored for this window — it is
NOT the absent original blind server and NOT an independent holdout; (b)
the recorded blind baseline (recall 0.137 / precision 0.6667) stands
as-is; (c) production_qualified still requires operator-deployed holdout
corpora per the M11 ladder. The prober reads the MANIFEST and the route
INDEX only; ground truth is read HERE, after all runs (the scorer's
privilege, mirroring the original blind_v3 discipline).

Usage: python scripts/run_blind_v3_generalization_measurement.py
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
from webpent.production.transition_sources import (  # noqa: E402
    ObservedSurfaceSource,
)

PORT = 9222
MANIFEST = ROOT / "benchmarks" / "blind_v3" / "manifest.json"
GROUND_TRUTH = ROOT / "benchmarks" / "blind_v3" / "ground_truth.json"
TARGET = ROOT / "benchmarks" / "blind_v3_replica" / "generalization_target.py"
REPORTS = ROOT / "reports" / "qualification"


def start_target() -> subprocess.Popen:
    proc = subprocess.Popen(
        [sys.executable, str(TARGET)],
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


def stop_target(proc: subprocess.Popen) -> None:
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
            tp += 1
            m["tp"] += 1
        elif flagged and not truth:
            fp += 1
            m["fp"] += 1
        elif not flagged and truth:
            fn += 1
            m["fn"] += 1
        else:
            tn += 1
            m["tn"] += 1
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

    proc = start_target()
    time.sleep(0.3)
    base_url = f"http://127.0.0.1:{PORT}"
    client = httpx.Client(timeout=10, base_url=base_url)

    mode_a: dict[str, dict] = {}
    mode_a2: dict[str, dict] = {}
    mode_a3: dict[str, dict] = {}
    total_requests_a2 = 0
    total_requests_a3 = 0
    discovery_requests = 0

    try:
        # --- one-time discovery: the fixture's root route index -------
        index_resp = client.get("/", headers={"X-Actor": "attacker"})
        discovery_requests += 1
        index_routes = index_resp.json().get("routes", [])
        observed_source = ObservedSurfaceSource(index_routes)

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

            # --- mode_a2: legacy name-grammar prober (control) ----------
            prober = StatefulCaseProber(client, base_url=base_url)
            outcome = prober.probe(case)
            mode_a2[cid] = outcome.to_dict()
            total_requests_a2 += outcome.requests_issued

            # --- mode_a3: observed-surface prober (generalization) ------
            prober3 = StatefulCaseProber(
                client, base_url=base_url, transition_source=observed_source
            )
            outcome3 = prober3.probe(case)
            mode_a3[cid] = outcome3.to_dict()
            total_requests_a3 += outcome3.requests_issued
    finally:
        client.close()
        stop_target(proc)

    # ---- scoring (ground truth read HERE, after all runs) ----------
    gt = json.loads(GROUND_TRUTH.read_text())
    metrics_a = classify(mode_a, gt)
    metrics_a2 = classify(mode_a2, gt)
    metrics_a3 = classify(mode_a3, gt)

    report = {
        "benchmark": "blind_v3_generalization",
        "replica_corpus": True,
        "generalization_fixture": True,
        "honesty_note": (
            "This fixture was AUTHORED for the UM-DR-27 window to remove "
            "the replica's name-grammar confound: same committed "
            "ground-truth spec, unguessable token routes, a root route "
            "index as the only discovery surface. It is NOT the absent "
            "original blind server and NOT an independent holdout. The "
            "recorded blind baseline (reports/goed_v1_8_4/"
            "differential_v184.json: recall 0.137 / precision 0.6667) "
            "stands as-is and is NOT replaced. The production_qualified "
            "label still requires operator-deployed holdout corpora per "
            "the M11 ladder."
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_size": len(cases),
        "discovery": {
            "surface": "GET / (the fixture's route index, fetched once)",
            "requests": discovery_requests,
            "routes_listed": len(index_routes),
        },
        "mode_a_read_only": {
            "note": "the recorded methodology on this fixture",
            "metrics": metrics_a,
        },
        "mode_a2_grammar_prober": {
            "note": "UM-DR-25 legacy name grammar — the control that must "
                    "NOT lift recall here (the grammar does not match the "
                    "token routes)",
            "metrics": metrics_a2,
            "total_requests": total_requests_a2,
            "avg_requests_per_case": round(total_requests_a2 / len(cases), 2),
        },
        "mode_a3_observed_source_prober": {
            "note": "UM-DR-27 grammar-free discovery: candidates from the "
                    "observed route index, resource-id scoped, bounded, "
                    "guarded_causal_evaluate remains the only confirmation "
                    "authority",
            "metrics": metrics_a3,
            "total_requests": total_requests_a3,
            "avg_requests_per_case": round(total_requests_a3 / len(cases), 2),
        },
        "delta": {
            "grammar_recall_gain": round(metrics_a2["recall"] - metrics_a["recall"], 4),
            "observed_recall_gain": round(metrics_a3["recall"] - metrics_a["recall"], 4),
            "observed_vs_grammar": round(metrics_a3["recall"] - metrics_a2["recall"], 4),
        },
        "per_case": {"mode_a": mode_a, "mode_a2": mode_a2, "mode_a3": mode_a3},
    }

    REPORTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = REPORTS / f"blind_v3_generalization_{stamp}.json"
    out.write_text(json.dumps(report, indent=2))

    print(f"discovery: {discovery_requests} request(s), "
          f"{len(index_routes)} routes listed")
    for name, met, tag in (
        ("mode_a  (read-only) ", metrics_a, ""),
        ("mode_a2 (grammar)   ", metrics_a2, ""),
        ("mode_a3 (observed)  ", metrics_a3, ""),
    ):
        print(f"{name} recall={met['recall']:.4f} "
              f"precision={met['precision']:.4f} "
              f"(tp={met['tp']} fp={met['fp']} fn={met['fn']} "
              f"tn={met['tn']}) {tag}")
    print(f"delta: grammar {report['delta']['grammar_recall_gain']:+.4f}, "
          f"observed {report['delta']['observed_recall_gain']:+.4f}, "
          f"observed-vs-grammar {report['delta']['observed_vs_grammar']:+.4f}")
    print(f"avg requests/case: grammar "
          f"{report['mode_a2_grammar_prober']['avg_requests_per_case']}, "
          f"observed {report['mode_a3_observed_source_prober']['avg_requests_per_case']}")
    print(f"report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
