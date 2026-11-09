#!/usr/bin/env python3
"""Benchmark gate (2026-10-25 proposals, Proposal 6).

Runs the vulnerable-apps self-test harness and fails (exit 1) when
detection quality regresses below the configured floor. Designed for
an OPTIONAL pre-commit/CI hook — it never runs in the default suite;
the operator wires it explicitly.

Usage:
    python scripts/benchmark_gate.py [--db benchmark/vulnbox_metrics.sqlite3]
        [--min-recall 0.9] [--max-false-positives 0] [--modes graphql,web,clean]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from webpent.benchmark.fixtures.runner import (  # noqa: E402
    VulnboxBenchmarkReport,
    run_vulnbox_campaign,
)
from webpent.benchmark.metrics_store import VulnboxMetricsStore  # noqa: E402


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--db", default="benchmark/vulnbox_metrics.sqlite3",
        help="SQLite file for run snapshots (created on demand).",
    )
    parser.add_argument("--min-recall", type=float, default=0.9,
                        help="Fail when recall (TP / (TP+FN)) drops below this.")
    parser.add_argument("--max-false-positives", type=int, default=0,
                        help="Fail when the FP count exceeds this.")
    parser.add_argument("--modes", default="graphql,web,clean",
                        help="Comma-separated fixture modes to run.")
    return parser.parse_args(argv)


def recall_of(report: VulnboxBenchmarkReport) -> float:
    tp, fn = len(report.tp), len(report.fn)
    if tp + fn == 0:
        return 1.0
    return tp / (tp + fn)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    modes = tuple(m.strip() for m in args.modes.split(",") if m.strip())
    report = run_vulnbox_campaign(modes=modes)

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = VulnboxMetricsStore(db_path)
    try:
        store.record_report(report)
    finally:
        store.close()

    recall = recall_of(report)
    fp_count = len(report.fp)
    ok = recall >= args.min_recall and fp_count <= args.max_false_positives

    summary = report.as_dict()
    print(f"[benchmark-gate] run_id={summary['run_id']}")
    print(f"[benchmark-gate] TP={summary['tp']} FP={summary['fp']} FN={summary['fn']}")
    print(f"[benchmark-gate] recall={recall:.2f} (floor {args.min_recall}), "
          f"FP={fp_count} (max {args.max_false_positives})")
    print(f"[benchmark-gate] server_requests={summary['total_server_requests']} "
          f"elapsed={summary['elapsed_seconds']}s")
    for r in summary["results"]:
        print(f"[benchmark-gate]   mode={r['mode']}: confirmed={r['confirmed']} "
              f"refuted={r['refuted']} errors={r['validator_errors']}")
    if not ok:
        print("[benchmark-gate] FAIL — detection quality regressed below the floor.")
        return 1
    print("[benchmark-gate] PASS.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
