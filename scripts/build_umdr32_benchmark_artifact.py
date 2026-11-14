#!/usr/bin/env python3
"""UM-DR-32 §9/§12.G — the EXPLICIT release-time benchmark artifact
generator.

Builds ``reports/qualification/umdr32_benchmark.json`` from the real
six-arm evaluation lab (same harness as
``tests/test_umdr32_evaluation_lab.py``), stamped with the full
UM-DR-32 §3.2 provenance contract (fail-closed on a dirty tree — this
is a release-grade measurement).

The artifact is a RUN RECORD (live fixture ports per run), never
implicitly regenerated: only this explicit command writes it.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

from experiment_provenance import capture_artifact_provenance  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "reports" / "qualification" / "umdr32_benchmark.json"),
    )
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    # fail FAST on a dirty tree (release-grade default)
    import experiment_provenance as _ep
    _ep.capture_source_provenance(ROOT, allow_dirty=args.allow_dirty)

    lab = _load(
        "test_umdr32_evaluation_lab", ROOT / "tests" / "test_umdr32_evaluation_lab.py",
    )
    target = _load(
        "campaign_identity_target",
        ROOT / "benchmarks" / "campaign_identity_target.py",
    )

    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    started = _dt.datetime.now(_dt.timezone.utc).isoformat()
    server = target.build_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    token = set_engagement_target_hosts(base)
    try:
        scores = lab._evaluate_all_arms(base)
    finally:
        clear_engagement_target_hosts(token)
        target.reset_state()
        server.shutdown()
        server.server_close()

    report = {
        "window": "UM-DR-32",
        "level": "controlled six-arm capability evaluation "
                 "(identity_workflow -> differentials/workflow engine -> "
                 "validator routes -> stateful discovery, live controlled "
                 "target, identical recon, equivalent budgets)",
        "population": "campaign_identity_target (team-authored, "
                      "author-known fixture) — NOT an independent holdout; "
                      "a development and mechanism-validation population. "
                      "No generalization claim.",
        "conditions": {
            "arm_budget": lab.ARM_BUDGET,
            "arms": sorted(lab.ARMS),
            "arms_differ_only_in": "which UM-DR-32 capability flags are "
                                   "enabled (cumulative, documented "
                                   "dependencies); recon identical",
        },
        "ground_truth": {
            "manifest_sha256": target._gt_manifest_hash(),
            "vulnerabilities": sorted(target.GROUND_TRUTH_MANIFEST["vulnerabilities"]),
            "safe_controls": target.GROUND_TRUTH_MANIFEST["safe_controls"],
            "fixed_before_measurement": True,
        },
        "arms": scores["arms"],
        "provenance": capture_artifact_provenance(
            ROOT,
            generator_script=Path(__file__).resolve(),
            fixture_files=[
                ROOT / "benchmarks" / "campaign_identity_target.py",
                ROOT / "tests" / "test_umdr32_evaluation_lab.py",
            ],
            lock_file=ROOT / "uv.lock",
            started_utc=started,
            request_budget=lab.ARM_BUDGET * len(lab.ARMS),
            requests_issued=sum(
                a["requests_issued"] for a in scores["arms"].values()
            ),
            ground_truth_manifest=target.GROUND_TRUTH_MANIFEST,
            allow_dirty=args.allow_dirty,
        ),
        "limitations": [
            "team-authored fixture (the honesty boundary)",
            "single-fixture population — no generalization claim",
            "not an independent holdout; no real-world recall/precision claim",
            "no cross-tool comparison (explicitly out of scope)",
        ],
        "generated_by": "scripts/build_umdr32_benchmark_artifact.py "
                        "(explicit release-time command, UM-DR-32 §9)",
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    for arm, score in scores["arms"].items():
        campaign = score["campaign"]
        print(
            f"  {arm:<20} scenarios={campaign['confirmed_scenarios']} "
            f"P={campaign['precision']} R={campaign['recall']} "
            f"requests={score['requests_issued']}/{score['budget']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
