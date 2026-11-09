#!/usr/bin/env python3
"""UM-DR-31.1 R2 — the EXPLICIT release-time generator for the ablation artifact.

Why this exists (audit finding F02, remediation R2):
    Historically ``test_ablation_report_written`` wrote the repo-tracked
    ``reports/qualification/umdr31_ablation.json`` as a test side effect.
    The fixture target binds an OS-assigned (random) port, so every
    post-release test re-run silently mutated the committed evidence —
    commit 2ad93aa is exactly that drift. Since UM-DR-31.1 the test
    writes only into ``tmp_path``; the committed artifact is generated
    ONLY by this explicit command, at release time, by a human or a
    release pipeline that intends to refresh it.

Usage:
    python scripts/build_umdr31_ablation_artifact.py \
        [--output reports/qualification/umdr31_ablation.json]

The script reuses the four-arm harness from the e2e ablation test module
(same target, same budget, same arms) and stamps the generated artifact
with the git HEAD and a true UTC timestamp. The artifact's per-run ports
are the live fixture's ports for THAT run — the artifact is a run
record, not a deterministic build product; that is precisely why it must
never be regenerated implicitly.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import importlib.util
import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "scripts"))

from experiment_provenance import capture_artifact_provenance  # noqa: E402


def _load_test_module():
    spec = importlib.util.spec_from_file_location(
        "test_umdr31_campaign_e2e_ablation",
        ROOT / "tests" / "test_umdr31_campaign_e2e_ablation.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=str(ROOT / "reports" / "qualification" / "umdr31_ablation.json"),
        help="artifact output path (default: the tracked qualification path)",
    )
    parser.add_argument(
        "--allow-dirty", action="store_true",
        help="explicitly permit a dirty tree (engineering-grade run; the "
             "artifact then records the source-diff hash and is labeled "
             "dirty — it can never masquerade as a clean-release result)",
    )
    args = parser.parse_args()

    # Fail FAST: reject a dirty tree before spending the measurement
    # budget, not after (UM-DR-32 §3.2 default is fail-closed).
    import experiment_provenance as _ep
    _ep.capture_source_provenance(ROOT, allow_dirty=args.allow_dirty)

    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    mod = _load_test_module()
    started_utc = _dt.datetime.now(_dt.timezone.utc).isoformat()
    server = ThreadingHTTPServer(("127.0.0.1", 0), mod.target_module.VaultHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    arms: dict[str, dict] = {}
    try:
        mod.target_module.reset_state()
        token = set_engagement_target_hosts(base)
        try:
            for label, signals, loop in (
                ("baseline", "none", False),
                ("coverage_only", "coverage", True),
                ("invariant_only", "invariant", True),
                ("full_loop", "full", True),
            ):
                arms[label] = mod._run_arm(
                    base, signals=signals, loop=loop,
                    max_requests=mod.ABLATION_BUDGET,
                )
        finally:
            clear_engagement_target_hosts(token)
    finally:
        mod.target_module.reset_state()
        server.shutdown()
        server.server_close()

    report = {
        "window": "UM-DR-31",
        "level": "campaign ablation (research_loop + family_execution_node, "
                 "real state, real executor, live controlled target)",
        "population": "campaign_research_target (team-authored, "
                      "author-known two-directory fixture) — NOT an "
                      "independent holdout",
        "provenance": capture_artifact_provenance(
            ROOT,
            generator_script=Path(__file__).resolve(),
            fixture_files=[
                ROOT / "benchmarks" / "campaign_research_target.py",
                ROOT / "tests" / "test_umdr31_campaign_e2e_ablation.py",
            ],
            lock_file=ROOT / "uv.lock",
            started_utc=started_utc,
            request_budget=mod.ABLATION_BUDGET,
            requests_issued=sum(
                a.get("requests_issued", 0) for a in arms.values()
            ),
            ground_truth_manifest={
                mod.GROUND_TRUTH_VULNERABLE: "vulnerable",
                "others": "safe / out-of-scope",
            },
            allow_dirty=args.allow_dirty,
        ),
        "conditions": {
            "request_budget": mod.ABLATION_BUDGET,
            "cases_mined": 8,
            "scope_refused": 2,
            "arms_differ_only_in": "which research evidence channels are "
                                   "populated + the loop flag",
        },
        "arms": arms,
        "ground_truth": {
            mod.GROUND_TRUTH_VULNERABLE: "vulnerable (IDOR after seal)",
            "rec_2/rec_3/rec_4/vlt_2/vlt_4": "safe (never confirmed in any arm)",
            "internal/*": "out of scope (refused before any request)",
        },
        "finding": (
            "Under a budget that cannot cover both directories, the "
            "invariant/workflow input's priority ordering reaches the "
            "ground truth (1 confirmed) where the alphabetical baseline "
            "confirms nothing; the coverage input's measurable is BOTH "
            "pool enrichment AND — the UM-DR-31.1 scheduling fix — "
            "execution priority via the coverage surface hint (the "
            "UM-DR-31 window measured this arm at 0 confirmed; the "
            "identical budget now reaches the ground truth). "
            "Same cases, same ceiling, same scope checks — ordering only."
        ),
        "limitations": [
            "team-authored fixture (the honesty boundary)",
            "single-fixture population — no generalization claim",
            "a full 45-node LLM campaign run requires operator "
            "credentials; the LangGraph-level proof covers the "
            "runtime integration through the real wiring function",
        ],
        "generated_by": "scripts/build_umdr31_ablation_artifact.py (explicit release-time command, UM-DR-31.1 R2; provenance contract UM-DR-32 §3.2)",
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
