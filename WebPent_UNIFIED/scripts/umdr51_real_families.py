#!/usr/bin/env python3
"""UM-DR-51 Phase 3 — real-target family campaigns (law 16 numbers).

One campaign per subprocess on each REAL authorized lab target
(Juice Shop, WebGoat), zero-prior-knowledge, through run_unified_hunt
(the official loop), brain ON, lanes ON. The raw per-run records feed
the DETECTION_FAMILY_MATRIX reconciliation against the PUBLIC truth
catalogs (window 49's deliverables/umdr49/truth_catalogs/*.json —
the apps' own published artifacts).

Usage:
  uv run --extra dev python scripts/umdr51_real_families.py \
      --app webgoat --url http://127.0.0.1:8080/WebGoat --runs 2
Writes: deliverables/umdr51/run_files/real_{app}_run<n>.json
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def child(app: str, url: str, run: int) -> int:
    os.environ["LLM_ENABLED"] = "false"
    os.environ["ENABLE_UMDR48_LANES"] = "true"
    os.environ["EMBEDDINGS_OFFLINE"] = "true"
    os.environ["DISABLE_RAG"] = "true"
    os.environ["WEBPENT_ENABLE_BRAIN_ENGINE"] = "true"
    os.environ["WEBPENT_GLOBAL_RATE_GOVERNOR_REQUESTS_PER_MINUTE"] = "10000"
    os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

    import sys as _sys
    import time
    import uuid
    from datetime import datetime, timezone

    _sys.path.insert(0, str(REPO / "src"))

    from webpent.cli.unified_hunt import run_unified_hunt
    from webpent.production.research_memory_store import _memory_path

    # zero-prior-knowledge: clean slate per campaign (law 1)
    try:
        mem = _memory_path(url, None)
        if os.path.isfile(mem):
            os.remove(mem)
    except OSError:
        pass

    campaign_id = f"umdr51-{app}-family-run{run}-{uuid.uuid4().hex[:6]}"
    t0 = time.monotonic()
    summary = run_unified_hunt(
        url=url, mode="standard",
        authorization="umdr51-owner-approved-local-lab",
        engagement_id=campaign_id,
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True,
    )
    elapsed = round(time.monotonic() - t0, 3)
    findings = summary.get("findings_detail") or []
    hyps = summary.get("hypotheses_dump") or []
    record = {
        "schema": "umdr51-real-family-campaign/1.0.0",
        "app": app,
        "target_url": url,
        "run": run,
        "campaign_id": campaign_id,
        "brain": "ON", "llm": "OFF", "lanes": "ON",
        "zero_prior_knowledge": True,
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": elapsed,
        "findings_total": len(findings),
        "findings_confirmed": sum(
            1 for f in findings
            if str(f.get("confidence_level") or "") == "Tool-Confirmed"),
        "findings_by_class": {},
        "hypotheses_total": len(hyps),
        "hypotheses_by_class": {},
        "findings_detail": [
            {"vuln_class": f.get("vuln_class"),
             "url": f.get("url"),
             "title": str(f.get("title") or "")[:80],
             "confidence_level": f.get("confidence_level"),
             "evidence_keys": f.get("evidence_keys")}
            for f in findings],
        "summary_keys": {
            k: v for k, v in summary.items()
            if isinstance(v, (int, float, str, bool))},
    }
    for f in findings:
        c = str(f.get("vuln_class") or "unknown").lower()
        record["findings_by_class"][c] = record["findings_by_class"].get(c, 0) + 1
    for h in hyps:
        c = str(h.get("vuln_class") or "unknown").lower()
        record["hypotheses_by_class"][c] = (
            record["hypotheses_by_class"].get(c, 0) + 1)
    out = REPO / "deliverables/umdr51/run_files"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"real_{app}_run{run}.json").write_text(
        json.dumps(record, indent=2) + "\n")
    print(f"[{app}] run{run}: findings={record['findings_total']} "
          f"confirmed={record['findings_confirmed']} hyps={len(hyps)} "
          f"elapsed={elapsed}s classes={sorted(record['findings_by_class'])}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--runs", type=int, default=2)
    ap.add_argument("--child-run", type=int, default=None)
    args = ap.parse_args()
    if args.child_run is not None:
        return child(args.app, args.url, args.child_run)
    env = {**os.environ, "EMBEDDINGS_OFFLINE": "true", "DISABLE_RAG": "true"}
    for n in range(1, args.runs + 1):
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()),
             "--app", args.app, "--url", args.url, "--child-run", str(n)],
            env=env, cwd=str(REPO), timeout=600,
            capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("["):
                print(line, flush=True)
        if r.returncode != 0:
            print(f"CHILD run{n} FAILED:\n{r.stdout[-600:]}\n{r.stderr[-1500:]}")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
