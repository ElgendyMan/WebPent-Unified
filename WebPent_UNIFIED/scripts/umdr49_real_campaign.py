#!/usr/bin/env python3
"""UM-DR-49 — the REAL-GROUND blind campaign (zero prior knowledge).

Law 1 (zero-prior-knowledge): this script passes ONLY the entrypoint
URL + the operator scope/authorization — no app-specific paths, IDs,
challenge names, or credentials. Everything else the engine DISCOVERS.

Usage:
  uv run --extra dev python scripts/umdr49_real_campaign.py \
      --app juiceshop --url http://127.0.0.1:3000 --run 1
Writes: deliverables/umdr49/run_files/<app>_run<n>.json
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
sys.path.insert(0, str(REPO / "src"))

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--run", type=int, default=1)
    ap.add_argument("--lanes-off", action="store_true")
    ap.add_argument("--llm-on", action="store_true")
    ap.add_argument("--out", default="deliverables/umdr49/run_files")
    args = ap.parse_args()

    if not args.llm_on:
        os.environ["LLM_ENABLED"] = "false"
    if not args.lanes_off:
        os.environ["ENABLE_UMDR48_LANES"] = "true"
    os.environ.setdefault("EMBEDDINGS_OFFLINE", "true")
    os.environ.setdefault("DISABLE_RAG", "true")

    campaign_id = (f"umdr49-{args.app}-run{args.run}-"
                   f"{uuid.uuid4().hex[:6]}")
    started_mono = time.monotonic()

    from webpent.cli.unified_hunt import run_unified_hunt
    summary = run_unified_hunt(
        url=args.url, mode="standard",
        authorization="umdr49-owner-approved-local-lab",
        engagement_id=campaign_id,
        auto_approve=True, no_llm=not args.llm_on, progress=False,
        run_graph=True,
        enable_umdr48_lanes=not args.lanes_off,
    )

    findings = summary.get("findings_detail") or []
    confirmed = [f for f in findings
                 if f.get("confidence_level") == "Tool-Confirmed"]
    record = {
        "schema": "umdr49-real-campaign/1.0.0",
        "app": args.app,
        "target_url": args.url,
        "run": args.run,
        "campaign_id": campaign_id,
        "lanes": "OFF" if args.lanes_off else "ON",
        "llm": "ON" if args.llm_on else "OFF",
        "zero_prior_knowledge": True,
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(time.monotonic() - started_mono, 3),
        "findings_total": len(findings),
        "findings_confirmed": len(confirmed),
        "confirmed_detail": [
            {"vuln_class": f.get("vuln_class"),
             "url": f.get("url"),
             "title": f.get("title"),
             "evidence_bundle_id": f.get("evidence_bundle_id")}
            for f in confirmed],
        "findings_detail": [
            {"vuln_class": f.get("vuln_class"),
             "url": f.get("url"),
             "confidence_level": f.get("confidence_level")}
            for f in findings],
        "summary_keys": {k: v for k, v in summary.items()
                         if isinstance(v, (int, float, str, bool))},
    }
    out = REPO / args.out
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"{args.app}_run{args.run}.json"
    path.write_text(json.dumps(record, indent=1, default=str))
    print(f"[real] {args.app}/run{args.run}: "
          f"findings={record['findings_total']} "
          f"confirmed={record['findings_confirmed']} "
          f"elapsed={record['elapsed_s']}s -> {path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
