#!/usr/bin/env python3
"""UM-DR-49 W2.4 — the N / N+1 learning pair on the real ground.

Same engagement id + thread id: campaign N+1 must run against the
state/memory N left behind (the persisted CampaignState + lessons).
Measured deltas: elapsed, endpoints, hypotheses, requests, findings.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

os.environ.setdefault("EMBEDDINGS_OFFLINE", "true")
os.environ.setdefault("DISABLE_RAG", "true")
os.environ["LLM_ENABLED"] = "false"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["ENABLE_JS_INTELLIGENCE"] = "true"

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

EID = "umdr49-learn-juiceshop-final"
OUT = REPO / "deliverables/umdr49/run_files/learning_pair.json"


def run_once(n: int) -> dict:
    t0 = time.monotonic()
    s = run_unified_hunt(
        url="http://127.0.0.1:3000", mode="standard",
        authorization="umdr49-owner-approved-local-lab",
        engagement_id=EID, thread_id=f"{EID}-thread",
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True)
    return {
        "n": n,
        "elapsed_s": round(time.monotonic() - t0, 2),
        "engine_elapsed_s": s.get("elapsed_s"),
        "endpoints": (s.get("surface_metrics") or {}).get("endpoints"),
        "hypotheses": len(s.get("hypotheses_dump") or []),
        "findings": s.get("findings_total"),
        "confirmed": s.get("findings_confirmed"),
        "llm_tokens": s.get("llm_tokens_used"),
        "thread_id": s.get("thread_id"),
    }


def main() -> int:
    runs = [run_once(1), run_once(2)]
    record = {
        "schema": "umdr49-learning-pair/1.0.0",
        "engagement_id": EID,
        "target": "http://127.0.0.1:3000 (OWASP Juice Shop v20.4.0)",
        "config": "blind, lanes ON, jsintel ON, LLM OFF",
        "runs": runs,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record, indent=1))
    for r in runs:
        print(f"[learn] N={r['n']}: elapsed={r['elapsed_s']}s "
              f"endpoints={r['endpoints']} hypotheses={r['hypotheses']} "
              f"findings={r['findings']} confirmed={r['confirmed']}")
    a, b = runs
    print(f"[learn] delta requests-proxy (endpoints): "
          f"{a['endpoints']} -> {b['endpoints']}, "
          f"elapsed {a['elapsed_s']} -> {b['elapsed_s']}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
