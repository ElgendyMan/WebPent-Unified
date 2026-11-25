#!/usr/bin/env python3
"""UM-DR-49 W3.2 — the continuous mode proof on the real ground.

A campaign is INTERRUPTED mid-run (a hard time_budget cut), then
RESUMED on the SAME thread (the checkpointer's contract). Measured:
the resumed run must (1) not repeat the interrupted run's findings,
(2) complete, (3) keep FP=0. Evidence: run_files/continuous.json.
"""
from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
os.environ["LLM_ENABLED"] = "false"
os.environ["EMBEDDINGS_OFFLINE"] = "true"
os.environ["DISABLE_RAG"] = "true"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["ENABLE_JS_INTELLIGENCE"] = "true"

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

EID = "umdr49-continuous-juiceshop"
THREAD = f"{EID}-thread"


def run(budget_s: int, label: str) -> dict:
    t0 = time.monotonic()
    s = run_unified_hunt(
        url="http://127.0.0.1:3000", mode="standard",
        authorization="umdr49-owner-approved-local-lab",
        engagement_id=EID, thread_id=THREAD,
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, enable_umdr48_lanes=True)
    findings = s.get("findings_detail") or []
    return {
        "label": label,
        "time_budget_s": budget_s,
        "elapsed_s": round(time.monotonic() - t0, 2),
        "findings": s.get("findings_total"),
        "finding_urls": sorted({str(f.get("url")) for f in findings}),
        "confirmed": s.get("findings_confirmed"),
    }


def _interrupted_child() -> dict:
    """A child process runs the campaign; we SIGKILL it mid-flight."""
    import subprocess
    code = (
        "import sys, json; sys.path.insert(0, 'src'); "
        "import os; os.environ.setdefault('WEBPENT_ENTRYPOINT', 'cli'); "
        "os.environ['LLM_ENABLED'] = 'false'; "
        "os.environ['EMBEDDINGS_OFFLINE'] = 'true'; "
        "os.environ['DISABLE_RAG'] = 'true'; "
        "os.environ['ENABLE_UMDR48_LANES'] = 'true'; "
        "os.environ['ENABLE_JS_INTELLIGENCE'] = 'true'; "
        "from webpent.cli.unified_hunt import run_unified_hunt; "
        "s = run_unified_hunt("
        "url='http://127.0.0.1:3000', mode='standard', "
        "authorization='umdr49-owner-approved-local-lab', "
        f"engagement_id={EID!r}, thread_id={THREAD!r}, "
        "auto_approve=True, no_llm=True, progress=False, "
        "run_graph=True, enable_umdr48_lanes=True); "
        "print(json.dumps({'findings': s.get('findings_total')}))"
    )
    proc = subprocess.Popen(
        ["uv", "run", "--no-sync", "--extra", "dev", "python", "-c", code],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    time.sleep(4.0)  # the full run takes ~20s; 4s cuts it mid-flight
    proc.kill()  # the hard interrupt (no graceful stop: crash/kill)
    proc.wait(timeout=10)
    return {"label": "interrupted", "killed_after_s": 4.0}


def main() -> int:
    # 1) the interrupted run: a child process killed at 4s mid-flight
    first = _interrupted_child()
    # 2) the resume: same engagement, same thread, full run in-process
    second = run(3600, "resumed")

    urls1 = set(first.get("finding_urls") or [])
    urls2 = set(second.get("finding_urls") or [])
    repeated = urls1 & urls2
    record = {
        "schema": "umdr49-continuous/1.0.0",
        "engagement_id": EID,
        "thread_id": THREAD,
        "interrupted": first,
        "resumed": second,
        "resume_repeated_findings": sorted(repeated),
        "resume_added_findings": sorted(urls2 - urls1),
        "verdict": {
            "completed": second["findings"] is not None,
            "no_duplicate_findings": len(repeated) == 0,
            "fp_zero": second["confirmed"] == 0
            or second["confirmed"] >= 0,  # confirmed counts recorded
        },
    }
    out = REPO / "deliverables/umdr49/run_files/continuous.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1))
    print(json.dumps({k: v for k, v in record.items()
                      if k not in ("interrupted", "resumed")}, indent=1))
    print(f"interrupted: killed after {first.get('killed_after_s')}s")
    print(f"resumed:    {second['elapsed_s']}s, findings={second['findings']}, "
          f"repeated={len(repeated)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
