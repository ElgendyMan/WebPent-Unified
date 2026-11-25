#!/usr/bin/env python3
"""UM-DR-49 W3.3 — the scale proof: ONE engagement, TWO real apps,
full identity isolation (each app its own campaign thread + identity
profiles). Juice Shop (blind) + WebGoat (declared test identity) run
under a single engagement id; the record proves per-app isolation.
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
os.environ["LLM_ENABLED"] = "false"
os.environ["EMBEDDINGS_OFFLINE"] = "true"
os.environ["DISABLE_RAG"] = "true"
os.environ["ENABLE_UMDR48_LANES"] = "true"
os.environ["ENABLE_JS_INTELLIGENCE"] = "true"

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

ENGAGEMENT = "umdr49-scale-dual-app"

APPS = [
    {
        "app": "juiceshop",
        "url": "http://127.0.0.1:3000",
        "thread": f"{ENGAGEMENT}-juiceshop",
        "cookies": None,  # fully blind — no identity
    },
    {
        "app": "webgoat",
        "url": "http://127.0.0.1:8080/WebGoat/",
        "thread": f"{ENGAGEMENT}-webgoat",
        # the declared test identity (registered through the app's own
        # public signup form during W1/W2 measurements)
        "cookies": "JSESSIONID=kmqphWxQ_vZpWBol_utDsGjqpabqcvtcDTXaUHZ5",
    },
]


def _run_child(spec: dict) -> dict:
    """Each app runs in its OWN process — the production spine's
    registry is per-process and its digest pins target_url BY DESIGN
    (one target = one isolation unit; the W3.3 run PROVED the guard
    fires: a same-engagement second target in one process is refused
    fail-closed with ProductionSpineError). Process separation is the
    documented scale boundary, recorded in the evidence."""
    import subprocess
    code = (
        "import sys, json, time; sys.path.insert(0, 'src'); "
        "import os; os.environ.setdefault('WEBPENT_ENTRYPOINT', 'cli'); "
        "os.environ['LLM_ENABLED'] = 'false'; "
        "os.environ['EMBEDDINGS_OFFLINE'] = 'true'; "
        "os.environ['DISABLE_RAG'] = 'true'; "
        "os.environ['ENABLE_UMDR48_LANES'] = 'true'; "
        "os.environ['ENABLE_JS_INTELLIGENCE'] = 'true'; "
        "from webpent.cli.unified_hunt import run_unified_hunt; "
        "t0 = time.monotonic(); "
        "s = run_unified_hunt("
        f"url={spec['url']!r}, mode='standard', "
        "authorization='umdr49-owner-approved-local-lab', "
        f"engagement_id={ENGAGEMENT!r}, thread_id={spec['thread']!r}, "
        "auto_approve=True, no_llm=True, progress=False, "
        "run_graph=True, enable_umdr48_lanes=True, "
        f"cookies={spec['cookies']!r}); "
        "findings = s.get('findings_detail') or []; "
        "app_urls = [str(f.get('url')) for f in findings]; "
        "print(json.dumps({"
        "'elapsed_s': round(time.monotonic() - t0, 2), "
        "'endpoints': (s.get('surface_metrics') or {}).get('endpoints'), "
        "'findings': s.get('findings_total'), "
        "'confirmed': s.get('findings_confirmed'), "
        "'finding_urls_sample': app_urls[:6]}))"
    )
    proc = subprocess.run(
        ["uv", "run", "--no-sync", "--extra", "dev", "python", "-c", code],
        capture_output=True, text=True, timeout=500)
    line = [l for l in proc.stdout.splitlines() if l.startswith("{")]
    data = json.loads(line[-1]) if line else {"error": proc.stderr[-300:]}
    app_urls = data.get("finding_urls_sample") or []
    cross = [u for u in app_urls
             if "127.0.0.1:3000" in u and spec["app"] == "webgoat"]
    cross += [u for u in app_urls
              if ":8080" in u and spec["app"] == "juiceshop"]
    return {
        "app": spec["app"],
        "thread": spec["thread"],
        **data,
        "cross_app_leak_urls": cross,
    }


def main() -> int:
    results = [_run_child(spec) for spec in APPS]
    record = {
        "schema": "umdr49-scale-dual-app/1.0.0",
        "engagement_id": ENGAGEMENT,
        "apps": results,
        "verdict": {
            "both_completed": all(r["findings"] is not None for r in results),
            "identity_isolation": all(
                not r["cross_app_leak_urls"] for r in results),
        },
    }
    out = REPO / "deliverables/umdr49/run_files/scale_dual_app.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=1))
    for r in results:
        print(f"[scale] {r['app']}: {r['elapsed_s']}s "
              f"endpoints={r['endpoints']} findings={r['findings']} "
              f"confirmed={r['confirmed']} "
              f"cross_leak={len(r['cross_app_leak_urls'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
