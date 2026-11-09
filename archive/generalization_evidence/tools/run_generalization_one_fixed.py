#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path

ROOT = Path("/tmp/webpent_remediation_project")
OUT = Path(os.environ.get("GENERALIZATION_OUT", str(ROOT / "docs" / "generalization_evidence" / "phase5_final")))
OUT.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(ROOT / "src"))

# Environment setup only; no WebPent source/config changes.
os.environ.setdefault("LLM_ENABLED", "true")
os.environ.setdefault("OPENAI_MODEL", "gpt-5-mini")
os.environ.setdefault("LLM_MAX_CALLS_PER_RUN", "12")
os.environ.setdefault("WEBPENT_LLM_KEY_POOL_ENABLED", "false")
os.environ.setdefault("WEBPENT_ENVIRONMENT_PROFILE", "lab")
os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("AUDIT_SECRET_KEY", os.environ["WEBPENT_AUDIT_SECRET_KEY"])
os.environ.setdefault("CELERY_PAYLOAD_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("WEBPENT_CELERY_PAYLOAD_KEY", os.environ["CELERY_PAYLOAD_KEY"])

from webpent.agents.hunter_runner import run_hunter_campaign
from webpent.recon.autonomous_crawler import CrawlConfig

TARGET_NAME = os.environ["GEN_TARGET_NAME"]
TARGET_URL = os.environ["GEN_TARGET_URL"]
TARGET_NOTE = os.environ.get("GEN_TARGET_NOTE", "authorized training target")
TARGETS = [{"name": TARGET_NAME, "target_url": TARGET_URL, "target_note": TARGET_NOTE}]

for item in TARGETS:
    name = item["name"]
    started = time.time()
    record = {
        "target": item,
        "phase": "phase5_final_rerun",
        "system_path": "run_hunter_campaign -> AutonomousCrawler/httpx -> HunterGraph -> ModernOrchestrator/AVI",
        "modifications_during_phase": True,
        "principal_count": 0,
        "credentials_in_llm_context": False,
        "started_at_epoch": started,
    }
    try:
        result = run_hunter_campaign(
            target_url=item["target_url"],
            engagement_id=f"generalization-{os.environ.get('GENERALIZATION_TAG', 'final')}-{name}",
            persona="stok",
            artifact_root=OUT / name,
            max_hypotheses=8,
            max_decisions=4,
            principal_count=0,
            max_llm_calls=12,
            max_cost_usd=1.0,
            crawl_config=CrawlConfig(
                max_pages=25, max_depth=2, per_host_min_interval_seconds=1.0, respect_robots=False
            ),
        )
        summary = result.get("summary", {})
        # Keep only structured/redacted campaign fields; raw target bodies remain out.
        record.update(
            {
                "status": "completed",
                "duration_seconds": round(time.time() - started, 3),
                "summary": summary,
                "artifact_root": str(result.get("artifact_root", "")),
                "answers": {
                    "crawler_discovered_application": bool(summary.get("routes_crawled", 0)),
                    "auth_mechanism_detected": "not independently asserted by untouched runner",
                    "hypotheses_generated": summary.get("candidates_generated", 0),
                    "exploiter_real_requests": "see validation counts and production trace",
                    "validator_confirmations": summary.get("validation_counts", {}),
                    "promoted_findings": len(summary.get("confirmed_findings", [])),
                },
            }
        )
    except Exception as exc:
        record.update(
            {
                "status": "failed",
                "duration_seconds": round(time.time() - started, 3),
                "error_class": type(exc).__name__,
                "error_message": str(exc)[:500],
            }
        )
    (OUT / f"{name}_raw_result.json").write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n")
    print(
        json.dumps(
            {
                "target": name,
                "status": record["status"],
                "duration_seconds": record["duration_seconds"],
                "error_class": record.get("error_class"),
            },
            sort_keys=True,
        ),
        flush=True,
    )

print(
    json.dumps(
        {
            "phase": "phase5_final_rerun",
            "output": str(OUT),
            "targets": [x["name"] for x in TARGETS],
        },
        sort_keys=True,
    )
)
