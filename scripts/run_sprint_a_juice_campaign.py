#!/usr/bin/env python3
"""Vulnerability Arsenal Sprint A — deterministic authorized Juice Shop campaign.

This runner is LLM-free on purpose. The live Juice Shop campaign in the previous
sprint used an OpenAI key that is NOT available in this environment; rather than
fabricate LLM evidence, this campaign exercises the SAME governed trust chain
deterministically:

    HypothesisGenerator -> governed catalog -> M4/AVI -> canonical validator
    -> ProofBundle -> ReplayVerifier -> PromotionPipeline (8 gates)

The target is the local OWASP Juice Shop. Every request is authorized by
ScopeLaw/ToolBoundary through ModernOrchestrator; no module here opens raw HTTP.
Results are reported honestly: what promotes, what is refuted, and why.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("WEBPENT_ENVIRONMENT_PROFILE", "lab")
os.environ.setdefault("LLM_ENABLED", "false")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY  # noqa: E402
from webpent.production.production_spine import (  # noqa: E402
    ProductionSpineConfig,
    resolve_production_spine,
)
from webpent.recon.autonomous_crawler import AutonomousCrawler, CrawlConfig  # noqa: E402
from webpent.recon.hypothesis_generator import HypothesisGenerator  # noqa: E402
from webpent.shared.engagement_audit import EngagementAuditChain, verify_chain  # noqa: E402
from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)

TARGET_URL = os.environ.get("WEBPENT_JUICE_URL", "http://127.0.0.1:3000")
CAMPAIGN_ID = "juice-sprint-a-20261003-r1"
ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / CAMPAIGN_ID
SPRINT_A_FAMILIES = ("RACE_CONDITION", "BUSINESS_LOGIC", "FILE_UPLOAD",
                     "JWT_MANIPULATION", "MASS_ASSIGNMENT")


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def status_of(decision: dict[str, Any]) -> str:
    promotion = decision.get("promotion") if isinstance(decision.get("promotion"), dict) else {}
    return str(promotion.get("decision") or "UNKNOWN").upper()


def main() -> int:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    config = ProductionSpineConfig(
        engagement_id=CAMPAIGN_ID, target_url=TARGET_URL.rstrip("/"), entrypoint="direct_invoke",
    )
    orchestrator, production_trace = resolve_production_spine(config)
    target_token = set_engagement_target_hosts(TARGET_URL)
    started = time.monotonic()
    try:
        audit = EngagementAuditChain(
            engagement_id=CAMPAIGN_ID,
            audit_dir=ARTIFACT_ROOT / "audit",
            workspace_dir=ARTIFACT_ROOT / "audit_workspace",
            trace=production_trace,
        )
        audit.append_event(event_type="campaign.started", details={"target": TARGET_URL, "llm": False})

        crawler = AutonomousCrawler(
            target_url=TARGET_URL,
            scope_law=orchestrator.scope_law,
            engagement_id=CAMPAIGN_ID,
            config=CrawlConfig(max_pages=60, max_depth=2, per_host_min_interval_seconds=0.5),
            scope_spec=None,
            should_halt=lambda: False,
            budget_check=lambda: True,
        )
        crawl = crawler.crawl()
        surface = crawl.surface_map
        audit.append_event(event_type="crawl.completed", details={
            "routes": len(surface.routes), "events": len(surface.events),
        })
        write_json(ARTIFACT_ROOT / "surface_map.json", surface.as_dict())

        hypotheses = HypothesisGenerator(max_hypotheses=120, principal_count=0).generate(surface)
        write_json(ARTIFACT_ROOT / "hypotheses.json", hypotheses)
        executable = [
            item for item in hypotheses
            if bool(item.get("executable"))
            and str(item.get("vulnerability_class", "")).upper() in EXPERIMENT_REGISTRY
        ]
        family_counts: dict[str, int] = {}
        for item in executable:
            family = str(item.get("vulnerability_class", "")).upper()
            family_counts[family] = family_counts.get(family, 0) + 1
        audit.append_event(event_type="hypotheses.generated", details={
            "generated": len(hypotheses), "executable": len(executable),
            "family_counts": family_counts,
        })

        campaign_result = orchestrator.run_autonomous_validation_campaign(
            target_url=TARGET_URL,
            hypotheses=executable[:40],
            max_decisions=min(40, len(executable)),
        ) if executable else {"decisions": [], "decisions_executed": 0, "promoted_count": 0,
                              "rejected_count": 0, "no_executable_hypotheses": True}
        write_json(ARTIFACT_ROOT / "campaign_result.json", campaign_result)

        decisions = campaign_result.get("decisions") if isinstance(campaign_result.get("decisions"), list) else []
        promoted = [item for item in decisions if isinstance(item, dict) and status_of(item) == "PROMOTED"]
        promoted_by_family: dict[str, int] = {}
        for item in promoted:
            family = str(item.get("vulnerability_class", "")).upper()
            promoted_by_family[family] = promoted_by_family.get(family, 0) + 1
        for item in decisions:
            if isinstance(item, dict):
                audit.append_event(event_type="finding.decision", details={
                    "hypothesis_id": item.get("hypothesis_id"),
                    "family": item.get("vulnerability_class"),
                    "status": status_of(item),
                    "validator_outcome": item.get("validator_outcome"),
                    "proof_sealed": item.get("proof_sealed"),
                })
        audit.finalize()
        audit_result = verify_chain(
            audit_path=audit.audit_path, workspace_path=audit.workspace_path, trace=production_trace,
        )

        summary = {
            "campaign_id": CAMPAIGN_ID,
            "target_url": TARGET_URL,
            "llm_enabled": False,
            "llm_note": "deterministic run; no LLM key available in this environment (honest limitation)",
            "routes_crawled": len(surface.routes),
            "hypotheses_generated": len(hypotheses),
            "hypotheses_executable": len(executable),
            "executable_family_counts": family_counts,
            "sprint_a_families_executable": {
                family: family_counts.get(family, 0) for family in SPRINT_A_FAMILIES
            },
            "decisions_executed": campaign_result.get("decisions_executed"),
            "promoted_count": campaign_result.get("promoted_count"),
            "rejected_count": campaign_result.get("rejected_count"),
            "promoted_by_family": promoted_by_family,
            "validator_outcomes": {
                str(item.get("vulnerability_class")): item.get("validator_outcome")
                for item in decisions if isinstance(item, dict)
            },
            "audit_verification": audit_result,
            "duration_seconds": round(time.monotonic() - started, 3),
            "security_boundary": {
                "raw_target_content_returned": False,
                "execution_authority": "ModernOrchestrator/ScopeLaw/AVI/PromotionPipeline",
            },
        }
        write_json(ARTIFACT_ROOT / "campaign_summary.json", summary)
        print(json.dumps(summary, indent=2, default=str))
        return 0
    finally:
        clear_engagement_target_hosts(target_token)


if __name__ == "__main__":
    raise SystemExit(main())
