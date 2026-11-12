#!/usr/bin/env python3
"""UM-DR-36 §5 — E2E compiled-graph campaign demonstration.

Runs the REAL production campaign entrypoint (run_unified_hunt ->
build_graph -> compiled LangGraph -> stream) against the controlled
local IDOR lab target (loopback only, authorized), deterministic path
(no LLM), with the UM-DR-36 capabilities enabled, and verifies:

  * the Application Semantic Model materializes from runtime state
    (application_model channel + entities from crawled endpoints);
  * the Discovery Funnel is produced during the campaign, persisted on
    its channel, and carried in the campaign summary;
  * the hard token budget record + honest budget status are present;
  * the campaign artifact is written for the acceptance report.

No unauthorized public targets. No fabricated observations.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "umdr36_e2e_key_32_chars_min_1234567890")
# R3 E-4: the spine refuses to guess its launch entrypoint — declare it
# explicitly (the documented escape for programmatic campaign drivers).
os.environ.setdefault("WEBPENT_ENTRYPOINT", "worker")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO))

from tests.lab.idor_lab_target import start_lab_server  # noqa: E402


def main() -> int:
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    from webpent.cli.unified_hunt import run_unified_hunt

    server, url = start_lab_server(vulnerable=True)
    token = set_engagement_target_hosts("127.0.0.1", "localhost")
    out_path = REPO / "umdr36_e2e_campaign_result.json"
    try:
        summary = run_unified_hunt(
            url=url,
            mode="quick",
            authorization="umdr36-e2e-lab-authorization",
            engagement_id="umdr36-e2e",
            no_llm=True,
            progress=False,
            run_graph=True,
            auto_approve=True,
            max_tokens=1_000_000,
        )
    finally:
        clear_engagement_target_hosts(token)
        server.should_exit = True

    checks: dict[str, Any] = {}
    appmodel = summary.get("application_model") or {}
    checks["appmodel_materialized"] = bool(appmodel.get("entity_count"))
    checks["appmodel_entity_count"] = appmodel.get("entity_count")
    checks["appmodel_relation_count"] = appmodel.get("relation_count")
    checks["appmodel_coverage_gaps"] = appmodel.get("coverage_gaps", [])[:8]

    funnel = summary.get("discovery_funnel") or {}
    checks["funnel_computed"] = bool(funnel.get("computed"))
    checks["funnel_version"] = funnel.get("version")
    stage_counts = funnel.get("stage_counts") or {}
    checks["funnel_stage_count"] = len(funnel.get("stages") or {})
    checks["funnel_not_materialized"] = (funnel.get("totals") or {}).get(
        "not_materialized", [])[:10]
    checks["funnel_endpoints"] = stage_counts.get("endpoints_discovered")
    checks["funnel_entities"] = stage_counts.get("application_entities_discovered")
    checks["funnel_hypotheses_in_pool"] = stage_counts.get("hypotheses_in_pool")

    budget = summary.get("llm_budget") or {}
    checks["budget_max_total_tokens"] = budget.get("max_total_tokens")
    checks["budget_status"] = summary.get("budget_status")
    checks["budget_status_in_vocabulary"] = summary.get("budget_status") in (
        "COMPLETED", "BUDGET_EXHAUSTED", "PARTIAL", "INTERRUPTED", "FAILED")

    checks["findings_total"] = summary.get("findings_total")
    checks["findings_confirmed"] = summary.get("findings_confirmed")
    checks["graph_invoked"] = summary.get("graph_invoked")

    out_path.write_text(
        json.dumps({"summary": summary, "checks": checks}, indent=2,
                   sort_keys=True, default=str) + "\n", encoding="utf-8")
    print(json.dumps(checks, indent=2, sort_keys=True, default=str))
    ok = (checks["appmodel_materialized"]
          and checks["funnel_computed"]
          and checks["budget_status_in_vocabulary"]
          and checks["graph_invoked"])
    print("E2E_RESULT:", "PASS" if ok else "PARTIAL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
