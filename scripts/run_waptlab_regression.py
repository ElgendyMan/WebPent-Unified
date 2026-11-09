"""Run the local, target-free WAPTLab regression contract.

This harness exercises declarative campaign accounting and Proof Engine transitions only.
It never clones, starts, mutates, or sends traffic to WAPTLab. Missing fixture evidence is
reported explicitly as ``inconclusive`` or ``missing-validator`` rather than negative.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.benchmark.waptlab_campaign_profile import build_waptlab_campaign_ledger
from webpent.shared.proof_engine import build_proof_plan, classify_probe_gaps

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = PROJECT_ROOT / "docs" / "waptlab_regression.json"

_CONTRACT_CASES = {
    "download_idor": {
        "required": ["surface", "identity", "negative_control", "oracle"],
        "complete": {
            "surface": "download",
            "identity": "opaque:owner",
            "negative_control": "foreign-object-denied",
            "oracle": {"causal_signal": True, "differential": "owner-vs-foreign"},
        },
    },
    "csv_ingestion_sqli": {
        "required": ["surface", "body", "content_type", "negative_control", "oracle"],
        "complete": {
            "surface": "csv-upload",
            "body": "opaque:csv-body",
            "content_type": "text/csv",
            "negative_control": "control-row",
            "oracle": {"causal_signal": True, "differential": "worker-result"},
        },
    },
    "tenant_context_switching": {
        "required": ["surface", "identity", "precondition", "negative_control", "oracle"],
        "complete": {
            "surface": "tenant-object",
            "identity": "opaque:tenant-a-to-b",
            "precondition": "approved-context-switch",
            "negative_control": "foreign-tenant-denied",
            "oracle": {"causal_signal": True, "differential": "tenant-boundary"},
        },
    },
    "xslt_injection": {
        "required": ["surface", "body", "content_type", "negative_control", "oracle"],
        "complete": {
            "surface": "xslt-transform",
            "body": "opaque:xslt-document",
            "content_type": "application/xml",
            "negative_control": "safe-transform",
            "oracle": {"causal_signal": True, "differential": "transform-output"},
        },
    },
}


def _run_contract_case(campaign_key: str, spec: dict[str, Any]) -> dict[str, Any]:
    complete = classify_probe_gaps(
        campaign_key=campaign_key,
        evidence=spec["complete"],
        source_refs=[f"synthetic:{campaign_key}:complete"],
        required=spec["required"],
    )
    incomplete_evidence = dict(spec["complete"])
    incomplete_evidence.pop("negative_control", None)
    incomplete = classify_probe_gaps(
        campaign_key=campaign_key,
        evidence=incomplete_evidence,
        source_refs=[f"synthetic:{campaign_key}:gap"],
        required=spec["required"],
    )
    plan = build_proof_plan(incomplete, max_actions=3)
    return {
        "campaign_key": campaign_key,
        "complete_fixture_gaps": [gap.gap_type for gap in complete],
        "gap_fixture_types": [gap.gap_type for gap in incomplete],
        "gap_fixture_actions": [action.action_type for action in plan.actions],
        "changes_plan_on_gap": bool(incomplete and plan.actions),
        "synthetic_contract_only": True,
    }


def run_regression() -> dict[str, Any]:
    ledger = build_waptlab_campaign_ledger()
    entries = []
    for entry in ledger["entries"]:
        if entry["status"] == "missing-validator":
            disposition = "missing-validator"
            reason = "No complete validator plugin is registered for this campaign."
        else:
            disposition = "inconclusive"
            reason = "No local WAPTLab fixture is available; no target was contacted."
        entries.append(
            {
                "id": entry["id"],
                "key": entry["key"],
                "disposition": disposition,
                "reason": reason,
                "evidence_complete": False,
                "target_contacted": False,
            }
        )
    contract_checks = [_run_contract_case(key, spec) for key, spec in _CONTRACT_CASES.items()]
    summary: dict[str, int] = {}
    for entry in entries:
        summary[entry["disposition"]] = summary.get(entry["disposition"], 0) + 1
    return {
        "schema_version": "waptlab-regression-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v60",
        "mode": "local-contract-only",
        "target_contacted": False,
        "waptlab_modified": False,
        "campaign_count": len(entries),
        "summary": summary,
        "campaigns": entries,
        "synthetic_contract_checks": contract_checks,
        "safety_statement": (
            "This artifact validates local campaign accounting and evidence-gap planning only. "
            "Inconclusive and missing-validator are not negative findings."
        ),
    }


def main() -> int:
    payload = run_regression()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
