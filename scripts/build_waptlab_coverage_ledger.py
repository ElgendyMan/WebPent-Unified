"""Build a strict, report-safe coverage ledger from a mock matrix."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webpent.benchmark.waptlab_campaign_profile import WAPTLAB_CAMPAIGNS


def _entry_by_key(campaign: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    status = str(observed.get("status", "not_discovered"))
    if status == "tool-confirmed":
        disposition = "tested"
        evidence_state = "complete"
    elif status == "candidate-or-review":
        disposition = "candidate_or_review"
        evidence_state = "incomplete"
    else:
        disposition = "not_discovered"
        evidence_state = "absent"
    return {
        "id": int(campaign["id"]),
        "key": str(campaign["key"]),
        "category": str(campaign.get("validator") or "human_review"),
        "validator": campaign.get("validator"),
        "disposition": disposition,
        "evidence_state": evidence_state,
        "confidence": str(observed.get("confidence_level", "Not Scanned")),
        "evidence_keys": list(observed.get("evidence_keys", [])),
        "reasoning": str(observed.get("reasoning", "No observation recorded.")),
        "source_url": str(observed.get("url", "")),
        "source_matrix": "docs/waptlab_mock_matrix.json",
        "live_waptlab_evidence": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    matrix = json.loads(args.matrix.read_text(encoding="utf-8"))
    observed = {str(item["label"]): item for item in matrix.get("campaigns", [])}
    entries = [
        _entry_by_key(campaign, observed.get(str(campaign["key"]), {}))
        for campaign in WAPTLAB_CAMPAIGNS
    ]
    summary: dict[str, int] = {}
    for entry in entries:
        disposition = str(entry["disposition"])
        summary[disposition] = summary.get(disposition, 0) + 1
    ledger = {
        "schema_version": "waptlab-coverage-ledger-v1",
        "catalog": "docs/waptlab_vulnerability_catalog.yml",
        "source_matrix": str(args.matrix),
        "target": "WAPTLab",
        "live_qualification": False,
        "target_contacted": False,
        "waptlab_modified": False,
        "entries": entries,
        "summary": summary,
        "status_definitions": {
            "tested": (
                "Deterministic evidence satisfied the validator contract in the local fixture."
            ),
            "candidate_or_review": (
                "A signal exists but an oracle, browser, OOB, or identity control is missing."
            ),
            "not_discovered": "No hypothesis or probe observation was recorded.",
            "missing_validator": (
                "The campaign requires a review-only or unimplemented validator contract."
            ),
            "probe_error": "The executor could not complete the probe and recorded the error.",
        },
    }
    args.output.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"entries": len(entries), "summary": summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
