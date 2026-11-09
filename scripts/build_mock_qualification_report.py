"""Compare the three local WAPTLab mock runs without claiming live qualification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNS = [
    PROJECT_ROOT / "docs" / "waptlab_mock_matrix_run1.json",
    PROJECT_ROOT / "docs" / "waptlab_mock_matrix_run2.json",
    PROJECT_ROOT / "docs" / "waptlab_mock_matrix_run3.json",
]
OUTPUT = PROJECT_ROOT / "docs" / "waptlab_qualification_report.json"
REQUIRED_RUNTIME_FIELDS = ("image_digest", "seed_hash", "execution_events")


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _campaign_signature(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": item.get("label"),
        "status": item.get("status"),
        "confidence": item.get("confidence"),
        "confidence_level": item.get("confidence_level"),
        "evidence_keys": sorted(item.get("evidence_keys", [])),
    }


def _sha256_signatures(items: list[dict[str, Any]]) -> str:
    encoded = json.dumps(items, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def main() -> int:
    missing_runs = [str(path.relative_to(PROJECT_ROOT)) for path in RUNS if not path.is_file()]
    if missing_runs:
        OUTPUT.write_text(
            json.dumps(
                {
                    "schema_version": "webpent-qualification-report-v1",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "live_qualification": False,
                    "status": "blocked_missing_runs",
                    "missing_runs": missing_runs,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        return 1

    payloads = [_load(path) for path in RUNS]
    signatures = [
        [_campaign_signature(item) for item in payload.get("campaigns", [])]
        for payload in payloads
    ]
    run_summaries = []
    for path, payload, signature in zip(RUNS, payloads, signatures, strict=True):
        status_counts: dict[str, int] = {}
        for item in payload.get("campaigns", []):
            status = str(item.get("status", "unknown"))
            status_counts[status] = status_counts.get(status, 0) + 1
        missing_fields = [field for field in REQUIRED_RUNTIME_FIELDS if field not in payload]
        run_summaries.append(
            {
                "run": str(path.relative_to(PROJECT_ROOT)),
                "campaign_count": payload.get("campaign_count"),
                "status_counts": status_counts,
                "final_confirmed_count": status_counts.get("confirmed", 0),
                "tool_confirmed_count": status_counts.get("tool-confirmed", 0),
                "signature": _sha256_signatures(signature),
                "missing_runtime_fields": missing_fields,
            }
        )
    stable = all(signature == signatures[0] for signature in signatures[1:])
    final_confirmed_counts = [item["final_confirmed_count"] for item in run_summaries]
    tool_confirmed_counts = [item["tool_confirmed_count"] for item in run_summaries]
    payload = {
        "schema_version": "webpent-qualification-report-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "mock_reproducible" if stable else "mock_non_reproducible",
        "live_qualification": False,
        "target_contacted": False,
        "waptlab_modified": False,
        "run_count": len(run_summaries),
        "stable_campaign_signatures": stable,
        "final_confirmed_counts": final_confirmed_counts,
        "final_confirmed_minimum": min(final_confirmed_counts) if final_confirmed_counts else 0,
        "tool_confirmed_counts": tool_confirmed_counts,
        "tool_confirmed_minimum": min(tool_confirmed_counts) if tool_confirmed_counts else 0,
        "precision": {
            "status": "not_measured",
            "reason": "no known-negative catalog was executed",
        },
        "recall": {
            "status": "blocked_live",
            "reason": "mock runs are not WAPTLab runtime qualification",
        },
        "required_runtime_fields": list(REQUIRED_RUNTIME_FIELDS),
        "runs": run_summaries,
        "notes": [
            "Candidate/review dispositions are not counted as confirmed findings.",
            "This artifact proves only local mock reproducibility and field completeness gaps.",
        ],
    }
    OUTPUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(OUTPUT),
                "stable": stable,
                "final_confirmed_minimum": payload["final_confirmed_minimum"],
                "tool_confirmed_minimum": payload["tool_confirmed_minimum"],
            },
            sort_keys=True,
        )
    )
    return 0 if stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
