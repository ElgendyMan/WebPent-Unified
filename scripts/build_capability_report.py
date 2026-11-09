"""Build a machine-readable capability report from catalog, ledger, and registry."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.agents.validator.registry import all_capabilities

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG = PROJECT_ROOT / "docs" / "waptlab_vulnerability_catalog.yml"
LEDGER = PROJECT_ROOT / "docs" / "waptlab_coverage_ledger.json"
OUTPUT = PROJECT_ROOT / "docs" / "capability_report.json"


def _load_catalog() -> list[dict[str, Any]]:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to build the capability report") from exc
    payload = yaml.safe_load(CATALOG.read_text(encoding="utf-8")) or {}
    entries = payload.get("entries", payload if isinstance(payload, list) else [])
    return [entry for entry in entries if isinstance(entry, dict)]


def _load_ledger() -> dict[str, dict[str, Any]]:
    payload = json.loads(LEDGER.read_text(encoding="utf-8"))
    return {
        str(entry["key"]): entry
        for entry in payload.get("entries", [])
        if isinstance(entry, dict) and entry.get("key")
    }


def main() -> int:
    catalog = _load_catalog()
    ledger = _load_ledger()
    registry = {item.vuln_class: item for item in all_capabilities()}
    entries: list[dict[str, Any]] = []
    for item in catalog:
        key = str(item.get("key", ""))
        validator = str(item.get("validator") or key)
        capability = registry.get(validator)
        observed = ledger.get(key, {})
        entries.append(
            {
                "id": item.get("id"),
                "key": key,
                "category": item.get("category"),
                "validator": validator,
                "validator_id": getattr(capability, "validator_id", None),
                "validator_status": getattr(capability, "status", "missing-validator"),
                "evidence_mode": getattr(capability, "evidence_mode", "human-review"),
                "disposition": observed.get("disposition", "not_observed"),
                "evidence_state": observed.get("evidence_state", "missing"),
                "live_waptlab_evidence": bool(observed.get("live_waptlab_evidence", False)),
                "negative_control": item.get("negative_control"),
                "cleanup": item.get("cleanup"),
            }
        )
    counts: dict[str, int] = {}
    for entry in entries:
        status = str(entry["validator_status"])
        counts[status] = counts.get(status, 0) + 1
    payload = {
        "schema_version": "webpent-capability-report-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "catalog": str(CATALOG.relative_to(PROJECT_ROOT)),
        "ledger": str(LEDGER.relative_to(PROJECT_ROOT)),
        "catalog_count": len(entries),
        "validator_status_counts": counts,
        "live_qualification": False,
        "entries": entries,
        "notes": [
            "A registered validator does not imply a confirmed vulnerability.",
            "Only deterministic evidence and completed negative controls may support confirmation.",
            "This report is contract/local evidence unless live_qualification is explicitly true.",
        ],
    }
    OUTPUT.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(OUTPUT), "catalog_count": len(entries)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
