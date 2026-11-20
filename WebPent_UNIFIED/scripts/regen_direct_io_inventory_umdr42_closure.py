#!/usr/bin/env python3
"""UMDR42-closure window regeneration of docs/direct_io_inventory.json
(2026-11-20).

Lineage: scripts/regen_direct_io_inventory_r9a_20261027.py is the
protocol precedent (reviewable-delta regen; the g02 no-drift test must
pass immediately after this regen; hand-edits are forbidden).

Measured closure delta (reviewed in this script's output):
  * The A1 scope-authority repairs touched src/webpent/api/app.py
    (503 mapping in the /api/v1/scope/* endpoints) and
    src/webpent/workers/pentest_worker.py (durable scope-store attach).
    Neither change imports or calls a scanned transport symbol; the
    ONLY expected delta is line drift of existing records in those two
    files (api/app.py +20 lines from the four 503 exception handlers;
    pentest_worker.py +25 lines from the attach block).
  * ZERO identity-level additions, ZERO identity-level removals
    (fail-closed gate holds; the unapproved-site pin is unchanged).
"""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402 — deliberate import order (P2-203 triage)

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

# The reviewed additive identities for this window (identity = file, kind,
# normalized_symbol). EMPTY: the closure window adds no new scanned identity.
REVIEWED_ADDITIVE_IDENTITIES: set[tuple[str, str, str]] = set()


def _key(record: dict) -> tuple:
    return (record.get("file"), record.get("kind"), record.get("normalized_symbol"))


def main() -> int:
    records = scan_direct_io(SRC)
    data = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    old_records = data["records"]
    old_keys = {_key(record) for record in old_records}
    new_keys = {_key(record) for record in records}

    added = sorted(new_keys - old_keys)
    removed = sorted(old_keys - new_keys)

    if removed:
        print("REFUSING: identity-level REMOVALS are fail-closed in this window:")
        for item in removed:
            print("  -", item)
        return 1
    unreviewed = [item for item in added if tuple(item) not in REVIEWED_ADDITIVE_IDENTITIES]
    if unreviewed:
        print("REFUSING: additive identities outside the reviewed closure set:")
        for item in unreviewed:
            print("  +", item)
        return 1

    moved = sum(
        1
        for old in old_records
        if any(_key(new) == _key(old) and new.get("line") != old.get("line") for new in records)
    )
    new_records_for_additions = [record for record in records if tuple(_key(record)) in REVIEWED_ADDITIVE_IDENTITIES]
    duplicate_delta = len(records) - len(old_records) - len(new_records_for_additions)

    print("=== reviewed additive records (full dump for review) ===")
    for record in new_records_for_additions:
        print("  +", json.dumps(record, sort_keys=True))
    print(
        f"=== {len(added)} additive identity(ies), {len(removed)} removals, "
        f"{moved} records moved lines, {duplicate_delta:+d} duplicate-count delta "
        f"(same-identity consolidation) ==="
    )

    data["records"] = records
    data["record_count"] = len(records)
    data["regenerated_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    data["regen_reason"] = (
        "umdr42-closure window regen (r9a protocol): the A1 scope-authority "
        "repairs touched api/app.py and workers/pentest_worker.py; "
        "ZERO identity-level delta, line drift only")
    generated_from = data.get("generated_from")
    if not isinstance(generated_from, dict):
        # older artifacts carry a prose string; convert to the structured form
        generated_from = {"previous": generated_from} if generated_from else {}
    generated_from["record_count"] = len(records)
    generated_from["regenerated_at"] = data["regenerated_at"]
    generated_from["regenerated_by"] = (
        "umdr42-closure window regen (scripts/regen_direct_io_inventory_umdr42_closure.py)"
    )
    generated_from["scan_root"] = "src"
    data["generated_from"] = generated_from
    coverage = data.get("coverage") or {}
    for field in ("record_count", "total_records", "count", "records", "total_sites"):
        if field in coverage:
            coverage[field] = len(records)
    data.setdefault("regen_history", []).append(
        {
            "at": generated_from["regenerated_at"],
            "delta": (
                f"{len(old_records)} -> {len(records)} records: 0 added identity, 0 removed "
                f"identity, {moved} moved (line drift), {duplicate_delta:+d} duplicate-count "
                "delta (same-identity consolidation)"
            ),
            "reason": (
                "umdr42-closure window regen (r9a protocol): the A1 scope-authority repairs "
                "touched api/app.py (ScopeStoreUnavailable -> 503 mapping in the "
                "/api/v1/scope/* endpoints) and workers/pentest_worker.py (durable "
                "scope-store attach block). ZERO identity-level delta (fail-closed gate "
                "held; unapproved-site pin unchanged); the only change is line drift of "
                "existing records in those two files. No raw-transport site added; the "
                "503 handlers and the store attach reuse governed imports only."
            ),
        }
    )
    ARTIFACT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"artifact regenerated: {len(records)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
