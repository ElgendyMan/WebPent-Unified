"""r6c identity-ladder window regeneration of docs/direct_io_inventory.json
(2026-10-27, Task r6c-CODE-impl; DR-016).

Lineage: regen_direct_io_inventory_m2a_20261006.py is the protocol precedent
(reviewable-delta regen; the g02 no-drift test must pass immediately after
this regen; hand-edits are forbidden). Unlike the M2A window (pure linedrift,
identity-level delta refused), the r6c window has one ADJUDICATED additive
identity — encoded below; any other identity-level delta REFUSES.

Adjudicated additive identity (reviewed in this script's output):
  * src/webpent/recon/principal_provisioning.py / dynamic_resolution /
    getattr(item.identity, ...) — the ``identity_resolution`` property
    (r6c identity-ladder block) reads ``identity.winner_strategy`` through
    a defensive getattr. Non-transport (dynamic_resolution on a runtime
    result object); no raw-transport site added; the unapproved-site pin
    is unchanged. Records additionally shift lines across the four scoped
    files (the S1-S4 ladder rewrite + honest-validation changes): 661 ->
    664 records, 425 line moves, 0 identity removals (fail-closed gate).

Lineage honesty: this is the THIRD derivation of the same r5+r6 end state
(r5/r6 artifact sets were lost to container recycles); the window unit is
the identity ladder + honest validation + refuted-replan routing.
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
# normalized_symbol). Any addition OUTSIDE this set refuses.
REVIEWED_ADDITIVE_IDENTITIES = {
    (
        "src/webpent/recon/principal_provisioning.py",
        "dynamic_resolution",
        "getattr(item.identity, ... )",
    ),
}


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
        print("REFUSING: additive identities outside the reviewed r6c set:")
        for item in unreviewed:
            print("  +", item)
        return 1

    moved = sum(
        1
        for old in old_records
        if any(_key(new) == _key(old) and new.get("line") != old.get("line") for new in records)
    )
    new_records_for_additions = [record for record in records if tuple(_key(record)) in REVIEWED_ADDITIVE_IDENTITIES]

    print("=== reviewed additive records (full dump for review) ===")
    for record in new_records_for_additions:
        print("  +", json.dumps(record, sort_keys=True))
    print(f"=== {len(added)} additive identity(ies), {len(removed)} removals, {moved} records moved lines ===")

    data["records"] = records
    generated_from = data.get("generated_from") or {}
    generated_from["record_count"] = len(records)
    generated_from["regenerated_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    generated_from["regenerated_by"] = (
        "r6c identity-ladder window regen (scripts/regen_direct_io_inventory_r6c_20261027.py)"
    )
    generated_from["scan_root"] = "src"
    data["generated_from"] = generated_from
    coverage = data.get("coverage") or {}
    for field in ("record_count", "total_records", "count", "records"):
        if field in coverage:
            coverage[field] = len(records)
    data.setdefault("regen_history", []).append(
        {
            "at": generated_from["regenerated_at"],
            "delta": (
                f"+{len(new_records_for_additions)} records ({len(old_records)} -> {len(records)}), "
                f"{len(added)} added identity, 0 removed, {moved} moved (line drift)"
            ),
            "reason": (
                "r6c identity-ladder window regen (DR-016, DR-009 protocol): the S1-S4 "
                "identity ladder + honest-validation + payload-capture + refuted-replan "
                "unit rewrote the four scoped files. ONE adjudicated additive identity: "
                "principal_provisioning.py dynamic_resolution getattr(item.identity, ...) "
                "— the identity_resolution property reading identity.winner_strategy; "
                "non-transport, unapproved-site pin unchanged. Zero identity removals "
                "(fail-closed gate held); remaining delta is line drift."
            ),
            "unit": "r6c (identity-ladder window; third derivation of the r5+r6 end state)",
        }
    )
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"regen OK: {len(old_records)} -> {len(records)} records; g02 no-drift test must pass now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
