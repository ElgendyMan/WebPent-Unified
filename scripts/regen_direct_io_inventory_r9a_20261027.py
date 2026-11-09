"""r9a identity-provisioning window regeneration of docs/direct_io_inventory.json
(2026-10-27, Task r9-CODE; DR-017).

Lineage: regen_direct_io_inventory_r6c_20261027.py is the protocol precedent
(reviewable-delta regen; the g02 no-drift test must pass immediately after
this regen; hand-edits are forbidden). Like the r6c window, any identity-level
delta REFUSES; the reviewed additive set for this window is EMPTY.

Measured r9a delta (reviewed in this script's output):
  * 664 -> 661 records; ZERO identity-level additions and ZERO identity-level
    removals (the fail-closed gate holds; the unapproved-site pin is
    unchanged). The -3 record delta is same-identity DUPLICATE
    CONSOLIDATION inside src/webpent/recon/login_executor.py: the r9 D1/D4
    rewrite of ``_validate_material`` computes the login status ONCE
    (``getattr(login_response, "status_code", None)``) instead of repeating
    that shape at four return sites, collapsing 3 duplicate records of
    identities that remain present.
  * 427 records moved lines (the D1 surface walk + D2 fallthrough + D3
    explicit-routing rewrite across the three r9 scoped files).
  * No raw-transport site was added; the walk reuses the same governed
    ``make_safe_httpx_client``-built client. Non-transport public helpers
    were added to identity_discovery.py (``load_identity_vocab``,
    ``classify_self_payload``) — neither imports nor calls a scanned
    transport symbol.
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
# normalized_symbol). EMPTY: the r9a window adds no new scanned identity.
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
        print("REFUSING: additive identities outside the reviewed r9a set:")
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
    generated_from = data.get("generated_from") or {}
    generated_from["record_count"] = len(records)
    generated_from["regenerated_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    generated_from["regenerated_by"] = (
        "r9a identity-provisioning window regen (scripts/regen_direct_io_inventory_r9a_20261027.py)"
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
                f"{len(old_records)} -> {len(records)} records: 0 added identity, 0 removed "
                f"identity, {moved} moved (line drift), {duplicate_delta:+d} duplicate-count "
                "delta (same-identity consolidation)"
            ),
            "reason": (
                "r9a identity-provisioning window regen (DR-017, DR-009 protocol): the D1 "
                "validation-surface walk + D2 operator-token fallthrough + D3 explicit "
                "auth-type routing + D4 status-honesty rewrite touched the three r9 scoped "
                "files (identity_discovery.py, login_executor.py, principal_provisioning.py). "
                "ZERO identity-level delta (fail-closed gate held; unapproved-site pin "
                "unchanged). The -3 record delta is duplicate consolidation inside "
                "login_executor._validate_material: the r9 D4 rewrite computes the login "
                "status once instead of repeating the getattr shape at four return sites. "
                "No raw-transport site added; the walk reuses the governed client."
            ),
            "unit": "r9a (identity-provisioning window; on top of the r6c lineage)",
        }
    )
    ARTIFACT.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"regen OK: {len(old_records)} -> {len(records)} records; g02 no-drift test must pass now")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
