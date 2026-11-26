#!/usr/bin/env python3
"""UM-DR-50 W1 regeneration of docs/direct_io_inventory.json.

Window: UM-DR-50 W1 (2026-11-26) — the governed raw-transport contract.

Scope of the window's I/O-relevant changes:
  src/webpent/shared/raw_transport.py   (NEW: the bare-transport contract
      node — its socket import + socket.create_connection are THE
      sanctioned chokepoint; approved in APPROVED_DIRECT_FILES /
      APPROVED_RAW_SYMBOLS_BY_FILE as
      governed_raw_transport_contract_node_umdr50_w1)
  src/webpent/production/detection_lanes_48.py  (the D5 raw-path helper
      MIGRATED onto governed_raw_request — its own raw socket sites are
      GONE from the tree; the "scope still enforced" claim is now the
      contract, not a comment)
  src/webpent/shared/h2_race.py, src/webpent/agents/request_smuggling/
  agent.py  (decision RECORDING added — no new transport sites)

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. removed unique identities MUST be exactly the two migrated
     detection_lanes_48 raw-socket identities (the migration this
     window exists for) — any other removal aborts;
  2. added raw-transport sites MUST be inside the approved contract
     file only;
  3. added identities MUST come only from the window's file set;
  4. the unapproved pin REDUCES by exactly 2 records / 2 identities
     (the migrated sites) — the deliberate reduction the pin demands
     (a raw dial moved INTO the governed authorization node), recorded
     in regen_history;
  5. every non-records artifact section is preserved; coverage,
     generated_from recomputed; a regen_history entry appended.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

#: Files this window may introduce identities from.
ALLOWED_NEW_FILES = {
    "src/webpent/shared/raw_transport.py",
}

#: The ONLY identities allowed to disappear — the D5 raw dial migrated
#: onto the governed contract (UM-DR-50 W1).
ALLOWED_REMOVED_IDENTITIES = {
    ("src/webpent/production/detection_lanes_48.py", "call",
     "socket.create_connection"),
    ("src/webpent/production/detection_lanes_48.py", "import", "socket"),
}

#: The pin must reduce by exactly the migrated sites' record count.
EXPECTED_PIN_DELTA = 2

WINDOW = "UM-DR-50 W1 (2026-11-26)"
REGEN_REASON = (
    "deliberate regen for UM-DR-50 W1: the bare-transport contract node "
    "shared/raw_transport.py is added (APPROVED — the sanctioned "
    "chokepoint every bare dial must route through) and the D5 raw-path "
    "helper's own socket sites are REMOVED from detection_lanes_48.py "
    "(migrated onto governed_raw_request). The unapproved pin reduces by "
    "exactly the migrated sites — the deliberate reduction the pin "
    "demands: a raw dial moved INTO the governed authorization node."
)


def _identity(record: dict) -> tuple[str, str, str]:
    symbol = record.get("normalized_symbol") or record.get("symbol", "")
    return (record["file"], record["kind"], symbol)


def _unapproved(records: list[dict]) -> list[dict]:
    return [r for r in records if r.get("approval_status") == "not_approved"]


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}

    # Gate 1 — removals: exactly the migrated D5 sites, nothing else.
    removed = recorded_ids - fresh_ids
    unexpected_removed = removed - ALLOWED_REMOVED_IDENTITIES
    if unexpected_removed:
        print(f"ABORT: {len(unexpected_removed)} unexpected identity removal(s):")
        for item in sorted(unexpected_removed)[:10]:
            print("  -", item)
        return 1
    missing_removals = ALLOWED_REMOVED_IDENTITIES - removed
    if missing_removals:
        print("ABORT: the migration removals are NOT present in the scan:")
        for item in sorted(missing_removals):
            print("  -", item)
        return 1

    # Gate 2 — added raw-transport sites only inside the contract file.
    raw_kinds = {"raw_transport"}
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") in raw_kinds or r.get("kind") in {"httpx", "socket"})
    ]
    bad_raw = [r for r in new_raw if r["file"] != "src/webpent/shared/raw_transport.py"]
    if bad_raw:
        print(f"ABORT: {len(bad_raw)} new raw site(s) outside the contract file:")
        for r in bad_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1
    approved_contract = [r for r in fresh
                         if r["file"] == "src/webpent/shared/raw_transport.py"
                         and r["kind"] in {"import", "call"}]
    if not approved_contract or any(
            r["approval_status"] != "approved" for r in approved_contract):
        print("ABORT: the contract file's socket sites are not approved — "
              "fix APPROVED_DIRECT_FILES/APPROVED_RAW_SYMBOLS_BY_FILE first")
        return 1

    # Gate 3 — added identities only from the window's file set, or
    # benign non-transport bookkeeping (dynamic_resolution records with
    # no transport signal — e.g. the new flag-read getattr) inside the
    # window's modified files.
    WINDOW_MODIFIED_FILES = {
        "src/webpent/production/detection_lanes_48.py",
        "src/webpent/shared/h2_race.py",
        "src/webpent/agents/request_smuggling/agent.py",
        "src/webpent/shared/raw_transport.py",
    }
    added = fresh_ids - recorded_ids
    by_id = {}
    for r in fresh:
        by_id.setdefault(_identity(r), r)
    bad_added = {
        ident for ident in added
        if ident[0] not in ALLOWED_NEW_FILES
        and not (
            ident[0] in WINDOW_MODIFIED_FILES
            and by_id[ident].get("approval_status") == "not_applicable"
            and by_id[ident].get("transport_family") == "non_transport"
        )
    }
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the window scope:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

    # Gate 4 — the unapproved pin reduces by exactly the migrated sites.
    pin_before = len([r for r in recorded
                      if r.get("approval_status") == "not_approved"])
    pin_after = len(_unapproved(fresh))
    if pin_before - pin_after != EXPECTED_PIN_DELTA:
        print(f"ABORT: unapproved record count moved {pin_before} -> "
              f"{pin_after} (expected -{EXPECTED_PIN_DELTA})")
        return 1

    # Preserve every non-records section; recompute records + coverage.
    new_artifact = {k: v for k, v in artifact.items() if k != "records"}
    new_artifact["records"] = fresh
    new_artifact["record_count"] = len(fresh)
    new_artifact["unapproved_transport_pin"] = pin_after
    new_artifact["coverage"] = {
        **(artifact.get("coverage") or {}),
        "files_scanned": len({r["file"] for r in fresh}),
        "records": len(fresh),
    }
    new_artifact["generated_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    new_artifact["generated_from"] = (
        f"{artifact.get('generated_from', 'canonical AST scan of src')} — "
        f"regenerated {WINDOW} (DR-009 protocol)"
    )
    history = new_artifact.setdefault("regen_history", [])
    history.append({
        "at": new_artifact["generated_at"],
        "window": WINDOW,
        "reason": REGEN_REASON,
        "records_before": len(recorded),
        "records_after": len(fresh),
        "added_unique": len(added),
        "removed_unique": len(removed),
        "removed_identities": sorted(removed),
        "unapproved_pin_before": pin_before,
        "unapproved_pin_after": pin_after,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n",
                        encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(added)} new unique identities (contract file, "
        f"approved); {len(removed)} migrated removals; unapproved pin "
        f"{pin_before} -> {pin_after}; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
