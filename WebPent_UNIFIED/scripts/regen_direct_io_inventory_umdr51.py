#!/usr/bin/env python3
"""UM-DR-51 (v0.49.0-window) regeneration of docs/direct_io_inventory.json.

Scope of the window's I/O-relevant edits (all four files edited this
window; every identity delta below is a dynamic_resolution getattr,
non_transport, not_applicable):

  1. src/webpent/agents/access_control/agent.py — ONE NEW identity:
     the promotion-origin getattr at line 1604 (origin_url wiring of
     the P3 promotion fix).
  2. src/webpent/cli/unified_hunt.py — severity added to
     findings_detail shifts five getattr line numbers below it.
  3. src/webpent/families/promotion.py — the origin_url contract
     shifts four getattr line numbers.
  4. src/webpent/production/modern_spine_integration.py — the
     console-script derivation case shifts one getattr line number.

Gates (fail-closed, nothing written unless ALL pass): no unexpected
removals; no new raw-transport site; added identities only inside the
window's four files (dynamic_resolution, non_transport); the
unapproved pin is UNCHANGED (29 -> 29 — the one new identity is
not_applicable, never an unapproved transport); every non-records
artifact section preserved; regen_history appended.
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
WINDOW = "UM-DR-51 v0.49.0-window (2026-11-26)"
REGEN_REASON = (
    "UM-DR-51: the promotion-origin getattr (access_control:1604, ONE "
    "new non-transport dynamic_resolution identity) + line-number drift "
    "in the window's four edited files (unified_hunt severity field, "
    "promotion origin_url contract, modern_spine_integration "
    "console-script derivation). Unapproved pin UNCHANGED (29 -> 29)."
)

WINDOW_MODIFIED_FILES = {
    "src/webpent/agents/access_control/agent.py",
    "src/webpent/cli/unified_hunt.py",
    "src/webpent/families/promotion.py",
    "src/webpent/production/modern_spine_integration.py",
}


def _identity(r: dict) -> tuple[str, int, str, str]:
    return (r["file"], int(r["line"]), r["kind"], r["symbol"])


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}

    removed = recorded_ids - fresh_ids
    added = fresh_ids - recorded_ids

    # Gate 1 — every removal/arrival lives inside the window's files.
    for label, group in (("removed", removed), ("added", added)):
        bad = {i for i in group if i[0] not in WINDOW_MODIFIED_FILES}
        if bad:
            print(f"ABORT: {len(bad)} unexpected {label} identit(ies) "
                  "outside the window's files:")
            for item in sorted(bad)[:8]:
                print("  -", item)
            return 1

    # Gate 2 — no new raw-transport site anywhere.
    by_id: dict = {}
    for r in fresh:
        by_id.setdefault(_identity(r), r)
    bad_raw = [r for r in fresh
               if _identity(r) in added
               and (r.get("transport_family") in {"raw_transport"}
                    or r.get("kind") in {"httpx", "socket", "dynamic_import"})]
    if bad_raw:
        print(f"ABORT: {len(bad_raw)} new transport site(s):")
        for r in bad_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1

    # Gate 3 — every added identity is a benign non-transport
    # dynamic_resolution (line drift or the one new flag-read getattr).
    bad_added = [i for i in added
                 if not (by_id[i].get("kind") == "dynamic_resolution"
                         and by_id[i].get("transport_family") == "non_transport"
                         and by_id[i].get("approval_status") == "not_applicable")]
    if bad_added:
        print(f"ABORT: {len(bad_added)} non-benign added identit(ies):")
        for item in sorted(bad_added)[:8]:
            print("  -", item, by_id.get(item))
        return 1

    # Gate 4 — the unapproved pin is UNCHANGED (the new identity is
    # not_applicable, never an unapproved transport).
    pin_before = len([r for r in recorded
                      if r.get("approval_status") == "not_approved"])
    pin_after = len([r for r in fresh
                     if r.get("approval_status") == "not_approved"])
    if pin_before != pin_after:
        print(f"ABORT: unapproved record count moved {pin_before} -> "
              f"{pin_after} (expected UNCHANGED — the window adds only "
              "not_applicable identities)")
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
        f"regenerated {WINDOW}"
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
        "unapproved_pin_before": pin_before,
        "unapproved_pin_after": pin_after,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n",
                        encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(added)} added / {len(removed)} removed (all "
        "dynamic_resolution non-transport inside the window's files); "
        f"unapproved pin UNCHANGED {pin_before} -> {pin_after}; all "
        "gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
