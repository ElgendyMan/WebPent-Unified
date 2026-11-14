#!/usr/bin/env python3
"""LEARNING A/B LAB window (v0.27.0) regeneration of
docs/direct_io_inventory.json.

Window: LEARNING A/B LAB 2026-10-29 (docs/PRODUCTION_FIX_PLAN_0270.md,
items C-9/C-10).

Scope of the window's I/O-relevant additions:
  src/webpent/memory/ab_lab.py  (make_hunt_subprocess_runner: the real
  ``webpent hunt`` subprocess launcher — process spawn, NOT network
  transport; plus its subprocess import)

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. no raw-transport (httpx/import-socket) site may be added;
  3. added unique identities MUST come only from the window's new
     scope-completion file (never from previously-recorded files);
  4. the unapproved-site pin is unchanged;
  5. every non-records artifact section is preserved; coverage and
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

#: New files this window may introduce identities from (the single
#: scope completion; it performs process spawn, never network transport).
ALLOWED_NEW_FILES = {
    "src/webpent/memory/ab_lab.py",
}

WINDOW = "LEARNING A/B LAB 2026-10-29 (v0.27.0)"
REGEN_REASON = (
    "deliberate regen for the LEARNING A/B LAB window (C-9/C-10): the new "
    "scope-completion file memory/ab_lab.py adds its subprocess import and "
    "subprocess.run call site (the real webpent hunt launcher — process "
    "spawn, not network transport). No raw-transport site added; the "
    "unapproved-site pin is unchanged; no identity removed."
)


def _identity(record: dict) -> tuple[str, str, str]:
    symbol = record.get("normalized_symbol") or record.get("symbol", "")
    return (record["file"], record["kind"], symbol)


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}

    removed = recorded_ids - fresh_ids
    if removed:
        print(f"ABORT: {len(removed)} unique identities REMOVED — deliberate review required:")
        for item in sorted(removed)[:10]:
            print("  -", item)
        return 1

    # No NEW raw-transport site anywhere — the core safety property.
    raw_kinds = {"raw_transport"}
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") in raw_kinds or r.get("kind") in {"httpx", "socket"})
    ]
    if new_raw:
        print(f"ABORT: {len(new_raw)} new raw-transport site(s):")
        for r in new_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1

    # New identities must come only from this window's new file.
    added = fresh_ids - recorded_ids
    bad_added = {
        ident for ident in added if ident[0] not in ALLOWED_NEW_FILES
    }
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the window scope:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

    # Preserve every non-records section; recompute records + coverage.
    pin = artifact.get("unapproved_transport_pin")
    new_artifact = {k: v for k, v in artifact.items() if k != "records"}
    new_artifact["records"] = fresh
    new_artifact["record_count"] = len(fresh)
    new_artifact["coverage"] = {
        **(artifact.get("coverage") or {}),
        "files_scanned": len({r["file"] for r in fresh}),
        "records": len(fresh),
    }
    new_artifact["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    new_artifact["generated_from"] = (
        f"{artifact.get('generated_from', 'canonical AST scan of src')} — "
        f"regenerated {WINDOW} (DR-009 protocol)"
    )
    if pin is not None:
        new_artifact["unapproved_transport_pin"] = pin
    history = new_artifact.setdefault("regen_history", [])
    history.append({
        "at": new_artifact["generated_at"],
        "window": WINDOW,
        "reason": REGEN_REASON,
        "records_before": len(recorded),
        "records_after": len(fresh),
        "added_unique": len(added),
        "removed_unique": 0,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(added)} new unique identities, all inside the "
        "window's new file; no raw transport; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
