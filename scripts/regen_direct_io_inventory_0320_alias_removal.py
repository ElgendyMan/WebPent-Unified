#!/usr/bin/env python3
"""RETIRED-ALIAS REMOVAL window (v0.32.0) regeneration of
docs/direct_io_inventory.json.

Window: v0.32.0 retired-alias removal, 2026-11-01 (declared in the
0.30.0 CHANGELOG item ج.2).

Scope of the window's I/O-relevant edits: the three retired CLI
commands (scan/hunt-auto/hunt-plan) left ``src/webpent/cli/commands.py``
together with the scan-only helpers. That removes exactly TWO recorded
identities — both ``dynamic_resolution getattr`` sites that lived inside
the removed ``scan`` body. One new src file exists
(``src/webpent/autonomous/authorization_recheck.py``) but performs no
I/O (plain re-export of the authorization gate; expected record count:
zero).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. removed identities must be EXACTLY the declared scan-body pair
     (file == commands.py, kind == dynamic_resolution) — anything else
     aborts;
  2. no raw-transport site may be added;
  3. no new identities outside the declared new-file allowlist;
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

#: The declared new file of this window (expected to contribute zero
#: records — kept as an explicit allowlist in case tooling changes).
ALLOWED_NEW_FILES: set[str] = {
    "src/webpent/autonomous/authorization_recheck.py",
}

#: The declared removals: the two getattr sites inside the removed
#: ``scan`` command body (lines 1148/1150 of the pre-window file).
DECLARED_REMOVED_FILES = {"src/webpent/cli/commands.py"}
DECLARED_REMOVED_KINDS = {"dynamic_resolution"}

WINDOW = "RETIRED-ALIAS REMOVAL 2026-11-01 (v0.32.0)"
REGEN_REASON = (
    "deliberate regen for the retired-alias removal window: the removed "
    "scan/hunt-auto/hunt-plan CLI commands take their two recorded "
    "dynamic_resolution getattr sites out of commands.py; the new "
    "authorization_recheck module contributes no I/O records. Zero new "
    "identities, zero new raw-transport sites, unapproved pin unchanged."
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
    bad_removed = {
        ident
        for ident in removed
        if ident[0] not in DECLARED_REMOVED_FILES
        or ident[1] not in DECLARED_REMOVED_KINDS
    }
    if bad_removed:
        print(f"ABORT: {len(bad_removed)} undeclared REMOVED identity/ies:")
        for item in sorted(bad_removed)[:10]:
            print("  -", item)
        return 1
    if removed:
        print(f"  declared removals accepted: {len(removed)}")
        for item in sorted(removed):
            print("  -", item)

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

    added = fresh_ids - recorded_ids
    bad_added = {
        ident for ident in added if ident[0] not in ALLOWED_NEW_FILES
    }
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the window scope:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

    # The unapproved-site pin must be byte-unchanged.
    pin = artifact.get("unapproved_transport_pin")
    fresh_unapproved = [
        r for r in fresh if r.get("approval_status") == "not_approved"
    ]
    if pin is not None:
        fresh_pin = {
            "record_count": len(fresh_unapproved),
            "identity_count": len({_identity(r) for r in fresh_unapproved}),
        }
        if (
            pin.get("record_count") != fresh_pin["record_count"]
            or pin.get("identity_count") != fresh_pin["identity_count"]
        ):
            print(
                "ABORT: unapproved-site pin drifted: "
                f"{pin} vs {fresh_pin}"
            )
            return 1

    # Preserve every non-records section; recompute records + coverage.
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
        "removed_unique": len(removed),
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(removed)} declared removals / {len(added)} additions; "
        "no raw transport; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
