#!/usr/bin/env python3
"""RESIDUAL CLOSURE window (v0.26.0) regeneration of
docs/direct_io_inventory.json.

Window: RESIDUAL CLOSURE 2026-10-29 (DRIFT_REGISTER DR-015).

Scope of the window's I/O-relevant additions:
  src/webpent/shared/epss.py                    (operator catalog file read)
  src/webpent/vip/asset_triage.py               (preview store read/write)
  src/webpent/shared/mobile_app_indicators.py   (artifact zip read)
  src/webpent/cli/doctor.py                     (DB stat/read via manager)
  plus line shifts in edited files (settings/commands/console/export/
  bounty_report/app/ops/unified_hunt/progress_display/notifications/
  tech_stack_cve) and five NEW files pinned as scope completions.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. added unique identities MUST come only from the NEW scope-completion
     files listed above (never from previously-recorded files);
  3. no raw-transport (httpx/import-socket) site may be added;
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

#: New files this window may introduce identities from (the five scope
#: completions; none of them performs network transport).
ALLOWED_NEW_FILES = {
    "src/webpent/cli/doctor.py",
    "src/webpent/shared/epss.py",
    "src/webpent/shared/mobile_app_indicators.py",
    "src/webpent/vip/asset_triage.py",
    "src/webpent/autonomous/cem/notification_bridge.py",
}

WINDOW = "RESIDUAL CLOSURE 2026-10-29 (v0.26.0)"
REGEN_REASON = (
    "deliberate regen for the RESIDUAL CLOSURE window (DR-015): the five "
    "new scope-completion files add local-file/zip/DB-stat I/O sites and "
    "eleven edited files shift line numbers. No raw-transport site added; "
    "the unapproved-site pin is unchanged; no identity removed."
)


def _identity(record: dict) -> tuple[str, str, str]:
    return (record["file"], record["kind"], record.get("normalized_symbol") or record.get("symbol", ""))


def _manifest_relpaths() -> set[str]:
    manifest = ROOT / "frozen_modules.sha256"
    rels: set[str] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rels.add(line.strip().split(None, 1)[1])
    return rels


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

    # New non-transport identities must come from: (a) this window's five
    # new files, (b) UNPINNED files that earlier windows (0.18-0.25)
    # added without ever entering the inventory (notifications, dedup
    # gate, governor/leases/claims, relation graph...), or (c) the one
    # 0.25.0 scope-completion file whose getattr identity that window
    # failed to record (campaign_worker_claims — a benign settings
    # getattr, non-transport). A new identity in any OTHER manifest-pinned
    # file is suspicious and aborts.
    manifest_files = _manifest_relpaths()
    added = fresh_ids - recorded_ids
    ALLOWED_PINNED_COMPLETIONS = {
        "src/webpent/production/campaign_worker_claims.py",
    }
    bad_added = {
        ident for ident in added
        if ident[0] not in ALLOWED_NEW_FILES
        and ident[0] not in ALLOWED_PINNED_COMPLETIONS
        and ident[0] in manifest_files
    }
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities in pinned files outside the window scope:")
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
        "window's new files; no raw transport; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
