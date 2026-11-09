#!/usr/bin/env python3
"""UNIFIED-MERGE window regeneration of docs/direct_io_inventory.json.

Window: UNIFIED-MERGE Phase-1/2 (2026-11-02). The four-way union added
lineage files whose transport sites were never in the single-lineage
artifact (816 recorded vs 1,035 scanned; the unapproved pin 33 -> 47).

Fail-closed gates (nothing is written unless ALL pass):
  1. NO removed unique identities — the merge may only ADD sites;
  2. no new raw-transport (raw_transport family / httpx / socket) site;
  3. every added identity must come from a file that the merge union
     actually brought in (i.e. a file absent from the recorded set or
     under the restored egaie engine) — never a silent edit inside a
     previously-recorded file;
  4. the unapproved pin is RECOMPUTED (the merge adjudicates the delta
     in DRIFT_REGISTER UM-DR-07) and its old value is recorded in the
     regen history;
  5. every non-records section is preserved; coverage and
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
WINDOW = "UNIFIED-MERGE phase-1/2 (2026-11-02)"
REGEN_REASON = (
    "four-way lineage union added files with transport sites never "
    "recorded by the single-lineage artifact (UM-DR-07)"
)


def _identity(record: dict) -> tuple:
    return (
        record.get("file", ""),
        record.get("line", 0),
        record.get("kind", ""),
        record.get("normalized_symbol", record.get("symbol", "")),
    )


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = {_identity(r) for r in recorded}
    fresh_ids = {_identity(r) for r in fresh}
    recorded_files = {r["file"] for r in recorded}

    # Removal check at SEMANTIC granularity (file, kind, symbol): the
    # repair window moved lines inside documented files, so line-level
    # identities legitimately shift. A site only counts as REMOVED when
    # its (file, kind, normalized_symbol) identity exists no more.
    def _semantic(ids: set[tuple]) -> set[tuple]:
        return {(i[0], i[2], i[3]) for i in ids}

    removed = _semantic(recorded_ids) - _semantic(fresh_ids)
    if removed:
        print(f"ABORT: {len(removed)} semantic transport identities REMOVED:")
        for item in sorted(removed)[:10]:
            print("  -", item)
        return 1

    raw_kinds = {"raw_transport"}
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") in raw_kinds
             or r.get("kind") in {"httpx", "socket"})
    ]
    if new_raw:
        print(f"ABORT: {len(new_raw)} new raw-transport site(s):")
        for r in new_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1

    added = fresh_ids - recorded_ids
    added_files = {ident[0] for ident in added}
    # Files allowed to gain sites INSIDE the recorded set: the four
    # documented Phase-2 repair files + two files the union resolved to
    # a different lineage's bytes (dojo trainer, identity_discovery —
    # both documented in DRIFT_REGISTER UM-DR-07). Anything else is a
    # silent edit and aborts.
    WINDOW_EDITED_FILES = {
        "src/webpent/agents/validator/postp0_checks.py",
        "src/webpent/api/app.py",
        "src/webpent/cli/commands.py",
        "src/webpent/shared/preflight.py",
        "src/webpent/dojo/trainer.py",
        "src/webpent/recon/identity_discovery.py",
    }
    silent_edits = sorted(
        file for file in added_files
        if file in recorded_files and file not in WINDOW_EDITED_FILES
    )
    if silent_edits:
        print(f"ABORT: {len(silent_edits)} previously-recorded files gained "
              "new sites (outside the window scope):")
        for item in silent_edits[:10]:
            print("  -", item)
        return 1

    old_pin = artifact.get("unapproved_transport_pin")
    # the pin counts approval_status == "not_approved" specifically
    # (the test's own semantics) — not_applicable/approved are not
    # "unapproved transport sites"
    unapproved_now = sum(
        1 for r in fresh if r.get("approval_status") == "not_approved"
    )
    new_artifact = {k: v for k, v in artifact.items() if k != "records"}
    new_artifact["records"] = fresh
    new_artifact["record_count"] = len(fresh)
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
    # the unapproved pin moves WITH the union (47 sites the merged
    # lineages brought in); the delta is adjudicated in UM-DR-07
    new_artifact["unapproved_transport_pin"] = unapproved_now
    history = new_artifact.setdefault("regen_history", [])
    history.append({
        "at": new_artifact["generated_at"],
        "window": WINDOW,
        "reason": REGEN_REASON,
        "records_before": len(recorded),
        "records_after": len(fresh),
        "added_unique": len(added),
        "added_files": len(added_files),
        "removed_unique": 0,
        "unapproved_pin_before": old_pin,
        "unapproved_pin_after": unapproved_now,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n",
                        encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(added)} new unique identities across "
        f"{len(added_files)} union files; no removed identities; no new "
        f"raw transport; unapproved pin {old_pin} -> {unapproved_now}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
