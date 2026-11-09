#!/usr/bin/env python3
"""PLAN-EXECUTION window (v0.30.0) regeneration of docs/direct_io_inventory.json.

Window: WEBPENT_FIX_PLAN_20261029.md execution, 2026-11-01 (v0.30.0).

Scope of the window's I/O-relevant edits: NONE. The window edited only
comments/docstrings and CLI deprecation-banner strings in
``src/webpent/cli/commands.py`` (banner text), plus provenance-comment
paths in ``src/webpent/autonomous/__init__.py`` and
``src/webpent/agents/validator/agent.py`` — pure LINE DRIFT, zero new
I/O call sites, zero removed identities, zero new files.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. no raw-transport site may be added;
  3. NO new unique identities at all (line-drift-only window: the allowed
     new-file set is empty by design);
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

#: Line-drift-only window — no new file may introduce identities.
ALLOWED_NEW_FILES: set[str] = set()

WINDOW = "PLAN-EXECUTION 2026-11-01 (v0.30.0, WEBPENT_FIX_PLAN_20261029.md)"
REGEN_REASON = (
    "deliberate regen for the PLAN-EXECUTION window: deprecation-banner "
    "text edits in cli/commands.py and provenance-comment path updates in "
    "autonomous/__init__.py + agents/validator/agent.py shift line numbers "
    "only. Zero new I/O identities, zero removed, zero new raw-transport "
    "sites, unapproved pin unchanged."
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

    # Line-drift-only window: no new identities whatsoever.
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
        "added_unique": 0,
        "removed_unique": 0,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        "records); pure line drift, 0 added / 0 removed identities; no raw "
        "transport; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
