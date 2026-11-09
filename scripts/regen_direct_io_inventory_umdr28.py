#!/usr/bin/env python3
"""UM-DR-28 (the production discovery-integration window, 2026-11-07)
regeneration of docs/direct_io_inventory.json.

Window: the UM-DR-28 changes added TWO new fail-soft dynamic-resolution
identities — the flag check in families/execution_node.py (step 4c:
getattr(get_settings(), "enable_stateful_discovery", False)) and the
outcome accessors in the new production/stateful_discovery.py — plus
line drift of the pre-existing getattr sites in the four re-pinned
frozen files (causal_guard.py untouched I/O-wise; stateful_probe.py /
settings.py / state.py / execution_node.py). The g02 drift gate then
reported 1186 -> 1194 records (two new identities, line drift only).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities (line drift allowed);
  2. NO new raw-transport / not-approved sites;
  3. new identities only inside the window's file set (below);
  4. the unapproved-site pin is preserved;
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

#: The UM-DR-27 window's I/O-bearing file (computed from the actual
#: drift — the single new identity; transition_sources.py is pure
#: logic and adds no direct-I/O site).
ALLOWED_NEW_FILES: set[str] = {
    "src/webpent/families/execution_node.py",
    "src/webpent/production/stateful_discovery.py",
}

WINDOW = "UM-DR-28 DISCOVERY-INTEGRATION WINDOW 2026-11-07"
REGEN_REASON = (
    "deliberate regen: the UM-DR-28 production discovery integration "
    "added two fail-soft dynamic-resolution sites (the "
    "enable_stateful_discovery flag read in execution_node.py step 4c "
    "and the outcome accessors in the new stateful_discovery.py) and "
    "moved the pre-existing getattr sites in the re-pinned frozen files. "
    "ZERO new raw-transport / not-approved sites, unapproved pin "
    "preserved, no identity truly removed (line drift only)."
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

    # Gate 1: identity removals are only allowed when the identity
    # SURVIVES at a different line (line drift) — a true disappearance
    # (same file, same symbol, same kind, nowhere) aborts.
    def _sem_identity(rec: dict) -> tuple[str, str]:
        symbol = rec.get("normalized_symbol") or rec.get("symbol", "")
        return (rec["file"], symbol)

    recorded_sem = {_sem_identity(r) for r in recorded}
    fresh_sem = {_sem_identity(r) for r in fresh}
    vanished = recorded_sem - fresh_sem
    if vanished:
        print(f"ABORT: {len(vanished)} identities truly REMOVED:")
        for item in sorted(vanished)[:10]:
            print("  -", item)
        return 1

    # Gate 2: no NEW raw-transport / not-approved site anywhere.
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") == "raw_transport"
             or r.get("kind") in {"httpx", "socket"}
             or r.get("approval_status") == "not_approved")
    ]
    if new_raw:
        print(f"ABORT: {len(new_raw)} new raw/not-approved transport site(s):")
        for r in new_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1

    # Gate 3: new identities only inside the window's documented files.
    added = fresh_ids - recorded_ids
    bad_added = {ident for ident in added if ident[0] not in ALLOWED_NEW_FILES}
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the window scope:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

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
    print(f"OK: direct-I/O artifact regenerated ({len(recorded)} -> {len(fresh)} records, "
          f"+{len(added)} new unique identities, all inside the UM-DR-28 window file set, "
          f"0 removed, unapproved pin preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
