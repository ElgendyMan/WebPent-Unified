#!/usr/bin/env python3
"""UM-DR-29 (dead-code disposition window, 2026-11-07) regeneration of
docs/direct_io_inventory.json.

Window: UM-DR-29 DEAD-CODE DISPOSITION (v0.35.0) — 24 verified-dead
packages left src/ (17 to the already-existing archive/pre_v10_prototypes/
copies completing ULTIMATE PLAN 2026-10-27 proposal 4; 7 moved to
archive/umdr29_dead_code/ per the DR-009 declared thaw + refreeze
scripts/refreeze_manifest_umdr29.py). Six frozen __init__.py docstring
corrections do not touch I/O. See archive/umdr29_dead_code/README.md.

This is a FILE-REMOVAL window: every removed identity belongs to a file
inside one of the archived package prefixes (declared below). Gate set:

  1. removed identities must ALL be inside the declared archived
     prefixes (nothing else may disappear);
  2. ZERO added identities (no new I/O surface in this window);
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

ARCHIVED_PREFIXES = tuple(
    f"src/webpent/{pkg}/"
    for pkg in (
        # completed Ultimate-Plan-2026-10-27-proposal-4 archive move
        "abhc", "abhie", "abhie_v6", "abhip", "adi", "asros", "avde",
        "avrip", "avrp", "cqa", "dcvu", "goed_v1", "rta",
        "vabhfil_v8", "vabhfqr_v10", "vabhfqr_v9", "vabhic_v7",
        # UM-DR-29 frozen-but-dead archive
        "contracts", "copilot", "experience", "persistence",
        "profiles", "security_models", "validation",
    )
)

WINDOW = "UM-DR-29 DEAD-CODE DISPOSITION 2026-11-07 (v0.35.0)"
REGEN_REASON = (
    "deliberate regen for the UM-DR-29 dead-code disposition window: "
    "24 verified-dead packages left src/ (17 completing the Ultimate "
    "Plan 2026-10-27 proposal-4 archive move to archive/"
    "pre_v10_prototypes/; 7 frozen-but-dead packages moved to "
    "archive/umdr29_dead_code/ with the DR-009 refreeze "
    "scripts/refreeze_manifest_umdr29.py). All removed I/O identities "
    "belong to the archived files; zero additions, zero new raw "
    "transport, unapproved pin unchanged."
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
    added = fresh_ids - recorded_ids

    outside = {r for r in removed if not r[0].startswith(ARCHIVED_PREFIXES)}
    if outside:
        print(f"ABORT: {len(outside)} removed identit(ies) OUTSIDE the "
              "declared archived prefixes:")
        for item in sorted(outside)[:10]:
            print("  -", item)
        return 1

    if added:
        print(f"ABORT: {len(added)} undeclared ADDED identit(ies):")
        for item in sorted(added)[:10]:
            print("  -", item)
        return 1

    print(
        f"  declared deltas accepted: {len(removed)} removed / "
        f"{len(added)} added identity(ies) — all removals inside the "
        "archived prefixes"
    )

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

    pin = artifact.get("unapproved_transport_pin")
    if pin is not None:
        fresh_unapproved = [
            r for r in fresh if r.get("approval_status") == "not_approved"
        ]
        recorded_unapproved = [
            r for r in recorded if r.get("approval_status") == "not_approved"
        ]
        fresh_ids_unapp = {_identity(r) for r in fresh_unapproved}
        rec_ids_unapp = {_identity(r) for r in recorded_unapproved}
        # File-removal window semantics: unapproved sites may ONLY shrink,
        # and only inside the declared archived prefixes. No additions ever.
        if fresh_ids_unapp - rec_ids_unapp:
            print("ABORT: NEW unapproved site identities appeared")
            return 1
        vanished_unapp = rec_ids_unapp - fresh_ids_unapp
        outside_unapp = {
            r for r in vanished_unapp
            if not r[0].startswith(ARCHIVED_PREFIXES)
        }
        if outside_unapp:
            print(
                f"ABORT: unapproved sites vanished OUTSIDE the archived "
                f"prefixes: {sorted(outside_unapp)[:5]}"
            )
            return 1

    new_artifact = {k: v for k, v in artifact.items() if k != "records"}
    new_artifact["records"] = fresh
    new_artifact["record_count"] = len(fresh)
    new_artifact["coverage"] = {
        **(artifact.get("coverage") or {}),
        "files_scanned": len({r["file"] for r in fresh}),
        "records": len(fresh),
    }
    new_artifact["generated_at"] = datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
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

    ARTIFACT.write_text(
        json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(removed)} declared removal / {len(added)} declared "
        "addition; no raw transport; all gates passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
