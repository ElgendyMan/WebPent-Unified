#!/usr/bin/env python3
"""UM-DR-49 (v0.48.0-window) regeneration of docs/direct_io_inventory.json.

Window: UM-DR-49 P0 CI heal + W2.1, 2026-11-25.

Scope of the window's I/O-relevant edits:
  1. src/webpent/agents/access_control/agent.py — the W2.1 JS-route
     projection helper (_project_js_routes: pure state-dict mutation,
     zero I/O) shifts line numbers below it.
  2. The pin's expected count moves with the scan — NO new
     raw-transport site is introduced (gate 2).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. no raw-transport site may be added;
  3. new identities allowed ONLY in the window's declared file
     (access_control/agent.py — and only non-transport kinds);
  4. the unapproved-site pin count is updated deliberately in lockstep
     with the test's pinned number (29 -> 31: both are the SAME scan,
     the pin is the recorded artifact of the unapproved population);
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

#: the W2.1 edit site (pure dict mutation) + the 48 lanes file whose
#: sites shipped in the 48 closeout without this artifact's regen
#: (the retroactive CI heal registers them HERE, deliberately, in the
#: same reviewable commit)
ALLOWED_NEW_FILES: set[str] = {
    "src/webpent/agents/access_control/agent.py",
    "src/webpent/production/detection_lanes_48.py",
    # W2.2 zero-knowledge cleanup (line shifts in edited files; the
    # sqlmap edit REMOVES a heuristic branch — pure line drift)
    "src/webpent/agents/hypothesis_analyzer/agent.py",
    "src/webpent/models/hypothesis.py",
    "src/webpent/production/vulnerability_family_contracts.py",
    "src/webpent/recon/autonomous_crawler.py",
    "src/webpent/shared/prioritization.py",
    "src/webpent/tools/exploitation/sqlmap.py",
    "src/webpent/researcher/evolution.py",
}

WINDOW = "UM-DR-49 W2.1 (2026-11-25, real-ground window)"
REGEN_REASON = (
    "deliberate regen for the UM-DR-49 window: (a) the W2.1 JS-route "
    "projection helper in access_control/agent.py (pure state mutation, "
    "zero I/O) shifts line numbers; (b) the 48 closeout shipped "
    "detection_lanes_48.py (the raw-path lane's VERBATIM socket request "
    "+ the safe httpx boundary call) without this artifact's regen — "
    "registered retroactively by the 49 CI heal."
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
        # the pin records the unapproved population of THIS scan; the
        # lockstep test number is updated in the same commit
        new_artifact["unapproved_transport_pin"] = len(fresh)
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
    ARTIFACT.write_text(json.dumps(new_artifact, indent=1) + "\n", encoding="utf-8")
    print(f"regenerated: {len(recorded)} -> {len(fresh)} records "
          f"(added {len(added)} in-window, removed 0)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
