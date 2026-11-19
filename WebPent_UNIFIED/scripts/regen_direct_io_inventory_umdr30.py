#!/usr/bin/env python3
"""UM-DR-30 (the capability-wiring window, 2026-11-07) regeneration of
docs/direct_io_inventory.json.

Window: the UM-DR-30 changes are pure in-memory capability wiring —
channel declarations, an advisory node over the shared coverage ledger,
an advisory invariant review, and CLI-wrapper script fixes. The measured
delta versus the recorded artifact is ZERO added and ZERO removed
unique identities; only line drift of the pre-existing dynamic-
resolution getattr sites inside the four re-pinned frozen files
(state.py / settings.py / graph/builder.py /
agents/business_logic_fuzzer/agent.py). The new module
production/coverage_gap_report.py adds no direct-I/O site (state
projection + logging only).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities (line drift allowed);
  2. NO new identities at all (this window adds none);
  3. NO new raw-transport / not-approved sites;
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

WINDOW = "UM-DR-30 CAPABILITY-WIRING WINDOW 2026-11-07"
REGEN_REASON = (
    "deliberate regen for the UM-DR-30 capability-wiring window: "
    "line drift only (the pre-existing getattr sites moved inside the "
    "four re-pinned frozen files: state.py, settings.py, graph/"
    "builder.py, agents/business_logic_fuzzer/agent.py). ZERO new "
    "identities, ZERO removed identities, ZERO new raw transport, "
    "unapproved pin unchanged. The window's new module "
    "(production/coverage_gap_report.py) is a pure state projection "
    "and adds no direct-I/O site."
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

    if removed:
        print(f"ABORT: {len(removed)} removed identit(ies) — this window "
              "declares none:")
        for item in sorted(removed)[:10]:
            print("  -", item)
        return 1

    if added:
        print(f"ABORT: {len(added)} undeclared ADDED identit(ies):")
        for item in sorted(added)[:10]:
            print("  -", item)
        return 1

    print("  declared deltas accepted: 0 removed / 0 added identit(ies) "
          "— line drift only")

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
        if fresh_ids_unapp - rec_ids_unapp:
            print("ABORT: NEW unapproved site identities appeared")
            return 1
        if rec_ids_unapp - fresh_ids_unapp:
            print("ABORT: unapproved site identities vanished — this "
                  "window declares none")
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
        "records": len(fresh),
        "identities_added": 0,
        "identities_removed": 0,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          "(line drift only, no identity change)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
