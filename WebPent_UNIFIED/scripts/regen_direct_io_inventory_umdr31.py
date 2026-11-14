#!/usr/bin/env python3
"""UM-DR-31 (the adaptive-research-loop window, 2026-11-07) regeneration
of docs/direct_io_inventory.json.

Window: the UM-DR-31 changes are in-memory research wiring — the
adaptive research loop node, new state channel, flag-gated graph
routing, and the stateful discovery's hint ordering. The measured
delta versus the recorded artifact:

  ADDED identities (exactly two, both dynamic-resolution getattr in
  the NEW non-frozen module production/adaptive_research.py):
    1. getattr(settings, ...)  — the fail-closed limits read
       (max_research_iterations / max_research_hypotheses_per_
       iteration) in _research_loop_limits: a missing/invalid field
       must read as 0 and fail the node closed, never crash.
    2. getattr(hypothesis, ...) — the pool-index dict/model dual-shape
       read in _pool_index (the V10 checkpoint-round-trip lesson:
       hypotheses in state may be Pydantic instances OR plain dicts).
  NO removed identities; NO new raw-transport sites; the unapproved
  pin is preserved.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities (line drift allowed);
  2. added identities exactly match the declared allowlist above;
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

WINDOW = "UM-DR-31 ADAPTIVE-RESEARCH-LOOP WINDOW 2026-11-07"
REGEN_REASON = (
    "deliberate regen for the UM-DR-31 adaptive-research-loop window: "
    "+2 declared identities (both dynamic-resolution getattr in the new "
    "non-frozen module production/adaptive_research.py — the fail-closed "
    "settings limits read and the checkpoint-round-trip-safe pool-index "
    "dual-shape read) plus line drift inside the re-pinned frozen files "
    "(state.py, settings.py, graph/builder.py, models/hypothesis.py, "
    "families/execution_node.py). ZERO removed identities, ZERO new raw "
    "transport, unapproved pin unchanged."
)

DECLARED_ADDED = {
    (
        "src/webpent/production/adaptive_research.py",
        "dynamic_resolution",
        "getattr(settings, ... )",
    ),
    (
        "src/webpent/production/adaptive_research.py",
        "dynamic_resolution",
        "getattr(hypothesis, ... )",
    ),
}


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

    undeclared = added - DECLARED_ADDED
    if undeclared:
        print(f"ABORT: {len(undeclared)} undeclared ADDED identit(ies):")
        for item in sorted(undeclared)[:10]:
            print("  -", item)
        return 1

    print(f"  declared deltas accepted: 0 removed / {len(added)} added "
          f"identit(ies) (exactly the declared allowlist)")

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
        "identities_added": len(added),
        "identities_removed": 0,
    })

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          f"(+{len(added)} declared identities, line drift otherwise)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
