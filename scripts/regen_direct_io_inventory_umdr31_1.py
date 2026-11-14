#!/usr/bin/env python3
"""UM-DR-31.1 regeneration of docs/direct_io_inventory.json (R11/F17).

Window: the UM-DR-31.1 intelligence & engineering uplift. The measured
delta versus the recorded artifact:

  ADDED identities: NONE (zero new dynamic-resolution sites; the
  research-hint surface extension reuses the existing inventory scan,
  and the classification contract adds no dynamic reads).
  REMOVED identities: NONE.
  Line drift only, inside the touched non-frozen modules
  (production/adaptive_research.py, production/stateful_discovery.py,
  shared/coverage_ledger.py, coverage/gap_detector.py) and the
  re-pinned frozen trio (__init__.py, coverage/gap_detector.py,
  shared/coverage_ledger.py).

ATtribution CORRECTION (R11/F17, appended as a new history entry —
history is never rewritten): the recorded UM-DR-31 entry declares
"+2 declared identities ... in production/adaptive_research.py". The
accurate attribution of the UM-DR-31 window's dynamic-resolution delta
is FOUR getattr sites in production/adaptive_research.py (the fail-
closed settings limits read at two call sites + the pool-index
dual-shape read at two call sites — two identity classes, four sites)
PLUS TWO getattr sites in families/execution_node.py (the research-
hints wiring: the loop-flag read and the stateful_research_hints
import-resolution block). The under-attribution is a documentation
defect in the UM-DR-31 regen reason only — the recorded identity set
itself was complete and correct (verified by this regeneration: the
fresh scan reproduces exactly the recorded identity set).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. NO added identities (this window declares none);
  3. NO new raw-transport / not-approved sites;
  4. the unapproved pin is preserved;
  5. every non-records artifact section is preserved; coverage and
     generated_at recomputed; a regen_history entry appended carrying
     BOTH the window delta and the F17 attribution correction.
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

WINDOW = "UM-DR-31.1 INTELLIGENCE & ENGINEERING UPLIFT WINDOW 2026-11-08"
REGEN_REASON = (
    "deliberate regen for the UM-DR-31.1 uplift window: ZERO added / "
    "ZERO removed identities (the R3 hypothesis-admission filter, the "
    "R4 fingerprint canonicalization, the R5 hint-semantics fix, the "
    "R6/F20 classification contract, the R7 corrupted-channel fail-"
    "closed handling and the §6.1 coverage-surface scheduling hints add "
    "no new dynamic-resolution sites), line drift only in the touched "
    "modules. ALSO carries the R11/F17 attribution correction for the "
    "UM-DR-31 entry (see attribution_correction)."
)

F17_CORRECTION = (
    "UM-DR-31 regen-reason attribution correction (audit F17, "
    "remediation R11): the UM-DR-31 reason declared '+2 declared "
    "identities in production/adaptive_research.py'. The accurate "
    "attribution of that window's dynamic-resolution delta is: FOUR "
    "getattr sites in production/adaptive_research.py (two identity "
    "classes — the fail-closed settings limits read and the pool-index "
    "dual-shape read — at two call sites each) PLUS TWO getattr sites "
    "in families/execution_node.py (the research-hints wiring: the "
    "loop-flag read and the stateful_research_hints resolution block). "
    "The recorded IDENTITY SET was complete and correct; only the "
    "reason text under-attributed the execution_node additions. This "
    "correction is appended, never rewritten into history."
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
        print(f"ABORT: {len(added)} ADDED identit(ies) — this window "
              "declares none:")
        for item in sorted(added)[:10]:
            print("  -", item)
        return 1

    print("  declared deltas accepted: 0 removed / 0 added identit(ies)")

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
        if {_identity(r) for r in fresh_unapproved} != {_identity(r) for r in recorded_unapproved}:
            print("ABORT: the unapproved-site pin set changed")
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

    history = list(new_artifact.get("regen_history") or [])
    history.append({
        "at": new_artifact["generated_at"],
        "window": WINDOW,
        "reason": REGEN_REASON,
        "attribution_correction": F17_CORRECTION,
        "records": len(fresh),
        "identities_added": 0,
        "identities_removed": 0,
    })
    new_artifact["regen_history"] = history

    ARTIFACT.write_text(json.dumps(new_artifact, indent=1) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          "(+0 declared identities, line drift otherwise; F17 correction appended)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
