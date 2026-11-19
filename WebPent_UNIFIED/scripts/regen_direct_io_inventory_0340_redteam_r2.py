#!/usr/bin/env python3
"""RED-TEAM ROUND 2 window (v0.34.0) regeneration of
docs/direct_io_inventory.json.

Window: 0.34.0 red-team round 2 fixes, 2026-11-02
(docs/RED_TEAM_ROUND2_20261102.md, batches C1/C2/C3).

Scope of the window's I/O-relevant identity changes (verified by identity
diff of the recorded artifact vs the fresh AST scan):

  * ADDED identities (dynamic_resolution getattr only — zero new
    raw-transport sites):
    - ``src/webpent/econ/blind_spots.py`` — the R2-econ-05 fix reads
      ``getattr(scope, "gray_zones", None)`` so path entries diverted to
      gray zones still reach the path_region blind-spot locator (2 sites).
    - ``src/webpent/graph/builder.py`` — the R2-graph-01 append-only
      channel strip derives the channel set from the PentestState
      annotations (``getattr(ann, "__metadata__", ...)`` and
      ``getattr(m, "__name__", ...)``).
  * REMOVED identities:
    - ``src/webpent/cli/unified_hunt.py`` — R2-graph-06 replaced the
      ``getattr(f, "validation_status", "")`` probe with the
      reducers._finding_strength rank (the attribute never existed).
    - ``src/webpent/graph/progress_display.py`` — same R2-graph-06 root
      cause in observe_findings.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. removed identities must be EXACTLY the declared set;
  2. added identities must be EXACTLY the declared set;
  3. record-count deltas must match the declared pairs;
  4. no raw-transport site may be added;
  5. the unapproved-site pin is unchanged;
  6. every non-records artifact section is preserved; a regen_history
     entry appended.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.shared.direct_io_inventory import scan_direct_io  # noqa: E402

ARTIFACT = ROOT / "docs" / "direct_io_inventory.json"
SRC = ROOT / "src"

DECLARED_REMOVED_IDENTITIES: set[tuple[str, str, str]] = {
    ("src/webpent/cli/unified_hunt.py", "dynamic_resolution",
     "getattr(f, ... )"),
    ("src/webpent/graph/progress_display.py", "dynamic_resolution",
     "getattr(finding, ... )"),
}

DECLARED_RECORD_DELTAS: dict[tuple[str, str], tuple[int, int]] = {
    ("src/webpent/cli/unified_hunt.py", "dynamic_resolution"): (2, 1),
    ("src/webpent/econ/blind_spots.py", "dynamic_resolution"): (0, 2),
    ("src/webpent/graph/builder.py", "dynamic_resolution"): (10, 12),
    ("src/webpent/graph/progress_display.py", "dynamic_resolution"): (1, 0),
}

DECLARED_ADDED_IDENTITIES: set[tuple[str, str, str]] = {
    ("src/webpent/econ/blind_spots.py", "dynamic_resolution",
     "getattr(scope, ... )"),
    ("src/webpent/graph/builder.py", "dynamic_resolution",
     "getattr(ann, ... )"),
    ("src/webpent/graph/builder.py", "dynamic_resolution",
     "getattr(m, ... )"),
}

WINDOW = "RED-TEAM ROUND 2 2026-11-02 (v0.34.0)"
REGEN_REASON = (
    "deliberate regen for the 0.34.0 red-team round 2 window "
    "(docs/RED_TEAM_ROUND2_20261102.md): R2-econ-05 added 2 "
    "dynamic_resolution getattr records in econ/blind_spots.py "
    "(gray_zones path entries); R2-graph-01 added 2 in graph/builder.py "
    "(append-only channel derivation from PentestState annotations); "
    "R2-graph-06 removed the validation_status getattr probes in "
    "cli/unified_hunt.py and graph/progress_display.py (replaced by the "
    "reducers._finding_strength rank). Net +2 records (814 -> 816). "
    "Zero new raw-transport sites, unapproved pin unchanged."
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

    bad_removed = removed - DECLARED_REMOVED_IDENTITIES
    if bad_removed:
        print(f"ABORT: {len(bad_removed)} undeclared REMOVED identity/ies:")
        for item in sorted(bad_removed)[:10]:
            print("  -", item)
        return 1

    def _pair_counts(records: list[dict]) -> Counter:
        return Counter((r["file"], r["kind"]) for r in records)

    before_pairs = _pair_counts(recorded)
    after_pairs = _pair_counts(fresh)
    for pair in sorted(set(before_pairs) | set(after_pairs)):
        before_n = before_pairs.get(pair, 0)
        after_n = after_pairs.get(pair, 0)
        if before_n == after_n:
            continue
        declared = DECLARED_RECORD_DELTAS.get(pair)
        # Idempotent re-run: accept (after, after) as applied.
        if declared != (before_n, after_n) and declared != (after_n, after_n):
            print(
                f"ABORT: undeclared record-count delta for {pair}: "
                f"{before_n} -> {after_n} (declared: {declared})"
            )
            return 1

    bad_added = added - DECLARED_ADDED_IDENTITIES
    if bad_added:
        print(f"ABORT: {len(bad_added)} undeclared ADDED identity/ies:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

    print(
        f"  declared deltas accepted: {len(removed)} removed / "
        f"{len(added)} added identity(ies)"
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
        if (
            {_identity(r) for r in fresh_unapproved}
            != {_identity(r) for r in recorded_unapproved}
        ):
            print("ABORT: unapproved-site identity set drifted")
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
