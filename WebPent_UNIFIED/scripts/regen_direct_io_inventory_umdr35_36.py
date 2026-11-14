#!/usr/bin/env python3
"""UM-DR-35/36 regeneration of docs/direct_io_inventory.json.

Window: the UM-DR-35/36 corrective closure (confirmation authority +
semantic-model production wiring). The measured delta versus the recorded
artifact:

  ADDED identities (4, all dynamic_resolution getattr sites, all inside
  the deliberately-touched UM-DR-35/36 modules):
    1. agents/hypothesis_analyzer/agent.py — getattr(hypothesis, ...)
       (UM-DR-36: the hypothesis-admission filter's fail-soft field read)
    2. graph/appmodel_nodes.py — getattr(...)
       (UM-DR-36: the new appmodel graph node's bounded state reads)
    3. production/autonomous_validation_v1.py —
       getattr(guard_decision.adjudication, ...)
       (UM-DR-35: the AVI path's guard-adjudication provenance read)
    4. production/confirmation_adapter.py — getattr(observation, ...)
       (UM-DR-35: the universal adapter's typed-observation mapping read)
  REMOVED identities: NONE.
  New raw-transport / not-approved sites: NONE (approval statuses all
  unchanged; the unapproved pin set is byte-identical).
  Line drift only, inside the re-pinned frozen modules touched by the
  closure (validator/agent.py, verifier.py, causal_guard.py, graph/
  builder.py, appmodel/builder.py, autonomous_validation_v1.py,
  structural_checks.py, hypothesis_analyzer/agent.py).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. added identities are EXACTLY the four declared above;
  3. NO new raw-transport / not-approved sites;
  4. the unapproved pin is preserved;
  5. every non-records artifact section is preserved; coverage and
     generated_at recomputed; a regen_history entry appended.
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

WINDOW = "UM-DR-35/36 CORRECTIVE CLOSURE WINDOW 2026-11-12"
REGEN_REASON = (
    "deliberate regen for the UM-DR-35/36 corrective closure: the "
    "confirmation-authority unification (CausalGuard sole authority via "
    "production/confirmation_adapter + shared/verifier mandatory "
    "adjudication + the SQLi reauth bypass removal) and the semantic-"
    "model production wiring (graph/appmodel_nodes, appmodel builder, "
    "hypothesis priority) add EXACTLY four declared dynamic-resolution "
    "identities (all getattr defensive reads on typed objects: "
    "hypothesis_analyzer agent, appmodel_nodes, autonomous_validation_v1 "
    "guard-adjudication read, confirmation_adapter observation mapping). "
    "Zero removals; zero new raw-transport or not-approved sites; the "
    "unapproved pin set is unchanged; line drift only inside the "
    "touched modules."
)

# UM-DR-35/36 (2026-11-13): all window identities are absorbed into the
# recorded artifact (1202 records). Future regens declare nothing — any
# NEW identity after this point must be declared here first (fail-closed).
DECLARED_ADDED: set[tuple[str, str, str]] = set()


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
    if added != DECLARED_ADDED:
        print(f"ABORT: added identities are not exactly the declared four:")
        for item in sorted(added - DECLARED_ADDED)[:10]:
            print("  + undeclared:", item)
        for item in sorted(DECLARED_ADDED - added)[:10]:
            print("  - declared but absent:", item)
        return 1

    print("  declared deltas accepted: 0 removed / 4 added identit(ies)")

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
        "records": len(fresh),
        "identities_added": len(DECLARED_ADDED),
        "identities_added_detail": sorted(
            [list(ident) for ident in DECLARED_ADDED]
        ),
        "identities_removed": 0,
    })
    new_artifact["regen_history"] = history

    ARTIFACT.write_text(json.dumps(new_artifact, indent=1) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          "(+4 declared identities, line drift otherwise)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
