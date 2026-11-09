#!/usr/bin/env python3
"""UM-DR-32 regeneration of docs/direct_io_inventory.json.

Window: the UM-DR-32 identity & business-logic evolution. The measured
delta versus the recorded artifact:

  ADDED identities (7, all dynamic_resolution getattr sites — dual-shape
  model/dict reads and fail-closed settings gates, the established
  identity classes):
    * src/webpent/production/composite_workflows.py (4):
        - getattr(... )            — the sequence-outcome evidence reads
        - getattr(causal, ... )    — the CausalGuard result fields
        - getattr(result, ... )    — the validator result fields
        - getattr(verdict, ... )   — the guard verdict enum/value read
      Every one is a dual-shape defensive read over injected/returned
      objects whose concrete type varies (pydantic model vs dataclass vs
      dict) — the same identity class as the UM-DR-31 pool-index reads.
    * src/webpent/production/identity_workflow.py (3):
        - getattr(h, ... ) / getattr(hypothesis, ... ) — the hypothesis
          pool dual-shape reads (pydantic Hypothesis vs checkpoint dict)
        - getattr(settings, ... )  — the fail-closed bounded-limits read
          (the coverage_gap_report double-gate precedent).
  REMOVED identities: NONE.

No new transport sites of any kind: the new modules are pure
computation; ALL network I/O happens through injected clients (the
StatefulCaseProber contract) inside the authorized executor layer.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities;
  2. added identities EXACTLY match the seven declared above;
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

WINDOW = "UM-DR-32 IDENTITY & BUSINESS-LOGIC EVOLUTION WINDOW 2026-11-09"
REGEN_REASON = (
    "deliberate regen for the UM-DR-32 window: SEVEN added "
    "dynamic_resolution identities (four dual-shape result reads in "
    "production/composite_workflows.py — the CausalGuard/validator/"
    "verdict/outcome fields over returned objects whose concrete type "
    "varies — and three in production/identity_workflow.py — the "
    "hypothesis-pool dual-shape reads and the fail-closed bounded-"
    "limits settings gate, the established identity classes), ZERO "
    "removed. No new transport sites: the four new capability modules "
    "are pure computation; every request flows through injected "
    "clients inside the authorized executor layer."
)

DECLARED_ADDITIONS = {
    ("src/webpent/production/composite_workflows.py", "dynamic_resolution", "getattr(... )"),
    ("src/webpent/production/composite_workflows.py", "dynamic_resolution", "getattr(causal, ... )"),
    ("src/webpent/production/composite_workflows.py", "dynamic_resolution", "getattr(result, ... )"),
    ("src/webpent/production/composite_workflows.py", "dynamic_resolution", "getattr(verdict, ... )"),
    ("src/webpent/production/identity_workflow.py", "dynamic_resolution", "getattr(h, ... )"),
    ("src/webpent/production/identity_workflow.py", "dynamic_resolution", "getattr(hypothesis, ... )"),
    ("src/webpent/production/identity_workflow.py", "dynamic_resolution", "getattr(settings, ... )"),
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
    if added != DECLARED_ADDITIONS:
        print(f"ABORT: added identities do not match the declared set "
              f"({len(added)} vs {len(DECLARED_ADDITIONS)}):")
        for item in sorted(added ^ DECLARED_ADDITIONS)[:10]:
            print("  ?", item)
        return 1

    print(f"  declared deltas accepted: 0 removed / {len(added)} added "
          f"identit(ies) (all dynamic_resolution)")

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
        if ({_identity(r) for r in fresh_unapproved}
                != {_identity(r) for r in recorded_unapproved}):
            print("ABORT: the unapproved-site pin set changed")
            return 1
        print("  unapproved-site pin set preserved")

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
        "identities_added": len(added),
        "identities_removed": 0,
    })
    new_artifact["regen_history"] = history

    ARTIFACT.write_text(json.dumps(new_artifact, indent=1) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          f"(+{len(added)} declared dynamic-resolution identities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
