#!/usr/bin/env python3
"""UM-DR-36.2/37 regeneration of docs/direct_io_inventory.json.

Window: the UM-DR-36.2 recovery-integrity closure + the UM-DR-37
zero-findings root-cause closure + the verification-round decoy
closure. Declared delta versus the pre-window artifact (1202 records):

  ADDED unique identities (6, all dynamic_resolution getattr sites,
  all inside deliberately-touched window modules):
    1. cli/unified_hunt.py — getattr(f, ...)/getattr(v, ...): the
       findings_detail dict-bundle projection repair (UM-DR-37 RC-3);
    2. families/promotion.py — getattr(bundle, ...)/
       getattr(verification, ...): the UM-DR-36.1 authority rewrite;
    3. research/lifecycle_view.py — getattr(hypothesis, ...)/
       getattr(status, ...): the UM-DR-37 unified lifecycle VIEW.
  REMOVED identities: NONE. New raw-transport / not-approved sites:
  NONE. The unapproved pin set is byte-identical.

Gates (fail-closed, nothing written unless ALL pass):
  1. NO removed unique identities;
  2. no UNDECLARED new identities; declared identities must exist
     somewhere (fresh, or already absorbed into the recorded artifact
     — the script is idempotent and may be re-run for line drift);
  3. NO new raw-transport / not-approved sites;
  4. the unapproved pin is preserved;
  5. non-records sections preserved; coverage/generated_at recomputed;
     a regen_history entry appended.
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

WINDOW = ("UM-DR-36.2/37 RECOVERY + ROOT-CAUSE + DECOY CLOSURE WINDOW "
          "2026-11-16")
REGEN_REASON = (
    "deliberate regen for the UM-DR-36.2/37 closure windows: the "
    "version-identity and evidence-integrity closure (36.2), the four "
    "zero-findings root-cause fixes (37), and the decoy/out-of-scope "
    "lab closure add EXACTLY six declared dynamic-resolution "
    "identities (all getattr defensive reads, listed in the script). "
    "Zero removals; zero new raw-transport or not-approved sites; the "
    "unapproved pin set is unchanged; line drift only inside the "
    "touched modules."
)

DECLARED_ADDED: set[tuple[str, str, str]] = {
    ("src/webpent/cli/unified_hunt.py", "dynamic_resolution",
     "getattr(f, ... )"),
    ("src/webpent/cli/unified_hunt.py", "dynamic_resolution",
     "getattr(v, ... )"),
    ("src/webpent/families/promotion.py", "dynamic_resolution",
     "getattr(bundle, ... )"),
    ("src/webpent/families/promotion.py", "dynamic_resolution",
     "getattr(verification, ... )"),
    ("src/webpent/research/lifecycle_view.py", "dynamic_resolution",
     "getattr(hypothesis, ... )"),
    ("src/webpent/research/lifecycle_view.py", "dynamic_resolution",
     "getattr(status, ... )"),
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

    # Idempotent gate: re-running after the declared identities are
    # already absorbed (then `added` is empty; only line drift
    # refreshes) is fine. What always aborts: UNDECLARED new
    # identities, or declared identities that exist NOWHERE.
    undeclared = added - DECLARED_ADDED
    truly_missing = DECLARED_ADDED - added - recorded_ids
    if undeclared or truly_missing:
        print("ABORT: identity gate failed:")
        for item in sorted(undeclared)[:10]:
            print("  + undeclared:", item)
        for item in sorted(truly_missing)[:10]:
            print("  - declared but absent everywhere:", item)
        return 1

    newly_absorbed = len(added & DECLARED_ADDED)
    print(f"  declared deltas accepted: 0 removed / {newly_absorbed} "
          f"newly absorbed identit(ies) "
          f"({len(fresh) - len(recorded)} record delta)")

    raw_kinds = {"raw_transport"}
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") in raw_kinds
             or r.get("kind") in {"httpx", "socket"})
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
            r for r in recorded
            if r.get("approval_status") == "not_approved"
        ]
        if ({_identity(r) for r in fresh_unapproved}
                != {_identity(r) for r in recorded_unapproved}):
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
        "%Y-%m-%dT%H:%M:%SZ")
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

    ARTIFACT.write_text(
        json.dumps(new_artifact, indent=1) + "\n", encoding="utf-8")
    print(f"OK: direct_io_inventory.json regenerated — {len(fresh)} records "
          "(+6 declared identities, line drift otherwise)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
