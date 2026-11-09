#!/usr/bin/env python3
"""PRODUCTION HARDENING window (v0.33.0) regeneration of
docs/direct_io_inventory.json.

Window: v0.33.0 hardening, 2026-11-01 (docs/PRODUCTION_HARDENING_PLAN_0330.md).

Scope of the window's I/O-relevant identity changes (verified by identity
diff of the recorded artifact vs the fresh AST scan):

  * REMOVED identity (net -2 records, 1 unique identity):
    - ``src/webpent/service/api.py`` dynamic_resolution ``getattr`` — the
      P2-02 fix replaced the always-False ``getattr(user, "is_admin", False)``
      checks with direct attribute reads, removing 2 of the file's 3
      getattr sites (the remaining one at line 46 stays).
  * ADDED identity (net +1 record, 1 unique identity):
    - ``src/webpent/llm_researcher/providers/pool.py`` dynamic_resolution
      ``getattr`` — the F-02 honest-failure branch reads
      ``getattr(response, "error", None)`` so an error-carrying LLMResponse
      is no longer recorded as slot success.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. removed identities must be EXACTLY the declared P2-02 set;
  2. added identities must be EXACTLY the declared F-02 set;
  3. no raw-transport site may be added;
  4. the unapproved-site pin is unchanged;
  5. every non-records artifact section is preserved; coverage and
     generated_from recomputed; a regen_history entry appended.
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

#: Identity-level removals of this window — NONE (the P2-02 change
#: removed 2 of service/api.py's 3 dynamic_resolution getattr RECORDS
#: but the identity (file, kind, symbol) survives with 1 remaining site,
#: so at identity granularity nothing was removed).
DECLARED_REMOVED_IDENTITIES: set[tuple[str, str, str]] = set()

#: Record-level deltas declared for this window, keyed by
#: (file, kind): (records_before, records_after). P2-02 rewrote the
#: service/api.py admin/owner checks (the always-False
#: ``getattr(user, "is_admin", False)`` probes) into direct attribute
#: reads: the artifact's 4 dynamic_resolution getattr records for that
#: file are now 2 (username/sub fallback + is_global_admin/role check).
DECLARED_RECORD_DELTAS: dict[tuple[str, str], tuple[int, int]] = {
    ("src/webpent/service/api.py", "dynamic_resolution"): (4, 2),
    ("src/webpent/llm_researcher/providers/pool.py", "dynamic_resolution"): (0, 1),
}

#: Exactly the declared addition of this window (F-02: pool.py honest
#: failure branch reads getattr(response, "error", None)).
DECLARED_ADDED_IDENTITIES: set[tuple[str, str, str]] = {
    (
        "src/webpent/llm_researcher/providers/pool.py",
        "dynamic_resolution",
        "getattr(response, ... )",  # normalized form: getattr(response, "error", None)
    ),
}

WINDOW = "PRODUCTION HARDENING 2026-11-01 (v0.33.0)"
REGEN_REASON = (
    "deliberate regen for the 0.33.0 hardening window "
    "(docs/PRODUCTION_HARDENING_PLAN_0330.md): P2-02 removed 2 of the 3 "
    "dynamic_resolution getattr records in service/api.py (is_admin checks "
    "replaced with direct attribute reads); F-02 added 1 dynamic_resolution "
    "getattr record in llm_researcher/providers/pool.py (honest-failure "
    "branch reads LLMResponse.error). Net -1 record (815 -> 814). All other "
    "diffs are pure line-number shifts from fix annotations; zero new "
    "raw-transport sites, unapproved pin unchanged."
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
    # Idempotent re-runs: a declared removal that is already absent from
    # the artifact (applied by an earlier pass of this same window script)
    # is satisfied — only a declared removal still present in the artifact
    # must actually disappear in the fresh scan.
    still_in_artifact = {
        ident for ident in DECLARED_REMOVED_IDENTITIES - removed
        if ident in recorded_ids
    }
    if still_in_artifact:
        print(f"ABORT: declared removal(s) did not occur: {still_in_artifact}")
        return 1

    # Record-level deltas must match the declaration exactly.
    def _pair_counts(records: list[dict]) -> Counter:
        return Counter((r["file"], r["kind"]) for r in records)

    before_pairs = _pair_counts(recorded)
    after_pairs = _pair_counts(fresh)
    all_pairs = set(before_pairs) | set(after_pairs)
    for pair in sorted(all_pairs):
        before_n = before_pairs.get(pair, 0)
        after_n = after_pairs.get(pair, 0)
        if before_n == after_n:
            continue
        declared = DECLARED_RECORD_DELTAS.get(pair)
        # Idempotent re-run: the artifact may already carry the "after"
        # count (applied by an earlier pass) — accept (after, after) too.
        if declared != (before_n, after_n) and declared != (after_n, after_n):
            print(
                f"ABORT: undeclared record-count delta for {pair}: "
                f"{before_n} -> {after_n} (declared: {declared})"
            )
            return 1
    print("  declared record deltas accepted:", {
        f"{k[0]}[{k[1]}]": f"{v[0]}->{v[1]}" for k, v in DECLARED_RECORD_DELTAS.items()
    })

    bad_added = added - DECLARED_ADDED_IDENTITIES
    if bad_added:
        print(f"ABORT: {len(bad_added)} undeclared ADDED identity/ies:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1
    # Idempotent re-run: a declared addition already present in the
    # artifact (applied by an earlier pass) just needs to persist in the
    # fresh scan.
    declared_added_missing_from_fresh = {
        ident for ident in DECLARED_ADDED_IDENTITIES if ident not in fresh_ids
    }
    if declared_added_missing_from_fresh:
        print(
            f"ABORT: declared addition(s) absent from the fresh scan: "
            f"{declared_added_missing_from_fresh}"
        )
        return 1

    print(
        f"  declared removals accepted: {len(removed)} identity(ies); "
        f"declared additions accepted: {len(added)} identity(ies)"
    )

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

    # The unapproved-site pin must be unchanged in identity terms.
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

    # Preserve every non-records section; recompute records + coverage.
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
