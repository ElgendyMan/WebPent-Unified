#!/usr/bin/env python3
"""r5-CODE identity-ladder window regeneration of docs/direct_io_inventory.json.

Window: r5-CODE "General Autonomous Identity Resolution Ladder"
(owner directive: runner must resolve identity on ANY target autonomously).

Scope of the window (documented in DRIFT_REGISTER.md r5 entry):
  src/webpent/recon/identity_discovery.py        (strategy ladder S1-S4)
  src/webpent/recon/principal_provisioning.py    (artifact wiring + transport boundary)
  src/webpent/recon/login_executor.py            (bounded login-response retention)
  src/webpent/agents/hunter_runner.py            (crawl_routes provisioning wiring)

Inventory impact: the S3 transport-retry path and the S1 owner-baseline
template-verification path add two NEW getattr(response, ... ) dynamic-resolution
INSTANCES inside recon/identity_discovery.py.  The UNIQUE identity set is
unchanged (no added identity, no removed identity, no raw-transport site) —
only the per-instance count of an already-recorded identity grows by 2.

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. removed unique identities MUST be empty;
  2. added unique identities MUST be empty (duplicate instances only);
  3. every new instance MUST be kind=dynamic_resolution, symbol=getattr,
     non_transport, in the scoped file set above;
  4. no import/httpx/raw-transport record may be added (unapproved-site pin
     is unchanged);
  5. every non-records artifact section is preserved verbatim; coverage and
     generated_from are recomputed; a regen_history entry is appended.
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

SCOPED_FILES = {
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/agents/hunter_runner.py",
}

WINDOW = "r5-CODE identity resolution ladder"
REGEN_REASON = (
    "deliberate regen for the r5-CODE window (DR-009 protocol): the S3 "
    "transport-retry path and the S1 owner-baseline verification path in "
    "recon/identity_discovery.py add 2 getattr(response, ... ) "
    "dynamic-resolution instances. Unique identity set unchanged; no raw "
    "transport site added; the unapproved-site pin is unchanged."
)


def _identity(record: dict) -> tuple[str, str, str]:
    return (record["file"], record["kind"], record.get("normalized_symbol") or record.get("symbol", ""))


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text(encoding="utf-8"))
    recorded = artifact["records"]
    fresh = scan_direct_io(SRC)

    recorded_ids = [_identity(item) for item in recorded]
    fresh_ids = [_identity(item) for item in fresh]

    removed = sorted(set(recorded_ids) - set(fresh_ids))
    added = sorted(set(fresh_ids) - set(recorded_ids))
    if removed:
        print("REFUSE: removed unique identities:", removed)
        return 1
    if added:
        print("REFUSE: added unique identities (adjudication required):", added)
        return 1

    recorded_multiset = sorted(recorded_ids)
    fresh_multiset = sorted(fresh_ids)
    surviving = list(recorded_multiset)
    new_instances: list[tuple[str, str, str]] = []
    for identity in fresh_multiset:
        if identity in surviving:
            surviving.remove(identity)
        else:
            new_instances.append(identity)
    if surviving:
        print("REFUSE: unexplained removals (multiset):", surviving)
        return 1
    if not new_instances:
        print("NO-OP: no new instances; artifact already current")
        return 0

    fresh_by_identity: dict[tuple[str, str, str], list[dict]] = {}
    for record in fresh:
        fresh_by_identity.setdefault(_identity(record), []).append(record)
    for identity in new_instances:
        instances = fresh_by_identity.get(identity, [])
        for record in instances:
            if record["file"] not in SCOPED_FILES:
                print("REFUSE: new instance outside scoped files:", record["file"], identity)
                return 1
            if record["kind"] != "dynamic_resolution" or record.get("symbol") != "getattr":
                print("REFUSE: new instance is not a getattr dynamic-resolution:", record)
                return 1
            if record.get("transport_family") != "non_transport" or record.get("classification") != "dynamic_resolution":
                print("REFUSE: new instance is not a non_transport dynamic-resolution:", record)
                return 1

    # Gates passed — rewrite records from the fresh scan, preserve all other
    # sections verbatim, recompute derived counts, append history.
    artifact["records"] = json.loads(json.dumps(fresh))
    artifact["coverage"] = {
        "files_scanned": len({record["file"] for record in fresh}),
        "records": len(fresh),
    }
    artifact["generated_from"] = {
        "record_count": len(fresh),
        "regenerated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "regenerated_by": f"{WINDOW} deliberate regen (DR-009 protocol)",
        "scan_root": "src",
    }
    artifact.setdefault("regen_history", []).append({
        "at": artifact["generated_from"]["regenerated_at"],
        "delta": f"+{len(new_instances)} duplicate instances ({len(recorded)} -> {len(fresh)}), 0 unique added, 0 removed",
        "reason": REGEN_REASON,
        "unit": WINDOW,
    })
    ARTIFACT.write_text(json.dumps(artifact, indent=1, sort_keys=False) + "\n", encoding="utf-8")
    print(f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} records); all gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
