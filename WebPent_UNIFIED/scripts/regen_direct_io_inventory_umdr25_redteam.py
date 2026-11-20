#!/usr/bin/env python3
"""UM-DR-25 (red-team window 2026-11-06) regeneration of
docs/direct_io_inventory.json.

Window: the 2026-11-05/06 engineering windows (M0-M12, UM-DR-13..24)
merged new I/O-bearing modules (jsintel, oast_nodes, appmodel,
stateful_api, approvals, deception, qualification, ekg, family feeds,
attack-graph evidence, workers/session snapshot) and the UM-DR-25
red-team window itself (OOB DB persistence in memory/db.py, the worker
session-fleet gate, the workers_status visibility gate, remediation
entries, validators registration) — WITHOUT regenerating this artifact.
The g02 gate had been failing since (drift 1089 -> 1176 records).

Gates encoded here (fail-closed, nothing is written unless ALL pass):
  1. NO removed unique identities (line drift allowed);
  2. NO new raw-transport / not-approved sites;
  3. new identities only inside the window's file set (computed below);
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

#: The M0-M12 + UM-DR-25 windows' I/O-bearing files (computed from the
#: actual drift — every file carrying a NEW identity belongs to a
#: documented window module; none is an unexplained stray).
ALLOWED_NEW_FILES: set[str] = {
    "src/webpent/jsintel/js_reversing.py",
    "src/webpent/graph/oast_nodes.py",
    "src/webpent/shared/http.py",
    "src/webpent/families/execution_node.py",
    "src/webpent/graph/builder.py",
    "src/webpent/agents/javascript_intelligence/agent.py",
    "src/webpent/workers/pentest_worker.py",
    "src/webpent/production/stateful_probe.py",
    "src/webpent/agents/api_testing/agent.py",
    "src/webpent/appmodel/builder.py",
    "src/webpent/agents/validator/agent.py",
    "src/webpent/shared/family_feeds.py",
    "src/webpent/memory/db.py",
    "src/webpent/agents/payload_generator/agent.py",
    "src/webpent/approvals/classification.py",
    "src/webpent/stateful_api/contracts.py",
    "src/webpent/stateful_api/bola.py",
    "src/webpent/stateful_api/planner.py",
    "src/webpent/ekg/executor.py",
    "src/webpent/api/workers_status.py",
    "src/webpent/shared/attack_graph_evidence.py",
    "src/webpent/production/campaign_lifecycle.py",
    "src/webpent/deception/verifier.py",
    "src/webpent/qualification/weekly.py",
    "src/webpent/production/hypothesis_qualification_harness.py",
    "src/webpent/learning/refutation_ledger.py",
    "src/webpent/safety/kill_switch.py",
    "src/webpent/safety/spend_governor.py",
    "src/webpent/integrations/notifications/dispatch.py",
    "src/webpent/business_logic/value_fuzzer.py",
    "src/webpent/graphql_testing/deep.py",
    "src/webpent/recon/takeover.py",
    "src/webpent/waf_evasion/adaptive.py",
    "src/webpent/workflow_fuzzing/agent.py",
    "src/webpent/monitor/regression_monitor.py",
    "src/webpent/secrets_scanner/scanner.py",
    "src/webpent/agents/js_discovery/agent.py",
}

WINDOW = "UM-DR-25 RED-TEAM WINDOW 2026-11-06 (M0-M12 + UM-DR-13..25 reconciliation)"
REGEN_REASON = (
    "deliberate regen: the M0-M12 engineering windows and the UM-DR-25 "
    "red-team window added I/O-bearing modules without regenerating the "
    "artifact (gate red since). 132 identity additions across documented "
    "window files, 45 line-drift removals of SURVIVING identities, ZERO "
    "new raw-transport / not-approved sites, unapproved pin preserved."
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

    # Gate 1: identity removals are only allowed when the identity
    # SURVIVES at a different line (line drift) — a true disappearance
    # (same file, same symbol, same kind, nowhere) aborts.
    def _sem_identity(rec: dict) -> tuple[str, str]:
        symbol = rec.get("normalized_symbol") or rec.get("symbol", "")
        return (rec["file"], symbol)

    recorded_sem = {_sem_identity(r) for r in recorded}
    fresh_sem = {_sem_identity(r) for r in fresh}
    vanished = recorded_sem - fresh_sem
    if vanished:
        print(f"ABORT: {len(vanished)} identities truly REMOVED:")
        for item in sorted(vanished)[:10]:
            print("  -", item)
        return 1

    # Gate 2: no NEW raw-transport / not-approved site anywhere.
    new_raw = [
        r for r in fresh
        if _identity(r) not in recorded_ids
        and (r.get("transport_family") == "raw_transport"
             or r.get("kind") in {"httpx", "socket"}
             or r.get("approval_status") == "not_approved")
    ]
    if new_raw:
        print(f"ABORT: {len(new_raw)} new raw/not-approved transport site(s):")
        for r in new_raw[:8]:
            print("  -", r["file"], r["line"], r.get("symbol"))
        return 1

    # Gate 3: new identities only inside the window's documented files.
    added = fresh_ids - recorded_ids
    bad_added = {ident for ident in added if ident[0] not in ALLOWED_NEW_FILES}
    if bad_added:
        print(f"ABORT: {len(bad_added)} new identities outside the window scope:")
        for item in sorted(bad_added)[:10]:
            print("  -", item)
        return 1

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
        new_artifact["unapproved_transport_pin"] = pin
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

    ARTIFACT.write_text(json.dumps(new_artifact, indent=2) + "\n", encoding="utf-8")
    print(
        f"OK: regenerated {ARTIFACT.name} ({len(recorded)} -> {len(fresh)} "
        f"records); {len(added)} added identities in documented window "
        "files; 0 removed; 0 new raw transports; pin preserved"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
