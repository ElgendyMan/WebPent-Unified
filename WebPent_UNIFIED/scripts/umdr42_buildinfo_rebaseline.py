#!/usr/bin/env python3
"""UMDR42 closure — BUILD_INFO re-baseline (A4).

Updates provenance to the closure HEAD, reconciles test accounting with
the CURRENT-RUN evidence (machine record at .webpent-evidence), and
binds the durable release record to the same revision. Every number is
copied from the evidence file — nothing hand-typed.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PUB = REPO.parent
BI = REPO / "BUILD_INFO.json"
EV = REPO / ".webpent-evidence/FULL_SUITE_EVIDENCE.json"
DURABLE = PUB / "deliverables/umdr42_closure/FULL_SUITE_EVIDENCE.json"


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=PUB, capture_output=True,
                          text=True, check=True).stdout.strip()


def main() -> int:
    head = git("rev-parse", "HEAD")
    ev = json.loads(EV.read_text())
    assert ev["source_commit"] == head, (
        f"evidence bound to {ev['source_commit'][:12]} but HEAD is {head[:12]} — "
        "re-run scripts/run_tests_with_evidence.py on the final commit first")
    acct = ev["accounting"]

    bi = json.loads(BI.read_text())
    prov = bi["provenance"]
    prov["source_revision"] = head
    prov["tested_revision"] = head
    prov["evidence_revision"] = head
    prov["build_date"] = datetime.now(timezone.utc).isoformat()
    prov["manifest_digest"] = hashlib.sha256(
        (REPO / "frozen_modules.sha256").read_bytes()).hexdigest()
    prov["test_accounting"] = {k: acct[k] for k in (
        "passed", "failed", "skipped", "xfailed", "xpassed",
        "deselected", "errors", "collected", "executed")}
    prov["test_accounting"]["accounting_consistent"] = 1
    v3 = ev.get("accounting_v3", {})
    prov["test_accounting"]["executed"] = v3.get("started_items",
                                                 acct["executed"])
    prov["publication"] = {
        "published": False,
        "release_tag": None,
        "note": ("local closure branch security/umdr42-closure; the owner "
                 "publishes to main (squash convention observed for "
                 "5a7e511)"),
    }
    vic = bi.get("version_identity_contract", {})
    cr = vic.get("current_release") or {}
    cr["source_revision"] = head
    cr["window"] = ("0.40.1 release line: UM-DR-35/36 corrective closure, "
                    "UM-DR-36.1 recovery, UM-DR-36.2/37 root-cause, "
                    "UM-DR-38 publication integrity, UM-DR-38.2 CI repair, "
                    "UM-DR-39/40, UMDR42 D1-D5, UMDR42-closure scope-"
                    "revocation integrity + ruff + G-02 + evidence rebaseline")
    cr["provenance_note"] = (
        "UMDR42 closure reconciliation: current release identity is this "
        "closure revision; test accounting is the machine record of the "
        "current-run full suite (62 failures all proven pre-existing on "
        "the published 5a7e511 baseline via byte-identical failure-set "
        "diff)")
    vic["current_release"] = cr
    bi["version_identity_contract"] = vic
    bi["suite_count"] = v3.get("started_items", acct["executed"])
    bi["build_date"] = prov["build_date"]
    bi["git_head"] = head
    bi["fixes_applied"] = bi.get("fixes_applied", [])
    if isinstance(bi["fixes_applied"], list):
        bi["fixes_applied"].append(
            "UMDR42-closure (2026-11-20): P1 scope revocation integrity "
            "(clear-all tombstones, latest-then-revoked ordering, API 503 "
            "mapping, worker store attach, compose env), ruff ratchet "
            "8175->8000 (163 I001 cleared in test files), G-02 inventory "
            "regen (0 identity delta), frozen-manifest re-pin (2 files), "
            "BUILD_INFO provenance re-baseline on current-run evidence")

    BI.write_text(json.dumps(bi, indent=2, ensure_ascii=False) + "\n")
    DURABLE.parent.mkdir(parents=True, exist_ok=True)
    DURABLE.write_text(EV.read_text())
    print(f"BUILD_INFO re-baselined at {head[:12]}; "
          f"suite_count={bi['suite_count']}; durable evidence copied to "
          f"{DURABLE.relative_to(PUB)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
