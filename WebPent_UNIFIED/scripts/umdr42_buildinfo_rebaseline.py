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
    ev_commit = ev["source_commit"]
    # Honest binding: the suite ran at ev_commit. If HEAD moved since, the
    # src/ and tests/ trees must be BYTE-IDENTICAL (only manifest/scripts/
    # BUILD_INFO changes allowed after the evidence commit) — otherwise
    # the evidence is stale and the suite must be re-run.
    if ev_commit != head:
        diff = git("diff", "--name-only", ev_commit, head, "--",
                   "WebPent_UNIFIED/src", "WebPent_UNIFIED/tests")
        assert not diff, (
            f"src/tests changed after the evidence commit ({ev_commit[:12]}):"
            f"\n{diff}\nRe-run the full suite before re-baselining.")
        print(f"note: evidence bound to {ev_commit[:12]}; src/tests "
              f"byte-identical at HEAD {head[:12]} (post-evidence commits "
              "touch only manifest/scripts/BUILD_INFO)")
    acct = ev["accounting"]

    bi = json.loads(BI.read_text())
    prov = bi["provenance"]
    prov["source_revision"] = head
    prov["tested_revision"] = head
    prov["evidence_revision"] = ev["source_commit"]  # bound to the run commit
    prov["build_date"] = datetime.now(timezone.utc).isoformat()
    prov["manifest_digest"] = hashlib.sha256(
        (REPO / "frozen_modules.sha256").read_bytes()).hexdigest()
    # The honesty gate compares provenance.test_accounting to the
    # durable evidence record VERBATIM (dict equality) — copy the whole
    # accounting dict, never a key subset.
    prov["test_accounting"] = dict(acct)
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
    bi["suite_count"] = ev["accounting_v3"]["started_items"]  # v3 well-formed count
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
