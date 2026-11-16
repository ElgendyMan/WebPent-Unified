#!/usr/bin/env python3
"""UM-DR-38 Phase 6 — the BUILD_INFO re-baseline.

Derives EVERY current claim from machine evidence (§10: never a
hand-typed count, never a copy from an old report):

* suite_count and provenance.test_accounting come from the CURRENT
  full-suite evidence (.webpent-evidence/FULL_SUITE_EVIDENCE.json);
* source_revision / current_release.source_revision come from git HEAD;
* release_history entries are pre-0.40.1 releases with RESOLVABLE
  revisions or explicit unverifiable-lineage notes;
* the stale current claims (suite_evidence_provenance 9178/9160/7 @
  51dfb44, the top-level 0.39.0 current_release block) are removed as
  CURRENT claims; historical narrative blocks stay, labeled as history.

The re-baseline is committed as a single commit touching ONLY
BUILD_INFO.json (the protocol the honesty gate enforces).
"""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
EVIDENCE = REPO / ".webpent-evidence" / "FULL_SUITE_EVIDENCE.json"
BUILD_INFO = REPO / "BUILD_INFO.json"


def main() -> int:
    if not EVIDENCE.is_file():
        print("FAIL: no current full-suite evidence — run "
              "scripts/run_tests_with_evidence.py first", file=sys.stderr)
        return 1
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    if record.get("exit_code") != 0:
        print(f"FAIL: the current evidence records exit_code="
              f"{record.get('exit_code')} — a failed run never "
              "re-baselines BUILD_INFO", file=sys.stderr)
        return 1
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
        text=True, check=False).stdout.strip()
    evidence_commit = record.get("source_commit")
    # the honest invariant: the evidence belongs to an ANCESTOR of HEAD
    # and nothing under src/ or tests/ changed after it (protocol
    # commits — BUILD_INFO re-baseline, verification-tool contracts,
    # generated deliverables — are the only allowed post-evidence
    # changes; the tested SOURCE is exactly what the evidence tested)
    is_ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", evidence_commit, head],
        cwd=REPO, capture_output=True).returncode == 0
    src_tests_changes = subprocess.run(
        ["git", "diff", "--name-only", evidence_commit, head,
         "--", "src/", "tests/"],
        cwd=REPO, capture_output=True, text=True).stdout.strip()
    if not is_ancestor or src_tests_changes:
        print(f"FAIL: evidence commit {evidence_commit} is not a valid "
              f"ancestor of HEAD {head} with unchanged src/tests "
              f"(changes: {src_tests_changes}) — re-baseline requires "
              "evidence for exactly the tested source", file=sys.stderr)
        return 1

    info = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
    accounting = dict(record["accounting"])
    accounting.pop("accounting_consistent", None)
    accounting.pop("summary_found", None)

    info["build_date"] = datetime.now(timezone.utc).isoformat()
    info["package_version"] = "0.40.1"
    info["suite_count"] = record["accounting"]["executed"]
    info["suite_evidence"] = (
        "current-release accounting: the full-suite v3 evidence run at "
        "commit " + head[:12] + " (machine record .webpent-evidence/"
        "FULL_SUITE_EVIDENCE.json, uploaded as the CI workflow "
        "artifact) — collected "
        f"{record['accounting']['collected']}, executed "
        f"{record['accounting']['executed']}, passed "
        f"{record['accounting']['passed']}, failed "
        f"{record['accounting']['failed']}, errors "
        f"{record['accounting']['errors']}; provenance block carries "
        "the identical counts")
    info["provenance"] = {
        "source_revision": head,
        "tested_revision": record.get("source_commit"),
        "evidence_revision": record.get("source_commit"),
        "recovery_baseline": subprocess.run(
            ["git", "rev-parse", "1968f63^{commit}"], cwd=REPO,
            capture_output=True, text=True,
            check=False).stdout.strip(),
        "package_version": "0.40.1",
        "manifest_digest": subprocess.run(
            ["python3", "-c",
             "import hashlib;print(hashlib.sha256(open("
             "'frozen_modules.sha256','rb').read()).hexdigest())"],
            cwd=REPO, capture_output=True, text=True,
            check=False).stdout.strip(),
        "build_date": info["build_date"],
        "publication": {"published": False, "release_tag": None,
                        "note": "remote publication BLOCKED_EXTERNAL_"
                                "DEPENDENCY (no push credentials); the "
                                "closure branch + bundle carry the "
                                "release"},
        "test_accounting": accounting,
        "evidence": {
            "runner": "scripts/run_tests_with_evidence.py",
            "record": ".webpent-evidence/FULL_SUITE_EVIDENCE.json",
            "schema": record.get("schema"),
            "tree_clean_at_test_start": record.get("tree_clean"),
            "lockfile_sha256": record.get("lockfile_sha256"),
            "coverage_percent": (record.get("coverage") or {}).get(
                "percent_covered"),
        },
        "note": "UM-DR-38 §10: every number here is derived from the "
                "current evidence record at generation time — never "
                "typed, never copied from an older report",
    }
    info["fixes_applied"] = [
        "umdr38-evidence-output-contract (.webpent-evidence/)",
        "umdr38-checker-provenance-freshness (§6.3)",
        "umdr38-workflows-to-repository-root (§5)",
        "umdr38-root-readme (§5.1)",
        "umdr38-campaign-instrumentation-reversible (§7.2.A)",
        "umdr38-authoritative-final-graph-state (§7.2.B)",
        "umdr38-campaign-cleanup-and-redaction (§7.2.E/F)",
        "umdr38-lab-version-ssot (Phase 5)",
        "umdr38-report-generators-fail-closed (§9.1)",
        "umdr38-buildinfo-historical-separation (Phase 6)",
        "umdr38-soupsieve-security-upgrade (4 CVEs, 2.9.2->4.1.1)",
        "umdr38-coverage-ratchet-env-fix (uv run make)",
        "umdr38-durable-evidence-publication (§7.1)",
    ]
    info["units_closed"] = sorted(set(
        info.get("units_closed", [])
        + ["UM-DR-36.1", "UM-DR-36.2", "UM-DR-37", "UM-DR-38"]))

    contract = info.get("version_identity_contract") or {}
    contract["package_version"] = "0.40.1"
    contract["current_release"] = {
        "package_version": "0.40.1",
        "window": "0.40.1 release line: UM-DR-35/36 corrective closure, "
                  "UM-DR-36.1 recovery, UM-DR-36.2/37 root-cause + "
                  "production campaigns, UM-DR-38 publication integrity "
                  "& release closure",
        "source_revision": head,
        "python_floor": ">=3.11 (pyproject.toml)",
        "python_tested": record.get("python_version"),
        "provenance_note": "UM-DR-38 §10 reconciliation: current "
                           "release identity is this revision; the "
                           "0.40.1 mission windows are documented in "
                           "the window field, historical entries live "
                           "in release_history below",
    }
    contract["release_history"] = [
        {"package_version": "0.38.0",
         "window": "UM-DR-32 identity & business-logic evolution",
         "source_revision": subprocess.run(
             ["git", "rev-parse", "989c49b^{commit}"], cwd=REPO,
             capture_output=True, text=True,
             check=False).stdout.strip(),
         "note": "public main publish (Update to v0.38.0 UMDR32)"},
        {"package_version": "0.39.0",
         "window": "UM-DR-33 researcher brain & autonomous campaigns",
         "source_revision": "4795f02377373a1a2dc4d3376987f7702cd24bf6",
         "note": "features/v0.39.0-umdr33 feature branch (never merged "
                 "to main)"},
        {"package_version": "0.40.0",
         "window": "UM-DR-34 scope authority, safe egress & execution "
                   "governance",
         "source_revision": None,
         "source_revision_note": "local lineage of the "
                                 "security/umdr34-origin-scope-hardening "
                                 "branch; no single published 0.40.0 "
                                 "commit on main — recorded as "
                                 "explicitly-unverifiable local lineage"},
    ]
    info["version_identity_contract"] = contract

    # the STALE current claims are removed (historical narrative blocks
    # above stay, clearly labeled as history)
    info.pop("current_release", None)
    info.pop("suite_evidence_provenance", None)
    info.pop("suite_count_note", None)

    BUILD_INFO.write_text(json.dumps(info, indent=1, default=str) + "\n",
                          encoding="utf-8")
    print(f"[re-baseline] suite_count = "
          f"{record['accounting']['executed']} (derived from evidence "
          f"at {head[:12]})")
    print(f"[re-baseline] {BUILD_INFO}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
