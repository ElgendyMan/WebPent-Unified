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
    provenance_only = "--provenance-only" in sys.argv
    if not EVIDENCE.is_file():
        print("FAIL: no current full-suite evidence — run "
              "scripts/run_tests_with_evidence.py first", file=sys.stderr)
        return 1
    record = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    if provenance_only:
        # UM-DR-38.2 §1.4 — break the provenance catch-22 HONESTLY: the
        # suite cannot go green while provenance points at commits that
        # resolve nowhere (the resolvability test is part of the suite),
        # and the full re-baseline refuses red evidence. A
        # provenance-only re-baseline re-points the revisions at the
        # CURRENT, resolvable HEAD and touches NOTHING else — the
        # accounting stays the previous release's values until the
        # green run lands and the full re-baseline derives it from
        # machine evidence. Guard: only permitted while the declared
        # revisions are actually unresolvable (this is a recovery, not
        # a way to point provenance anywhere).
        import re as _re
        info_probe = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
        prov_probe = info_probe.get("provenance") or {}
        _hex40 = _re.compile(r"^[0-9a-f]{40}$")
        claimed = [str(prov_probe.get(k, "")) for k in
                   ("source_revision", "tested_revision",
                    "evidence_revision")]
        resolvable = []
        for sha in claimed:
            if _hex40.match(sha):
                r = subprocess.run(
                    ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
                    cwd=REPO, capture_output=True)
                resolvable.append(r.returncode == 0)
            else:
                resolvable.append(False)
        if all(resolvable):
            print("FAIL: provenance-only re-baseline requires the "
                  "declared revisions to be UNRESOLVABLE — they all "
                  "resolve; use the full re-baseline", file=sys.stderr)
            return 1
        if record.get("exit_code") != 0:
            print("NOTE: provenance-only mode proceeds with a red "
                  "current run — accounting is NOT re-derived (the "
                  "full re-baseline after the green run owns it)",
                  file=sys.stderr)
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
            text=True, check=False).stdout.strip()
        info = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
        prov = info["provenance"]
        prov["source_revision"] = head
        prov["tested_revision"] = head
        prov["evidence_revision"] = head
        contract = info["version_identity_contract"]
        contract["current_release"]["source_revision"] = head
        contract["current_release"]["provenance_note"] = (
            "UM-DR-38.2 §1.4 provenance recovery: the previously "
            "declared revisions (" + ", ".join(
                s[:12] for s in claimed) + ") were authored in a build "
            "environment that was never pushed and no longer exists; "
            "they are recorded as intentionally-unverifiable "
            "historical local lineage, never fabricated. The current "
            "release identity is this resolvable revision; the "
            "accounting is re-derived by the full re-baseline after "
            "the green suite.")
        info["fixes_applied"] = [
            "umdr38-2-provenance-recovery (unresolvable revisions "
            "declared + re-pointed at the reachable lineage)"
        ] + list(info.get("fixes_applied") or [])
        BUILD_INFO.write_text(
            json.dumps(info, indent=1, default=str) + "\n",
            encoding="utf-8")
        print(f"[provenance-only re-baseline] source/tested/evidence "
              f"-> {head[:12]} (resolvable)")
        print(f"[provenance-only re-baseline] {BUILD_INFO} — commit "
              "this as 'BUILD_INFO re-baseline (...)' touching ONLY "
              "BUILD_INFO.json")
        return 0
    if record.get("exit_code") != 0:
        print(f"FAIL: the current evidence records exit_code="
              f"{record.get('exit_code')} — a failed run never "
              "re-baselines BUILD_INFO", file=sys.stderr)
        return 1
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True,
        text=True, check=False).stdout.strip()
    # UM-DR-38.2: the freshness contract is owned by the GATE itself
    # (scripts/check_test_evidence.py — commit binding, lockfile digest,
    # the NARROW metadata-ancestor policy). The re-baseline pre-validates
    # through the actual gate so there is exactly ONE policy source; a
    # stale/invalid evidence run can never re-baseline BUILD_INFO.
    gate = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "check_test_evidence.py")],
        cwd=REPO, capture_output=True, text=True)
    if gate.returncode != 0:
        print("FAIL: the current evidence does not pass "
              "check_test_evidence.py — a stale or invalid run never "
              f"re-baselines BUILD_INFO:\n{gate.stdout}", file=sys.stderr)
        return 1

    info = json.loads(BUILD_INFO.read_text(encoding="utf-8"))
    # the FULL accounting dict, verbatim: the honesty gate compares
    # the committed evidence record's accounting against
    # provenance.test_accounting with strict equality
    accounting = dict(record["accounting"])

    info["build_date"] = datetime.now(timezone.utc).isoformat()
    info["package_version"] = "0.40.1"
    v3_block = record.get("accounting_v3") or {}
    # the WELL-FORMED executed count: the v2 "executed" conflates item
    # outcomes with collection-phase reports (the runner's contract);
    # suite_count must satisfy BOTH the honesty rule and the release
    # gate's suite_count <= collected
    info["suite_count"] = (
        int(v3_block["started_items"])
        if v3_block.get("started_items") is not None
        else record["accounting"]["executed"])
    info["suite_evidence"] = (
        "current-release accounting (UM-DR-38.2 drift-register "
        "window; see DRIFT_REGISTER.md): the full-suite v3 evidence "
        "run at commit " + str(record.get("source_commit"))[:12]
        + " — collected "
        f"{record['accounting']['collected']}, well-formed executed "
        f"{info['suite_count']}, passed "
        f"{record['accounting']['passed']}, failed "
        f"{record['accounting']['failed']}, errors "
        f"{record['accounting']['errors']}. DURABLE release evidence: "
        "deliverables/umdr38/test_evidence/ (tracked; validated by "
        "check_build_info_honesty.py); current-run evidence: "
        ".webpent-evidence/ (ignored; validated by "
        "check_test_evidence.py against the workflow run id/attempt)")
    info["provenance"] = {
        "schema": "umdr36-1-provenance-v1",
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
            "current_run_record": ".webpent-evidence/"
                                  "FULL_SUITE_EVIDENCE.json",
            "durable_release_record": "deliverables/umdr38/test_evidence/"
                                      "FULL_SUITE_EVIDENCE.json",
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
        "umdr38-2-evidence-domain-separation (durable release vs "
        "current CI run)",
        "umdr38-2-ci-checkout-full-history-and-gate-order",
        "umdr38-2-narrow-evidence-freshness-allowlist",
        "umdr38-2-campaign-classification-honesty (raw classes + "
        "fixture-backed differential, no blanket IDOR claim)",
        "umdr38-2-zip-fatal-extras-conflicts-and-full-member-validation",
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
                  "production campaigns, UM-DR-38 publication integrity, "
                  "UM-DR-38.2 CI & release-integrity repair",
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

    # UM-DR-38.2 §1.2: refresh the DURABLE RELEASE EVIDENCE copy from
    # the same machine record, so the tracked deliverables copy is
    # byte-identical to the run the re-baseline derives from (the
    # honesty gate then validates BUILD_INFO against this copy)
    durable_dir = (REPO.parent / "deliverables" / "umdr38" / "test_evidence"
                   if (REPO.parent / "deliverables").is_dir()
                   else REPO / "deliverables" / "umdr38" / "test_evidence")
    durable_dir.mkdir(parents=True, exist_ok=True)
    import shutil
    for name in ("FULL_SUITE_EVIDENCE.json", "FULL_SUITE_EVIDENCE.txt",
                 "coverage_last_run.json"):
        src_file = REPO / ".webpent-evidence" / name
        if src_file.is_file():
            shutil.copy2(src_file, durable_dir / name)
    print(f"[re-baseline] suite_count = {info['suite_count']} "
          f"(well-formed executed count, derived from evidence at "
          f"{str(record.get('source_commit'))[:12]})")
    print(f"[re-baseline] {BUILD_INFO}")
    print(f"[re-baseline] durable release evidence refreshed: "
          f"{durable_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
