UM-DR-36.1 — FINAL PROJECT ARCHIVE
==================================

This archive is the complete WebPent UNIFIED project (v0.40.1) at the end of
the UM-DR-36.1 recovery-integrity & production-E2E mission, INCLUDING all
mission deliverables.

Layout
------
WebPent_UNIFIED/               <- the full project working tree
  src/webpent/                   package source (recovery + authority fixes applied)
  tests/                          test suite (incl. the new umdr36_1 suites: 48/48 green)
  scripts/                        build/CI/recovery scripts + the new umdr36_1
                                  campaign & learning scripts + verification command
  docs/                           reports incl. FULL_SUITE_EVIDENCE.{txt,json}
  artifacts/                      campaign/learning machine-readable artifacts
  .github/, config/, alembic/...  everything else of the project
  WebPent_UNIFIED/UMDR36_1_DELIVERABLES/   <- THIS folder (mission handoff)

Deliverables (this folder)
--------------------------
HANDOFF_NOTES.md               exact next steps for continuation (E2E zero-findings
                               diagnosis, suite follow-ups, BUILD_INFO re-baseline, push/PR)
UMDR36_1_RECOVERY_INTEGRITY_REPORT.md    Stage A/B: ZIP==tree proof, 4809=4802+7,
                               recovery ledger, portable toolchain, §1.4 command
UMDR36_1_TEST_EVIDENCE_INTEGRITY_REPORT.md  §3/§4: new evidence contract, provenance
                               gate, REAL full-suite outcome (9141 collected /
                               9019 passed / 101 failed / 7 errors — no green claim)
UMDR36_1_PRODUCTION_E2E_REPORT.md        §5: the true-production-path campaign state
                               (ran the real entrypoint; zero findings — honest)
UMDR36_1_READINESS_SUMMARY.json          machine-readable honest readiness:
                               NOT_READY_FOR_UM_DR_37
UMDR36_1_RECOVERY_VERIFICATION.json      output of scripts/verify_recovery_umdr36.py
UMDR36_1_CHANGED_FILES_MANIFEST.txt      every file changed vs baseline 1968f63 + SHA-256
WebPent_Unified_recovery-umdr36-closure.bundle   pushable git bundle of the whole
                               recovery branch (git clone <bundle> to restore)

Git state
---------
branch : recovery/umdr36-closure
base   : 1968f63c2076b1b804537f91cd5cfa01c3eee0bb (public main at mission start)
head   : see UMDR36_1_CHANGED_FILES_MANIFEST.txt (latest commits listed in reports)
push   : NOT pushed — no GitHub credentials in the build environment; use the
         provided git bundle to push/open the PR.

Honest bottom line
------------------
Recovery integrity verified, dependencies green, evidence/provenance contract
implemented with 48/48 adversarial tests, confirmation-authority bypasses
closed, manifest re-pinned. The full suite does NOT pass green yet (101
pre-existing environment-dependent failures + 7 errors), the production E2E
campaign produced zero findings through the real path, and remote CI is
unverified. Readiness stays NOT_READY_FOR_UM_DR_37. Nothing failed is
reported as passed anywhere in this archive.
