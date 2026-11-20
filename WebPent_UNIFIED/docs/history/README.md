# docs/history — migrated historical evidence (UM-DR-38 §6.2)

The files in this directory are HISTORICAL RECORDS, deliberately
preserved when UM-DR-38 moved the live evidence output out of tracked
source. They are not the current release evidence and must never be
reused as proof for a new source revision.

## What moved here, and why

| File | What it is |
| --- | --- |
| `UMDR37_FULL_SUITE_EVIDENCE_1386d57.json` / `.txt` | The final UM-DR-36.2/37 full-suite evidence (9,228 collected / 9,217 passed / 0 failed / 0 errors, exit 0) recorded at mission commit `1386d5707296aca629417e45318a212b0da1a257`. |
| `UMDR37_COVERAGE_LAST_RUN.json` | The coverage JSON produced by that same run. |

Until UM-DR-38 the runner wrote evidence to `docs/FULL_SUITE_EVIDENCE.*`
(TRACKED files). That contract had two documented defects, both fixed in
UM-DR-38 §6.2:

1. **`tree_clean: false` was structural.** The runner deleted the tracked
   evidence files before the run to prevent stale evidence, which made
   the checkout dirty at test start — so every recorded run carried
   `tree_clean: false` even when the source revision itself was clean.
2. **A test run modified the source tree it was testing.**

The live evidence contract is now: run output goes to the git-ignored
`.webpent-evidence/` directory (see `scripts/run_tests_with_evidence.py`
and `scripts/check_test_evidence.py`), `tree_clean` is captured at test
START before anything is written, and CI uploads the directory as a
workflow artifact. Nothing under `docs/` is written by a test run.

## About the commit `1386d57...`

The `source_commit` recorded in the migrated record belongs to the
UM-DR-36.2/37 mission branch. The segment of that branch containing
`1386d57` was lost in a build-environment recycle and was never pushed;
its *content* survives as public `main` commit `2338fd5` ("Update
project to v0.40.1 UMDR36-2-37 FINAL"), and the recoverable mission
history was preserved as ancestors of `mission/umdr38-closure` (see
`deliverables/umdr38/UMDR38_RECOVERY_AND_PROVENANCE_REPORT.md`). The
recorded SHA is therefore not resolvable in this repository's history —
which is exactly why §6 of UM-DR-38 forbids reusing it as evidence for
the current release. The current release evidence lives in
`.webpent-evidence/` (CI artifact) and is bound to the exact release
commit.
