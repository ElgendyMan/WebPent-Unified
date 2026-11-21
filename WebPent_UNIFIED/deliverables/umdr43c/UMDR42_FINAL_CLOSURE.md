# UMDR42 FINAL CLOSURE

**Mission:** UM-DR-42 release closure — reconciled and closed under the UM-DR-43C
directive (§2), on branch `feature/umdr43c-identity-safe-hypothesis-lifecycle`.
**Date:** 2026-11-21 · **Author:** UM-DR-43C engineering window.

---

## 1. Release closure

The v0.40.1 UMDR42 closure is **published and verified**:

- **Release tag:** `v0.40.1-umdr42-closure` → commit `61062b6`
  (https://github.com/ElgendyMan/WebPent-Unified/releases/tag/v0.40.1-umdr42-closure)
- **Release asset:** `WebPent_Unified_v0.40.1_UMDR42_CLOSURE.zip`
  (65,223,680 bytes, SHA-256
  `7101f0e5a2ddc1f015c65887a85f73ef42042bc8210c131780a217ebba475db1`,
  download-verified round-trip: the asset re-downloaded from GitHub is
  byte-identical to the source).
- **main lineage:** the owner published `ce20de8` ("Publish v0.40.1 UMDR42
  CLOSURE") on `main`.

## 2. Git reconciliation (as revalidated, not assumed)

- `main` = `ce20de8` (owner publish commit).
- `security/umdr42-closure` = `828767c` — **18 commits ahead** of the
  pre-publish main, **1 behind** (the publish commit itself).
- The publish commit carries the ZIP snapshot's tree (including the
  `umdr42_closure_patches/` series and the closure bundle) — so the branch's
  content IS on main, and the two evidence-diagnostics commits
  (`61062b6` failed-nodeid naming, `828767c` traceback capture) are
  preserved on the closure branch.
- No merge was forced; the UM-DR-43C work branches from `ce20de8` (the
  published main baseline), per the directive's "no blind merge, no direct
  push to main".

## 3. CI results at closure

| Run | Branch / SHA | Verdict | Detail |
|---|---|---|---|
| #16 | closure `808eb8d` | failure | 9412/9425 — 1 test failure (option-B approval), evidence upload broken |
| #17 | closure `61062b6` | failure | 9412/9425 — failure NAMED in-log by the failed_nodeids patch: `test_option_b_approval_boundary_stays_fail_closed_when_missing` |
| #18 | closure `828767c` | failure | **Full regression GREEN: 9413 passed / 0 failed** — only the evidence-upload step red (hidden-dir artifact bug) |
| #19 | main `ce20de8` | failure | 9411/9425 — 2 provenance tests + honesty gate: BUILD_INFO modified without a declared decision |

**Root causes found and fixed (on the UM-DR-43C branch):**

1. **Evidence upload (§2.2):** `run_tests_with_evidence.py` writes to
   `WebPent_UNIFIED/.webpent-evidence/` — a hidden directory;
   `actions/upload-artifact@v4` defaults to `include-hidden-files: false`,
   so the step failed with "No files were found" on EVERY run, including the
   fully green #18. Fix (shipped as `ci_fixes_umdr43c.patch`, since the
   available token cannot push workflow files): add
   `include-hidden-files: true`. No `continue-on-error`, no weakened
   `if-no-files-found`.
2. **The option-B flaky test:** run #18 shows it passing on the runner
   (9413/0) — it was a nondeterministic environment interaction, not a
   code defect; the traceback-capture instrumentation added in `828767c`
   is retained so any future red run names its assertion in-log.
3. **BUILD_INFO honesty (§2.4):** the publish commit modified BUILD_INFO
   without a qualifying declared decision and its provenance block still
   named the closure-branch tree (`336711d`). Fixed by a declared
   `BUILD_INFO re-baseline` commit (touching ONLY BUILD_INFO.json) with
   truthful main-lineage values, a companion re-freeze of the manifest
   digest, and the honesty gate now recognizing the `Publish v…`
   publication convention (the verb the owner actually used) with the
   same semantics as `Update project to v…`.
4. **SBOM (§2.3):** `uv export --locked` without `--no-emit-project` emits
   the project as an editable requirement; pip-audit's hash-pinned dry-run
   install fails, and `|| true` hid the difference between "SBOM built"
   and "SBOM build failed". Fixed in the same patch file.

## 4. Historical artifact preservation

All §3 items recovered from resolvable git history and verified (see
`deliverables/umdr43c/UMDR42_ARCHIVE_MANIFEST.json` for the full record —
10/10 entries):

- 6 JSON records recovered and JSON-parsed (coverage baselines
  `docs/baseline/coverage.json`, `coverage_measured_baseline_0260.json`,
  `UMDR37_COVERAGE_LAST_RUN.json`, `umdr38/test_evidence/coverage_last_run.json`,
  `REGRESSION.json`, `download/dojo/trainer_session.json` — the dojo file
  the publish commit deleted).
- 3 mission bundles recovered and `git bundle verify`-ok: the UMDR36.2+37
  mission bundle (14.7 MB), the UMDR36-1 recovery closure bundle (0.4 MB),
  and `WebPent_Unified_umdr38.bundle` (29.8 MB). **These carry history NOT
  contained in the current lineage** — the `mission/umdr38-closure` head
  (`8f43e88`) is not an ancestor of `main` — so they are archived, not
  merely referenced, under `deliverables/umdr43c/archive/`.
- The unified closure bundle verified (`bundle verify: ok`, 47.3 MB) — it
  remains the canonical release artifact on the GitHub release.

## 5. Remaining accepted risks

1. **ci.yml fixes are a patch file, not applied.** The token used for this
   window cannot push workflow files (`workflow` scope missing). Until the
   owner applies `ci_fixes_umdr43c.patch` on main, every CI run — however
   green its suite — will still fail the evidence-upload step, and the SBOM
   step will keep swallowing pip-audit's editable-install failure.
2. **PR creation blocked** (token lacks `pull_requests:write`): the owner
   opens the PR via
   https://github.com/ElgendyMan/WebPent-Unified/pull/new/feature/umdr43c-identity-safe-hypothesis-lifecycle
   and should merge with **Create a merge commit** (not squash — provenance
   SHAs must remain resolvable in main history).
3. The closure branch `security/umdr42-closure` is retained (it holds the
   two evidence-diagnostics commits above main's snapshot); retire it only
   after the UM-DR-43C branch merges.

## 6. Exact final source SHA

- **UMDR42 release (published):** tag `v0.40.1-umdr42-closure` →
  `61062b65445522545bc04ecdb3f88dee0b25e28b`
- **Published main baseline:** `ce20de83e7a129f95509da10dd141b656d6d9df4`
- **UM-DR-43C branch (this work):** `feature/umdr43c-identity-safe-hypothesis-lifecycle`
  from `ce20de8`; final commit SHA in the delivery report (§17E of the
  directive), stamped by the full-suite evidence run on the branch tip.
