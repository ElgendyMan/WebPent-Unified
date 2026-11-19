# UM-DR-39.1 — Publication Provenance Reconciliation Report

Generated 2026-11-18T09:41:28.264919+00:00 at `bcebc8c0e731` (mission branch from published main `ca4ae448`).

## What was verified and how

1. **Fresh verified clone** of the published repository: HEAD `ca4ae44855c4…` on `main` (parent `54fc95c`), clean tree, 4992 tracked files, no tags, remote branches `features/v0.39.0-umdr33` and `security/umdr34-origin-scope-hardening`.
2. **Tree identity**: the published checkout is **byte-identical** to the delivered release package `WebPent_Unified_v0.40.1_UMDR39_FINAL.zip` (sha256 `12c38190a2bc5df5…`): a full recursive content diff over all 4,989 tracked files returned **0 differences**. The published source is exactly the tree that carried the validated UM-DR-39 work.
3. **Remote resolution of every referenced revision** (GitHub commit pages, fetched out-of-band 2026-11-18; the sandbox's direct API access is blocked):

| revision | role | remote | classification |
|---|---|---|---|
| `ca4ae44855c4` | currently published source revision | resolvable | VERIFIED_REMOTE |
| `a0807294694c` | declared tested source revision of the published tree | not_resolvable | HISTORICAL_UNRESOLVABLE |
| `e50900d0e7c3` | 39-lineage release/reporting revision | not_resolvable | HISTORICAL_UNRESOLVABLE |
| `1968f63c2076` | declared recovery baseline | resolvable | VERIFIED_REMOTE |
| `989c49ba5cb3` | historical release identity anchor | resolvable | VERIFIED_REMOTE |
| `4795f0237737` | previous release source (0.39.0 features window) | resolvable | VERIFIED_REMOTE |
| `54fc95c87306` | previous published final (UMDR38-1) | NOT_CHECKED_FROM_SANDBOX | VERIFIED_LOCAL_ONLY |
| `30d091727538` | recorded TREE hash of the 0.39.0 baseline (not a commit) | NOT_APPLICABLE (tree object, not a commit URL) | VERIFIED_LOCAL_ONLY |

## The reconciliation, stated honestly

* The published `ca4ae448` squashed the UM-DR-39 mission tree into a single new commit on `main`. The mission branch's own commits — including the declared source/tested/evidence revision `a080729` and the 39-lineage release revision `e50900d` — existed only in the mission's local build repositories, which the build environment recycled before publication. They resolve neither in a fresh clone nor on GitHub (404).
* The durable evidence record (9330 passed / 0 failed / 0 errors at `a080729`) is therefore **historical evidence for the tree** — and the tree IS what was published — but it is NOT a commit-level verified claim about `ca4ae448`, and it is not re-bound by textual substitution. It stays in place, classified `HISTORICAL_UNRESOLVABLE`.
* `remote_resolvable` facts for the remaining anchors (`1968f63`, `989c49b`, `4795f02`) are confirmed; the recovery baseline and release-history anchors are valid and resolvable.
* **The repair** (§A5): a provenance-only re-baseline on this mission branch re-points BUILD_INFO at a resolvable commit under the guarded tool's unresolvable-revisions condition; a fresh full suite then runs on the exact re-baselined source; the machine evidence and the accounting update land as a metadata-only descendant; BUILD_INFO honesty is re-verified under the unchanged contract. This establishes a NEW verified chain (source → tested → evidence) without touching any historical record.
* **Remote CI on the exact commits** remains `BLOCKED_EXTERNAL_DEPENDENCY` from this environment: no push credentials (the previous session's push attempts failed with `could not read Username`), no authenticated `gh`, and the GitHub API answers HTTP 403 to this sandbox. The existing run history (if any) on `ca4ae448` could not be queried; the exact missing permission is repository push access (or an authenticated API token) to trigger `workflow_dispatch` and read the run.

See `PROVENANCE_RECONCILIATION_MATRIX.json` for the machine-readable rows and `CI_VERIFICATION_REPORT.md` for the CI state.
