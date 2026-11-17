# UM-DR-38 — Recovery and Provenance Report

Generated: 2026-11-17T04:52:59.218515+00:00 — every claim below is backed by a git command executed at generation time.

## The situation at mission start

* Public `main` HEAD: **2338fd5c172e** (“Update project to v0.40.1 UMDR36-2-37 FINAL”) — the mission RESULT published as a squash; its parent lineage is the publish-squash chain (… ← 64a5bea65303 ← 1968f63).
* The detailed mission branch (`mission/umdr36.2-umdr37` in the build-environment repository) had its final segment (**01d1708…073c64b**, including the evidence commit **1386d57**) lost to a build-environment recycle; it was never pushed. The recoverable mission history ended at **01d1708**; the old git bundle ended even earlier, at **9ee46b5**.
* Therefore the evidence commit `1386d57` recorded in the published `docs/FULL_SUITE_EVIDENCE.json` was NOT resolvable in the public history — the exact finding of the previous review — and cannot be resurrected: no copy of that commit object exists anywhere reachable. Its CONTENT survives as the published squash tree **2338fd5c172e**.

## Lineage reconciliation (mission/umdr38-closure)

1. Based the closure branch on the ACTUAL public `main` (2338fd5c172e) — the public lineage is preserved and never rewritten.
2. Fetched the recoverable mission branch and verified a LEGITIMATE shared ancestor: merge-base with public main = **1968f63** (the v0.40.1 UMDR35-36 publish) — the mission branch is genuine lineage, not unrelated history.
3. Merged the mission branch with the **`-s ours`** strategy: the mission COMMITS become resolvable ancestors of the closure branch while the TREE stays identical to public main. This is an ancestry-preserving merge, documented as such — no tree identity is claimed between the mission branch tip and the published tree (the mission tip predates the final state).
4. Verified the tree was unchanged by the merges: `git diff origin/main <merge> --stat` = **0 lines**.
5. No force-push, no history rewrite, no invented commits: the lost segment is recorded as lost, never fabricated.

## Merge commits

```
b0d760e merge(umdr38.1): restore the UM-DR-38 mission history from the published bundle
3a9c25f merge(umdr38.1): preserve the recoverable UM-DR-36.2/37 mission history as ancestry
```

## The evidence contract consequence (§6)

Because `1386d57` is unrecoverable, the old evidence file is explicitly unusable as current-release proof: it was migrated to `docs/history/` with a README explaining exactly this, and the CURRENT release evidence is generated fresh by the §6.2 runner at the release revision (source_commit below).

* Release branch HEAD at generation: **b7b0b4fd77adf5374e756d7f72c4e27e04dc8460**
* Current evidence source_commit: see UMDR38_TEST_EVIDENCE_INTEGRITY_REPORT.md.

## What is authoritative now

* **Source tree**: the closure branch tree (public main + the UM-DR-38 repairs).
* **History**: public publish-squash lineage + the recoverable mission commits as ancestors (all mission SHAs up to 01d1708 resolve; 1386d57 and 073c64b are recorded as permanently lost).
* **Test evidence**: the `.webpent-evidence/` record bound to the exact release commit (workflow artifact), not any historical file.
