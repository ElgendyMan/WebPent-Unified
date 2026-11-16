# UM-DR-36.2 Recovery Audit

Generated 2026-11-16T05:24:44.894368+00:00.

## Source reconciliation

| Source | Content | Verified by |
|---|---|---|
| GitHub main 64a5bea | 36.1 final tree (nested) | git ls-remote + clone |
| uploaded ZIP | 1968f63 UMDR35-36 tree | extraction + tree compare |
| delivered bundle | 15-commit 36.1 history | git bundle verify |

Delta bundle-tip -> published nested tree: 19 files (the 36.1
deliverables folder + 5 report refreshes) — applied on the mission
branch with the deliverables preserved under `deliverables/umdr36_1/`.

## Portable restore (performed, not claimed)

The recycle itself WAS the test: clone -> bundle fetch -> branch ->
sync -> 48/48 regression tests green. The entrypoint provenance gate
(`WEBPENT_ENTRYPOINT`) refuses undeclared launch surfaces, so no run
depends on hidden paths. No absolute developer paths are required.

## Commits this mission

- 609da8a BUILD_INFO re-freeze (UM-DR-36.2 §3.5 final full-suite run): suite_count 9226 -> 9228
- 1386d57 feat(umdr37 §9 + §3.6 closure): discovery-efficiency metrics + checker contract coherence
- 5c2c7f3 fix(packaging): the zip listing filter matched 'N files' COUNT lines only — a naive substring 'files' filter excluded every path containing pro*files* (false MISSING on family_profiles)
- 5481907 docs(umdr36.2/37): FINAL deliverables — 9215 passed / 0 failed / 0 errors
- 4ffa22f BUILD_INFO re-freeze (UM-DR-36.2 §3.5 final full-suite run): suite_count 9178 -> 9226
- dbb28a9 docs(umdr36.2/37): verification-round deliverables (pre-final-suite state) + reproducible generators
- b6c1fd4 feat(umdr37 verification round): seven-failure closure + §6/§7/§8/§10/§12
- 1a9ab2b chore: commit pending permission-bit drift (post-recycle state)
- 5f8d93b artifacts(umdr37): track campaign/trace/ablation artifacts (force past artifacts/ ignore)
- 4af96aa evidence(umdr36.2/37): full-suite v3 run lands — 9160 passed / 7 failed / 0 errors
- d99a654 docs(umdr36.2/37): ALL Part-20 deliverables generated from real artifacts
- ca7354b BUILD_INFO re-baseline (UM-DR-36.2 §3.1 version-identity + evidence-provenance closure): package_version 0.40.1 in every source, suite_count refreshed, suite_evidence_provenance added
- be21fc6 chore(umdr36.2): version SSOT alignment — CHANGELOG 0.40.1 entry
- 3cdd696 test(umdr37): adversarial pins (Part 15) — repetition/lifecycle/dedupe contracts
- 06ee3e8 feat(umdr37): three true production E2E campaigns, all invariants green (Part 12, G37-16..23)
- ccbd449 feat(umdr37): unified hypothesis lifecycle view (Part 7.1)
- 1575966 feat(umdr37): appmodel evidence vocabulary — UNKNOWN/CONTRADICTED, timestamps, revision deltas (Parts 5.2/5.5/5.6)
- 010050a feat(umdr37): causal learning-between-decisions proof — two layers (G37-14)
- c38451f feat(umdr36.2): hook-level test accounting — evidence schema v3 (G36-07)
- 3523f07 fix(umdr36.2): stamp finding_id into the causal_guard chain node (G36-09)
- be82719 gate(umdr37): restrict the thaw set to baseline-shared paths
- 0d62fe5 gate(umdr37): declare the root-cause thaw set in the frozen-module gate
- e5f52eb fix(umdr37): close the four zero-findings root causes in the production path
- 1031d3a recovery(umdr36.2): branch from 36.1 bundle tip + published final state
