# UM-DR-38 — Documentation Consistency Report

Generated: 2026-11-16T08:09:15.575640+00:00.

## The reconciliation rule

Historical records are preserved but LABELED historical; exactly ONE current status statement exists per claim, and it is bound to machine evidence.

## The eight reader questions (§14)

1. **What did UM-DR-36.2 change?** — the recovery of the mission repository from the recycled environment, the v3 hook-level accounting contract, BUILD_INFO honesty repairs. Historical records: docs/UMDR36_2_* (labeled historical).
2. **What did UM-DR-37 change?** — production root-cause fixes, the three production campaigns, decoy closure, full-loop learning proof, discovery funnel. Historical records: docs/UMDR37_* (labeled historical; the two missing-stubs were replaced by regenerated real records).
3. **What was independently reproduced?** — the full regression suite at the release commit: 9249 collected / 9238 passed / 0 failed / 0 errors, exit 0, coverage 77.09% (floor 72).
4. **Which controlled campaigns ran?** — three fresh production campaigns through run_unified_hunt at the release revision (IDs in UMDR38_CAMPAIGN_EVIDENCE.json), plus the full-loop four-arm proof and the root-cause campaign.
5. **Which vulnerability family is production-path verified?** — access control (IDOR/auth_bypass) on the controlled invoice lab ONLY; other families are not production-confirmed (not claimed).
6. **What tests passed on the current release revision?** — the current evidence record at commit `e31cad5efcf8` (tree_clean=True).
7. **Which CI run verified the revision?** — NONE remotely: BLOCKED_EXTERNAL_DEPENDENCY (no push credentials). The local gate re-execution is in UMDR38_CI_VERIFICATION_REPORT.md; push/PR commands provided.
8. **Which limitations remain?** — remote CI verification; generalization beyond the controlled fixtures; families beyond access control; the permanently lost mission history segment 01d1708..073c64b (documented in the provenance report).

## Removed contradictions

* The ~101-failures acceptance narrative (UM-DR-36.2 era) is a historical record of that window; the current status is the evidence-bound statement above — both exist, only one claims currency.
* No stale suite counts remain as current claims: suite_count is derived from the current evidence.
* No missing-artifact claims: the durable evidence set under deliverables/umdr37/evidence/ carries 16 files with SHA-256 digests.
* No unexplained None metrics: the §9.1 generators refuse null mandatory metrics and record explicit missing-data states otherwise.
