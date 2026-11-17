# UM-DR-38 — Test Evidence Integrity Report

Generated: 2026-11-17T04:55:45.472845+00:00 — from `.webpent-evidence/FULL_SUITE_EVIDENCE.json`, the machine record of the current run (§6.2: evidence is a build artifact, never tracked source).

## The current run (authoritative for this release)

* **Source commit:** `9802cd22f2b7c11ed5350eaa33a965573d4b339b`
* **Tree clean at test START:** **True** (captured BEFORE anything is written; the evidence directory is git-ignored, so a clean checkout stays clean — the structural `tree_clean: false` of every earlier recorded run is impossible under this contract)
* Python: 3.12.16 | uv: uv 0.13.8 (x86_64-unknown-linux-gnu)
* Lockfile SHA-256: `6d714ff5ed5212b8e751d19fc50917aa52fec042583f4d69d9d6b2a75c4ef650`
* Test scope digest: `55304f036becaf0c79ad3e14da5fa851bb842b61919d3f9d61ddac7d254722af`
* Collected **9288** | executed **9289** | passed **9277** | failed **0** | errors **0** | skipped 9 | xfailed 3 | xpassed 0
* Hook-level v3: collected_items 9288, started 9288, not_started 0, collection errors 0, collection skips 1, setup errors 0, teardown errors 0, interrupted False
* v3 invariants all true: **True**; terminal cross-check agrees: **True
* Coverage: 77.09% (floor 72% — OK)
* Exit code: **0**

## What changed and why (§6)

* Evidence output moved from tracked `docs/` files to the git-ignored `.webpent-evidence/` directory (WEBPENT_EVIDENCE_DIR-overridable) — a test run no longer modifies the source revision it tests, and `tree_clean` describes the checkout at test start.
* Writes are ATOMIC (tmp + os.replace); stale evidence in the directory is deleted before the run (an interrupted run cannot leave an older green record).
* The checker enforces the full §6.3 set: commit binding (stale rejected), schema/runner identity, v3 invariants + cross-check, coverage floor, lockfile freshness (a mismatch against the CURRENT uv.lock rejects the evidence), GitHub run/attempt identity under CI, timestamps, and fail-closed when Actions runs without a run id. Eleven regression tests pin stale/incomplete/tampered/mismatched/below-floor/wrong-identity rejection.
* The historical evidence migrated to `docs/history/` with a README documenting the lost 1386d57 segment; it is never reusable as current-release proof.
