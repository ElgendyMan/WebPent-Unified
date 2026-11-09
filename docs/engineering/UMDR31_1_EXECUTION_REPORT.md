# UM-DR-31.1 EXECUTION REPORT

**Window:** UM-DR-31.1 — Intelligence & Engineering Uplift (autonomous execution directive).
**Base:** v0.37.0_UMDR31 — release tree `2d7b928`, audit verdict *ACCEPTED WITH LIMITATIONS* (20 findings F01–F20, remediation plan R1–R11).
**Branch:** `umdr31-1-intelligence-engineering-uplift` (created from HEAD `914061c`; v0.37.0 history untouched).
**Result:** **v0.37.1** — commits `ca0b9ec` (the window), `86e6117` (suite-closure corrections + BUILD_INFO freeze), `21f591a` (deterministic packaging builder); tag **`v0.37.1-umdr31.1`** (the first git tag in this repository's history — audit F19 closed).
**Date:** 2026-11-08 (all timestamps true UTC).

---

## 1. Baseline versus final state

| | Baseline (verified at window start) | Final (this window) |
|---|---|---|
| Git | HEAD `914061c`, branch `main`, clean tree | branch `umdr31-1-intelligence-engineering-uplift`, HEAD `21f591a`, tagged `v0.37.1-umdr31.1`, clean tree |
| Version | 0.37.0 | 0.37.1 (pyproject + `__init__.py` + Dockerfile + uv.lock + CHANGELOG) |
| Suite | 8,711 collected (audit record); window spot-checks: frozen gate 641 ✅, UM-DR-31 research suites 42 ✅ | **8,744 collected → 8,735 passed / 0 failed / 6 skipped / 3 xfailed** (chunked 13/13; exact collected↔outcome reconciliation: 8735+6+3 = 8744) |
| Frozen gate | 641 green (639 entries) | 641 green (639 entries; 3 re-pinned per DR-009: `__init__.py`, `coverage/gap_detector.py`, `shared/coverage_ledger.py`) |
| direct-I/O | 1,155 records | 1,155 records (+0/−0 identities; F17 attribution correction appended as a new history entry) |
| Broad-exception register | 18 handlers | 19 handlers (adaptive_research +1: the advisory hints re-scan; register + gate updated together per the gate's protocol) |
| Python floor | `>=3.10` (silently resolving vulnerable dnspython 2.8.0 on 3.10) | **`>=3.11` (deliberate)** — the patched dnspython line (≥2.9.2) publishes no 3.10 release; lock re-resolved: single dnspython 2.9.2, zero forks |
| Tags | zero (F19) | `v0.37.1-umdr31.1` |
| ablation artifact | mutated post-release by a test side effect (2ad93aa) | reverted to released bytes; regenerated only by the explicit release command; test writes `tmp_path` only |
| CausalGuard / ProofBundle / replay / strategist thresholds / IDOR guard | frozen | **UNTOUCHED** (verified: `git diff a2e05a3..HEAD -- src/webpent/cqa_v2` empty; thresholds and the M1-B guard unmodified) |

## 2. Exact files changed and why

**Production code (4):**
| File | Change | Why (audit item) |
|---|---|---|
| `src/webpent/production/adaptive_research.py` | R3 `_admit_endpoint` + `_campaign_origin` + `_effective_port` (hypothesis-admission scope filter, rejections recorded in `scope_violations`); R4 `_normalize_url` (host case-folding, query identity preserved with duplicate-safe deterministic sort, fragment stripped, idempotent); R6 `classify_coverage_status` public pure contract + `CLASSIFICATION_*` vocabularies + unknown-status second gate in the inventory; R7 non-mapping `research_loop` channel → fail-closed no-op with cap-flooded counter; §6.1 coverage-surface hints in `stateful_research_hints` | F05, F10, F11, F08, F12, F20, F18, §6.1 |
| `src/webpent/production/stateful_discovery.py` | R5 honest hint semantics (`research_hints_applied` = ≥1 real case match; `research_hints_matched_cases`/`_count` telemetry); §6.1 segment-aligned suffix matching at `_SURFACE_HINT_DISCOUNT = 0.5` | F06, §6.1 |
| `src/webpent/shared/coverage_ledger.py` | F20 projection: producer aliases (`not_observed`, `tested`, `tool_unconfirmed`) reconcile to `not_scanned`; ANY other unrecognized status → explicit non-gap `unknown_status` + `unrecognized-status` gap marker | F20, F08 |
| `src/webpent/coverage/gap_detector.py` | Documented deliberate exclusion of `unknown_status` from `_OPEN` (membership unchanged — documentation-only delta) | F20 |

**Tests (4):** `tests/test_umdr31_adaptive_research.py` (+31 net new tests: R3 ×9, R4 ×8, R6 ×7, R7 ×7, R5 rewrite +2 new), `tests/test_umdr31_research_loop_integration.py` (surface-hint pin updated + journey assertion), `tests/test_umdr31_campaign_e2e_ablation.py` (R2 tmp_path fix + measured coverage-arm expectations + report text), `tests/test_frozen_module_gate.py` (UMDR31_1 thaw set).

**Packaging/metadata (5):** `pyproject.toml` (version 0.37.1, floor 3.11, dnspython≥2.9.2, mypy 3.11), `uv.lock` (re-locked), `Dockerfile` (version agreement), `BUILD_INFO.json` (true-UTC build date, suite evidence, window record, git_head), `frozen_modules.sha256` (3 re-pins).

**Docs/records (6):** `WEBPENT_MASTER_GUIDE.md`, `WEBPENT_ENGINEERING_REFERENCE.md`, `DRIFT_REGISTER.md` (UM-DR-31.1 entry), `CHANGELOG.md`, `docs/engineering/UMDR31_RELEASE_READINESS_MATRIX.json` (F04 correction), `docs/ACCEPTED_EXCEPTIONS_REGISTER.md` (+1 handler).

**Inventory/qualification (2):** `docs/direct_io_inventory.json` (regen + F17 correction), `reports/qualification/umdr31_ablation.json` (reverted to released bytes, then regenerated by the explicit release-time command).

**New scripts (5):** `scripts/build_umdr31_ablation_artifact.py` (R2), `scripts/build_release_archive_umdr31_1.py` (R1 deterministic packaging), `scripts/refreeze_manifest_umdr31_1.py` (DR-009), `scripts/regen_direct_io_inventory_umdr31_1.py` (R11), `scripts/experiment_umdr31_1_bottleneck.py` (the §6.1 evidence), `scripts/run_suite_chunks_umdr31_1.sh` (chunked runner).

## 3. What deliberately did NOT change

- `cqa_v2/causal_guard.py` — zero behavioral change (sole confirmation authority).
- ProofBundle generation and the replay verification requirements.
- The strategist's ranking formula, `_PROMOTION_THRESHOLD=0.5`, `_ABANDON_THRESHOLD=0.15`, `_MAX_PROMOTIONS_PER_PASS`.
- The M1-B IDOR promotion guard — research scheduling is execution ORDERING, never a promotion/confirmation path.
- All request/iteration budgets (3×12 research, 360 stateful discovery) and every scope/authorization gate.
- The six conditional research-loop routes and flag-off byte-comparability.
- Historical v0.37.0 commits (all corrections move forward).

## 4. Remediation closure summary

All R1–R11 actions are **completed with real corrections**; no item was closed silently and none required an evidence-supported blocker. The full finding-by-finding linkage (F01–F20 → action → file → regression test → verification → status) is in `UMDR31_1_REMEDIATION_MATRIX.md`.

## 5. Intelligence improvement (Gate C)

Exactly one intelligence improvement was implemented, after the bottleneck was demonstrated on the real code: **coverage-surface research hints** (ordering-only scheduling). The bottleneck measurement, the controlled four-arm validation under identical budgets, and the explicit non-goals (no confidence/severity inflation, no authority change) are documented in `UMDR31_1_INTELLIGENCE_BOTTLENECK_REPORT.md`. Honest boundary: the validation population is the team-authored two-directory fixture — a mechanism-level result, not an independent benchmark; M10 remains CLOSED.

## 6. Security verification (Gate B)

See `UMDR31_1_SECURITY_REGRESSION_REPORT.md`. Summary: out-of-scope rejection before requests (measured in every ablation arm: 2 refusals, zero internal confirmations); foreign-host hypotheses cannot reach the pool (new admission gate, regression-tested); research priorities cannot change confidence (hints never touch Hypothesis confidence fields — verified by code path + tests); malformed loop state cannot increase budgets (cap-flood fail-closed, tested); only the established CausalGuard path confirms (cqa_v2 diff empty; the honest-numbers ablation re-run shows zero false positives in every arm).

## 7. Release integrity (Gate E)

See `UMDR31_1_RELEASE_INTEGRITY_REPORT.md`. Summary: deterministic archive built from the tagged tree (double-build digest equality verified), SHA-256 computed from the actual artifact, contents inspected (4,728 files, sorted, zip-epoch timestamps, version 0.37.1 inside), the historical v0.37.0 lineage preserved, and the reconstructed-UMDR31-archive digest never claimed to verify the missing original.

## 8. Remaining limitations (honest, unchanged in kind)

1. Independent holdout qualification remains BLOCKED_EXTERNAL_DEPENDENCY (M10 stays closed; recall ≥0.5 ∧ precision ≥0.7 on an operator-deployed corpus is still the unmet re-open condition).
2. The intelligence improvement is demonstrated on the team-authored fixture only — no generalization claim.
3. `privilege_differential` research hypotheses still have no deterministic validator route (they are honestly recorded as missing-validator and never executed).
4. Stateful blind spots documented in the bottleneck report §5 (alias/alternate resource representations, composite operations) — assessed, not built (no executable path justified a change this window).
5. The original v0.37.0 announced digest remains unverifiable (the archive file never existed); the reconstructed archive's digest is recorded separately and is NOT a verification of the original.
