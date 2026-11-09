# FULL-SUITE EVIDENCE — UNIFIED-MERGE phase-1/2 window (2026-11-02)

Environment: Python 3.12.16, uv.lock-pinned (257 packages), `uv sync
--locked --extra dev` — venv OUTSIDE the tree. Every number below is a
real run of this tree, not a projection.

## Baseline (delivery zip) vs post-window

| Suite | Baseline | Post-window |
|---|---|---|
| tests/egaie + tests/appsuite + tests/labsuite | 67 failed / 222 passed | **0 failed / 288 passed / 1 documented skip** (UM-DR-03) |
| tests/oracle | 2 failed (reportlab missing, R3-class) | **0 failed** (285 passed) |
| tests/apex bridge campaign deep dojo econ forge ground_truth jc lab prism scenario_lab team1_acceptance | — | **2,492 passed** |
| standalone test files (395 files, chunked a-f / g-p / q-z) | ~353 failed + 14 errors (pre-existing v4/v15.2 contract debt, UM-DR-06) | ~238 residual after Phase-2 fixes (see below) |
| test-count gate | 7,958 floor | **8,003 floor = collected 8,003** |

## Post-window fixes that closed additional debt
- Settings flag gates (`enable_feedback_loop`, `enable_scheduler`,
  `feedback_outcomes_path`, `scheduler_state_path`): test_feedback_loop
  (16) + test_campaign_scheduler (11 of 13) → green.
- CLI contracts: `--version`/`--build-info` (TestCliSelfIdentification),
  `scheduler add/list/run-due` → test_r4_production_hardening +
  test_campaign_scheduler fully green.
- postp0 deterministic validators (prototype_pollution,
  cache_poisoning) → r4 validator classes green.
- reportlab dev-extra (oracle PDF writer) → tests/oracle green.
- isolation A-01 allowlist catch-up (esprima, jsbeautifier, h2,
  starlette, langchain_huggingface) → check_isolation_denylist green.
- G-08 inventory regenerated under DR-009 protocol (816 → 1,035
  records; zero removed semantic identities; zero new raw-transport).
- P2-107: 3 manual asyncio.run() test sites → native async tests.

## Gates (scripts/production_ready_gate.sh, structural set)
PASS 01_uv_sync_locked, 02_uv_lock_check, 03_state_contract,
04_orchestrator_auth, 05_isolation_deny, 06_vault_import,
07_test_count_floor, 08_g08_inventory, 09_no_asyncio_run,
13_build_info_honesty, 14_vip_gap, 15_frozen_gate (661/661).
Known-open by documented decision: 10/11 (ruff zero-ratchet —
unadopted per merge decision, thousands of legacy findings),
12 (pip-audit: msgpack FIXED 1.2.4; chromadb PYSEC-2026-311*/3813-3815
— no upstream fix at pin ==1.5.9, tracked), 17 (full-suite triple run —
nightly canary scope, Phase 4).

## Feature window (ق1-ق4) — 45 new tests, all green
- tests/safety/test_autonomy_tiers.py (11)
- tests/oast/test_bridge.py (10)
- tests/learning/test_lessons_ledger.py (14)
- tests/memory/test_experience_corpus.py (10)
