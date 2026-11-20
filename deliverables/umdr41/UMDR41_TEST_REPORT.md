# UMDR41 Test Report
## Commands and results (exact)
| # | Command | Result |
|---|---|---|
| 1 | python3 -m pytest tests/test_umdr41_p0_correctness.py -q | 22 passed |
| 2 | python3 -m pytest tests/test_umdr41_scope_registry.py -q | 8 passed |
| 3 | python3 -m pytest tests/test_umdr41_rc6_rc7.py -q | 4 passed |
| 4 | python3 -m pytest tests/test_umdr41_p0_correctness.py tests/test_umdr41_scope_registry.py tests/test_umdr41_rc6_rc7.py tests/test_repair_recon.py tests/test_five_families.py tests/test_principal_provisioning_completion.py tests/test_m1d_legacy_disposition_overmatch.py tests/test_m3_research_wiring.py tests/test_umdr34_canonical_scope_authority.py tests/test_scope_program_policy.py tests/test_hardening_0330_b1.py -q | 298 passed, 2 skipped, exit 0 |
| 5 | python3 -m pytest tests/test_umdr34_canonical_scope_authority.py tests/test_scope_program_policy.py tests/test_repair_recon.py tests/test_campaign_pack_contract.py -q | 69 passed, 1 pre-existing env failure (CLI-not-installed; reproduced identically on pristine baseline via git stash — NOT a regression) |
| 6 | python3 scripts/check_build_info_honesty.py | GATE FAILURE (5) — reproduces the known release defects (expected, documented) |
| 7 | python3 -m pytest tests/test_g02_direct_io_inventory.py | NOT RUN in final env form; expired-approval failure reproduced directly via expired_approval_errors() → 49 records (2026-11-19) |
## Environment
Python 3.12.16 (/home/z/.venv); installed to match lockfile exact pins for affected suites: langgraph==1.2.10, langgraph-checkpoint-sqlite==3.1.1, langchain-core==1.6.7, bcrypt==5.0.0.
## Scope honestly NOT covered
Full 9,365-test suite (torch/chromadb/sentence-transformers not installable in sandbox within budget); browser integration (Playwright Chromium); Docker build tests; benchmark campaigns. Remote CI on branch commits: NOT run (no push authorization — directive §3.1 forbids unauthorized push).

## Follow-up window (CI + supply chain + RC-7) — additional runs
| # | Command | Result |
|---|---|---|
| 8 | python3 -m pytest tests/test_umdr41_rc6_rc7.py -q (after RC-7 persistence tests) | 6 passed |
| 9 | python3 -m pytest tests/test_umdr41_p0_correctness.py tests/test_umdr41_scope_registry.py tests/test_umdr41_rc6_rc7.py tests/test_umdr40_rc6_rc7_decision_ledger.py tests/test_postp0_phase1_replan.py tests/test_postp0_phase2_memory_readback.py tests/test_team1_post_validation_replan.py tests/test_umdr31_research_loop_integration.py tests/test_coverage_ledger.py tests/test_m1b_prioritization_guards.py tests/test_repair_recon.py tests/test_five_families.py tests/test_principal_provisioning_completion.py tests/test_hardening_0330_b1.py tests/test_v10_exhaustive_audit.py -q | 314 passed, 2 skipped, exit 0 |
| 10 | python3 -m pytest WebPent_UNIFIED/tests/test_production_deployment_contract.py -q (after ci.yml restructure) | 10 passed, 1 skipped (root-runner requirement) |
| 11 | YAML structural check (yaml.safe_load + assertions) | jobs=[g08-inventory, tests]; all 5 action uses pinned to SHAs; G-08 exactly once, in its own job |

Note on run #9: two intermediate failures were found and fixed during this window — (1) strategist crash when a dict-shaped state carried a non-dict coverage_ledger (fixed with defensive typing, cycle degrades to 1), (2) the pre-existing umdr40 RC-6 test asserting the OLD false-positive semantics (updated to the corrected contract with inline rationale). Both fixes are covered by the runs above.
