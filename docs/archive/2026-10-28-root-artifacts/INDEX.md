# Root artifacts archive — moved 2026-10-29

Track 0.1 (Repository organization) of WEBPENT_UNIFIED_MASTER_ROADMAP:
the project root was carrying ~95 historical report/artifact files
alongside the active tree. They were reference-checked (tests, src,
Makefile, CI, README) and moved here UNMODIFIED; their findings and
numbers are snapshots of their dates and are superseded by
CHANGELOG.md (the single active release log) and DRIFT_REGISTER.md
(the single active deviations register).

## Files (78)

- `ACCEPTANCE_RESULT.txt`
- `AUDIT_REPORT.md`
- `AUTONOMOUS_BUG_HUNTER_MASTER_PLAN.md`
- `BASELINE_HASH.txt`
- `CAUSAL_REASONING_MERGE.md`
- `CHANGES_AND_FIXES.md`
- `CLEANUP_REPORT.md`
- `CLEANUP_SUMMARY_2026-10-02.md`
- `DEFERRAL_REGISTER.md`
- `DEPLOYMENT_CHECKLIST.md`
- `DS_MATRIX_SPEC.md`
- `EVIDENCE_REPORT_20261005.md`
- `EVIDENCE_REPORT_20261005_v5.md`
- `EVIDENCE_REPORT_20261005_v6.md`
- `EVIDENCE_REPORT_20261005_v7.md`
- `EVIDENCE_REPORT_20261006_v8.md`
- `EVIDENCE_REPORT_20261006_v9.md`
- `EXTERNAL_OBSERVATION_ADAPTER.json`
- `FABRIC_CROSS_TARGET.json`
- `FABRIC_LONG_HORIZON.json`
- `FABRIC_PRODUCTION_EXECUTION_MATRIX.json`
- `FABRIC_PRODUCTION_INTEGRATION.json`
- `FABRIC_PRODUCTION_INTEGRATION_REPORT.md`
- `FABRIC_PRODUCTION_MATRIX.json`
- `FABRIC_PRODUCTION_TRACE.json`
- `FABRIC_PRODUCTION_WIRING_REPORT.md`
- `FABRIC_PROOF_REPLAY_RESULTS.json`
- `FABRIC_RESEARCH_FEEDBACK.json`
- `FABRIC_RUNTIME_TRACE.json`
- `FABRIC_SECURITY_RESULTS.json`
- `FABRIC_VALIDATOR_RESULTS.json`
- `FIVE_FAMILY_COVERAGE_REPORT.json`
- `FIX_AUDIT_REPORT.md`
- `FIX_SUMMARY.md`
- `FROZEN_HASH_VERIFICATION.txt`
- `FULL_SUITE_POSTFIX_RESULT.txt`
- `HOSTILE_REVIEW_FIXES.md`
- `LEGACY_CONFIRMATION_PATHS.md`
- `MERGE_NOTES.md`
- `MERGE_NOTES_TRACK123_x_PROJECTZERO_20261024.md`
- `POST_FIX_SHA256.txt`
- `POST_HASH.txt`
- `POST_HASHES.txt`
- `POST_PATCH_SHA256.txt`
- `PRE_HASHES.txt`
- `QUICKSTART_CAMPAIGNS.md`
- `RED_TEAM_REPORT.md`
- `REFACTOR_REPORT.md`
- `RESEARCH_LOOP_ACTIVATION_REPORT.md`
- `RUNNING_LOG.md`
- `SECURITY.md`
- `SESSION_SUMMARY_TRACK2_TRACK3_20261022.md`
- `TEAM1_AVI_V1_1_REAL_TARGET_QUALIFICATION_REPORT.md`
- `TEAM1_AVI_V1_2_100_DECISION_RUNTIME.json`
- `TEAM1_AVI_V1_2_ENVIRONMENT.md`
- `TEAM1_AVI_V1_2_RELEASE_CLOSURE.json`
- `TEAM1_AVI_V1_2_RELEASE_CLOSURE.md`
- `TEAM1_AVI_V1_2_TRUST_HARDENING.json`
- `TEAM1_AVI_V1_2_TRUST_HARDENING.md`
- `TEAM1_AVI_V1_PRODUCTION_RELEASE_REPORT.md`
- `TEAM1_MERGE_NOTES.md`
- `TEAM2_FINAL_EVIDENCE.json`
- `TEAM2_FINAL_HASHES.txt`
- `TEAM2_FINAL_VALIDATION_REPORT.md`
- `UNFREEZE_ARJUN_TRACK1_20261018.md`
- `UNFREEZE_FIX_REPORT_20261005.md`
- `VALIDATOR_COVERAGE_V1_REPORT.md`
- `VALIDATOR_CROSS_TARGET.json`
- `VALIDATOR_EVIDENCE_RESULTS.json`
- `VALIDATOR_EXECUTION_FABRIC_V2_REPORT.md`
- `VALIDATOR_EXPERIMENT_MATRIX.json`
- `VALIDATOR_LONG_HORIZON.json`
- `VALIDATOR_PROOF_REPLAY_RESULTS.json`
- `VALIDATOR_RESEARCH_FEEDBACK.json`
- `VALIDATOR_RUNTIME_TRACES.json`
- `WORKLOG.md`
- `demo_refactor.py`
- `build_sprint_a_zip.py`

## Legacy root dirs (5)

- `goed_v1_8*` moved to `docs/archive/2026-10-28-goed-v1.8-root-dirs/` — provenance freeze dirs of the GOED v1.8.x line; their canonical manifests already live under docs/archive/goed-v1.8.*/.

## Held back (referenced by an active surface)

- `ADDITIONS_AND_FIXES_20261022.md` — src/webpent/autonomous/__init__.py
- `CHANGED_FROM_BASELINE.txt` — tests/test_frozen_module_gate.py.orig, tests/test_frozen_module_gate.py
- `MERGE_20261026.md` — tests/test_frozen_module_gate.py, src/webpent.egg-info/PKG-INFO, src/webpent/models/findings.py
- `MERGE_REPORT.md` — tests/test_frozen_module_gate.py.orig, tests/test_frozen_module_gate.py
- `REMEDIATION_REPORT.md` — src/webpent/agents/validator/agent.py
- `REVIEW_REFREEZE_REPORT.md` — tests/test_frozen_module_gate.py.orig, tests/test_frozen_module_gate.py
- `ULTIMATE_PLAN_EXECUTION_20261027.md` — tests/test_g02_direct_io_inventory.py, tests/test_frozen_module_gate.py, src/webpent.egg-info/PKG-INFO
- `UNFREEZE_APPLIED_REPORT_20261005.md` — tests/test_frozen_module_gate.py.orig, tests/test_frozen_module_gate.py
- `UNFREEZE_TRACK2_PARALLEL_RECON_20261019.md` — tests/test_vip_parallel_recon.py, src/webpent/graph/builder.py, src/webpent/graph/builder.py.orig
- `UNFREEZE_TRACK3_RABBIT_HOLE_DRAFTING_20261020.md` — tests/test_vip_rabbit_hole_parallel_drafting.py, src/webpent/config/settings.py
- `viewer.py` — referenced by active surface
