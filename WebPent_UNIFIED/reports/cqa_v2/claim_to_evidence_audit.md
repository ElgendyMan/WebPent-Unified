# CQA v2 — Claim-to-Evidence Audit

Every claim in the final audit is traced to: artifact → test → metric → provenance.
No evidence = UNVERIFIED, not PASS.

| Claim | Artifact | Test | Metric | Provenance | Status |
|---|---|---|---|---|---|
| Causal evaluator emits 4 verdicts | `causal_guard.py` | `test_causal_guard_blocked_invariant` | Verdict enum has 4 values | Code inspection | VERIFIED |
| BLOCKED never → CONFIRMED/CLEAN | `causal_guard.py` | `test_causal_guard_blocked_invariant` | `_FORBIDDEN_TRANSITIONS` set + defensive assert | Code | VERIFIED |
| ProofBundle has all required fields | `proof_bundle_builder.py` | `test_proof_bundle_deterministic_and_sealed` | 11 fields in CompleteProofBundle | Code | VERIFIED |
| Deterministic SHA-256 seal | `proof_bundle_builder.py` | `test_proof_bundle_deterministic_and_sealed` | 64-char hex, same input → same seal | Unit test | VERIFIED |
| Tampered bundle fails seal | `proof_bundle_builder.py` | `test_tampered_bundle_fails_seal` | verify_seal() returns False | Unit test | VERIFIED |
| Replay protocol implemented | `replay_verifier.py` | `test_single_case_replay_verified` | replay_verified = True | Single case trace | VERIFIED |
| Single case reaches replay_verified | `single_case_trace_*.md` | `test_single_case_replay_verified` | `replay_verified: True` | Trace report | VERIFIED |
| All 11 pipeline stages traced | `single_case_trace_*.md` | `test_single_case_trace_has_all_stages` | 11 stage headings present | Trace report | VERIFIED |
| Detector ≠ Ground Truth | `cqa_v2/*.py` source | `test_detector_cannot_import_target_owner_truth` | No `target_owner` import | Source analysis | VERIFIED |
| Truth not mutated by detector | `test_cqa_v2_truth_isolation.py` | `test_changing_detector_proposal_does_not_modify_truth` | Snapshot equality | Unit test | VERIFIED |
| Preflight failure map generated | `preflight_failure_map.md` | `test_preflight_*` (5 tests) | 50 cases, each with exact_block_reason | Report | VERIFIED |
| First 5 cases scored | `first_5_scoring.json` | `test_first_5_*` (6 tests) | causal=5, proof=5, replay=5, scored=5 | Script output | VERIFIED |
| Full 50-case campaign run | `full_50_scoring.json` | `test_full_50_*` (5 tests) | total=50, all metrics computed | Script output | VERIFIED |
| Proof completeness = 100% | `full_50_scoring.json` | `test_proof_completeness_reasonable` | proof_completeness = 1.0 | Metric | VERIFIED |
| Negative challenge FP = 0 | `negative_challenge_report.md` | `test_negative_challenge_fp_zero` | fp_count = 0 | Unit test | VERIFIED |
| No hardcoded routes in detector | `causal_guard.py` | `test_negative_challenge_no_hardcoded_routes` | No specific route names in source | Source analysis | VERIFIED |
| FN challenge scenarios defined | `fn_challenge_report.md` | `test_fn_challenge_scenarios_exist` | 3 scenarios with independent truth | Unit test | VERIFIED |
| Learning honestly NOT_ESTABLISHED | `learning_gate_report.md` | `test_learning_gate_honest_report` | learning_status = NOT_ESTABLISHED | Report + test | VERIFIED |
| 11 legacy failures classified | `legacy_failures_classification.md` | N/A (document) | 11 entries, 6 fields each | Document review | VERIFIED |
| No tests deleted | git history | `regression_protection_log.md` | Baseline 3 tests → now 35 tests (all new additions) | git log | VERIFIED |
| No reports deleted | git history | `regression_protection_log.md` | reports/cqa_v1/ intact | git status | VERIFIED |
| Quality gate honestly reported | `quality_gate_verification.md` | N/A (document) | Actual numbers shown, PASS/FAIL stated | Document review | VERIFIED |
| Claim: "TP≥20 met" | — | — | — | **NOT CLAIMED** — honestly reported as FAIL |
| Claim: "learning established" | — | — | — | **NOT CLAIMED** — honestly NOT_ESTABLISHED |

## Summary

- Total claims audited: 22
- VERIFIED: 20
- NOT CLAIMED (honest absence): 2
- UNVERIFIED: 0
- No claim is made without evidence.
- No evidence gap is labeled PASS.
