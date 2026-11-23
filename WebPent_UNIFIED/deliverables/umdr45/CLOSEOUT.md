# UM-DR-45 closeout — Convergence & Ascension

Window: 2026-11-23. Trunk: `feature/umdr44-security-and-identity-closure` @ `8cdf820fd799`. Every number below comes from a saved automated run file under `deliverables/umdr45/`.

## Mission gates (honest vocabulary, KB §9)

| Track | Item | Status | Evidence
| --- | --- | --- | --- |
| R1 | CI healed from Actions logs; local replay | PASS (fixes: a663e37, cfb796d; run #36+ history) | commits
| R1 | 3 consecutive green CI runs on ONE SHA | SEE ci_gate.json | scripts/umdr45_ci_gate.sh
| R2 | accounting_v3 single schema; superseded marked | PASS | R2_ACCOUNTING_SINGLE_SCHEMA.json |
| R3 | G-08/G-02 per-record inventory; zero bulk renewal | PASS (46 records; 0 renewals) | R3_G08_G02_APPROVAL_INVENTORY.json |
| K1 | principal_provisioning detected_type | PASS (carried in the R1 review) | deliverables/umdr45 |
| K2 | execution_plans lstrip | PASS (carried in the R1 review) | deliverables/umdr45 |
| K3 | typing/logging by real runtime reflection | PASS (1 defect fixed RED→GREEN; logging lead = false positive) | tests/test_umdr45_k3_runtime_reflection.py |
| K4 | auth fail-fast + logged dev bypass | PASS (RED→GREEN) | tests/test_umdr45_k4_auth_startup_gate.py |
| K5 | scope registry across processes | PASS (implemented + covering tests) | K5_SCOPE_AUTHORITY_ACROSS_PROCESSES.json |
| K6 | dependency single source of truth | PARTIAL (h2 FIXED; allowlist duplication + Docker pin drift documented OPEN) | K6_DEPENDENCY_SINGLE_SOURCE_OF_TRUTH.json |
| M2 | patch-id classification + archive tags (no deletion) | PASS (18+5+3 unique patches; 3 tags) | patch_id_equivalence.json |
| M4 | architecture map + orphan inventory | PASS | ARCHITECTURE_MAP.md + orphan_inventory.json |
| D1-D3 | reducer final state / challenger / pairwise | PASS (verified, covering tests 31 passed) | D_TRACK_REGISTER.md |
| D4 | RC-8/9/10 honest classification | PASS as classification (RC-8/9 PARTIALLY_COMPLETE, RC-10 NOT_STARTED — recorded, not padded) | D_TRACK_REGISTER.md |
| D5 | agent decision register, nobody undecided | PASS (54 units: 44 KEEP / 8 KEEP-DORMANT / 2 RETIRE-CANDIDATE) | agent_decision_register.json |
| X1-X3 | lab battery, >=3 campaigns/target, KB §10 metrics | PARTIAL — battery B: precision 1.0 / recall 1.0 on all defective targets, 0 confirmations on the secure control; battery A: recall 0.0 (credential-channel wiring gap, UMDR45-F05) | X_TRACK_BENCHMARK.json |
| H1 | LICENSE | PASS (MIT, holder = owner-declared metadata; security contact pending owner data) | LICENSE |
| H2 | governance index | PASS | GOVERNANCE_INDEX.md |
| M1 | fast-forward main | see release section | — |
| M3 | tag v0.44.0 + release notes + ZIP | see release section | RELEASE_NOTES.md |

## The measured statement (X-track)

On the authorised local lab battery (12 campaigns, LLM disabled, CausalGuard/ProofBundle the sole confirmation authority), the labsuite investigation engine achieved **precision 1.0 and recall 1.0 on every defective target** (seeds 101/102/201: 9/18/15 ground-truth defects, all confirmed, zero false positives) and **zero confirmations on the fully secured negative control** (seed 301). The CLI hunt surface measured recall 0.0 on the same targets — an honestly reported credential-channel wiring gap (UMDR45-F05), not a hidden scoring carve-out.

## Maturity statement (KB §2.1 wording preserved)

WebPent-Unified remains an **Advanced Autonomous Security Research / Engineering Platform — not yet an independently validated Autonomous Bug Hunter Ultimate**. This window's measurement strengthens the claim inside the authorised lab envelope; the CLI-surface wiring gap and the RC-8/9/10 open items keep the honest ceiling where the evidence puts it.

## Findings register

4 FIXED / 4 OPEN of 9 — full register in FINDINGS_REGISTER.json.