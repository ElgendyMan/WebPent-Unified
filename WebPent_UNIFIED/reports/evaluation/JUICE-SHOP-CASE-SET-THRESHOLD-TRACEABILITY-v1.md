# Juice Shop Case Set and Threshold Traceability v1

> AI Independent Technical Review completed within the stated scope. This is a non-human attributable technical review and is not a human signature, human countersign, or independent human governance approval.

## Executive decision

The current set remains **3 proposed scoring cases across 3 classes**, pending the required governance signoff. P10 requires **at least 10 approved cases across at least 6 classes and 3 valid isolated runs**; therefore the current gap is **7 cases and 3 classes**, and the Official P10 Run Gate remains closed.

| Control | Current value | Required value | Decision |
|---|---:|---:|---|
| Proposed approved cases | 3 | 10 | FAIL-CLOSED: gap 7 |
| Proposed approved classes | 3 | 6 | FAIL-CLOSED: gap 3 |
| Isolated Official P10 runs | 0 | 3 | Not authorized / not started |
| Human independent signoff | false | true before governance closure | Pending |
| P10 / P9 / VIP | NOT_QUALIFIED | Formal requirements | Not qualified |

## Case traceability

| Case | Category | Mapping | Oracle | Governance disposition | Scoring status |
|---|---|---|---|---|---|
| juice.access_log_disclosure.v1 | Observability Failures | approved | frozen_contract_pending_live_proof | implemented_pending_governance_confirmation | not_in_final_approved_set |
| juice.application_version_surface.v1 | Sensitive Data Exposure | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.basket_manipulate.v1 | Broken Access Control | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.deprecated_interface.v1 | Security Misconfiguration | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.directory_listing.v1 | Sensitive Data Exposure | approved | frozen_contract_pending_live_proof | blocked | excluded_until_reopened |
| juice.error_handling.v1 | Security Misconfiguration | approved | approved_oracle_pending_full_set_metrics | approved_oracle_set_proposed_pending_signoff | proposed_scoring |
| juice.exposed_metrics.v1 | Observability Failures | approved | approved_oracle_pending_full_set_metrics | approved_oracle_set_proposed_pending_signoff | proposed_scoring |
| juice.forgotten_backup.v1 | Sensitive Data Exposure | approved | frozen_contract_pending_live_proof | blocked | excluded_until_reopened |
| juice.local_xss.v1 | XSS | approved | approved_oracle_pending_full_set_metrics | approved_oracle_set_proposed_pending_signoff | proposed_scoring |
| juice.login_admin.v1 | Injection | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.misplaced_signature_file.v1 | Observability Failures | approved | frozen_contract_pending_live_proof | blocked | excluded_until_reopened |
| juice.negative_order.v1 | Improper Input Validation | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.nosql_command.v1 | Injection | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.persisted_xss_feedback.v1 | XSS | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.privacy_policy_proof.v1 | Security through Obscurity | approved | frozen_contract_pending_live_proof | out_of_scope | non_scoring_pending_governance_confirmation |
| juice.public_scoreboard_route.v1 | Miscellaneous | approved | frozen_contract_pending_live_proof | out_of_scope | non_scoring_pending_governance_confirmation |
| juice.redirect_crypto.v1 | Unvalidated Redirects | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.redirect_local.v1 | Unvalidated Redirects | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.reflected_xss.v1 | XSS | out_of_scope | out_of_scope | not_in_current_governance_non_scoring_registry | not_currently_scored |
| juice.security_policy.v1 | Miscellaneous | approved | frozen_contract_pending_live_proof | out_of_scope | non_scoring_pending_governance_confirmation |
| juice.well_known_security_policy.v1 | Miscellaneous | approved | frozen_contract_pending_live_proof | out_of_scope | non_scoring_pending_governance_confirmation |

The 3 proposed scoring cases are `juice.error_handling.v1`, `juice.exposed_metrics.v1`, and `juice.local_xss.v1`. The governance registry contains 8 additional non-scoring cases: one implemented pending governance confirmation, three blocked, and four out of scope. The remaining Ground Truth entries are not current approved scoring cases and must not be promoted merely to satisfy arithmetic.

## Required evidence before any promotion

A candidate may move from diagnosis to an approved scoring set only when a target-backed semantic causal predicate, safe reproducible precondition, baseline/candidate distinction, independent negative control, central verifier, and sealed/replayable ProofBundle are all demonstrated. Source reachability, a successful HTTP status, a static resource, an observation-only signal, or a blocked precondition is insufficient.

## Hash interpretation

The report records the current hashes of the authoritative artifacts for traceability. The historical `hash_lock.mapping_hash` in the Governance Packet is intentionally distinct from the current canonical source-mapping hash; this difference is not treated as a failure by itself and must not be silently rewritten.

| Artifact | SHA-256 |
|---|---|
| governance_packet (`docs/juice_shop_governance_decision_v1.json`) | `sha256:34e02a1b1b20c02d77b1afb946f16650e5aac3b1f396ffafdb310a6a393c3dd0` |
| ground_truth (`docs/juice_shop_p10_ground_truth_v1.json`) | `sha256:84bf4111235b546b337fbd3e76207d43a8e7a05f39685dd9ed51f739468aea52` |
| oracle_decision (`docs/p10_oracle_semantics_decision_v1.json`) | `sha256:637b1f7e10e4224d60e3bcf29abdcaadb2e87aa66ed03d776668b94f1454a97c` |
| expansion_plan (`docs/juice_shop_p10_expansion_plan_v1.json`) | `sha256:0a5a1d38c6f2fe9b7434245acf186cb21a7a3e006682d0116acc491a887776d6` |

## State boundary

`official_isolated_p10_runs_authorized=false` remains unchanged. No external target, Bug Bounty activity, credentials, state-changing action, frozen Ground Truth modification, or qualification declaration is permitted under this review.

## Reproducibility

Machine-readable source: `reports/evaluation/JUICE-SHOP-CASE-SET-THRESHOLD-TRACEABILITY-v1.json`. The report is generated from the Governance Packet, frozen Ground Truth, Oracle Decision, and P10 Expansion Plan at the WebPent revision recorded in the JSON artifact.
