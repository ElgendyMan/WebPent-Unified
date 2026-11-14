# Juice Shop — Unscored Case Decision Matrix v1

## Scope

This decision matrix covers only the eight cases that were not scoring in the approved local baseline run. It is target-local to the Juice Shop adapter/profile and does not change Generic Core, shared verifier semantics, or frozen P10 artifacts. The baseline run remains the source of observed execution status; the decisions below are contract decisions, not retrospective FN/FP labels.

A case may be promoted only when its contract defines a semantic causal predicate, a safe and reproducible precondition, target-backed baseline/candidate observations, an independent negative control, central verification, and a sealed/replayable ProofBundle. Metadata-only observation is never promoted to a vulnerability finding by itself.

## Independent case decisions

| Case | Baseline status | Decision | Contract decision and boundary |
|---|---|---|---|
| `juice.access_log_disclosure.v1` | `blocked_by_precondition` | `implemented_and_retested` | Contract approved and implemented in a case-local change. The semantic predicate is a publicly retrievable server access-log resource, proved by redacted log-shape metadata. The loopback/read-only precondition held; baseline, candidate, and independent same-target non-log control produced distinct digests; central sealing and replay passed. |
| `juice.directory_listing.v1` | `observation_only` | `blocked` | The source semantics are a directory-listing exposure, but the local runtime precondition did not hold: `/ftp` and `/ftp/` returned an HTML error-shaped response with `directory_shape=false` and no child-link shape. The candidate and independent nonexistent-path control both failed the causal predicate, so no contract was implemented and no ProofBundle was created. Re-open only after a target-local runtime/configuration review establishes the directory-index predicate without bypassing controls. |
| `juice.forgotten_backup.v1` | `blocked_by_precondition` | `blocked` | The source contains `ftp/coupons_2013.md.bak`, but the local runtime returned `403 Forbidden` for both the candidate resource and an unrelated nonexistent backup control. The anonymous-read precondition and causal delta were not demonstrated; no contract implementation or ProofBundle promotion is justified. Re-open only after an authorized target-local configuration review changes the runtime precondition without bypassing controls or exposing raw backup content. |
| `juice.misplaced_signature_file.v1` | `blocked_by_precondition` | `blocked` | The mapped `ftp/suspicious_errors.yml` resource is absent from the local source checkout, and the local runtime returned `403 Forbidden` for both the candidate and an unrelated signature control. The safe precondition and causal predicate are unavailable on this target version; no target-local contract or ProofBundle implementation is justified. Re-open only after a version-matched, authorized source/runtime mapping is established without retaining raw YAML. |
| `juice.privacy_policy_proof.v1` | `blocked_by_precondition` | `out_of_scope` | Source semantics are a challenge-completion proof that the user read a privacy policy, not a security weakness. A route hit cannot be a causal vulnerability oracle; no P10 scoring contract is approved. It may remain an observation-only compatibility case. |
| `juice.public_scoreboard_route.v1` | `observation_only` | `out_of_scope` | Source semantics are discovering a hidden Score Board page. Route reachability is not a vulnerability predicate and must not become a confirmed finding. Retain only as non-scoring inventory/observation. |
| `juice.security_policy.v1` | `observation_only` | `out_of_scope` | Source semantics describe ethical-research guidance and a good-practice policy document. Public policy availability is not a vulnerability oracle. No exploit or scoring contract is approved. |
| `juice.well_known_security_policy.v1` | `observation_only` | `out_of_scope` | This is an alternate policy-resource location sharing the `securityPolicyChallenge` semantics. It is not an independent vulnerability case and cannot be promoted by route existence or duplicate policy content. Retain as observation-only inventory. |

## Approval boundary

The exposure cases are reviewed one at a time. `juice.access_log_disclosure.v1` completed its target-local implementation, regression, rerun, and before/after comparison in its own case commit. The remaining exposure cases are not started until their individual contract review is explicitly closed. These are engineering decisions for the local lab, not independent governance approval of P10 ground truth.

The four `out_of_scope` decisions close their review without code changes. They are excluded from FN/FP calculations and from approved P10 coverage. No metrics are released until the independent ground-truth and oracle gates are closed.

## Required evidence for every approved implementation

The adapter must produce redaction-safe target-backed baseline, candidate, and independent negative-control observations. The central verifier must derive the causal result, and only a sealed ProofBundle that passes `verify_seal()` and replay may promote the case. CaseResult serialization must exclude runtime verification and raw cookies, credentials, headers, and response bodies. The implementation must declare no network outside the authorized loopback target and no state mutation.

## Current decision

`decision_matrix_status = case_8_closed_out_of_scope_all_unscored_cases_reviewed`

`p10_qualification = NOT_QUALIFIED`

`vip_qualification = NOT_QUALIFIED`
