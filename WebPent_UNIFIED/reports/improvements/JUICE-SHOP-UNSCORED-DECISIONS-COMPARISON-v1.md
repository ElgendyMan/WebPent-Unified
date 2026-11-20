# Juice Shop — Unscored Cases Final Decision and Comparison

## Scope and decision rule

This report closes the one-by-one review of the eight cases that were not scoring in the approved Juice Shop local baseline. The review is target-local to the Juice Shop adapter/profile. It does not modify Generic Core, shared verifier semantics, or frozen P10 artifacts.

A case can be approved for implementation only when its contract proves a semantic causal predicate, a safe reproducible precondition, target-backed baseline and candidate observations, an independent negative control, central verification, and a sealed/replayable ProofBundle. Route reachability, source presence, metadata-only observation, and challenge-completion behavior are not sufficient vulnerability proof.

## Final decision matrix

| Case | Baseline classification | Final decision | Implementation status | Evidence boundary |
|---|---|---|---|---|
| `juice.access_log_disclosure.v1` | Blocked by precondition | Contract approved and implemented | Retested successfully | Redacted log-shape predicate; distinct target-backed candidate/control digests; central verification, seal, and replay passed |
| `juice.directory_listing.v1` | Observation-only | Blocked | No implementation | `/ftp` and `/ftp/` did not satisfy directory-index semantics in runtime; no causal delta |
| `juice.forgotten_backup.v1` | Blocked by precondition | Blocked | No implementation | Candidate and control returned `403`; anonymous-read precondition was absent |
| `juice.misplaced_signature_file.v1` | Blocked by precondition | Blocked | No implementation | Mapped file was absent from the local source checkout and both candidate/control returned `403` |
| `juice.privacy_policy_proof.v1` | Blocked by precondition | Out of scope | No implementation | Policy-reading challenge behavior is not a security vulnerability predicate |
| `juice.public_scoreboard_route.v1` | Observation-only | Out of scope | No implementation | Hidden/public route discovery is not a causal vulnerability predicate |
| `juice.security_policy.v1` | Observation-only | Out of scope | No implementation | `/security.txt` is a policy resource, not a vulnerability finding |
| `juice.well_known_security_policy.v1` | Observation-only | Out of scope | No implementation | Alternate policy route duplicated the same resource semantics and metadata |

## Before/after comparison

The baseline contained three proof-backed confirmations overall, four observation-only cases, and four blocked cases. The access-log improvement was the only approved implementation in this review. Its baseline was blocked because the prior mapping and download-navigation handling did not produce a usable semantic candidate observation. The post-fix run used the version-matched `/support/logs` resource and the browser-side semantic download fallback, while retaining transient-only content handling and the central verifier path.

| Measure | Baseline | Post-fix | Interpretation |
|---|---:|---:|---|
| Access-log proof-backed confirmation | 0 | 1 | The case passed its approved target-local contract after the mapping and download-handling fix |
| Access-log independent negative control | Not reached | Passed | Control remained same-target and semantically distinct |
| Access-log ProofBundle seal | Not available | Passed | Promotion was allowed only after central sealing |
| Access-log replay | Not available | Passed | Replay used the verifier-provided context and observations |
| Other seven unscored cases implemented | 0 | 0 | No contract was approved without a demonstrated predicate and precondition |
| Official P10 metrics | Null | Null | Correctly withheld because full ground-truth/oracle approval and isolated full-set runs remain open |

The comparison is not a qualification result. The eight-case review produces one locally implemented and retested contract, three blocked cases, and four out-of-scope cases. The blocked and out-of-scope cases are excluded from FN/FP calculations and are not silently counted as misses.

## Quality and safety boundaries

All approved evidence remains metadata-only and redacted. No raw response body, cookie, credential, or sensitive header is retained in the case results or audit artifacts. Runtime validation was restricted to the authorized Juice Shop loopback service. No bypass, external target, OAST, SSRF, authentication bypass, OTP handling, or destructive state mutation was used.

The implementation and review commits are separate from the earlier Mock fixture implementation. The final review does not alter Generic Core or frozen benchmark artifacts. Local scratch files remain outside Git staging.

## Qualification status

```text
unscored_case_review = CLOSED
approved_implementations_in_this_review = 1
blocked_cases = 3
out_of_scope_cases = 4
p10_qualification = NOT_QUALIFIED
vip_qualification = NOT_QUALIFIED
```

The next valid gate is independent approval of the remaining Juice Shop causal-oracle contracts or an authorized target/version change that makes their preconditions true. No P10 metric may be reported until the approved ground truth, full case set, and three isolated sealed/replayable runs are complete.

## Internal evidence

1. `reports/evaluation/JUICE-SHOP-unscored-case-decisions-v1.md`
2. `reports/evaluation/juice_shop_baseline_quality_v1.md`
3. `reports/improvements/JUICE-SHOP-ACCESS-LOG-001_comparison.md`
4. `audit/juice_shop_baseline_quality_run_v1.json`
5. `audit/juice_shop_access_log_postfix_v5.json`
6. `audit/juice_shop_baseline_analysis_v1.json`
