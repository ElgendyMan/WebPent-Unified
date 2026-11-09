# JUICE-SHOP-ACCESS-LOG-001 — Before/After Comparison

## Scope

This comparison covers only `juice.access_log_disclosure.v1` on the authorized local Juice Shop instance at `http://127.0.0.1:3000`. It does not modify or qualify the frozen P10 ground truth, and it does not establish P10/VIP qualification.

## Runs

| Dimension | Before | After |
|---|---|---|
| Run artifact | `audit/juice_shop_baseline_quality_run_v1.json` | `audit/juice_shop_access_log_postfix_v5.json` |
| Case status | `blocked_by_precondition` | `confirmed_proof` |
| Causal signal | absent | `true` |
| Independent negative control | not reached | complete and independent |
| Central verifier | not reached | passed |
| ProofBundle | absent | sealed |
| `verify_seal()` / replay | not reached | passed / passed |
| Target-backed observations | unavailable | baseline, candidate, and negative control present |
| Raw data retention | false | false |
| Network policy | authorized loopback only | authorized loopback only |
| Mutation policy | no state mutation | no state mutation |

## Change

The case-local Juice Shop mapping now uses the source-backed log resource under `/support/logs` instead of the previous `/ftp/access.log` path. The semantic profile is `juice.access_log.v1` and requires a bounded public access-log shape: HTTP 200, an application content-type family, and at least two bounded log-record matches. The control is a same-target non-log path with distinct request and response digests.

The shared Playwright adapter received a narrowly generic semantic-navigation fallback for responses that Chromium reports as aborted downloads. It executes a browser-context `fetch` with `credentials: omit`, retains the response body only transiently for the existing semantic extractor, returns categorical/bucketed facts, and does not persist or print the body. This is generic infrastructure behavior, not a Juice Shop route or oracle.

## Evidence result

The post-fix artifact v5 records three target-backed replayable observations, `causal_signal=true`, `negative_control_independent=true`, a sealed ProofBundle, `proof_verified=true`, and `replay_verified=true`. Candidate and control request/response digests are distinct. The artifact contains no raw response body, cookie, authorization value, or credential.

## Decision

The access-log contract is **implemented successfully for this authorized local target and case**. It may be counted as one proof-backed local observation, but it remains outside any final P10 qualification decision until the independent ground-truth, approved-case, three-run, and metrics gates are closed.

No FN, FP, or weak-confirmation metric is inferred from this before/after pair. The before state was blocked, not a negative ground-truth result.
