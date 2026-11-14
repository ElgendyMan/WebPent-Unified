# JUICE-SHOP-ACCESS-LOG-001 — Improvement Proposal and Closure

## Baseline diagnosis

`juice.access_log_disclosure.v1` was `blocked_by_precondition` in the approved Juice Shop local baseline. The baseline path `/ftp/access.log` did not provide a usable proof observation under the current target version. This was a target-local mapping/precondition gap, not an FN and not a Generic Core defect.

## Approved contract

The contract is limited to a public access-log exposure predicate on the authorized loopback Juice Shop instance. A finding is promotable only when the candidate is HTTP 200 and its redacted semantic observation contains a bounded access-log shape with at least two request-log record matches. The baseline is a non-log application navigation. The independent negative control is a same-target non-existent path. All three observations must be target-backed, replayable, and digest-distinct where applicable. Central verification must produce the causal signal, and only a sealed ProofBundle that passes `verify_seal()` and replay may confirm the case.

The operation is anonymous, read-only, loopback-only, and does not retain or print raw log content. No authentication bypass, state mutation, public target, OAST, or external network is permitted.

## Implementation and result

The case-local mapping was corrected to the source-backed `/support/logs/access.log.2026-08-26` resource. The shared Playwright adapter was extended only with generic handling for semantic navigations that Chromium reports as aborted downloads: browser-context fetch with omitted credentials, transient body use by the existing semantic extractor, and metadata-only output. No Juice Shop route or oracle was added to shared core.

The post-fix run is recorded in `audit/juice_shop_access_log_postfix_v3.json`:

- `status = confirmed_proof`
- `verification_passed = true`
- `causal_signal = true`
- `negative_control_complete = true`
- `negative_control_independent = true`
- `proof_bundle_sealed = true`
- `proof_verified = true`
- `replay_verified = true`
- `raw_data_retained = false`
- `raw_data_printed = false`

## Closure decision

The improvement is **accepted for this bounded Juice Shop local case**. The case is now one proof-backed local result. This does not close the global P10 oracle gate, does not establish independent ground-truth approval, and does not qualify P10, P9, or VIP.

The before/after comparison is in `JUICE-SHOP-ACCESS-LOG-001_comparison.md`. The next case must start only after this case's code, regression, rerun, and comparison are committed independently.
