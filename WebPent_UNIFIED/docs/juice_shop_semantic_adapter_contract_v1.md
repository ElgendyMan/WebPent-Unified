# Juice Shop Semantic Adapter Contract v1

## Purpose

This contract defines how a Juice Shop response may become a proof candidate without retaining raw response bodies, headers, cookies, payloads, screenshots, or probe values. A route returning HTTP 200 is never sufficient. A semantic adapter may only emit bounded categories, counters, booleans, and digests. The central `SemanticProofRunner` must then demonstrate a candidate delta against both a baseline and an independent negative control before the central verifier can seal and replay a `ProofBundle`.

## Promotion invariant

A `proof_case_id` is emitted only when all of the following are true:

| Requirement | Required value |
|---|---|
| Candidate target-backed | `true` |
| Baseline target-backed | `true` |
| Negative control target-backed | `true` |
| Candidate semantic predicate | `true` |
| Baseline semantic predicate | `false` |
| Negative-control semantic predicate | `false` |
| Candidate response differs from baseline | required |
| Candidate response differs from negative control | required |
| Causal signal | `true` |
| Negative control complete | `true` |
| Central proof verification | `proof_verified=true` |
| ProofBundle seal | verified by the central verifier |
| Replay | `replay_status=passed` |

Any missing or contradictory condition remains `blocked_by_precondition` or `confirmed_metadata_only`; it is not a TP, FP, or FN.

## Current profiles

| Case / profile | Semantic predicate | Current status | Reason for status |
|---|---|---|---|
| `juice.exposed_metrics.v1` | HTTP 200, `text/plain` family, bounded Prometheus publication-shape count | Promotable adapter implemented | The candidate can be distinguished from root and an independent not-found control using redacted facts. It still requires independent oracle approval before P10 counting. |
| `juice.error_handling.v1` / `juice.error_disclosure.v1` | HTTP 5xx plus bounded verbose-error stack shape | Promotable adapter implemented | The candidate must expose both server-error status and a redacted stack-shape predicate; a 4xx or ordinary error page does not match. It still requires independent oracle approval before P10 counting. |
| `juice.directory_listing.v1` | Bounded directory-listing shape | Observation-only | Directory wording or an `/ftp/` route is not, by itself, proof of an unintended sensitive resource exposure. A class-specific resource oracle is required. |
| `juice.forgotten_backup.v1` / `juice.static_resource.v1` | Resource fingerprint and class-specific backup semantics | Blocked | Status, length, and content type cannot establish that the resource is an unintended backup. A reviewed redacted fingerprint and expected-resource exclusion are required. |
| `juice.access_log_disclosure.v1` / `juice.log_disclosure.v1` | Bounded log-record-shape count | Blocked | Log-shaped lines alone do not establish disclosure of a sensitive server log. An independently reviewed disclosure oracle is required. |
| `juice.misplaced_signature_file.v1` / `juice.signature_disclosure.v1` | Bounded signature-field count | Blocked | Generic `version`/`signature`/`error` fields do not establish exposure of a signature file. A class-specific file fingerprint and disclosure oracle are required. |
| `juice.security_policy.v1` / `juice.policy_resource.v1` | Bounded policy-directive count | Observation-only | A valid policy document is normally a public resource, not a vulnerability. A reviewed misconfiguration predicate is required before promotion. |
| `juice.well_known_security_policy.v1` / `juice.policy_resource.v1` | Bounded policy-directive count | Observation-only | `.well-known` policy existence is not itself a security finding. The adapter deliberately refuses promotion. |
| `juice.public_scoreboard_route.v1` / `juice.public_route.v1` | Bounded scoreboard-shape boolean | Observation-only | A public scoreboard route is application functionality, not automatically an access-control flaw. An authorization differential oracle is required. |
| `juice.privacy_policy_proof.v1` | Bounded privacy-page shape | Blocked | Privacy-policy content is not an approved vulnerability oracle. It is intentionally excluded from semantic promotion. |

## Implementation boundary

`semantic_observations.py` is target-independent in its projection mechanics but the registered profile names and predicates are target-specific. `semantic_proof_runner.py` is generic and delegates all transport to the existing browser control plane. Juice Shop case mappings are kept in the full runner and must not be reused for another target.

The response body is read only inside the transient Playwright derivation boundary. The adapter returns no body text, header map, cookie, metric name, log line, signature value, stack path, or probe value. The persisted observation contains only allowlisted redacted fields.

## Oracle readiness rule

Adding a parser or a live semantic match does not make an oracle ready. The ground-truth oracle remains `frozen_contract_pending_live_proof` until an independent review approves the vulnerability semantics and the exact predicate. Therefore the current full-run evaluator must continue to withhold P10 metrics even though three live proof paths can now be exercised.

## Required next adapters

The next implementation work should focus on reviewed class-specific predicates, not generic status checks:

1. A backup-resource fingerprint that distinguishes an unintended backup from an ordinary static resource without persisting names or content.
2. A log-disclosure oracle that proves a sensitive log publication rather than merely matching request-line syntax.
3. A signature-file oracle that distinguishes a known signature artifact from a generic JSON error response.
4. An authorization differential for the public scoreboard route using anonymous, non-authenticated controls only; no account creation, login, credentials, OTP, or bypass is allowed.
5. A reviewed policy-misconfiguration oracle, if the benchmark definition considers one in scope; otherwise the policy cases remain observation-only.

Until those predicates are independently reviewed and pass the central baseline/candidate/negative-control contract, the cases must remain blocked.
