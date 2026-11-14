# Juice Shop Oracle Semantics Review v1

## Review status

This document is a **review packet**, not an approval record. It was prepared from the implementation review and must be completed by an independent reviewer who is not the author of the adapters. No ground-truth `oracle_status` may be changed based on this document alone.

| Field | Current value |
|---|---|
| Target | `http://127.0.0.1:3000` only |
| Scope | Oracle semantics for three already implemented proof paths |
| Review status | `pending_independent_decision` |
| Results seen by reviewer | Must be recorded by reviewer; default `false` |
| P10/VIP approval | `false` |
| Metrics publication | Prohibited until approval and full-set gates pass |

## Immutable inputs

The reviewer should calculate and record the hashes independently before making a decision.

| Input | SHA-256 |
|---|---|
| `src/webpent/benchmark/juice_shop_oracles.py` | `sha256:d16e139eebcbe7e88f62058e22aa4ffa31ed96a5af8c5187cc29937304902dee` |
| `docs/juice_shop_p10_ground_truth_v1.json` | `sha256:c0b247da1c4aeecbdaa0785621fca9066f51df0178ec92379844e82b9dc3ff07` |
| `src/webpent/shared/semantic_observations.py` | `sha256:c42d0c5d995e03b6e043912bd535653c5394325edf24f1e9186ddd96abcf3fb6` |
| `src/webpent/shared/semantic_proof_runner.py` | `sha256:4f857ca74f0caf3528cbafa93af86580950ccf3f795ee4d01495d07410e286d2` |
| `scripts/run_juice_shop_p10_full.py` | `sha256:afed23ead2359abed92f1f0a6a615f7f8fa1e18686de81e9909cd0541a98ab3b` |

## Common acceptance requirements

The reviewer must evaluate the exact predicate, not only the fact that a live run produced a match. A predicate is acceptable only if it identifies the benchmark vulnerability semantics and excludes ordinary application behavior.

| Requirement | Required decision |
|---|---|
| Candidate, baseline, and independent negative control are target-backed | Accept / Reject |
| Semantic match is allowed only on candidate | Accept / Reject |
| Candidate differs from both baseline and negative control | Accept / Reject |
| No status-only or route-existence-only promotion | Accept / Reject |
| No raw body, header, cookie, payload, screenshot, or probe-value retention | Accept / Reject |
| Central verifier, seal, and replay are mandatory | Accept / Reject |
| Predicate is specific to the benchmark vulnerability, not merely suspicious content | Accept / Reject |
| False-positive control cases are sufficient | Accept / Reject |

## Case A — Exposed Metrics

### Identifiers

| Field | Value |
|---|---|
| Case ID | `juice.exposed_metrics.v1` |
| Semantic profile | `juice.exposed_metrics.v1` |
| Adapter status | Implemented and mechanically promotable |
| Ground-truth status | `frozen_contract_pending_live_proof` |
| Candidate path | The mapped Juice Shop metrics path from `juice_shop_safe_cases.py` |
| Negative-control path | `/p10-negative-control-not-found` |

### Implemented predicate

The candidate must produce all of the following redacted facts:

1. A target-backed response.
2. A `text/plain`-family content type.
3. A bounded, non-zero Prometheus publication-shape count derived from valid `# HELP` / `# TYPE` lines and metric samples.
4. A response digest different from baseline and negative control.
5. A semantic match absent from baseline and negative control.

The adapter persists only content-type family, length bucket, bounded shape counts, path digest, and response digest. It does not persist metric names, labels, values, or body text.

### Vulnerability-semantics question

Does the benchmark define **public Prometheus publication shape on this Juice Shop path** as the expected oracle for the `exposed_metrics` challenge, or is the route merely an intended public observability endpoint? The reviewer must inspect the benchmark definition and challenge intent. A technically valid Prometheus response is not automatically a security vulnerability.

### Decision

```text
oracle_decision: pending
accepted_as_official_gt_oracle: pending
reviewer_reason: pending
```

## Case B — Error Handling / Error Disclosure

### Identifiers

| Field | Value |
|---|---|
| Case ID | `juice.error_handling.v1` |
| Semantic profile | `juice.error_disclosure.v1` |
| Adapter status | Implemented and mechanically promotable |
| Ground-truth status | `frozen_contract_pending_live_proof` |
| Candidate path | The mapped Juice Shop error path from `juice_shop_safe_cases.py` |
| Negative-control path | `/p10-negative-control-not-found` |

### Implemented predicate

The candidate must produce all of the following redacted facts:

1. A target-backed response with a 5xx status class.
2. A bounded verbose-error or stack-shape predicate.
3. A response digest different from baseline and negative control.
4. No semantic match in baseline or negative control.
5. A central causal signal showing that the candidate-specific behavior is attributable to the tested path.

The adapter persists only status class, length bucket, content-type family, bounded error-shape booleans/counts, path digest, and response digest. It does not persist stack paths, source text, body text, headers, or exception values.

### Vulnerability-semantics question

Does the benchmark define **5xx plus verbose stack/error disclosure** as the expected Error Handling vulnerability oracle, rather than treating any server error as a finding? The reviewer must reject the predicate if a normal framework error page or an intentionally exposed challenge response also satisfies it without representing the benchmarked vulnerability.

### Decision

```text
oracle_decision: pending
accepted_as_official_gt_oracle: pending
reviewer_reason: pending
```

## Case C — Existing Local XSS

### Identifiers

| Field | Value |
|---|---|
| Case ID | `juice.local_xss.v1` |
| Proof path | Central `BrowserProofRunner` typed-search workflow |
| Ground-truth status | `frozen_contract_pending_live_proof` |
| Candidate control | Browser input producing a dialog plus response differential |
| Negative control | Independent non-triggering control under the same target scope |

### Implemented predicate

The candidate must satisfy the existing central browser-proof contract: target-backed receipts, candidate-only dialog/response behavior, a causal delta against baseline, an independent negative control, central verification, sealed ProofBundle, and replay status `passed`. Ephemeral probe values remain memory-only and are not retained in artifacts.

### Vulnerability-semantics question

Does the benchmark accept the observed dialog and response differential as the official oracle for the mapped local XSS challenge? The reviewer should confirm that the sink and input path correspond to the intended vulnerability and that the negative control excludes ordinary dialog behavior.

### Decision

```text
oracle_decision: pending
accepted_as_official_gt_oracle: pending
reviewer_reason: pending
```

## Non-approval decisions that remain binding

The following cases are intentionally not proposed for oracle approval by this memo:

| Cases | Current treatment |
|---|---|
| Directory listing / FTP | Observation or blocked; directory shape alone is insufficient |
| Backup resource | Blocked; requires class-specific resource fingerprint |
| Access-log disclosure | Blocked; log-shaped lines alone are insufficient |
| Signature-file disclosure | Blocked; generic signature-like fields are insufficient |
| Security policy / `.well-known` policy | Observation-only; public policy existence is not a vulnerability |
| Public scoreboard route | Observation-only; requires a reviewed authorization differential |
| Privacy policy | Blocked; ordinary policy content is not a vulnerability oracle |

This memo must not be used to widen any of those cases or to convert them into FN/TP records.

## Required independent decision record

An independent reviewer should complete a separate signed or otherwise attributable record containing at least:

```json
{
  "reviewer_id": "",
  "reviewed_at_utc": "",
  "results_seen_by_reviewer": false,
  "reviewed_input_hashes": {
    "oracle_contract": "sha256:",
    "ground_truth": "sha256:",
    "semantic_observations": "sha256:",
    "semantic_proof_runner": "sha256:",
    "full_runner": "sha256:"
  },
  "case_decisions": {
    "juice.exposed_metrics.v1": "pending",
    "juice.error_handling.v1": "pending",
    "juice.local_xss.v1": "pending"
  },
  "accepted_predicate_scope": [],
  "rejected_predicate_scope": [],
  "approval_decision": "pending",
  "reason": ""
}
```

Only after an independent reviewer explicitly accepts the exact predicates may the maintainer update the corresponding ground-truth oracle status. Even then, P10 requires the remaining coverage, approved-set execution, isolation, and scoring gates; oracle approval alone cannot qualify P10 or VIP.
