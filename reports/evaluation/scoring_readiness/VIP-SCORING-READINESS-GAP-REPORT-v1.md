# VIP Scoring Readiness Gap Report v1

## Executive decision

The Real Local Autonomous Validation phase proved **lifecycle portability and safety** across three loopback targets. It did not prove detection-quality portability. This phase therefore produces readiness packages and evidence boundaries, not a P10 or VIP qualification decision.

> A target is not scoring-ready because a route responds, a lesson loads, a health check succeeds, or an HTTP status is interesting. Scoring requires an admitted semantic causal predicate, safe precondition, independent ground truth, independent negative control, central verification, and sealed/replayable proof.

## Current status

| Gate | Current state |
|---|---|
| Generic architecture | PASS |
| Loopback safety | PASS |
| Juice Shop causal readiness | Partial: 3 cases / 3 classes |
| WebGoat causal readiness | Blocked: 0 cases / 0 classes |
| crAPI causal readiness | Blocked: 0 cases / 0 classes; runtime image provenance not immutable |
| Official isolated P10 run gate | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |

## What was executed in this phase

The following artifacts were prepared and validated without target I/O: three machine-readable Target Packages, a multi-target ground-truth matrix, an oracle contract register, a quality-baseline register, a package validator, and regression tests. Juice Shop references its existing bounded baseline and three already admitted proof-backed cases. WebGoat and crAPI are represented as explicit blocked packages with empty approved sets; no synthetic ground truth or oracle was created.

For the three admitted Juice Shop cases, the existing evidence chain remains: baseline, target-local semantic contract, safe precondition, independent negative control, central verifier mapping, sealed ProofBundle, `verify_seal()`, replay, and regression coverage. No new root/health observation was rerun because it cannot create scoring evidence.

## Target-specific blockers

### Juice Shop

Juice Shop has only the current partial approved set: `juice.error_handling.v1`, `juice.exposed_metrics.v1`, and `juice.local_xss.v1`. The current frozen mapping and oracle register admit **3 cases across 3 classes**. The existing baseline contains 11 mapped cases, but the remaining rows are not automatically eligible: observation-only, blocked, and out-of-scope dispositions remain non-scoring and are not FN, FP, TP, clean, or confirmed.

To reach the formal P10 threshold, seven additional cases and three additional classes must be admitted with independent causal contracts. This cannot be achieved by relabeling the remaining rows or modifying frozen ground truth.

### WebGoat

No target-local scoring adapter/profile, independent ground-truth mapping, causal oracle, safe precondition, or independent negative-control contract is admitted. The existing lifecycle result is observation-only. Lesson completion, route reachability, redirects, and HTTP status are explicitly excluded as vulnerability predicates. The next safe work is source-backed candidate inventory and contract proposals, one case at a time, with no credentials or state-changing workflow.

### crAPI

No target-local scoring adapter/profile, independent ground-truth mapping, causal oracle, safe precondition, or independent negative-control contract is admitted. The existing lifecycle result is observation-only. The compose configuration uses mutable `latest` image references, so strict runtime reproducibility is not admitted. Before any scoring claim, the runtime must be pinned to an immutable digest and recorded in the source/runtime manifest.

## Generic versus target-local classification

| Work item | Classification | Decision |
|---|---|---|
| Readiness package schema/validator | Generic | Implemented and regression-tested across all three packages; no target I/O |
| Loopback/GET-only/no-raw-retention invariants | Generic | Reused and validated; no relaxation |
| Juice Shop semantic predicates and routes | Target-local | Remain in Juice Shop adapter/profile and frozen mapping |
| WebGoat lesson semantics | Target-local | Not implemented or inferred; requires independent contract |
| crAPI API/business semantics | Target-local | Not implemented or inferred; requires independent contract |
| Official thresholds, frozen GT, run authorization | Governance | Not changed; owner approval remains required |

## Required workflow for each future admitted case

For each candidate that passes scope and safety review, the evidence sequence is:

`Baseline → Quality Measurement → Failure Diagnosis → Improvement Proposal → Generic-vs-Target-Local Classification → Safe Implementation → Regression → Same-Condition Re-test → Before/After Comparison → Central Verification → Seal → verify_seal() → Replay → Metrics Recompute`.

A candidate is rejected or remains blocked if any causal predicate, precondition, negative control, verifier mapping, or proof requirement is missing. A failure in a target-local adapter may produce a target-local proposal; a generic change is accepted only after passing regression evidence for more than one target.

## Remaining path to P10 and VIP

The immediate engineering path is to build independent, source-backed candidate inventories for WebGoat and crAPI and to review additional Juice Shop candidates without forcing admission. Each accepted candidate needs a complete contract package and a bounded local run. After the final approved set genuinely reaches at least 10 cases and 6 classes, and after independent governance signoff, the owner may decide whether to open the Official P10 run gate.

Only after that gate is explicitly opened may three isolated official runs be performed, each with an independent run ID, workspace, ProofBundle set, seal/replay verification, and metrics recomputation. Final qualification remains a separate decision. No step in this pack opens that gate, changes thresholds, modifies frozen ground truth, uses credentials, contacts an external target, or starts Bug Bounty activity.
