# Juice Shop Governance Decision — Corrected Packet

**Decision ID:** `juice-shop-governance-20260826-01`

**Packet status:** `CHANGES_REQUESTED_CORRECTED_PENDING_HUMAN_INDEPENDENT_REVIEW`

**Scope:** Authorized local loopback lab only (`http://127.0.0.1:3000`)

**Juice Shop version/source:** `20.2.0` / `1618a611b173b4bf114028e6e02549950606e29d`

## Decision status

> **Governance status: `PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF`.**

This corrected packet addresses the source-to-governance drift identified in review. It does **not** self-approve, does not authorize Official P10 Runs, and does not confer P10, P9, or VIP qualification. A human independent reviewer must inspect this exact packet, the referenced hashes, the frozen ground truth, the oracle decision, the source-derived snapshot, and the source-to-ground-truth manifest.

The earlier packet is treated as superseded for review purposes because its provenance and current-source hash references were incomplete. The corrected source manifest is generated from WebPent commit `88991a96d2f02d98aa652bc452ad33bf30b17615` and tree `74f1f9730fd8f58b9d3349347319824321d6767e`.
The frozen ground-truth document remains unchanged; the corrected materials expose the drift instead of rewriting it.

## Corrected drift register

| Review finding | Corrected treatment | Remaining governance status |
|---|---|---|
| WebPent commit provenance was not verifiable from the project archive | The corrected release process records the commit and tree provenance separately from the release manifest, and the corrected project archive includes a provenance sidecar | Requires human verification against the corrected archive |
| Access-log path differed between frozen GT and current source | The source registry remains the current runtime mapping `/support/logs/access.log.2026-08-26`; frozen GT remains `/ftp/access.log`; the mismatch is explicitly recorded in the source-to-ground-truth manifest | Requires an independently governed mapping decision; frozen GT is not silently changed |
| Oracle contract hash was stale | The packet now records the current source oracle hash `sha256:63977f...aeb71c`, preserves the prior independently reviewed hash `sha256:d16e...902dee`, and marks current reconfirmation pending | Human reviewer must reconfirm current source hash |
| Release manifest was stale | It is regenerated from the corrected source tree and records reproducible provenance with its own output excluded from the file-hash list | Release artifact must be checked against the recorded provenance commit |
| Seven-vs-eight non-scoring discrepancy | The authoritative Juice Shop count is 8; the value 7 comes only from a separate synthetic 10-case unit-test fixture | Neither blocked nor out-of-scope cases are FN |

## Case dispositions

| Case | Current disposition | Official scoring treatment | Basis |
|---|---|---|---|
| `juice.access_log_disclosure.v1` | Implemented and retested; governance confirmation pending | Excluded until the current source mapping and causal predicate are independently confirmed | Target-local implementation produced verified, sealed, replayable proof, but the prior oracle decision accepted only three other predicates |
| `juice.directory_listing.v1` | `blocked` | Excluded until safely reopened | Directory-index causal predicate was not established |
| `juice.forgotten_backup.v1` | `blocked` | Excluded until safely reopened | Anonymous-read precondition and causal delta were not demonstrated |
| `juice.misplaced_signature_file.v1` | `blocked` | Excluded until safely reopened | Version-matched signature exposure was not established |
| `juice.privacy_policy_proof.v1` | `out_of_scope` pending human confirmation | Non-scoring | Policy/challenge-completion behavior is not a vulnerability causal predicate |
| `juice.public_scoreboard_route.v1` | `out_of_scope` pending human confirmation | Non-scoring | Route reachability does not establish a security weakness |
| `juice.security_policy.v1` | `out_of_scope` pending human confirmation | Non-scoring | A public security-policy resource is not a vulnerability oracle |
| `juice.well_known_security_policy.v1` | `out_of_scope` pending human confirmation | Non-scoring | The alternate policy location duplicates policy semantics |

There are **8 engineering-reviewed non-scoring cases** in this local decision cycle. The three blocked cases and four out-of-scope cases are not FN and must not be counted as TP, FP, or recall denominators. Access-log is the eighth engineering-reviewed case and remains pending confirmation rather than being silently scored.

## Seven-versus-eight reconciliation

The authoritative Juice Shop governance count is **8 mapping-approved but oracle-unapproved cases**: access-log, directory listing, forgotten backup, misplaced signature, privacy policy, public scoreboard, security policy, and well-known security policy. The value **7** is produced only by `tests/test_p10_benchmark.py`, which uses a separate synthetic fixture containing 10 truth cases and 3 oracle-approved cases. That unit-test value is not the Juice Shop production inventory and must not be used in the governance packet as the target count.

## Proposed scoring set and P10 gate

The prior oracle decision explicitly accepted only:

```text
juice.error_handling.v1
juice.exposed_metrics.v1
juice.local_xss.v1
```

The corrected packet carries this as a **proposed** set pending human independent reconfirmation. It contains 3 cases and 3 classes, below the minimum 10 cases and 6 classes. Therefore:

```text
official_isolated_p10_runs_authorized = false
p10 = NOT_QUALIFIED
p9 = NOT_QUALIFIED
vip = NOT_QUALIFIED
bug_bounty = BLOCKED
```

No Official P10 Runs, metrics calculation, or qualification claim is permitted at this stage.

## Hash and provenance locks

| Input | Corrected value/status |
|---|---|
| Prior canonical mapping lock | `sha256:602b2411df9b259911b1ae0757e5e26fabdc86b928fb5b43b040750182762ad5` |
| Prior canonical oracle mapping lock | `sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c` |
| Prior independently reviewed oracle-contract hash | `sha256:d16e139eebcbe7e88f62058e22aa4ffa31ed96a5af8c5187cc29937304902dee` |
| Current source mapping hash | `sha256:db72b2b70ab3b05ef5d93f82376d21c69b10058f3cac026ee2f60bf45c51069a` |
| Current source oracle-contract hash | `sha256:63977f8451f0709abff5671d1ac24943abe35b0bb0a4f399791e2c1f66aeb71c` |
| Oracle decision file hash | `sha256:637b1f7e10e4224d60e3bcf29abdcaadb2e87aa66ed03d776668b94f1454a97c` |
| Frozen ground-truth file hash | `sha256:84bf4111235b546b337fbd3e76207d43a8e7a05f39685dd9ed51f739468aea52` |
| Corrected source snapshot ID/hash | `gt-snapshot-20260826-corrected` / `sha256:4bc02c4664aa06230b6617085134ba12080e99767f457c82ddd917c48f471963` |
| Source-to-ground-truth manifest hash | `sha256:1ad18256e8d0b42041bc9b008ece8de7573603a21c8a898f639d1049ec2b5575` |
| Source manifest WebPent commit/tree | `88991a96d2f02d98aa652bc452ad33bf30b17615` / `74f1f9730fd8f58b9d3349347319824321d6767e` |
| Loopback runtime manifest hash | `sha256:cbe1c85fe8e7393449595d59de03d84cb45692f020709d30f4516e9c8995a524` |

Canonical review locks are distinct from current-source hashes and raw file hashes. The current oracle hash has **not** yet received human independent reconfirmation. The frozen ground truth was not modified.

## Required human independent review

The reviewer must identify themselves as a human independent reviewer, record a UTC timestamp, verify the corrected archive provenance, inspect all listed hashes, confirm the access-log path drift, resolve each of the eight engineering-reviewed dispositions, distinguish the synthetic value 7 from the authoritative Juice Shop value 8, and explicitly record `official_isolated_p10_runs_authorized=false`. A reviewer identity must not be fabricated by the packet preparer.

Only after a signed decision freezes an approved set of at least 10 cases and 6 classes, with accepted causal-oracle contracts and safe evidence requirements for every approved case, may the project consider three isolated P10 runs. Each run would then require independent run ID, workspace, ProofBundle IDs, sealing, `verify_seal()`, replay, recomputed metrics, and final independent review.

## Safety boundaries

All reviewed activity remains limited to the authorized loopback target and bounded read-only GET operations. No external destination, credentials, raw HTTP bodies, cookies, Generic Core modification, frozen P10 artifact modification, or administrative elevation is authorized by this packet.

## References

1. `docs/juice_shop_p10_ground_truth_v1.json` — frozen mapping-only ground truth.
2. `docs/p10_oracle_semantics_decision_v1.json` — prior partial oracle decision.
3. `docs/juice_shop_source_ground_truth_manifest_v1.json` — corrected source-to-ground-truth drift manifest.
4. `docs/juice_shop_loopback_runtime_manifest_v1.json` — loopback safety evidence.
5. `docs/release_manifest.json` — corrected release inventory and provenance metadata.
