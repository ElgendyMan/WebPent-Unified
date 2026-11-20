# AVDE v2 Completion Report

## Scope

This release implements the AVDE advisory discovery layer over the existing ASROS and AREX contracts. It remains deterministic, target-neutral, redacted, and bounded. AVDE proposes hypotheses, paths, validation plans, invariant candidates, reviews, and optional scoped reasoning-memory records; it does not create findings, execute transport, grant authority, override policy, or promote qualification.

All benchmark execution in this phase is offline replay of the previously recorded ASROS controlled artifact. The AVDE runner sent zero requests and created no observations or ProofBundles. No external target, credential, login, callback, mutation, or Bug Bounty activity was used.

## Implemented stages

| Stage | Status | Evidence |
|---|---|---|
| Discovery Hypothesis Engine v2 | Complete | Deterministic IDs, vulnerability class, reasoning chain, source lineage, deduplication, redaction, advisory-only output |
| Security Invariant Miner | Complete | Requires actual role/subject contrast, affected entities, validation method, matching WorldModel lineage, fail-closed behavior |
| Active Attack Path Explorer | Complete | Deterministic ranking, capability-aware blocking, bounded cost, generator-safe validation selection, no I/O |
| Behavioral Surface Discovery | Complete | Redacted grouping and deterministic behavioral surface projections |
| Autonomous Validation Strategy | Complete | Lowest-cost bounded path selection; unavailable capability and budget remain blocked |
| Senior Reasoning Reviewer | Complete | Competing explanations, disproof questions, evidence requirements, no finding or signoff |
| Competition Loop | Complete | Advisory deterministic prioritization under budget; no promotion or authority |
| ASROS integration | Complete | Advisory pipeline over WorldModel/attack-graph inputs plus scoped existing SecurityReasoningMemory projection |
| Multi-class controlled benchmark | Complete | Six registered target-neutral class contracts; only recorded evidence is scorable |

## Verification results

| Gate | Result |
|---|---|
| Focused AVDE regression | 9 passed |
| Scoped Ruff format | Passed; 11 files already formatted |
| Scoped Ruff lint | Passed |
| Compileall | Passed |
| Generic target neutrality | Passed; 227 files, 5 roots |
| Secret scan on changed AVDE scope | Passed after replacing a test-only false-positive marker |
| Direct-I/O inventory/G-02 | Passed; 353 records, no external target contact |
| Diff check | Passed |
| Full pytest | 2104 passed, 7 historical failures |

The seven full-suite failures remain the documented pre-existing failures: four `approval_source_hash_mismatch` cases and three missing local source fixtures for WebGoat, crAPI, and Juice Shop. No new AVDE regression appeared.

## Benchmark result

The recorded artifact contains four cases. One case is scorable: the recorded IDOR case is canonically mapped to Broken Access Control. Three cases remain blocked because the source artifact lacks an approved local causal fixture and candidate/control observations. Blocked, inconclusive, and unsupported cases are excluded from TP, FP, FN, clean, confirmed, and qualification calculations.

The benchmark therefore reports one scorable class out of six, with production precision and production recall set to null and `real_world_detection_rate_measured=false`. Conditional internal research indicators are not production quality claims: hypothesis relevance 1.00, proof completeness 1.00, evidence completeness 1.00, validation efficiency 0.333, and registered-class coverage 1/6.

## Governance state

The governing state is unchanged:

| Control | State |
|---|---|
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Human independent signoff | `false` |
| Qualification effect | `false` |
| Real-world detection rate | Not measured |

This release is an engineering completion of the bounded AVDE advisory layer and its truthful offline benchmark. It is not evidence of stable multi-target detection quality, three official isolated runs, P10 qualification, P9 qualification, or VIP qualification.

## Reproducibility

The benchmark source, runner, class inventory, tests, pipeline, gate records, release manifest, and provenance sidecar are included in the release archive. The benchmark command reads only the recorded artifact and must not be interpreted as a live campaign.
