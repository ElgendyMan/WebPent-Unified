# ABHIE v4 — Autonomous Bug Hunter Intelligence Evolution

## Purpose and status

ABHIE v4 is an **expert research-reasoning layer** for WebPent. It is bounded, advisory, target-neutral, and deterministic. It organizes observations, unknowns, security-boundary hypotheses, competing explanations, safe strategy proposals, reflection memory, and attack-chain hypotheses. It does not execute requests, create findings, promote hypotheses, override policy, or qualify a target.

The implementation is intentionally narrower than the project’s qualification and detection-control planes. A research hypothesis is not a vulnerability finding. A quality score in the ABHIE benchmark describes recorded-evidence coverage only; it is not a production precision, recall, F1, or real-world detection claim.

> **Governance invariant:** `official_isolated_p10_runs_authorized=false`, `P10/P9/VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `human_signoff=false`, and `qualification_effect=false` remain unchanged.

## Architecture

The package lives under `src/webpent/abhie/` and is composed of the following bounded components:

| Component | Responsibility | Authority boundary |
|---|---|---|
| `contracts.py` | Frozen dataclasses and enums for brain state, evidence, hypotheses, strategies, chains, quality, and review | Data contracts only; no transport or promotion |
| `brain.py` | Deterministic target/engagement-scoped state construction, snapshot, restore, and digest | Scoped memory; no global state |
| `discovery.py` | Emits five unknown weakness directions from current state | Research directions only; never findings |
| `boundaries.py` | Builds a deterministic security-boundary graph and marks risky crossings | Graph interpretation only; no authorization decision |
| `competition.py` | Generates competing hypotheses, including a benign alternative | Ranking/advisory reasoning only |
| `strategy.py` | Selects a safe read-only/local strategy proposal and blocks unsafe capabilities | Proposal gate only; no execution authority |
| `reflection.py` | Stores redacted, versioned lessons scoped by target and engagement | Reflection only; no cross-engagement leakage |
| `chains.py` | Builds evidence-dependent attack-chain hypotheses | Advisory chain model; no finding or proof creation |
| `review.py` | Performs senior-style fail-closed technical review | Cannot create findings or override the central quality controller |
| `core.py` | Composes the above into one deterministic in-process run | Zero-request, no-mutation orchestration |

ABHIE may consume observations and recorded evidence references from existing WebPent contracts, but the central execution, causal-oracle, sealing, replay, and qualification controls remain authoritative. ABHIE does not duplicate those authorities.

## Research Brain State

Each state is keyed by `(target_ref, engagement_ref)` and carries known observations, unknown directions, risky assumptions, history, and evidence references. Snapshots include the explicit `abhie-v4` version and are restored with enum and tuple semantics intact. Digest calculation is deterministic and supports tamper/version checks. Map-shaped entity and node sources are normalized through values rather than accidentally treating dictionary keys as observations.

## Unknown discovery and boundary reasoning

Discovery produces five neutral research directions: unexpected trust relationships, missing authorization boundaries, incorrect workflow assumptions, inconsistent state transitions, and data-ownership mistakes. Each direction includes a bounded validation strategy that requires an actual causal oracle and independent negative control before any technical confirmation could be considered elsewhere.

Boundary mapping represents users, roles, resources, actions, workflows, trust levels, and states as a graph. Dangerous crossings are opportunities for review, not proof of an access-control failure. Target-specific route semantics belong in adapters or profiles, not in the generic ABHIE package.

## Competing hypotheses and strategy selection

For a boundary-related observation, the hypothesis engine retains multiple explanations, including a benign explanation. The selected item is marked as prioritized for research, not confirmed. Strategy selection is deterministic and prefers a local, read-only, recorded path when the caller provides compatible capabilities. Credential use, login, mutation, destructive behavior, callbacks, and external-target concepts are hard-blocked at proposal level.

## Reflection and attack-chain intelligence

Reflection lessons are redacted before storage and are isolated by target and engagement. A lesson from one scope cannot silently influence another scope. Attack chains require evidence dependencies and explicitly retain causal-oracle, negative-control, sealed-proof, and replay requirements. A chain’s disposition is advisory and cannot become a finding or a qualification result.

## Quality and benchmark contract

`benchmarks/abhie_v4_controlled.py` reads only the historical recorded artifact at `reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json`. It does not contact a target and does not create observations. The benchmark registers exactly six classes:

| Class | Required readiness semantics | Current status |
|---|---|---|
| IDOR | Candidate/control observations, causal oracle, independent negative control, sealed proof, replay | Scorable from the recorded IDOR case only |
| Privilege escalation | Same target-neutral evidence contract | Blocked; no complete recorded evidence |
| Business-logic authorization failure | Same target-neutral evidence contract | Blocked; no complete recorded evidence |
| Tenant isolation | Same target-neutral evidence contract | Blocked; no complete recorded evidence |
| Workflow abuse | Same target-neutral evidence contract | Blocked; no complete recorded evidence |
| Sensitive-information exposure | Same target-neutral evidence contract | Blocked; no complete recorded evidence |

A class is scorable only when the source contains confirmed validation and ground-truth outcomes, a completed proof field, a generated hypothesis, a positive request count, a ground-truth source, and a recorded proof-bundle reference. Missing or incomplete fields remain blocked and are excluded from TP/FN/clean accounting. `abhie_v4_quality.py` reports evidence coverage and execution integrity while keeping production precision, recall, F1, and real-world detection rate null.

## Safety and governance

ABHIE is one-off and in-process. It is not a scheduler, daemon, persistent service, Docker workload, callback listener, or external integration. The milestone sends zero requests, uses no credentials, performs no mutation, and contacts no external target. It cannot open Official P10, start Bug Bounty activity, or change frozen ground truth, thresholds, policy, or human-signoff state.

Technical confirmation outside this layer still requires actual candidate and independent-control observations, a central causal oracle, sealed and replayable proof material, and the project’s existing quality and governance controls. If any of those are missing, the result remains blocked, inconclusive, observation-only, or advisory.

## Verification surface

The focused suite is `tests/test_abhie_v4.py` and `tests/test_abhie_benchmark.py`. It covers deterministic round-trip state integrity, scope isolation, unknown contracts, boundary crossings, benign competition, unsafe strategy blocking, redaction, chain dependencies, fail-closed review, zero-request core behavior, six-class registration, blocked semantics, null production metrics, and governance invariants.

The release gate sequence is documented in the completion report and gate summary. Generated inventory drift is treated as source data and must be committed when the direct-I/O scanner changes it; it is not hidden or rewritten to improve test results.
