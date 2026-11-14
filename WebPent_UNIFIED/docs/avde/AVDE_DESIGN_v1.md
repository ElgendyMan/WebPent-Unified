# Autonomous Vulnerability Discovery Engine (AVDE) v1

## Purpose and status

AVDE is an advisory discovery layer built on the existing ASROS world model and AREX-controlled execution path. It converts redacted target knowledge, security invariants, behavior projections, and attack-graph hints into deterministic research proposals. It does not execute transport, create findings, promote hypotheses, override policy, or approve qualification.

The implementation is a bounded engineering milestone. It is not evidence of real-world detection rate, official P10/P9 qualification, VIP qualification, or Bug Bounty readiness.

| Boundary | AVDE behavior |
|---|---|
| Input | `SecurityWorldModel`, redacted observations, target-scoped graph metadata |
| Output | Hypotheses, paths, validation plans, invariant candidates, advisory reviews |
| Execution | None; any later action remains under existing ActionAuthority/CampaignExecutor/AREX gates |
| Evidence | References only; no fabricated observations or ProofBundles |
| Governance | `qualification_effect=false`; official run gate remains closed |
| Scope | Generic and target-neutral; target semantics belong in adapters/profiles |

## Discovery contracts

`DiscoveryHypothesisEngine` derives stable SHA-256 identifiers from target, asset, and falsifiable failure condition. It uses ASROS invariants and behavior deviations, deduplicates prior hypothesis IDs, redacts sensitive-shaped values, and orders output by novelty and deterministic ID. A hypothesis includes identity boundary, affected asset, security assumption, failure condition, validation strategy, expected evidence, source references, capabilities, novelty, confidence, and lifecycle status.

`AttackPathExplorer` converts already available graph metadata into typed paths for privilege transitions, trust boundaries, ownership, and workflow abuse. Each path records impact, confidence, validation cost, required capability, expected security value, and an explicit unavailable-capability reason. It never resolves or sends a request.

`BehavioralSurfaceDiscovery` groups observable, redacted behavior by asset and tracks method, role, subject, status, and response class variants. `SecurityInvariantMiner` emits candidates only when role or subject contrast is actually present. A candidate is a falsifiable expectation and always requires an independent negative control; it is not a vulnerability verdict.

`AutonomousValidationStrategy` selects the lowest-cost available bounded proof path under a caller-supplied budget. Empty or unavailable capabilities produce a blocked plan rather than a guessed route. `AVDEAdvisoryPipeline` composes these outputs with `SeniorReasoningReviewer` and preserves explicit no-finding, no-transport, and no-policy-override flags.

## Reasoning and competition

`CompetitionLoop` ranks hypotheses by deterministic confidence multiplied by novelty under a budget. The winner is an advisory prioritization only. `SeniorReasoningReviewer` challenges every proposal with alternative explanations, disproof questions, required evidence, and confidence. It requires causal validation and sealed replayable evidence before any later central verifier can consider a claim. The reviewer cannot create findings, grant human signoff, or approve qualification.

## Verification policy

A later live controlled campaign may score a case only when an immutable target/source reference, ground truth, causal oracle, safe precondition, candidate observation, independent negative-control observation, central verification, and sealed/replayable proof are all present. Route reachability, HTTP success, lesson completion, or health responses are not vulnerability predicates. Blocked, inconclusive, observation-only, and out-of-scope cases remain visible but are excluded from TP/FN/clean scoring.

## Safety and integration

AVDE is in-process and deterministic. It introduces no daemon, scheduler, polling service, Docker dependency, direct transport, credentials, login flow, callback, mutation, or external target support. Any future execution must be represented as an advisory proposal and routed through the existing ASROS/AREX/CampaignExecutor authority chain. The official gate remains `official_isolated_p10_runs_authorized=false`, with P10/P9/VIP `NOT_QUALIFIED` and Bug Bounty `BLOCKED`.
