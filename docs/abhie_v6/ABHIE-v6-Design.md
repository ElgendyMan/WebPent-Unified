# ABHIE v6 Design

## Purpose

ABHIE v6 is an **offline, deterministic, advisory research-intelligence layer** for WebPent. It improves how a bounded campaign can organize security assumptions, discover unknown research directions, compare alternative explanations, reason about invariants, construct attack-chain hypotheses, learn from prior investigations, and review evidence quality. It is not an execution engine, finding generator, oracle replacement, or qualification authority.

> A research hypothesis remains a hypothesis until an independently authorized execution path produces candidate/control observations, a central causal oracle accepts them, and the evidence is sealed and replayable.

## Architecture

The package is implemented under `src/webpent/abhie_v6/` and is additive to ABHIP v5 and the existing ASROS contracts. `ResearchAgentCoreV6` consumes target intelligence and produces deterministic advisory decisions containing expected value, confidence, cost, risk, and a bounded next-research objective. `DeepDiscoveryEngineV6` derives hidden-assumption opportunities from recorded graph information. `InvariantReasoningSystemV6` delegates the underlying model semantics to `SecurityWorldModel` and reports `supported`, `disputed`, `unassessed`, or `blocked` states with evidence lineage.

`AttackChainIntelligenceV6`, `ResearchCreativityEngineV6`, and `DifferentialAnalysisV6` provide explainable alternatives and comparisons over identity, role, permission, resource, workflow, and time dimensions. None of them performs transport, mutates state, creates findings, or promotes a hypothesis. `ResearchLearningV4` delegates scoped storage to the existing memory boundary and redacts lessons and evidence references before persistence. Lessons carry situation, decision, outcome, and future recommendation, and are isolated by target and engagement.

`ArchitectReviewV6` consumes the central `ResearchQualityController` before and after review. It reports challenges concerning assumption validity, evidence sufficiency, realistic impact, alternative explanations, and reproducibility. It cannot override policy, oracle, evidence gates, or qualification status.

## Safety and authority boundary

All v6 core paths are in-process and replay-oriented. They have no HTTP client, callback, credential, login, token, cookie, external-target, mutation, destructive-action, scheduler, daemon, or persistent-service behavior. Benchmark execution is explicitly zero-request and reads historical artifacts without editing them.

ABHIE v6 does not create `Finding` objects, claim production detection, convert blocked or observation-only records into false negatives or clean results, generate human signoff, or open Official P10/Bug Bounty gates. The authoritative state remains `official_isolated_p10_runs_authorized=false`, `P10/P9/VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `human_signoff=false`, and `qualification_effect=false`.

## Benchmark and scorecard

The v6 benchmark is the fifth research benchmark contract. It registers six required classes: multi-step IDOR, privilege-escalation chain, business workflow abuse, tenant-isolation failure, complex authorization issue, and sensitive-data exposure chain. Every class requires a realistic target model, hidden assumptions, multiple investigation paths, autonomous reasoning, a causal oracle, a sealed ProofBundle, and replay verification. Missing evidence is blocking.

The current historical artifact contains no case satisfying all seven v6 requirements. Therefore the benchmark records candidates as `BLOCKED`, uses zero requests, leaves production precision/recall/F1 and real-world detection rate as `null`, and excludes blocked records from metrics. The scorecard measures only recorded research-intelligence contract readiness: discovery depth, reasoning quality, evidence strength, research efficiency, strategy improvement, and coverage growth. It does not claim real-world detection.

## Verification

Regression tests cover autonomous decisions, deep discovery, invariant states and lineage, attack-chain dependencies, creativity alternatives, differential dimensions, learning isolation and redaction, architect fail-closed behavior, benchmark quality, evidence integrity, zero requests, and unchanged governance. Static gates are scoped to the new v6 files; full-suite failures, if any, remain explicitly classified rather than hidden.

## Release boundary

The supplied governing specification is preserved as a raw provenance file in the delivery archive. The repository release follows the existing source → manifest → provenance → push workflow. The final archive is built only after parity with `origin/master`, a clean tree, artifact verification, and checksum validation.
