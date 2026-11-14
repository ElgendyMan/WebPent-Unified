# ABHIE v6 Gap Analysis

## Baseline

The repository is clean and aligned with `origin/master` at commit `cdb64203badd786ffe34d25af045ed9d086251ee`. ABHIP v5 already provides a target-scoped intelligence graph, ranked security questions, bounded mission planning, a recorded-input research loop, differential comparison contracts, advisory vulnerability reasoning, scoped memory, benchmark generation, and a non-authoritative reviewer.

## Reuse decisions

ABHIE v6 will extend the existing contracts instead of creating a second execution or evidence authority. `TargetKnowledgeV2`, `SecurityWorldModel`, `SecurityInvariant`, `BehaviorObservation`, `ResearchQualityController`, `ResearchBudget`, `SecurityReasoningMemory`, and the ABHIP v5 graph/question/loop contracts remain the source of truth for their respective concerns. New v6 code will consume these contracts through adapters and will only produce advisory plans, hypotheses, invariant assessments, chains, lessons, scorecards, and review reports.

## Remaining gaps

| Specification capability | Existing baseline | v6 additive closure |
|---|---|---|
| Unified autonomous research controller | ABHIP v5 mission planner | `ResearchAgentCoreV6` combines graph, attack graph, boundaries, memory, evidence and coverage into deterministic strategy decisions without execution authority. |
| Deep discovery of assumption violations | Security-question generation | `DeepDiscoveryEngineV6` emits candidates with violated assumptions, assets, reasoning, evidence requirements, and validation plans. |
| Invariant reasoning | ASROS world-model primitives | `InvariantReasoningSystemV6` composes `SecurityWorldModel` and keeps supported/disputed/unassessed/blocked states fail-closed. |
| Complex attack chains | Existing chain contracts in earlier milestones | `AttackChainIntelligenceV6` creates dependency-linked hypotheses only; it never creates findings or proof. |
| Controlled creativity | Competing-hypothesis behavior | `ResearchCreativityEngineV6` ranks alternative explanations and related directions with evidence links. |
| Differential analysis | ABHIP v5 five-dimension report | v6 adds permissions, resources, workflow-state, and time-state dimensions while preserving no-promotion semantics. |
| Learning v4 | Scoped ABHIP memory | `ResearchLearningV4` stores target/engagement-isolated lessons from success, rejection, false leads, blocks, and incomplete evidence. |
| Benchmark v5 | ABHIP v4 controlled artifact | v6 benchmark registers the six required classes and joins only recorded complete evidence; missing evidence remains blocked and production metrics remain unavailable. |
| Research Intelligence Scorecard | Internal benchmark metrics | v6 scorecard reports depth, reasoning, evidence, efficiency, strategy improvement, coverage, and learning without claiming real-world detection. |
| Architect review | ABHIP v5 advisory reviewer | `ArchitectReviewV6` challenges validity, evidence, impact, alternatives, and reproducibility while delegating the actual gate boundary to the central quality controller. |

## Safety and governance boundary

The v6 milestone is offline and in-process. It sends zero requests, accepts no callback, credential, login, token, mutation, destructive action, or external target, and does not run a service or scheduler. No component can create findings, override policy or oracle, seal proof, approve qualification, or change the permanent governance state. `official_isolated_p10_runs_authorized` remains false and P10/P9/VIP remain not qualified.

## Implementation order

The implementation will proceed from contracts and the agent core, through discovery/invariants/chains/creativity/differential analysis, then learning/benchmark/scorecard/review, followed by focused regression, full-suite gates, manifest/provenance, and a final archive. All new behavior will be deterministic and driven by supplied recorded inputs.
