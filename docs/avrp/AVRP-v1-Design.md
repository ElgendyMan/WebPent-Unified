# Autonomous Vulnerability Research Platform Upgrade (AVRP) v1

## Purpose and boundary

AVRP v1 adds a bounded advisory research layer to WebPent. It maintains scoped research memory, relates recorded observations, generalizes target-neutral reasoning patterns, adapts research direction, tracks coverage, reasons about possible chains, proposes explainable learning updates, and composes with the central ASROS quality review. It does **not** execute requests, create findings, promote hypotheses, open a qualification gate, or replace ActionAuthority, AREX, CampaignExecutor, the causal oracle, or the central quality controller.

The implementation is deliberately in-process and deterministic. The AVRP benchmark is an offline replay/inventory over an already recorded controlled artifact. The runner emitted zero requests and created no observations or ProofBundles. External targets, credentials, login, callbacks, mutation, destructive actions, polling, daemons, schedulers, Docker services, and persistent infrastructure are outside this release boundary.

## Architecture

| Layer | Implementation | Contract boundary |
|---|---|---|
| Scoped continuity | `ResearchMemoryState`, `ResearchStateUpdate`, `StateTransition` | Target and engagement are part of the state identity; snapshots are versioned and tamper-checked. |
| Evidence correlation | `EvidenceCorrelationEngine`, `EvidenceRelationshipGraph`, `SecurityRelationship` | Accepts typed `InformationObservation` values and emits redacted deterministic relationships. |
| Generic reasoning | `VulnerabilityPatternLibrary` and five reusable patterns | Authorization, ownership, privilege, workflow, and data-exposure patterns are target-neutral. |
| Adaptive loop | `AutonomousResearchLoopV2` | Reuses AVDE discovery/exploration/strategy contracts and emits advisory research steps only. |
| Coverage | `CoverageRecord`, `CoverageIntelligence` | Records explored/unexplored dimensions, missing evidence, and blind spots without claiming detection. |
| Chain reasoning | `AttackChainHypothesis`, `AdvancedAttackChainReasoner` | Requires explicit evidence linkage and remains blocked without causal, control, seal, and replay evidence. |
| Self-improvement | `ResearchOutcome`, `PriorityWeightUpdate`, `SelfImprovementReport` | Produces scoped, explainable proposals; it does not mutate global or cross-target policy. |
| Quality review | `AdvancedResearchQualityReviewer`, `ResearchQualityReview` | Composes with ASROS `PostExecutionReview`; it cannot create findings, override an oracle, or sign off qualification. |
| Evaluation | `avrp_multiclass_controlled.py` | Five scenario contracts; only complete recorded evidence can become scorable. |

## State and evidence invariants

State updates require a field, evidence references, a reason, and a confidence value. Update identifiers are deterministic for the same scoped content, and duplicate updates are rejected or deduplicated according to the state contract. Snapshot restoration validates schema version, target/engagement scope, and integrity. The implementation redacts bounded free-form values before persistence.

Correlation uses `InformationObservation` instances rather than untyped mappings. Relationships are derived from explicit observation evidence and target scope. A graph hash is stable for the same normalized graph. The result is a reasoning artifact, not a proof of exploitability.

A chain may remain a hypothesis even when relationships exist. The chain reasoner requires explicit source references; accidental identifier overlap is not treated as evidence. Causal evidence, an independent negative control, a sealed bundle, and replayability are all required before the review can be advisory-ready. Even then, the reviewer returns no finding and no qualification effect.

## Loop behavior

The loop uses the current AVDE interfaces: hypothesis generation, path exploration, and advisory strategy selection. It records observations and failures into scoped memory, correlates typed observations when provided, summarizes coverage, and proposes adaptive direction. A recorded failure can deprioritize a path and allow the loop to continue without retrying the same hypothesis. The loop never calls a transport, executor, validator mutation path, or external service.

## Evaluation contract

The v1 benchmark registers exactly five scenario classes: IDOR, privilege escalation, business-logic authorization failure, information disclosure, and authentication-boundary issue. It joins those contracts only to actual recorded source cases. The current source artifact contains one complete IDOR case and blocked records for three other classes; there is no complete recorded authentication-boundary case. Consequently, the AVRP artifact reports one scorable case and four blocked scenarios. Blocked, observation-only, inconclusive, or unavailable scenarios are excluded from TP/FN/clean scoring.

Research-quality indicators are calculated only over complete recorded cases. Production precision, production recall, F1, and real-world detection rate remain unavailable because the approved multi-case ground truth and official isolated runs do not exist in this milestone. The historical ASROS artifact is read-only input and is not rewritten.

## Governing statuses

The release preserves the required closed governance state:

| Status | Value |
|---|---|
| Official isolated P10 runs authorized | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Human signoff | `false` |
| Qualification effect | `false` |

## References

[1]: ../../pasted_content_11.txt "AVRP v1 governing specification"
[2]: ../../src/webpent/asros/quality_controller.py "ASROS central quality controller"
[3]: ../../src/webpent/avde/discovery.py "AVDE discovery contracts"
[4]: ../../src/webpent/avde/exploration.py "AVDE exploration and strategy contracts"
[5]: ../../reports/evaluation/asros/asros_advanced_controlled_benchmark_v1.json "Recorded controlled source artifact"
