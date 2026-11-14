# AVRIP v2 Design

**Author:** Manus AI
**Scope:** additive, target-neutral, bounded advisory intelligence inside WebPent.

## Purpose

AVRIP v2 adds deeper research intelligence to WebPent without changing the execution authority, policy gates, causal oracle, proof sealing, or qualification state. It converts existing ASROS, AVDE, knowledge, workflow, adaptive-strategy, and security-reasoning-memory contracts into a deterministic composition that can explain why a research direction is valuable and what evidence is still missing.

> AVRIP v2 produces research projections and hypotheses. It does not create findings, authorize requests, execute validation, promote evidence, or qualify P9/P10/VIP.

## Contract reuse

| AVRIP layer | Existing contract reused | AVRIP responsibility |
| --- | --- | --- |
| Intent | `SecurityWorldModel`, workflow observations, `TargetKnowledgeV2` | Build a target-scoped application-intent projection with business entities, goals, workflows, boundaries, transitions, and lineage. |
| Assumptions | ASROS invariants and AVRIP intent | Extract falsifiable ownership, permission, workflow, state, and data-exposure assumptions with missing-evidence requirements. |
| Deep reasoning | ASROS reasoning structures, attack graph, knowledge, memory | Produce ranked hypotheses, explicit reasoning steps, evidence gaps, and advisory validation directions. |
| Cross-domain reasoning | `AttackGraph`, `TargetKnowledgeV2`, knowledge relations | Join identity, resource, workflow, permission, and state domains into bounded hypothetical paths. |
| Strategy optimization | `AdaptiveStrategyEngine` and existing research outcomes | Learn from recorded strategy outcomes within exact target/engagement scope; output explainable priorities only. |
| Evidence intelligence | Existing evidence polarity and redaction contracts | Classify evidence as supporting, contradicting, missing, or insufficient; require causal/control/proof/replay before readiness. |
| Memory | `SecurityReasoningMemory` and `MemoryBoundary` | Persist redacted, scope-isolated lessons and expose non-authoritative summaries. |
| Senior review | Central quality-controller boundary | Return advisory review dispositions and insufficiency reasons; never create a finding or signoff. |

## Determinism and isolation

Every public AVRIP component accepts explicit scope identifiers and returns serializable models. Ordering is stable, evidence references are preserved as lineage, and cross-target memory retrieval is prohibited by the underlying memory boundary. Sensitive values are passed through the existing redaction function before storage. No AVRIP module starts a process, opens a socket, polls a target, reads credentials, or performs state mutation.

The cross-domain join is deliberately bounded to the first sixteen deterministic combinations. This prevents a large graph from turning advisory reasoning into an unbounded search process while retaining a useful explanation of domain linkage.

## Evidence boundary

AVRIP uses a tri-state/fail-closed evidence assessment. A strong hypothesis remains `insufficient` when any required causal oracle, independent negative control, sealed proof bundle, or replay verification is absent. `confirmed` is not inferred from HTTP reachability, route presence, status codes, or a hypothesis score.

## Integration flow

```text
SecurityWorldModel + TargetKnowledgeV2 + AttackGraph
        |
        v
ApplicationIntentV2 -> SecurityAssumptionDiscoveryEngine
        |                         |
        +-------------------------+--> DeepVulnerabilityReasoner
                                      |
                                      +--> CrossDomainAttackReasoner
                                      +--> ResearchStrategyOptimizerV2
                                      +--> EvidenceIntelligenceV2
                                      +--> AutonomousResearchMemoryV2
                                      +--> SeniorResearchReviewerV2
        |
        v
AVRIPAnalysisReport (advisory, scoped, serializable, no execution authority)
```

## Benchmark boundary

`benchmarks/avrip_deep_controlled.py` replays the existing recorded controlled artifact only. It registers five vulnerability classes, retains one complete historical IDOR case as scorable, and leaves four classes blocked because the source artifact contains no complete AVRIP v2 intent/assumption/cross-domain/optimizer telemetry. Production precision, recall, F1, and real-world detection rate remain unavailable. The benchmark sends zero requests and creates no observations or proof bundles.

## Governance invariants

The release preserves `official_isolated_p10_runs_authorized=false`, `P10/P9/VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `human_signoff=false`, and `qualification_effect=false`. These values are governance facts, not benchmark scores.
