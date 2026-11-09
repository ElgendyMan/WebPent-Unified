# ABHIP v5 Gap Analysis

## Scope and safety boundary

ABHIP v5 is implemented as a deterministic, in-process, advisory research layer. It consumes caller-supplied observations and existing target-scoped contracts. It does not send network requests, create credentials, perform login, mutate target state, create findings, seal ProofBundles, override policy, or open P10/Bug Bounty gates.

The current governance state remains unchanged: `official_isolated_p10_runs_authorized=false`, `P10/P9/VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `human_signoff=false`, and `qualification_effect=false`.

## Existing capabilities reused

| ABHIP v5 requirement | Existing bounded capability | Integration decision |
| --- | --- | --- |
| Mission planning, budget, stopping | `webpent.research_engine.orchestrator.ResearchOrchestrator`, `ResearchBudget`, `ResearchState` | Compose through a v5 mission wrapper; do not duplicate budget authority. |
| Unknown discovery and security questions | `KnowledgeGapEngine`, `SmartNextBestActionEngine` in `webpent.shared.research_intelligence` | Use these for explicit gaps, questions, utility ranking, and anti-loop behavior. |
| Target model and evidence lineage | `TargetKnowledgeV2` and `SecurityWorldModel` | Build a target-intelligence projection over these source-linked models. |
| Differential reasoning | `DifferentialWorkflowRunner` in `webpent.shared.differential_workflow` | Consume recorded variant observations only; keep differential signals non-confirmatory. |
| Evidence-aware loop gates | `EvidenceAwareAgentLoop` | Reuse for capability/evidence/central-proof admission and fail-closed status. |
| Research learning memory | `SecurityReasoningMemory` | Delegate storage and retrieval to the existing exact engagement/target scoped boundary. |
| Senior quality review | `ResearchQualityController` | Compose before/after reviews; the ABHIP reviewer remains advisory and cannot approve qualification. |
| Existing v4 reasoning primitives | `webpent.abhie` | Preserve v4 contracts and use them as compatibility inputs for v5 bridges. |

## New v5 surfaces required

1. A typed `ResearchMissionPlan` and `AutonomousResearchOrchestratorV2` that selects bounded objectives, ranks them, accounts for budget, and emits explicit stop decisions.
2. A `TargetIntelligenceGraph` adapter with evidence source, confidence, lifecycle, and validation status on every node and relation.
3. An automatic `SecurityQuestionGenerator` that turns graph gaps and invariants into target-neutral research objectives.
4. A differential reasoning report that compares identities, roles, tenants, states, and allowed/forbidden actions without treating a difference as a finding.
5. A deterministic `AutonomousResearchLoopV3` that records Observe → Understand → Question → Hypothesis → Experiment → Evidence → Evaluate → Learn → Update transitions, recovers from failed paths, and suppresses repeated work.
6. An expert reasoning report and v3 memory facade that preserve alternative explanations, attacker capability, conditions, impact, evidence strength, and exact scope isolation.
7. A six-class controlled benchmark v4 and internal metrics for autonomy, decision quality, hypothesis quality, evidence completeness, efficiency, coverage improvement, and learning effectiveness. Production detection rate remains unavailable unless a valid ground-truth denominator exists.
8. An autonomous reviewer v3 that challenges validity, evidence, impact, reasoning, and reproducibility while delegating evidence-quality decisions to the central controller and never promoting a finding.

## Phase 1 conclusion

The repository baseline is clean and at parity with `origin/master` at `d68c3d5b9902a492c8826cd25042124097ea1f6f`. The implementation path is additive: new v5 contracts will live under `src/webpent/abhip/`, while existing ABHIE v4 and shared governance contracts remain backward compatible. No frozen historical evidence or validator thresholds require modification.
