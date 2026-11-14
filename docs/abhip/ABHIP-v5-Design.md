# ABHIP v5 Design

## Purpose and boundary

ABHIP v5 is an **advisory, target-neutral research-intelligence layer** inside WebPent. It upgrades the existing research primitives into a bounded operating loop that can understand recorded target context, define research objectives, compare observations, adapt priorities, retain scoped lessons, and explain evidence quality. It does not replace ActionAuthority, CampaignExecutor, AREX, the central quality controller, the causal oracle, or the qualification gates.

The implementation is deliberately one-off and in-process. The benchmark runner reads recorded artifacts only; it does not contact a target, create observations, use credentials, perform mutations, or open an external integration.

## Architecture

| Capability | ABHIP v5 component | Reused or protected contract | Output boundary |
| --- | --- | --- | --- |
| Mission planning | `abhip.orchestrator.AutonomousResearchOrchestratorV2` | Existing budget/planning utilities | Advisory `ResearchMissionPlan` only |
| Target understanding | `abhip.target_graph.TargetIntelligenceGraphBuilder` | `TargetKnowledgeV2` entities, relations, observations | Evidence-linked nodes and relations |
| Security questions | `abhip.questions.SecurityQuestionGenerator` | `KnowledgeGapEngine` and target graph | Research objectives, not actions |
| Differential discovery | `abhip.differential.DifferentialReasoningEngineV3` | Existing differential workflow contracts | Candidate differences with validation requirements |
| Research loop | `abhip.loop.ResearchLoopV3` | Existing evidence-aware loop concepts | Bounded checkpoints and recovery decisions |
| Expert reasoning | `abhip.reasoning.ExpertVulnerabilityReasoningEngineV5` | Evidence and oracle boundaries | Advisory reasoning report; no confirmation |
| Research memory | `abhip.memory.ResearchMemoryV3` | `SecurityReasoningMemory` scoping/redaction | Versioned target/engagement-scoped lessons |
| Self-review | `abhip.reviewer.AutonomousSecurityReviewerV3` | Central quality-controller boundary | Advisory assessment; no qualification |
| Controlled benchmark | `benchmarks/abhip_v4_controlled.py` | Historical recorded artifact only | Six-class readiness and capability accounting |
| Internal metrics | `benchmarks/abhip_v4_metrics.py` | Conservative evidence metric conventions | Research-capability metrics only |

## Research flow

```text
recorded context
    -> target intelligence graph
    -> security questions
    -> mission objectives
    -> differential reasoning
    -> hypothesis and experiment proposal
    -> evidence-aware evaluation
    -> scoped memory lesson
    -> strategy update or bounded stop
    -> advisory self-review
```

Every transition remains explainable. A missing oracle, missing control, missing proof, or missing replay result is a blocking condition for confirmation rather than a reason to infer success.

## Target Intelligence Graph

The graph is an adapter over `TargetKnowledgeV2`, not a second target model. Nodes carry a stable identifier, evidence source, confidence, lifecycle state, and validation status. Relations are retained only when their source and scope are available. Dictionary-backed entity and node collections are normalized through values, preserving deterministic ordering and avoiding accidental key-as-entity behavior.

Target-specific semantics belong in adapters or profiles. Generic ABHIP code does not contain Juice Shop, WebGoat, crAPI, route, credential, token, login, or mutation assumptions.

## Differential reasoning and loop control

The differential engine compares identity, role, state, action, and tenant dimensions. A difference is useful only as a research direction: it contains the observation source, reasoning, possible impact, and the validation requirement. It cannot become a finding or a confirmed vulnerability.

The research loop executes conceptual phases—observe, understand, question, hypothesize, select, collect, evaluate, learn, and update strategy—without performing transport. It prevents repeated work through stable event/checkpoint keys, records failed-path recovery as advisory state, and stops when budget or evidence boundaries require stopping.

## Evidence, memory, and reviewer boundaries

The reasoning engine explicitly records attacker capability, required conditions, boundary, impact, alternative explanations, and evidence strength. Without an oracle it returns a fail-closed advisory state. The memory wrapper delegates to the existing scoped and redacted reasoning memory; target and engagement scopes are never merged, and updates are versioned and explainable.

The reviewer challenges validity, evidence quality, impact, reasoning, and reproducibility. Its `qualification_approved`, `oracle_overridden`, and `evidence_modified` values remain false. The central quality controller and sealed/replayable ProofBundle remain the only relevant technical confirmation boundary, and no ABHIP reviewer output can promote a hypothesis.

## Benchmark and metrics

ABHIP v5 registers six controlled classes: complex IDOR, privilege-escalation chain, business-logic authorization failure, tenant isolation failure, workflow authorization issue, and sensitive-information exposure. Each class has a target-neutral readiness contract requiring hidden assumptions, multiple research paths, an autonomous decision record, a causal oracle, a sealed ProofBundle, and replay verification.

The runner joins only actual complete records from the historical artifact. The current artifact contains one complete recorded IDOR case; the other five classes remain `BLOCKED`. Missing and blocked cases are excluded from TP/FN/clean accounting. Internal metrics report readiness coverage, evidence completeness, decision quality, hypothesis quality, efficiency, and available comparison fields. Production detection rate, precision, recall, and F1 remain null because there is no approved multi-run ground-truth denominator or production measurement.

## Safety and governance invariants

ABHIP v5 is offline and sends zero requests in the benchmark path. It uses no real credentials, cookies, tokens, external callbacks, destructive actions, or state-changing operations. It cannot open official P10 runs, Bug Bounty scope, or qualification. The required governance state remains:

| Control | State |
| --- | --- |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Human signoff | `false` |
| Qualification effect | `false` |

## Verification strategy

The regression suite covers orchestration, graph construction, security questions, differential reasoning, loop recovery, memory isolation, benchmark reliability, evidence integrity, and reviewer fail-closed behavior. Release gates additionally cover Ruff, compileall, generic target neutrality, tracked-secret scanning, direct-I/O inventory, G-02, release-manifest verification, provenance, archive integrity, and parity with the pushed branch.
