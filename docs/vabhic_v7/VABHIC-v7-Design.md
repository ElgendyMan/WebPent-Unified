# VABHIC v7 Design

## Scope

VABHIC v7 is an additive, target-neutral **Expert Autonomous Research Intelligence** layer for WebPent. It converts recorded world-model, attack-graph, coverage, memory, and prior-result inputs into explainable research commands, security reasoning, hypotheses, attack narratives, budget allocations, specialist questions, skepticism challenges, offline benchmark records, and readiness review output.

The layer is deliberately bounded. It does not send HTTP or other network requests, select external scope, use credentials or sessions, mutate application state, create findings, override a causal oracle, alter policy, issue human signoff, or grant P10/VIP qualification.

## Composition

| Component | Responsibility | Authority boundary |
|---|---|---|
| `AutonomousResearchCommanderV7` | Chooses high-value questions and expected evidence | Planning only; no routing or execution |
| `SecurityMentalModelBuilderV7` | Models assets, business logic, journeys, trust, authorization, state, workflows, and assumptions | Descriptive; unresolved fields remain explicit |
| `UnknownVulnerabilityDiscoveryV2` | Derives opportunities from missing controls, broken assumptions, inconsistencies, and boundary gaps | Hypotheses only |
| `AutonomousAttackNarrativeBuilderV7` | Builds attacker-goal narratives and dependency chains | No causal confirmation |
| `ResearchBudgetIntelligenceV7` | Ranks likelihood, impact, uncertainty, evidence value, cost, and duplicate-path penalty | Advisory prioritization only |
| `MultiAgentResearchCoordinatorV7` | Collects specialist perspectives and unresolved conflicts | No consensus authority |
| `FalsePositiveSkepticismV7` | Challenges intended behavior, alternatives, capability, impact, and replayability | Cannot override oracle or create a finding |
| `VIPControlledBenchmarkV6` | Evaluates supplied recorded artifacts with strict readiness | Offline; zero requests |
| `AutonomousResearchAnalyticsV7` | Emits null metrics without valid ground truth and evidence | No production claim |
| `VIPReadinessReviewV7` | Summarizes maturity and blockers | Cannot grant VIP or open P10 |

The implementation reuses existing WebPent research and graph contracts conceptually rather than creating a second execution or quality controller. The v7 package is a reasoning facade whose outputs remain separate from the central verification and policy authorities.

## Fail-closed contracts

Every command and candidate carries success criteria, stopping criteria, missing evidence, and validation requirements. Candidates and narratives cannot be constructed as causally confirmed findings. Analytics reject non-zero request counts and qualification approval. Benchmark cases are scorable only when realistic behavior, hidden assumptions, adaptive strategy, causal oracle, ProofBundle, and replay verification are all present.

The benchmark runner defaults to an empty recorded-case set. Consequently, it registers six scenario classes but returns six blocked cases, zero scorable cases, zero requests, and null real-world detection metrics. This is an honest readiness result, not a detection claim.

## Safety and governance invariants

The following invariants are fixed in this implementation:

| Invariant | State |
|---|---|
| Network execution from v7 | prohibited; zero requests |
| State mutation | prohibited |
| Credentials, login, tokens, callbacks | not used |
| External targets and bug bounty | out of scope |
| Finding creation | prohibited |
| Oracle/policy override | prohibited |
| Official isolated P10 runs | unauthorized |
| P10/P9/VIP | `NOT_QUALIFIED` |
| Human signoff | false |
| Benchmark production detection metric | null until valid evidence exists |

## Reproducibility

The evaluation script `scripts/run_vabhic_v7_evaluation.py` regenerates the benchmark, analytics, readiness assessment, and machine-readable summary from no external inputs. It is safe to run repeatedly and does not start a service, scheduler, daemon, callback, or target process.
