# EGAIE Phase 0 — Repository & Integration Audit (2026-10-21)

Method: three parallel source audits + interface reads + baseline suite run.
Everything below is grounded in actual files, not filenames.

## Baseline

- Main suite: **4,330 passed, 0 failed** (180.35s, `--ignore=tests/lab`).
- tests/lab adds 7 → 4,337 total. Monotonic with the 2026-10-20 full sweep.

## Capability-by-capability (actual state)

| Capability | Implementation | Wired? | Notes |
|---|---|---|---|
| ASROS | `src/webpent/asros/` (6 modules: adaptive_strategy, attack_surface, knowledge_graph, quality_controller, reasoning, world_model) | Heavily (abhie_v6, adi, avde, avrp, avrip) | 0 stubs. Advisory, deterministic. |
| AREX | **Does not exist.** `agents/team.py:67-96` declares 5 `AgentRoleSpec`s pointing at `webpent.agents.arex.*`; no such modules. Only artifact: `research_engine/autonomous_scheduler.py::AutonomousScheduler` — **zero importers**. | No | Dangling role specs never fail (no resolver consumer). |
| Target Brain | `intelligence/target_brain.py` — `build_target_brain()` → `TargetBrainSnapshot` | One consumer (`agents/target_understanding/agent.py`) | Read-only projection; 1 file. |
| World Model | **Two divergent impls**: `asros/world_model.py::SecurityWorldModel` (from TargetKnowledgeV2) and `llm_researcher/world_model.py::WorldModel` (over StoredObservation). No shared base. | Both used, separately | Duplication risk, documented not fixed. |
| Attack Graph | `attack_graph/` (builder, engine, reasoner, path_ranker, chain_reasoning, source_lane) | Moderate (asros/reasoning, autonomous/hunt_knowledge, research/hypothesis_generator) | 0 stubs. |
| Research Memory | `llm_researcher/interface.py::ResearchMemory` + **5 parallel generations** (cqa_v2 SmartMemory, avrp, avrip, vabhfil_v8, vabhfqr_v9) + `experience/store.py::ExperienceMemory` (**island**, zero importers) | Core one heavily used | Generation sprawl; no persistence. |
| CausalGuard | `cqa_v2/causal_guard.py::guarded_causal_evaluate` (Gates 1+2, fail-closed, Verdict enum) | The ONLY verdict authority; widely used | 0 getattr; contract: observations need `status_code`, `semantic_digest`, X-* context headers. |
| ProofBundle | Canonical `models/proof_bundle.py` (HMAC seal, custody) + `cqa_v2/proof_bundle_builder.py::CompleteProofBundle` | Wide | Both alive; wrapper converts via `to_native_proof_bundle()`. |
| Replay | `cqa_v2/replay_verifier.py::verify_replay` + `ProofBundle.replay()` | Wide | cqa_v2 "context destruction" is in-process simulation, not cross-process. |
| ToolBoundary / scope | `llm_researcher/tool_boundary.py` (allow-list, FORBIDDEN_TOOLS, hypothesis citation, SSRF pin) + `agents/scope_enforcer` (fail-closed) | Wide | Preserved as-is. |
| The 7 reviewed layers (campaign/forge/deep/prism + verdict/emulator/rehearsal) | All real, tested | **All inter-layer edges test-only** (see gaps) | Isolated packages untouched. |

## Existing loops (what already exists)

- `llm_researcher/research_loop.py::ResearchLoop.run` — OBSERVATION→…→PROOF/REJECTION with information-gain gating (`_estimate_information_gain` L194).
- `production/modern_spine.py::ModernOrchestrator` → `production/autonomous_validation_v1.py` 11-stage chain (selector → runner → normalizer → CausalGuard → ProofBundle → replay → promotion).
- `cqa_v2/autonomous_loop.py` and `cqa_v2/pipeline.py` — full hypothesize→execute→causal→prove→replay→learn loop, exercised by tests only.
- `autonomous/hunt_orchestrator.py::AutonomousHuntOrchestrator` — gated hunt loop, separate memory paths.
- Decision engines: `research/decision_loop.py::decide_next_step`, `research_engine/evidence_aware_loop.py`, `shared/research_intelligence.py::SmartNextBestActionEngine`.

## Where the research loop actually breaks (file:line evidence)

1. **campaign brief → execution**: `modern_spine.py:783/886` reads `campaign_bridge.approved_plan_for()` but the plan is an advisory dict (`_plan_block`, campaign_bridge.py:129) — never reconstructed into `Phase`/`PhaseRunner` objects. `production/campaign_bridge.py:182` fails open and gates nothing.
2. **phase → payloads**: `forge/integration.py:96 get_payloads_for_phase` fully implemented, **no production caller** (tests only).
3. **deep finding → hypothesis**: `deep/bridge.py:91,133 findings_to_hypotheses` returns `campaign.schemas.Hypothesis` objects, **no production caller**.
4. **PhaseRunner → evidence**: `campaign/executor/phase_runner.py:70` requires injected brain/apex; **no production code constructs PhaseRunner** (tests only).
5. **PhaseResult → next decision**: `campaign/warroom/integration.py:38` stores results, but nothing feeds `PhaseResult` back into `ThesisBuilder.refine` or `PhasePlanner.plan`.
6. **No campaign-aware loop**: none of the four existing loops imports `webpent.campaign` (grep: only production/campaign_bridge and deep/bridge do).
7. **Islands**: `experience.ExperienceMemory`, `persistence/*`, `contracts/*`, `research_engine.AutonomousScheduler` — zero importers.
8. AREX/ASROS agent roles in `agents/team.py` are declared but the modules don't exist.

## Gap analysis conclusion

Every leg of the loop exists as an implemented, tested component. What is missing
is one small, persistent, inspectable **investigation engine** that: seeds
hypotheses from campaign/deep, draws ammunition from forge, drives bounded
advisory experiments, routes every verdict through CausalGuard + ProofBundle +
Replay, updates the world model / attack graph, detects uninformative
repetition, records its rationale, and can resume after interruption. Nothing
like that composes the campaign/forge/deep edges today.