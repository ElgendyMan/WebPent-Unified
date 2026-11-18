# UM-DR-39 — AS-BUILT ARCHITECTURE (§5.1)

> Generated from a READ-ONLY wiring audit of the actual production
> code (three parallel audits; every claim carries file:line). This
> documents what IS — not what module names suggest. A component
> existing on disk is never proof it runs.

## 1. The production dataflow (actual graph)

Entry: `webpent.cli.unified_hunt.run_unified_hunt`
(`src/webpent/cli/unified_hunt.py:191`) → `build_graph()`
(`src/webpent/graph/builder.py:1707-2641`, `StateGraph(PentestState)`
at `:1751`). The final state is read via `graph.get_state(config)`
(`unified_hunt.py:534`).

```
START → target_package_preflight → wildcard_scope → planner
  → lesson_consultation → [identity_provisioning_pre_auth] → auth
  → recon → research_campaign → crawler → [javascript_intelligence
  | identity_provisioning | subdomain_takeover → cloud_storage]
  → [target_understanding] → scope_enforcer → [scope_review]
  → waf_detector → surface_sizing → appmodel → hypothesis
  → access_control → api_testing → business_logic_fuzzer
  → request_smuggling → graphql_testing → cache_poisoning
  → prototype_pollution → oauth_misconfig → disclosed_report_intel
  → [smart_campaigns ⇄ execution ⇄ autonomous_controller ⇄
     knowledge_gap → next_best_action → research_session →
     active_research → causal_research]
  → strategist → payload_generator → execution_sandbox (HITL)
  → validator → [payload_optimizer → execution_sandbox | devils_advocate]
  → devils_advocate → [validator | exploit_chainer]
  → exploit_chainer → [payload_generator | post_exploitation]
  → post_exploitation → rabbit_hole → [strategist | cvss_engine]
  → cvss_engine → business_impact → cross_reasoning → executive_summary
  → [dedup_gate] → reporter → reflection → lesson_extraction → END
```

Conditionally-registered (builder.py line; default in
`config/settings.py`): `recon_fanout/join` (:2035, OFF :568),
`research_loop` (:2078, OFF :771), **`identity_workflow` (:2089, OFF
:836-879 — four flags)**, `attack_graph` (:2151, OFF :606),
`vip_orchestrator` (:2153, OFF), family execution spine (:2584, OFF
:713), OAST (:2625, OFF), coverage-gap report (:2599, OFF);
`dedup_gate` (:2560, **ON** :1993).

Known asymmetry: the `hypothesis` router's `HYPOTHESIS_PATH_MAP`
(builder.py:1315-1319, edge :2323-2330) is NOT wrapped in
`_research_route_redirects` (:529-537) — the budget-pressure
`hypothesis → strategist` route bypasses identity_workflow/research_loop
even when enabled.

## 2. The state model and reducers

`PentestState` (`src/webpent/state/state.py:61`, TypedDict
total=False; reducers `src/webpent/state/reducers.py`). Key channels:

| Channel | Reducer | Semantics |
|---|---|---|
| `findings` (:99) | `merge_findings` (:86) | upsert-by-id, keeps strongest |
| `hypotheses` (:111) | `merge_hypotheses` (:190) | upsert-by-id (UUID) |
| `surface_metrics` (:161) | `merge_dicts` (:276) | deep-merge |
| `workflow_observations` (:491) | `merge_lists` (:164) | append-only |
| `object_identity_registry` (:529) | `merge_dicts` | deep-merge |
| `identity_alias_graph` (:530) | `merge_dicts` | deep-merge |
| `multi_identity_reasoning` (:531) | `merge_dicts` | accumulating |
| `composite_workflow_candidates` (:551) | `merge_lists` | append-only |
| `identity_workflow` (:553) | `merge_dicts` | telemetry |
| **`authorization_observations`** | **NOT DECLARED** | LangGraph silently drops undeclared keys (the law documented at state.py:767-794) |

## 3. Who writes what (and whether the writer is registered)

| Channel | Sole writer | Registered? |
|---|---|---|
| `multi_identity_reasoning` (.principals/.differential_questions) | `identity_workflow_node` (production/identity_workflow.py:303-307, questions :299-302) | **NO by default** — only inside the four-flag gate (builder.py:2086-2092 → identity_workflow.py:66-79 → settings.py:836-879) |
| `authorization_observations` | **NO WRITER EXISTS in src/** (readers only: identity_workflow.py:275, discovery_funnel.py:373,456) | n/a — key also undeclared |
| `workflow_observations` | `business_logic_fuzzer_node` (agents/business_logic_fuzzer/agent.py:184,1012) | YES (:2134) |
| `object_identity_registry` / `identity_alias_graph` / `composite_workflow_candidates` / `identity_workflow` telemetry | `identity_workflow_node` (:245-327, :394) | NO by default |
| `hypotheses` | `hypothesis_node` (agents/hypothesis_analyzer/agent.py:2388), `strategist_node`, `rabbit_hole` (+ flag-off writers) | YES |
| `findings` | `access_control_node` (:1390), `validator_node` (`_validate_with_tool` :2387; Tool-Confirmed :3752-3761), AVI merge (builder.py:1977-1995) | YES |
| `surface_metrics` | `surface_sizing_node` (graph/surface_sizing.py:125) | YES (:2180) |
| appmodel channels | `appmodel_node` (graph/appmodel_nodes.py:112-116) | YES (:2186, unconditional) |

## 4. Tool-Confirmed promotion (the authority chain)

`verify_replay_evidence` (`shared/verifier.py:92`) writes into the
finding's evidence: `proof_verified`, `proof_bundle_sealed`,
`proof_bundle` (:514), `causal_guard` (:321), and — critically —
`replay_metadata["replay_verified"]=True` (:506-508) and
`promotion_guard["replay_verified"]=True` (:533-539). **No top-level
`evidence["replay_verified"]` key exists anywhere in production.** The
AVI merge renames flags to `avi_replay_verified` / `avi_promotion`
(builder.py:1986,1994). The strategist's own promotion emits
`confidence_level="Pending"` (shared/prioritization.py:852-869) — only
the validator/access-control/AVI paths mark Tool-Confirmed.
CausalGuard remains the SOLE confirmation authority
(production/confirmation_adapter.py:1-38; cqa_v2/causal_guard.py:1-45
— BLOCKED never becomes CONFIRMED; proof_bundle_builder.py:29-80;
replay_verifier.py:62-125 — seal equality alone does not prove replay).

## 5. Component classification (the audit's verdict)

| Component | Classification | One-line evidence |
|---|---|---|
| hypothesis_node | LIVE_PRODUCTION | builder.py:55→:2041; sole belief generator feeding promotion |
| strategist | LIVE_PRODUCTION (authoritative decider) | builder.py:2052; the only promoter to Findings |
| planner node | LIVE_ADVISORY | builder.py:1761 but "never controls graph routing" (planner/agent.py:6) |
| rabbit_hole | LIVE_PRODUCTION (bounded) | builder.py:2051; caps depth 3 / branches 5 / actions 10 (config/policies.py:198+, agents/rabbit_hole/agent.py:131,135,367-396) |
| dedup_gate (findings) | LIVE_ADVISORY | default ON (settings.py:1993), annotation-only (vip/dedup_gate.py:44-47) |
| appmodel node | LIVE_PRODUCTION (advisory semantics) | unconditional :2186; `owns` relations ONLY from real `owner_identity` evidence (appmodel/builder.py:69-105; "never invented from hypothesis text" :80-81) |
| identity workflow + multi-identity + object registry + alias + composite workflows | **PARTIALLY_WIRED** | complete implementations, registered only behind four default-OFF flags (builder.py:2086-2092) |
| adaptive research loop | PARTIALLY_WIRED | builder.py:2066-2080 behind enable_adaptive_research_loop=False (settings.py:771) — carries the ONLY precondition-faithful hypotheses |
| EGAIE / InformationGainSelector | **TEST_ONLY** (benchmark lineage) | zero imports from graph/agents/production (egaie/*; consumers: evalsuite/labsuite/appsuite/scripts only) |
| `Hypothesis.info_gain` → strategist score | LIVE_PRODUCTION (advisory weight) | W_INFO_GAIN=0.10 (prioritization.py:185,478-499) |
| EVScheduler | LIVE_ADVISORY | only chain_composer's uplift receipt (chain_composer.py:559-572) |
| curiosity engine (agents/curiosity_engine.py) | LIVE_PRODUCTION (hunter CLI runtime only) | hunter_runner.py:853 via `agent-hunt`; absent from build_graph |
| brain/curiosity.py | ORPHAN | zero importers (only the frozen-module gate mention, tests/test_frozen_module_gate.py:1265) |
| research/hypothesis_engine.py | LEGACY/side-stack | used by research_engine only; the strategist bypasses it with direct model_copy status writes (strategist/agent.py:598,639) |
| research/planner.py | ORPHAN | intra-package consumers only; no tests |
| MultiPathPlanner | PARTIALLY_WIRED | flag-gated family spine (families/execution_node.py:384; settings.py:713) |
| Knowledge v1 (target_knowledge) | LIVE but flag-gated (default OFF) | written by target_understanding_node (target_understanding/agent.py:600); enable_target_understanding=False (settings.py:561) |
| Knowledge v2 (model_v2) | LIVE_ADVISORY (hunt paths) | hunt_knowledge.py:55-61; the main graph never builds v2 directly |
| Target Brain (intelligence/) | LIVE_ADVISORY, flag-gated | target_understanding/agent.py:532 |
| attack_graph node | flag-gated default OFF | builder.py:2151; tests/test_v20_attack_graph_wiring.py:12 |
| hunter_graph + hunter_runner | LIVE_PRODUCTION (separate CLI entry) | cli/commands.py:1367-1403; delegates promotion to AVI/ProofBundle (hunter_runner.py:538-542) |
| autonomous hunt orchestrator + runtime + hunt_discovery | **TEST_ONLY / ORPHAN entry-point** | library-complete, no CLI/worker caller (autonomous/__init__.py:102,132; tests only) |
| lessons loop (LessonsManager + graph nodes) | LIVE_PRODUCTION (default ON) | enable_lesson_consultation=True (settings.py:1507-1516); nodes builder.py:2178-2179,2573-2574 |
| SmartMemory / ScopedHuntMemory | LIVE_ADVISORY behind opt-in flags | smart/memory_engine.py:52-140; autonomous/hunt_memory.py:30-33 |
| CQA v2 CausalGuard/ProofBundle/replay | LIVE_PRODUCTION (confirmation authority) | confirmation_adapter.py:1-38 |

## 6. Memory/knowledge isolation (verified)

* Lessons SQLite: `client_id` is a mandatory isolation filter,
  fail-closed when missing (memory/lessons.py:797-842); legacy
  pre-scope rows excluded (:640-653); UNIQUE(client_id, fingerprint)
  (:517-520). Tests: tests/test_v62_ingest_and_memory_isolation.py:62
  (cross-client search → []), tests/test_postp0_phase2_memory_readback.py:71
  (poisoned lesson invisible across targets).
* Chroma lessons: `_lesson_scope_filter` requires client+engagement on
  writes; reads never broaden past the client (memory/vectorstore.py:259-347).
* ScopedHuntMemory: keyed `engagement_id:target_id`
  (autonomous/hunt_memory.py:30-33), tamper-evident (:76-83).
* Knowledge graphs: engagement-scoped by construction
  (target_knowledge.py:114, model_v2.py:169-170,
  intelligence/entity_graph.py:48-58); attack-graph knowledge nodes
  namespaced per engagement (shared/attack_graph.py:494-497).
* KNOWN GAP (recorded): the writeup/payload/WSTG knowledge collection
  is deliberately GLOBAL (vectorstore.py:439-480) — public methodology
  only; ingestion discipline is the guard against client-specific
  content leaking into it.
* Memory is advisory-only by hard contract: "changes ranking metadata
  only; never removes a hypothesis or makes an execution, validation,
  proof, or promotion decision" (memory/lesson_consultant.py:1-5);
  modifiers clamped [-0.5, 0.5] (:97-103); lesson content is DATA
  (graph/lesson_nodes.py:29-34).

## 7. Four parallel knowledge representations

| Model | Types | Relations | Provenance | Conflicts |
|---|---|---|---|---|
| Knowledge v1 (knowledge/target_knowledge.py:15-62) | 9 kinds closed | free-string ("contains" only in use) | confidence+evidence_refs | **overwritten** (:122-128) |
| Knowledge v2 (knowledge/model_v2.py:46-63) | 14 kinds closed | free-string, source_observation REQUIRED | observed_at, lifecycle OBSERVED..BLOCKED | last-write-wins |
| AppModel (appmodel/models.py:52-108) | 7 kinds closed | **closed enum** (contains/hosts/exposes/performs/authenticates_as/observed_on/reachable_from/owns) | DECLARED/OBSERVED/INFERRED/UNKNOWN/CONTRADICTED + confidence map (:148-157) + evidence_refs + observed_at | **preserved** (mark_contradicted :237-342) |
| Target Brain (intelligence/entity_graph.py:16-58) | 7-kind Literal | free-string + evidence_refs | engagement-scoped | — |

The AppModel is the strictest (typed relations, contradiction
preservation, provenance-gated confidence) and is the model the
unconditional `appmodel` node feeds. No PRINCIPAL_OWNS_OBJECT-style
relation vocabulary exists anywhere; the closest are appmodel `OWNS`
(identity→endpoint, evidence-gated) and `identity_has_permission`
(shared/attack_graph.py:596-604).
