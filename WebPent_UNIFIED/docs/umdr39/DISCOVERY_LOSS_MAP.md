# UM-DR-39 — DISCOVERY LOSS MAP (§5.2)

> The research chain: `HTTP Observation → Endpoint/Resource → Identity
> → Object Ownership → Relationships → App Model → Hypothesis →
> Information Gain → Planned Experiment → Governed Execution →
> Observation → CausalGuard → ProofBundle → Replay → Learning`.
> Each row: what is created, what is LOST, and the exact code-level
> cause. "Do not solve this by changing dashboard counters."

## The chain, transition by transition

| # | Transition | Information created | Information LOST / never materialized | Exact cause (file:line) |
|---|---|---|---|---|
| 1 | HTTP → Endpoint/Resource | crawled routes, surface records, shadow endpoints (crawler; `surface_metrics.endpoints` via surface_sizing node graph/surface_sizing.py:125-128) | endpoints WITHOUT dynamic-budget gating: `surface_sizing` returns `{}` when `enable_dynamic_step_budget` off — it is ON by default, so this holds | graph/surface_sizing.py:101-102, settings.py:1517 |
| 2 | HTTP → Identity | the campaign passes `identity_profiles` into initial state (cli/unified_hunt.py:448-459); the lab observes User_A/User_B issuing requests; access_control's multi-identity rows execute as those principals | **the principals are never materialized as a state channel**: `multi_identity_reasoning.principals` stays empty in EVERY default campaign — the sole writer (`identity_workflow_node`) sits behind four default-OFF flags | production/identity_workflow.py:303-307 (sole writer); graph/builder.py:2086-2092 (flag gate); config/settings.py:836-879 (all four default False) |
| 3 | Identity → Authorization observations | the executors (access_control, AVI, validator) hold full authorization context INSIDE finding `evidence` (causal_guard adjudication with actor/role/tenant/resource/ownership — CausalGuard fails to BLOCKED without it, cqa_v2/causal_guard.py:51-130) | **three stacked losses, all fixed in UM-DR-39**: (a) the key was undeclared on PentestState — LangGraph silently drops undeclared keys; (b) NO producer existed in src/; (c) even after (a)+(b) were fixed, the checkpoint redactor's generic "authorization" fragment (meant for HTTP auth headers) blanked the ENTIRE channel to [] at every checkpoint write — the observations existed in the live state (a downstream node read all four) and silently vanished from every persisted final state | readers: identity_workflow.py:274-277, discovery_funnel.py:373,456; the drop law state.py:767-794; the blanking graph/checkpoints.py `_redact_value` ("authorization" in `_SECRET_KEY_FRAGMENTS`) |
| 4 | Identity → Object ownership | `appmodel` builds `OWNS` relations from REAL `owner_identity` evidence ("No ownership relation is ever invented from hypothesis text") | the ownership ontology's ceiling is the crawler's structured `owner_identity` channel — for targets that never expose it, zero ownership relations (recorded as an honest gap `appmodel_no_ownership_relations_derived`) | appmodel/builder.py:69-105, :245-269, :360-362; proven by tests/test_umdr36_appmodel_influence.py:70 |
| 5 | Ownership/identity → Hypothesis | hypothesis_analyzer applies appmodel semantic priority boosts (agents/hypothesis_analyzer/agent.py:2283-2319) | **identity/ownership context does NOT shape hypothesis PRECONDITIONS**: the production generator emits hypotheses with `preconditions=[]` (never populated by any producer at :677-1155); the fields exist on the model but only the flag-off writers fill them | hypothesis.py:326-333 (optional default); the writers that fill them: production/adaptive_research.py:814-924 + identity_workflow.py:117-199 (both default-off) |
| 6 | Hypothesis → Information gain | `Hypothesis.info_gain` enters the strategist score at weight 0.10 | **info_gain is a lookup prior, not measured uncertainty reduction**: `_INFO_GAIN_PRIORS` (adaptive_research.py:780) / hardcoded gap templates (shared/research_intelligence.py:289-403: 0.65/0.7/0.75/0.9) / `research/planner.py:91-94` (0.18+confidence*0.34+coverage terms). The principled machinery (EGAIE's InformationGainSelector with real DecisionRecords + repetition registers) **never touches the production graph** — zero imports from graph/agents/production | egaie/selection.py:26,179-226; consumers grep: evalsuite/labsuite/appsuite/scripts only; prioritization.py:185,478-499 |
| 7 | Hypothesis pool → Planner selection | the strategist ranks the full pool and promotes every hypothesis over threshold (portfolio, not top-1); coverage ledger records status/action/reason per candidate | **preconditions are never checked on the promotion path** — `recommend_action` gates on IDOR guard/deterministic match/score/abandon/rabbit-hole availability, with NO precondition gate; **no "alternatives considered" in the production decision record** (rule_fired+outcome only; the alternatives-with-scores record exists only inside EGAIE) | shared/prioritization.py:711-834 (no precondition check), :389-501 (score never reads preconditions); strategist/agent.py:614-627; egaie/selection.py:192-194 |
| 8 | Pool growth → Dedup | per-batch `(target_url, vuln_class)` string dedup inside one hypothesis_node pass | **content duplicates re-enter across passes**: the reducer upserts by UUID and the generator mints fresh `uuid4` ids; the semantic fingerprint (target+class+objective+principals+preconditions+state keys) exists ONLY in the flag-off research loop (adaptive_research.py:719-752) | state/reducers.py:190-236; hypothesis.py:175-178; adaptive_research.py:728-733 |
| 9 | Planned → Governed execution | the full authority chain holds (scope authority, budget governor, HITL interrupts, CausalGuard→ProofBundle→replay; promotion only via validator/access_control/AVI) | nothing lost here — this is the part the platform gets right; the strategist's own promotion stays "Pending" (never Tool-Confirmed) | shared/prioritization.py:852-869; verifier.py:509-540; confirmation_adapter.py:1-38 |
| 10 | Execution → Final-state measurement | the verifier records replay success INSIDE evidence: `replay_metadata.replay_verified=True`, `promotion_guard.replay_verified=True` (verifier.py:506-508, 533-539); AVI renames to `avi_replay_verified` (builder.py:1986) | **the funnel counts a vocabulary no producer writes**: `evidence["replay_verified"]` top-level / `evidence["replay"]["verified"]` (discovery_funnel.py:143-146) — so funnel `replay_verified`, `promoted_findings` and `confirmed_findings` read 0 in EVERY campaign while the instrumentation records passing replays; `promoted_ok` also expects a `finding.promotion` field the model forbids (models/findings.py:215-219, extra="forbid") | discovery_funnel.py:112-190 vs verifier.py:506-540; the only objects shaped like the funnel expects are synthetic recovery fixtures (scripts/recover_umdr35_36.py:637-661) |
| 11 | Run → Learning | lessons extracted (POSITIVE only for PROMOTED+sealed+replayed+identity-bound; NEGATIVE with failure taxonomy; PRIORITY family rates; COVERAGE_GAP) and CONSULTED before planning (default ON, between planner and auth) | learning is real but **advisory-only and demotion-only**: modifiers clamped [-0.5,0.5], "never promotes: scores only decrease" — by design (safety), recorded here as a boundary, not a defect. The v4 lessons brain was removed in 0.29.0 (tests/test_lessons_learning_loop.py:21-27 skips) | memory/lesson_extractor.py:56-166; graph/lesson_nodes.py:152-201; lesson_consultant.py:97-103; strategist/agent.py:107-165 |

## The three headline losses (the campaign discrepancies, explained)

1. **Principals observed = 0 while the lab logs User_A/User_B** —
   transition 2: the identity data EXISTS in state
   (`identity_profiles`) and the appmodel even derives 2 ownership
   relations from it, but the identity-REASONING channel that would
   count principals has no registered writer by default.
2. **Authorization observations = 0, differential questions = 0** —
   transition 3: the channel does not exist as a state key and has no
   producer; the richest authorization context (the CausalGuard
   adjudication inside each confirmed finding's evidence) is never
   projected onto a researchable channel.
3. **Funnel replay_verified/promoted = 0 while instrumentation records
   passing replays** — transition 10: a producer/consumer vocabulary
   mismatch, not a failed promotion.

## What is NOT lost (verified, keep intact)

The governed-execution spine (transition 9), the appmodel's
evidence-gated ownership (transition 4), the lessons loop's scoping
and advisory-only contract (transition 11), and the CausalGuard
authority chain. No fix in this mission may weaken any of them.
