# src/webpent/state/state.py
"""webpent.state.state

LangGraph state schema for the WebPent Framework V3.

V3 extends V2's state with ``auth_state`` (Phase 1) and
``optimization_retries`` (Phase 2 — Payload Optimizer loop).

V5 Sprint 6: Adds ``stealth_mode`` flag propagated from the CLI
``--stealth`` option. Tool wrappers and the Playwright sandbox read
this flag to insert jitter and rate-limit delays.

V5 Sprint 11: Adds ``executive_summary`` and ``risk_score`` fields
populated by the new ``executive_summary_node`` before the reporter
finalizes the report.

V6 Absolute-Flawless P0 FIX (CISO audit — LangGraph State Mutation):
    ``crawled_data``, ``session_cookies``, and ``credentials`` were
    previously declared as bare ``dict[...]`` fields without
    ``Annotated[..., reducer]`` annotations. LangGraph treats
    un-annotated dict fields as last-write-wins, which means parallel
    branches writing to the same field silently overwrite each other.
    Worse, nodes that needed to update a single entry (e.g. one new
    session cookie) had to read the whole dict, mutate it in place,
    and write it back — and the in-place mutation was invisible to
    LangGraph's snapshot/checkpoint logic, so resuming a paused
    engagement could lose the update.

    All three fields now carry the ``merge_dicts`` reducer, which
    deep-merges new values into the existing dict instead of
    overwriting. This makes parallel-branch writes safe AND makes
    per-key updates visible to the checkpoint layer. Downstream
    nodes (e.g. ``pentest_worker._mark_pending_as_human_review``)
    now return ``{"findings": [updated_list]}`` dicts instead of
    mutating ``state["findings"]`` in place — see the matching fix
    in ``pentest_worker.py``.
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from webpent.models.findings import Finding
from webpent.models.hypothesis import Hypothesis
from webpent.models.targets import Target
from webpent.state.reducers import (
    merge_auth_state,
    merge_dicts,
    merge_findings,
    merge_hypotheses,
    merge_lists,
    merge_payloads,
    merge_retries,
    replace_runtime_capability_gaps,
)


class PentestState(TypedDict, total=False):
    """Central LangGraph state shared across all V3.5 pentest agents.

    V7 Cognitive Upgrade (Phase 1 — Hypothesis Engine):
        ``hypotheses`` was previously ``list[str]`` — a flat list of
        free-form text with no provenance, status, or confidence. It
        is now ``list[Hypothesis]``, where each entry is a first-class
        Pydantic model with stable UUID, lifecycle status, numeric
        confidence score, evidence refs, origin tracking, and an
        optional parent-hypothesis reference for Rabbit Hole branches
        (Phase 7). The reducer stays ``merge_lists`` (append-only) —
        only the element type changed. This is a breaking type change
        done as a single atomic migration per Section 3 of the plan:
        there is no window where the field holds a mixed-type list.
    """

    target: Target
    # Optional redaction-safe Target Package v2 projection. Raw provider
    # responses, credentials, cookies and live handles are never stored here.
    target_package: dict[str, Any]
    target_package_status: str
    target_package_id: str | None
    target_package_sha256: str | None
    target_package_scope_digest: str | None
    target_package_policy_digest: str | None
    target_package_capability_digest: str | None
    target_package_authorization: dict[str, Any]
    target_package_preflight_status: str
    target_package_capability_matrix: Annotated[dict[str, Any], merge_dicts]
    target_package_knowledge_gaps: Annotated[list[dict[str, Any]], merge_lists]
    target_package_blocked_tasks: Annotated[list[dict[str, Any]], merge_lists]
    # Redacted one-time lease identity; raw package and trust roots never enter state.
    target_package_binding: dict[str, Any]
    # Explicit operator-declared companion origins (for example a separate
    # frontend origin used by the target login flow). Legacy checkpoints omit
    # this optional field and remain valid.
    additional_target_origins: list[str]
    messages: Annotated[list[BaseMessage], add_messages]
    findings: Annotated[list[Finding], merge_findings]
    # Track 11 item 5 (2026-10-28): dedup-before-nomination report produced
    # by webpent.vip.dedup_gate.dedup_gate_node (flag-gated by
    # enable_dedup_gate). Last-write-wins (no reducer): exactly one gate
    # runs per campaign, immediately before the reporter. Legacy
    # checkpoints omit this optional field and remain valid. The report is
    # advisory/auditable data — it never mutates findings by itself.
    dedup_report: dict[str, Any] | None
    current_phase: str
    # V9 P0 B2: hypotheses now uses merge_hypotheses (upsert-by-id) instead
    # of merge_lists (append-only). This prevents duplicates when the
    # strategist returns model_copy(update={"status": ...}) on promote/abandon.
    hypotheses: Annotated[list[Hypothesis], merge_hypotheses]
    lessons: Annotated[list[str], merge_lists]
    payloads_to_test: Annotated[dict[str, list[str]], merge_payloads]
    # V6 Absolute-Flawless: crawled_data now uses merge_dicts so parallel
    # crawler branches (e.g. one per HTTP method) don't clobber each
    # other's results, and per-key updates are visible to checkpoints.
    crawled_data: Annotated[dict[str, Any], merge_dicts]
    # Team 2 review, item 8.3 ("Adaptive WAF Evasion"): structured,
    # deterministic WAF detection output (see
    # agents/waf_detector/agent.py and shared/waf_fingerprints.py) — a
    # dict shaped like WafProfile.as_dict(): detected, vendor,
    # confidence, signals, blocks_attack_shaped_requests,
    # baseline_status, probe_status. Replaces the prior gap where WAF
    # detection was LLM-free-text only with no structured field
    # downstream agents could act on (see this file's own prior "V10
    # P3-6" comment, now resolved). merge_dicts is the correct reducer
    # here, matching crawled_data immediately above: a later
    # waf_detector run (e.g. on re-entry after scope changes) should
    # overwrite the specific keys it recomputes, not be unioned
    # key-by-key with a stale prior result the way merge_lists would
    # append rather than replace.
    waf_profile: Annotated[dict[str, Any], merge_dicts]
    # ------------------------------------------------------------------
    # ULTIMATE PLAN 2026-10-27 (proposals 2/3/7). Four additive,
    # optional channels — every one advisory/observability, never
    # finding authority. Absent from legacy checkpoints by construction
    # (total=False), so old runs load unchanged.
    #
    # (proposal 3) Closed-loop learning outputs:
    #   consulted_lessons — bounded redacted lesson summaries consulted
    #     after planning; DATA (priority hints), never instructions.
    #   lesson_priority_adjustments — numeric route/family modifiers in
    #     [-0.5, 0.5] for the hypothesis/payload nodes' PRIORITIZATION
    #     only.
    #   extracted_lessons — what this campaign stored at reflection.
    # (proposal 2) Dynamic budget:
    #   surface_metrics — bounded counts measured right after crawling
    #     ({"endpoints","forms","parameters","graphql_operations",
    #     "surface_size","budget_source"}).
    #   dynamic_step_budget — the per-run derived budget; absent = the
    #     flat max_graph_steps ceiling applies (legacy behavior,
    #     budget_governor._active_budget).
    # (proposal 7) New deterministic detectors:
    #   detector_results — advisory ValidationResult dicts (GraphQL /
    #     cache poisoning / prototype pollution / OAuth). Promotion to
    #     Finding stays with the validator/strategist authority chain.
    # ------------------------------------------------------------------
    consulted_lessons: Annotated[list[dict[str, Any]], merge_lists]
    lesson_priority_adjustments: Annotated[dict[str, Any], merge_dicts]
    extracted_lessons: Annotated[list[dict[str, Any]], merge_lists]
    surface_metrics: Annotated[dict[str, Any], merge_dicts]
    dynamic_step_budget: int
    detector_results: Annotated[list[dict[str, Any]], merge_lists]
    # ------------------------------------------------------------------
    # UM-DR-24 (post-window release-gate compliance, 2026-11-06): the M3
    # UM-DR-17 OAST correlation node (graph/oast_nodes.py — a NEW file
    # outside the frozen gate) writes three state channels that were not
    # declared on PentestState — the state-contract law
    # (scripts/check_state_contract.py) correctly refused them. Declared
    # here with the SAME advisory semantics as detector_results above:
    # candidate-only OAST correlations, promotion to Finding stays with
    # the deterministic validator (the bridge's CandidateOnlyRule is
    # structural). oast_candidate_findings accumulates with merge_lists
    # exactly like detector_results (per-round candidates carry nonce +
    # hypothesis_id so cross-round repeats stay identifiable);
    # oast_correlation_status / oast_sessions_armed are per-run scalars
    # (last-write-wins, matching scope_compile_status /
    # dynamic_step_budget precedent). Flag-off / unavailable / no-secret
    # paths write ONLY the honest status string.
    # ------------------------------------------------------------------
    oast_correlation_status: str
    oast_sessions_armed: int
    oast_candidate_findings: Annotated[list[dict[str, Any]], merge_lists]
    # (proposal 1) Unified-hunt budget bookkeeping: the mode presets'
    # ceilings, mirrored into the graph state so the surface-sizing node
    # can clamp the dynamic budget by the run's actual cost ceiling
    # (graph nodes receive ONLY schema-declared keys). Advisory
    # bookkeeping only — the enforcement points stay where they were
    # (budget_governor, hunt_runtime, the LLM client's cost guard).
    llm_budget_usd: float
    max_llm_calls: int
    llm_calls_used: int
    cost_spent_usd: float
    max_hypotheses: int
    persona: str
    # V9 P0-B-2 FIX: auth_state now uses merge_auth_state instead of
    # plain merge_dicts. See merge_auth_state's docstring — plain
    # merge_dicts concatenates auth_state["cookies"] (a list) instead
    # of upserting by cookie name, which corrupts the cookie jar the
    # first time a second write happens (e.g. the validator's mid-scan
    # reauth fix).
    auth_state: Annotated[dict[str, Any], merge_auth_state]
    optimization_retries: Annotated[dict[str, int], merge_retries]
    # Last optimizer input fingerprint per finding. Digests only; no payload,
    # body, cookie, authorization, or other secret values are stored.
    optimization_attempt_fingerprints: Annotated[dict[str, str], merge_dicts]

    # Additive Agent Evolution graph projection. These fields are opaque,
    # redaction-safe hunter-loop state and are optional for legacy graphs.
    hunter: Any
    transition: str
    current_hypothesis: Any
    last_exploitation: Any
    last_validation: Any
    replan_feedback: dict[str, Any]

    # V3.5 Phase 3 additions
    errors: Annotated[list[str], merge_lists]
    # V6 Absolute-Flawless: session_cookies now uses merge_dicts so the
    # auth agent can append cookies without overwriting cookies set by
    # the crawler, and per-cookie updates survive checkpoint/resume.
    session_cookies: Annotated[dict[str, str], merge_dicts]
    # Optional target-issued auth headers (for example a bearer token used by
    # SPA APIs). Values are runtime secrets and are redacted before checkpoint
    # persistence; legacy cookie-only runs remain unchanged.
    session_headers: Annotated[dict[str, str], merge_dicts]

    # Addendum: operator-declared wildcard scope is compiled before graph work.
    # Raw entries are policy input; compiled_scope is a redaction-safe projection.
    raw_scope_entries: list[str]
    compiled_scope: Annotated[dict[str, Any], merge_dicts]
    scope_compile_status: str
    scope_compile_error: str

    # SCENARIO CONTRACT: where the engagement boundaries came from and their
    # redaction-safe declaration. ``scope_source`` is "scope_file" when the
    # operator supplied an explicit file/entries contract (the target had to
    # pass a fail-closed membership check before the graph started) or
    # "inferred_from_url" when the tool derived the cautious default scope
    # from the URL alone — the report surfaces this so reviewers know the
    # boundaries are estimates, not contractual. ``scope_declaration`` is the
    # ScopeFileSpec.as_dict() projection: allow entries, excluded hosts,
    # include/exclude path prefixes, and the sha256 fingerprint of the
    # contract. Secrets never appear here — scope files are host/path policy
    # only by grammar.
    scope_source: str
    scope_declaration: Annotated[dict[str, Any], merge_dicts]

    # Addendum: signup/identity handoff is report-safe and optional. Runtime
    # secret values remain in the vault and are never represented here.
    signup_forms_detected: Annotated[list[dict[str, Any]], merge_lists]
    signup_submissions: Annotated[list[dict[str, Any]], merge_lists]
    verification_material_events: Annotated[list[dict[str, Any]], merge_lists]
    # Redaction-safe browser/execution telemetry. These records explain
    # attempted, skipped, and blocked validation without granting authority
    # or acting as a confirmation/proof channel.
    execution_observations: Annotated[list[dict[str, Any]], merge_lists]
    identity_records: Annotated[dict[str, Any], merge_dicts]
    identity_provisioning_status: str

    # V11 BAC/IDOR evidence-first multi-identity context.  These fields are
    # additive and optional so old checkpoints remain loadable.  Identity
    # profiles may contain runtime cookies for the active process, but every
    # report-facing observation is redacted by bac_identity_tester.
    identity_profiles: Annotated[dict[str, Any], merge_dicts]
    bac_observations: Annotated[list[dict[str, Any]], merge_lists]
    bac_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    relational_evidence: Annotated[list[dict[str, Any]], merge_lists]
    # V55 Phase 9: bounded multi-identity authorization matrix. It is a
    # report-safe projection and remains empty unless explicitly enabled.
    authorization_matrix: Annotated[dict[str, Any], merge_dicts]
    subdomain_takeover_observations: Annotated[list[dict[str, Any]], merge_lists]
    subdomain_takeover_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    cloud_storage_observations: Annotated[list[dict[str, Any]], merge_lists]
    cloud_storage_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    jwt_deep_observations: Annotated[list[dict[str, Any]], merge_lists]
    jwt_deep_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    # Operator-supplied, bounded offline candidates only. Never export values.
    jwt_weak_secret_candidates: list[str]
    jwt_public_key_available: bool
    disclosed_report_advisories: Annotated[list[dict[str, Any]], merge_lists]
    advisory_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]
    # Optional operator-supplied local corpus; never fetched automatically.
    disclosed_report_corpus: list[Any]

    # V4.5 Sprint 2 additions
    # V6 Absolute-Flawless: credentials now uses merge_dicts so multi-step
    # auth flows (e.g. first set username, then set session-token after
    # login) don't lose the username when the second step writes a
    # different key.
    credentials: Annotated[dict[str, str], merge_dicts]
    # Opaque worker-vault references only; never store secret values here.
    secret_refs: Annotated[dict[str, str], merge_dicts]
    playwright_enabled: bool  # Pre-flight health check result

    # V5 Sprint 6 addition
    stealth_mode: bool  # When True, insert jitter + rate-limit delays
    # Operations UX additions. These remain optional for legacy checkpoints
    # because the TypedDict is declared with total=False.
    stealth_telemetry: Annotated[dict[str, Any], merge_dicts]
    custom_payloads: list[str]
    report_formats: list[str]
    llm_enabled_override: bool | None

    # Optional durable runtime ledger; absent in legacy/tests means in-memory only.
    action_ledger_path: str | None

    # P0 execution-policy persistence: keep the operator's approval mode in
    # the checkpoint so a resumed engagement cannot silently downgrade from
    # auto-approved execution to an HITL interrupt. Optional for legacy
    # checkpoints; missing values are treated as False by resume code.
    auto_approve: bool

    # V5 Sprint 11 additions
    executive_summary: str  # C-Suite summary generated by executive_summary_node
    risk_score: str  # Overall risk: "Critical" | "High" | "Medium" | "Low"

    # V6.1 addition: phase skipping
    skip_recon: bool  # When True, bypass recon + crawler, go straight to hypothesis

    # Smart Hunter governance is additive and persisted so conditional graph
    # routes remain stable across node transitions and checkpoint resume.
    scan_mode: str
    # Public per-run profile selected by the CLI. Optional for legacy
    # checkpoints, but explicitly declared so LangGraph preserves it between
    # nodes (crawler and hypothesis analysis use it for bounded qualification
    # behavior).
    profile: str
    smart_governance: Annotated[dict[str, Any], merge_dicts]
    # Explicit opt-in for the bounded controller-owned Smart Hunter loop.
    # Legacy and ordinary safe-smart scans remain on the existing adapter path.
    enable_autonomous_controller: bool
    # Count of graph-level controller entries; bounds re-entry across checkpoints.
    autonomous_controller_runs: int
    # VIP campaign-leader telemetry (2026-10-24 layer 2). Additive and
    # advisory-only: the gated node records its one bounded perceive->plan
    # pass summary here and never promotes findings, executes payloads,
    # or sends requests. vip_campaign_runs bounds the node to one pass.
    vip_campaign_state: Annotated[dict[str, Any], merge_dicts]
    vip_campaign_runs: int
    capability_manifest: Annotated[dict[str, Any], merge_dicts]
    action_budget: Annotated[dict[str, Any], merge_dicts]
    # Bounded-controller governance telemetry. These fields are additive and
    # report-safe; they never grant execution authority or confirm findings.
    autonomous_cycle_records: Annotated[list[dict[str, Any]], merge_lists]
    stop_decision: Annotated[dict[str, Any], merge_dicts]
    research_loop_contract: Annotated[dict[str, Any], merge_dicts]
    # Optional LLM advisory validation trace. It is report-safe and never
    # grants execution authority; absent in legacy checkpoints.
    llm_reliability_trace: Annotated[list[dict[str, Any]], merge_lists]
    # Phase 5.2: one bounded Devil's Advocate hard-gate revalidation pass.
    # Optional so legacy checkpoints remain loadable.
    devils_advocate_revalidation_count: int
    devils_advocate_revalidation_ids: Annotated[list[str], merge_lists]
    devils_advocate_gate_active: bool
    # Phase 5.6: discovered resources outside declared scope require HITL.
    scope_drift_detected: bool
    scope_drift_events: Annotated[list[dict[str, Any]], merge_lists]
    # R2-graph-03: the operator's approval to continue past a scope-drift
    # pause. Undeclared keys are dropped by langgraph channel filtering,
    # so leaving this undeclared made the HITL resume path structurally
    # impossible (route_after_scope_review could never see True).
    scope_drift_approved: bool
    # R2-graph-07: smart-campaign enablement flags read by
    # _smart_campaigns_enabled (builder). Undeclared, they were dropped by
    # langgraph channel filtering and the gating silently reduced to the
    # governance profile alone.
    smart_mode: bool
    enable_smart_campaigns: bool
    llm_budget_trace: Annotated[list[dict[str, Any]], merge_lists]
    # Actual provider token telemetry; redaction-safe and never an authority,
    # finding, or proof-confirmation channel. Legacy checkpoints may omit it.
    llm_usage_trace: Annotated[list[dict[str, Any]], merge_lists]
    kev_catalog: list[str]

    # V7 Cognitive Upgrade — Phase 2: Mental Model / Knowledge Graph.
    #
    # Engagement-scoped structured picture of the target — typed nodes
    # (host / endpoint / credential / artifact / service / technology)
    # and typed edges (contains / authenticates_to / discovered_via /
    # references / same_host_as). Populated additively by every
    # discovery node (recon, crawler, hypothesis_analyzer, the four
    # V7 Sprint-2 deep-probers, post_exploit) via the deterministic
    # extractor in webpent.models.mental_model.extract_mental_model_updates.
    #
    # Reducer: merge_dicts (deep-merges node dicts, concatenates edge
    # lists) — same discipline as crawled_data/session_cookies/
    # credentials per the V6 Absolute-Flawless CISO audit fix. Parallel
    # branches can't clobber each other's discoveries; per-key updates
    # are visible to checkpoints.
    #
    # NOT persisted to ChromaDB (engagement-scoped, not cross-
    # engagement). Checkpoint-survives via the existing SqliteSaver
    # that already handles crawled_data. Will contain sensitive
    # material (credential fingerprints — never raw credentials,
    # internal IPs, artifact URLs) by design; treat its persistence
    # with the same care as evidence_bundle/evidence_hash (Phase 6 /
    # Section 6 risk note).
    mental_model: Annotated[dict[str, Any], merge_dicts]

    # POST-P0 Phase 2 (memory read-back): retrieved-only LearnedStrategy
    # record (negative lessons + structured-hypothesis ledger for the
    # target signature). Advisory projection produced by
    # shared/learned_context.retrieve_learned_strategy — NEVER
    # confirmation evidence, NEVER LLM-authored fact; consumers may only
    # demote or inform. Written by the strategist/planner read paths.
    learned_strategy: Annotated[dict[str, Any], merge_dicts]

    # POST-P0 Phase 3 (session liveness): redacted-by-construction
    # liveness record (status, last_verified_at, reauth attempt counters,
    # downgrade_requested). Produced by
    # shared/session_liveness.ensure_live_session — NEVER carries cookie
    # or credential values.
    session_liveness: Annotated[dict[str, Any], merge_dicts]

    # SCENARIO CONTRACT (two-layer recon): the pre-login anonymous baseline
    # and the authenticated-vs-anonymous surface diff derived from it.
    # ``pre_auth_snapshot`` is a redaction-safe projection (status code,
    # safe header subset, page title, bounded same-origin link/form paths,
    # body digest) captured by shared/auth_surface.capture_anonymous_snapshot
    # before any login attempt; it never stores Set-Cookie, tokens, or
    # response bodies. ``auth_surface_diff`` classifies each crawled endpoint
    # as ``both`` / ``auth_only`` / ``anonymous_only`` so auth-only resources
    # become priority BAC/IDOR hypothesis fuel, and the report can show the
    # two-layer coverage honestly.
    pre_auth_snapshot: Annotated[dict[str, Any], merge_dicts]
    auth_surface_diff: Annotated[dict[str, Any], merge_dicts]

    # SCENARIO CONTRACT (honest authentication status): machine-readable
    # outcome of the auth phase — "authenticated" (session validated),
    # "credentials_rejected" (credentials/cookies supplied but no validated
    # session obtained; the engagement continues unauthenticated with a
    # declared limitation), "unauthenticated" (no identity material
    # supplied), or "" (legacy checkpoints / not yet reached). Surfaced by
    # the report's limitations block so a silent anonymous downgrade can
    # never hide behind an empty message list.
    authentication_status: str

    # SCENARIO CONTRACT (declared limitations): append-only, redaction-safe
    # records of campaign constraints the report must state openly — failed
    # login, dead-session downgrade, single-principal coverage gaps, snapshot
    # unavailability, scope-source caveats. Producers append dicts of the
    # shape {"code", "detail", "source"}; values never include secrets.
    engagement_limitations: Annotated[list[dict[str, Any]], merge_lists]

    # V55 canonical evidence boundary. These fields are additive and
    # optional: old checkpoints and legacy node outputs remain valid. The
    # adapter layer stores only normalized, redacted model dumps and uses
    # append-only reducers so parallel tool branches cannot overwrite one
    # another. Raw commands and raw outputs stay outside state and are
    # represented by fingerprints / EvidenceRef records.
    canonical_executions: Annotated[list[dict[str, Any]], merge_lists]
    canonical_observations: Annotated[list[dict[str, Any]], merge_lists]

    # V55 Target Understanding projection. Optional and additive so legacy
    # checkpoints and graph consumers continue to work unchanged.
    target_understanding: Annotated[dict[str, Any], merge_dicts]
    # V62 additive Target Knowledge projection derived from observed state only.
    target_knowledge: Annotated[dict[str, Any], merge_dicts]
    # Deterministic, evidence-linked security proposals. These are advisory
    # hypotheses only; promotion and execution remain in existing proof and
    # Action Authority paths.
    security_reasoning_proposals: Annotated[list[dict[str, Any]], merge_lists]
    # Application intent is a bounded, report-safe projection used by
    # business-logic and hypothesis agents. Optional for legacy checkpoints.
    application_intent: Annotated[dict[str, Any], merge_dicts]
    policy_assumptions: Annotated[list[str], merge_lists]
    # Cross-engagement pattern hints are advisory, redacted, and append-only.
    pattern_hints: Annotated[list[dict[str, Any]], merge_lists]
    # Human feedback calibration is report-safe and never an execution gate.
    trust_matrix: Annotated[dict[str, Any], merge_dicts]

    # V55 additive Attack Graph projection. The graph is derived from the
    # Mental Model and relational evidence; it is optional and remains absent
    # from legacy runs unless explicitly enabled.
    attack_graph: Annotated[dict[str, Any], merge_dicts]

    # POST-P0 Phase 7: bounded chain plan derived from attack-graph output
    # (chain-plan-v1). Operator artifact only — steps execute exclusively
    # through the existing HITL sandbox/validator pipeline; status stays
    # "pending" until steps individually confirm through that pipeline.
    chain_plan: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 11 report-quality projection. It contains only contract
    # statuses and missing field names, never raw evidence or credentials.
    report_quality_gate: Annotated[dict[str, Any], merge_dicts]

    # V55 workflow understanding projection.  Passive observations and
    # explicit coverage gaps are additive; hypotheses continue through the
    # existing merge_hypotheses reducer and are never auto-promoted.
    workflow_observations: Annotated[list[dict[str, Any]], merge_lists]

    # UM-DR-30 (Workstream D §6 business-logic): the deterministic
    # invariant review over the workflow observations above (see
    # business_logic/invariant_checker.py — previously a zero-importer
    # orphan while its input already flowed through state). Advisory and
    # strictly non-promoting: every entry is a *candidate signal* whose
    # required_validation names the causal-guard evidence contract
    # (target-backed causal signal, independent negative control, sealed
    # replayable ProofBundle). The causal guard stays the sole
    # confirmation authority; this channel only tells planning where a
    # guarded probe is worth budget. Append-only: a re-run after a
    # model refresh adds signals without erasing the audit trail.
    invariant_review: Annotated[list[dict[str, Any]], merge_lists]

    # --- UM-DR-31 (evidence-driven adaptive research loop): the
    # research_loop node's own telemetry block
    # (production/adaptive_research.py — the bounded adaptive engine
    # that turns coverage-gap / invariant / workflow-boundary signals
    # into ordinary pool hypotheses for the strategist planner).
    # Deep-merged dict: per-iteration subkeys accumulate, scalar
    # counters are last-write-wins (the node is the only writer and
    # reads its own prior channel state first). Advisory only: no
    # finding vocabulary, no promotion, no confirmation authority —
    # the causal guard stays the sole confirmation authority and the
    # strategist's ranking/promotion gates stay the only path from a
    # research hypothesis to execution. ---
    research_loop: Annotated[dict[str, Any], merge_dicts]

    # --- UM-DR-32 (identity & business-logic evolution): the four
    # capability channels written by the identity_workflow node
    # (production/identity_workflow.py) and consumed by the strategist
    # line, stateful discovery hint scheduling, and the validator
    # routes. All advisory, typed, provenance-aware, and strictly
    # non-promoting: no finding vocabulary, no confirmation authority —
    # cqa_v2.guarded_causal_evaluate stays the sole confirmation
    # authority (UM-DR-32 §1.1). Deep-merged dicts: the node is the only
    # writer and re-reads its own prior channel state first. ---
    object_identity_registry: Annotated[dict[str, Any], merge_dicts]
    identity_alias_graph: Annotated[dict[str, Any], merge_dicts]
    multi_identity_reasoning: Annotated[dict[str, Any], merge_dicts]
    identity_research_hints: Annotated[dict[str, Any], merge_dicts]
    # bounded composite-workflow sequence candidates (§7): advisory
    # records carrying the invariant under test, the supporting
    # observations and the safety classification; execution happens only
    # through the authorized executor under the fixture safety contract.
    composite_workflow_candidates: Annotated[list[dict[str, Any]], merge_lists]
    # the node's own telemetry block (same contract as research_loop).
    identity_workflow: Annotated[dict[str, Any], merge_dicts]

    # POST-P0 Phase 8: bounded stateful-flow replay hypothesis specs
    # (skip/reorder differentials over crawler-recorded form sequences).
    # Advisory candidates that still route through the normal validation
    # pipeline; the probe sequence itself is the deterministic validation
    # attempt and claims no confirmation authority.
    flow_hypotheses: Annotated[list[dict[str, Any]], merge_lists]
    workflow_coverage_gaps: Annotated[list[dict[str, Any]], merge_lists]

    # V7 Cognitive Upgrade — Phase 4: Working Memory formalization.
    #
    # The remaining V7 state fields are declared here with proper
    # LangGraph reducers (following the exact merge_dicts / merge_lists
    # discipline already used for crawled_data / session_cookies /
    # credentials / mental_model per the V6 Absolute-Flawless CISO
    # audit fix). They are populated by Phase 5 (Self-Critique),
    # Phase 6 (Decision Log, Goal Tree, Rabbit Hole ledger), and
    # Phase 7 (Rabbit Hole branch goals) — declaring them now (with
    # empty defaults) means Phase 5/6/7 can populate them without
    # further state-schema changes, and the reducers are in place
    # from day one so parallel-branch writes are safe.
    #
    # goal_tree: dict-shaped (one root per engagement, child nodes
    #   per active investigation thread). Phase 6 populates this;
    #   Phase 3's Dynamic Prioritization will select from the tree's
    #   open leaves rather than from a flat list, giving "abandon
    #   this branch" (Phase 5) somewhere concrete to point at.
    #
    # decision_log: append-only list of DecisionLogEntry dicts.
    #   Phase 6 persists each entry to a new SQLite table following
    #   the same CREATE TABLE IF NOT EXISTS + manager-class pattern
    #   already used for findings and hypotheses.
    #
    # rabbit_hole_ledger: dict-shaped visited-assets dedup set
    #   powering Loop Prevention (Phase 6). Keyed by normalised
    #   identity (canonical URL / content hash / credential
    #   fingerprint); value is the discovery_source that first
    #   visited the asset. Phase 7's Rabbit Hole checks this before
    #   any branch action — already-visited -> stop, log it, done
    #   (direct generalization of exploit_chainer's
    #   _already_proposed_pairs).
    goal_tree: Annotated[dict[str, Any], merge_dicts]
    decision_log: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter G5: report-safe, append-only action-selection trace.  It is
    # additive so legacy checkpoints remain loadable and never grants authority.
    decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    # Typed action lifecycle audit; report-safe and append-only.
    lifecycle_events: Annotated[list[dict[str, Any]], merge_lists]
    # R-B step-budget governor: append-only per-superstep trace of node
    # executions ({"seq","node","under_pressure",...}).  Written by the
    # central tracer in graph/builder.py; read by budget_governor.py to
    # compute remaining budget.  Report-safe observability: never grants
    # authority and never gates a finding decision.  Duplicates are
    # intentional (a node may legitimately run more than once).
    node_step_trace: Annotated[list[dict[str, Any]], merge_lists]
    rabbit_hole_ledger: Annotated[dict[str, Any], merge_dicts]
    # P1 coverage accounting: every strategist candidate gets an explicit
    # disposition; this is advisory metadata and never authorizes execution.
    coverage_ledger: Annotated[dict[str, Any], merge_dicts]
    # Declarative application-aware campaign coverage.  It is report-safe and
    # never authorizes execution or promotes findings.
    campaign_ledger: Annotated[dict[str, Any], merge_dicts]
    # Bounded campaign contracts and hypothesis DAG; advisory only and never
    # an authorization or finding-confirmation channel.
    campaign_plan: Annotated[dict[str, Any], merge_dicts]
    # Redaction-safe causal records; entries are advisory and never findings.
    evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter positive/negative evidence ledgers are report-safe and
    # append-only; they never authorize actions or promote findings.
    positive_evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    negative_evidence_ledger: Annotated[list[dict[str, Any]], merge_lists]
    # Proof Engine outputs are proposals and telemetry, never execution authority.
    proof_gap_assessments: Annotated[list[dict[str, Any]], merge_lists]
    proof_plan: Annotated[dict[str, Any], merge_dicts]
    proof_observability: Annotated[dict[str, Any], merge_dicts]
    proof_outcomes: Annotated[list[dict[str, Any]], merge_lists]
    # G7 additive artifact channel; bundles are immutable once sealed.
    proof_bundles: Annotated[list[dict[str, Any]], merge_lists]
    # Smart Hunter task-level runtime outcomes. These records are advisory and
    # never promote a campaign or finding without the proof engine.
    campaign_task_outcomes: Annotated[list[dict[str, Any]], merge_lists]
    smart_next_actions: Annotated[list[dict[str, Any]], merge_lists]
    smart_replanning: Annotated[dict[str, Any], merge_dicts]
    # Smart Hunter research-intelligence projections. These fields are
    # report-safe planning telemetry only; they never confirm findings or
    # authorize execution. Legacy checkpoints may omit them safely.
    knowledge_gaps: Annotated[list[dict[str, Any]], merge_lists]
    research_session: Annotated[dict[str, Any], merge_dicts]
    research_decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    smart_information_actions: Annotated[list[dict[str, Any]], merge_lists]
    # Typed research contracts are additive planning telemetry only. They never
    # authorize execution, promote hypotheses, or replace proof validation.
    research_context: Annotated[dict[str, Any], merge_dicts]
    research_candidate_actions: Annotated[list[dict[str, Any]], merge_lists]
    research_unified_decision_trace: Annotated[list[dict[str, Any]], merge_lists]
    research_active_observations: Annotated[list[dict[str, Any]], merge_lists]
    # RIT-5: bounded DeepReconEngine producer telemetry (per hypothesis run).
    # merge_dicts: repeated projections merge key-wise (idempotent and
    # checkpoint-safe). Advisory summary — never evidence, never a verdict.
    deep_recon_summary: Annotated[dict[str, Any], merge_dicts]
    surface_coverage: Annotated[dict[str, Any], merge_dicts]
    research_failed_paths: Annotated[list[dict[str, Any]], merge_lists]
    # One deterministic, redaction-safe summary per research round. The map is
    # keyed by round so repeated projections are idempotent and checkpoint-safe.
    research_round_artifacts: Annotated[dict[str, Any], merge_dicts]
    # Bounded recovery telemetry. These records are report-safe and advisory;
    # they never bypass policy, scope, idempotency, or proof gates.
    recovery_events: Annotated[list[dict[str, Any]], merge_lists]
    recovery_state: Annotated[dict[str, Any], merge_dicts]
    # Phase 4 evidence-only behavior and causal projections. They never create
    # findings, authorize transport, or replace proof validation.
    novel_behavior_observations: Annotated[list[dict[str, Any]], merge_lists]
    causal_attack_edges: Annotated[list[dict[str, Any]], merge_lists]
    causal_attack_graph: Annotated[dict[str, Any], merge_dicts]
    # Read-only HTTP observations from the bounded Smart Hunter executor.
    # Bodies, cookies, and raw headers are intentionally excluded.
    smart_http_observations: Annotated[list[dict[str, Any]], merge_lists]

    # V55 Phase 6 adaptive hunt fields.
    # These remain additive and empty on
    # legacy runs. Tasks are scheduler records only; executors continue to
    # enforce scope, evidence, and HITL gates.
    adaptive_revisit_tasks: Annotated[dict[str, Any], merge_dicts]
    adaptive_revisit_ledger: Annotated[dict[str, Any], merge_dicts]
    adaptive_hunt: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 7 advisory planner decisions. These records are optional and
    # empty on legacy runs; they never control graph routing or execute tools.
    planner_decision: Annotated[dict[str, Any], merge_dicts]
    planner_gate_audits: Annotated[list[dict[str, Any]], merge_lists]

    # P2 execution safety projection.  Records why live PoC execution was
    # allowed, paused for HITL, or rejected; never stores payloads/secrets.
    execution_gate: Annotated[dict[str, Any], merge_dicts]

    # V55 Phase 10 static JavaScript intelligence. The projection stores
    # hashes, redacted metadata, and bounded mapping tasks only; source text
    # and raw secret values never enter checkpoint state.
    javascript_intelligence: Annotated[dict[str, Any], merge_dicts]
    js_targeted_tasks: Annotated[list[dict[str, Any]], merge_lists]

    # V55+ passive broad-surface coverage. Observations are report-safe,
    # bounded, and never equivalent to confirmed findings.
    surface_security: Annotated[dict[str, Any], merge_dicts]

    # Project Zero production wiring (2026-10-22). Advisory-only outputs
    # from the six library-tier modules; all default-off via settings
    # flags and never derived from or applied to Findings.
    surface_drift: Annotated[dict[str, Any], merge_dicts]
    tech_stack_cve: Annotated[dict[str, Any], merge_dicts]
    taint_sources_recorded: int
    red_vs_blue_selfcheck: Annotated[dict[str, Any], merge_dicts]

    # Project Zero catalog injection (2026-10-24). Declared so a producer
    # node can populate it (LangGraph drops undeclared keys) and so the
    # crawler's tech-stack CVE correlation actually sees the operator's
    # feed. Operator file paths: settings cve_feed_catalog_path.
    # kev_catalog above is declared but still has no producer node; the
    # reporter resolves it via shared.operator_catalogs.load_kev_catalog.
    cve_feed_catalog: Annotated[list[dict[str, Any]], merge_lists]

    # V55 Phase 12 memory boundary. The projection stores safe counters,
    # provenance metadata, and feedback audits; it never replaces findings or
    # historical evidence and never persists raw external credentials.
    memory_summary: Annotated[dict[str, Any], merge_dicts]
    memory_feedback: Annotated[list[dict[str, Any]], merge_lists]

    # V8 P0 A2: Rabbit Hole → Strategist closed loop counter.
    #
    # Bounded re-entry cap. The graph's `route_after_rabbit_hole`
    # conditional edge inspects this counter to decide whether to
    # route new RABBIT_HOLE-origin hypotheses back to the Strategist
    # for promotion, or to fall through to cvss_engine (the previous
    # one-directional behaviour). The Strategist on re-entry filters
    # to RABBIT_HOLE-origin hypotheses only — heuristic and cross-
    # reasons hypotheses already decided in the first pass are not
    # re-processed.
    #
    # The cap itself (max_loop_back_iterations) lives in
    # RabbitHolePolicy (config/policies.py) — default 1 — so operators
    # can tune it via policy overrides. This state field is just the
    # counter; the Strategist increments it on every re-entry pass.
    rabbit_hole_loop_back_count: int

    # V10 P0-2 Option A: thread_id stamped into state so the validator
    # can look up the sealed re-auth secret in the worker-only vault
    # (src/webpent/auth/reauth_vault.py) when FIX-10 has scrubbed
    # ``credentials["password"]`` from the checkpoint. Set once by
    # the worker (pentest_worker.run_pentest_task) in initial_state;
    # no node modifies it. Treated as last-write-wins (no reducer) —
    # same pattern as ``current_phase``, ``stealth_mode``, etc.
    #
    # Not sensitive: thread_id is already in the LangGraph config
    # (configurable.thread_id), already in Celery task kwargs, and
    # already in DB rows (findings.thread_id). Persisting it in state
    # does not expand the disclosure surface.
    thread_id: str
    # Cross-engagement and cross-owner isolation identifiers. Optional for
    # legacy checkpoints; cumulative history reads fail closed to the
    # anonymous partition when owner scope is absent.
    owner_username: str | None
    client_id: str | None
    engagement_id: str | None
    # Runtime spine identity is additive. The live object is checkpoint-redacted
    # to a descriptor and rebuilt at resume boundaries.
    campaign_id: str
    runtime_context: Any
    # Current, report-safe runtime capability gaps. This is a projection, not
    # an append-only history: a resolved gap must disappear from the snapshot.
    runtime_capability_gaps: Annotated[
        list[dict[str, Any]], replace_runtime_capability_gaps
    ]

    # =========================================================================
    # TEAM-1 Phase 5 (P0 state-contract repair): keys previously written by
    # graph nodes WITHOUT a PentestState declaration. LangGraph silently drops
    # undeclared keys, so these writers were producing state that vanished
    # before any reader (or the checkpoint layer) could observe it. Each key
    # below now has an explicit writer -> declaration -> reader contract:
    #
    #   target_brain             — written by target_understanding_node
    #                              (agents/target_understanding/agent.py);
    #                              read by the research projection layer
    #                              (research_engine/projection_adapter.py).
    #   runtime_feedback         — written by smart_campaigns_execution_node
    #                              (agents/smart_campaigns/agent.py); read by
    #                              shared/research_intelligence.py and the
    #                              smart planner's feedback projection.
    #   campaign_allocation      — written by smart_campaigns_node; consumed
    #                              on planner re-entry for allocation continuity.
    #   scope_review_blocked /   — written by scope_review_node
    #   scope_review_required      (graph/builder.py) so the HITL scope-review
    #                              checkpoint persists its outcome.
    #   scope_runtime_fingerprint— written by subdomain_takeover_node and
    #                              crawler_node result records; ties a run's
    #                              observations to the exact compiled scope.
    #   coverage_gaps            — generic append-only coverage-gap channel;
    #                              written by attack_graph_node's fail-closed
    #                              error path so a projection failure is
    #                              visible downstream instead of dropped.
    # =========================================================================
    target_brain: Annotated[dict[str, Any], merge_dicts]
    runtime_feedback: Annotated[dict[str, Any], merge_dicts]
    campaign_allocation: Annotated[dict[str, Any], merge_dicts]
    # TEAM-1 Phase 6 (post-validation replan): bounded strategist re-entry
    # counters. post_validation_replan_count consumes one of the 2 allowed
    # replan entries per run; post_validation_replan_evidence_count is the
    # deterministic-evidence baseline (Tool-Confirmed + Refuted findings)
    # recorded at the last strategist pass — the router requires a strictly
    # higher count before allowing another replan entry.
    # TEAM-1 Phase 9: supplementary CQA v2/Smart post-process artifacts
    # (non-authoritative; original findings are never mutated by the layer).
    cqa_v2_postprocess: Annotated[dict[str, Any], merge_dicts]
    post_validation_replan_count: int
    post_validation_replan_evidence_count: int
    scope_review_blocked: bool
    scope_review_required: bool
    scope_runtime_fingerprint: str
    coverage_gaps: Annotated[list[str], merge_lists]

    # Sprint I-1b, item 1.1 (surfaced by wiring scripts/check_state_contract.py
    # into CI for the first time): _research_campaign_node
    # (graph/builder.py) has written these 7 keys since it was added, but
    # they were never declared here -- a pre-existing gap this sprint's CI
    # wiring caught immediately. Types below match every actual write site
    # in graph/builder.py's _research_campaign_node (verified, not guessed).
    research_campaign_skipped: str
    research_campaign_result: dict[str, Any]
    fabric_dispatch_trace: list[dict[str, Any]]
    research_campaign_executed: bool
    avi_production_dispatch: bool
    manual_path_used: bool
    research_campaign_error: str

    # =========================================================================
    # M2-impl WP-B (Dispatch #009 — R1 of Ruling M2-001): DECLARED-KEY
    # INGRESS. The corrected dynamic census (RED-2 P-5, adopted as the
    # implementation baseline by Ruling R1) proved every key the modern-spine
    # seam and the research-campaign node rely on was UNDECLARED — so
    # langgraph 1.2.10 silently dropped it at graph input AND at node-update
    # writes (NF-M2-01: the entire I-3/campaign chain was transport-dead).
    # Each key below now has an explicit writer -> declaration -> reader
    # contract. ADDITIVE ONLY: old checkpoints resume unchanged (RED-2
    # P-2.2 proved additive extension loads; C10).
    #
    # NOT DECLARED, deliberately (M2 transport design):
    #   _modern_orchestrator — LIVE-OBJECT transport is PROHIBITED (Ruling
    #     R2; the checkpoint layer fails loudly on it per RED-2 V13). The
    #     campaign lane acquires via factory re-derivation
    #     (modern_spine_integration.resolve_spine_orchestrator).
    #   _tool_boundary / _advisory_memory — live-object in-process
    #     conveniences; declaring them would make any caller-supplied value
    #     crash every checkpoint write (V13). They stay in-process-only.
    #   _audit_chain holds a JSON-serializable DESCRIPTOR (engagement id +
    #     audit file paths), not the live chain (same V13 lesson). The chain
    #     object itself is produced and used in-process by the seam (WP-A).
    # =========================================================================
    # --- ingress / routing (caller- or launch-supplied) ---
    target_url: str | None
    entrypoint: str | None
    engagement_instance_id: str | None
    target_fingerprint: str | None
    default_vulnerability_class: str | None
    campaign_budget_remaining: int | None
    admitted_fixtures: Annotated[list[dict[str, Any]], merge_lists]
    advisory_matrix_row_spec: dict[str, Any]
    openapi_spec: Any
    schema_docs: Any
    observed_routes: Any
    observed_preconditions: Any
    candidate_hypotheses: Annotated[list[Any], merge_lists]
    # --- seam production (modern_spine_recon_node) ---
    _production_trace: dict[str, Any]
    _audit_chain: dict[str, Any]
    advisory_intake_records: Annotated[list[dict[str, Any]], merge_lists]
    advisory_intake_rejections: Annotated[list[dict[str, Any]], merge_lists]
    # Serializable projection of the registered advisory candidates
    # (intake_id/dedupe_key/terminal_state/...); the live dataclass objects
    # never enter state (C10/V13).
    advisory_registered: Annotated[list[dict[str, Any]], merge_lists]
    advisory_registered_count: int
    advisory_telemetry: Annotated[dict[str, Any], merge_dicts]
    advisory_hypotheses_published: int
    recon_window_remaining: int
    _hypotheses_produced: int
    _hypotheses_registered: int
    _hypotheses_failed: Annotated[list[dict[str, Any]], merge_lists]
    _registered_candidate_ids: Annotated[list[str], merge_lists]
    _active_research_loop_candidates: int
    _modern_hypotheses: Annotated[list[dict[str, Any]], merge_lists]
    _modern_research_decision: dict[str, Any]
    _modern_spine_trace: dict[str, Any]
    _modern_spine_hypothesis_evidence: dict[str, Any]
    # --- spine status markers (must survive to final state) ---
    modern_spine_active: bool
    modern_spine_mode: str
    modern_spine_version: str | None
    legacy_compatibility_mode: bool
    legacy_authority_blocked: bool
    # --- campaign dispatch artifacts (_research_campaign_node) ---
    avi_version: str | None
    avi_trace_summary: dict[str, Any]
    avi_security_report: dict[str, Any]
    avi_decisions_executed: int | None
    avi_promoted_count: int | None
    avi_promoted_merged: int
    avi_promoted_merge_failed: int
    # WP-C rehydration evidence (design keys introduced by this window; see
    # scripts/m2_corrected_census.json for the pre/post declaration record).
    research_loop_rehydrated: int
    research_loop_rehydrated_failed: int
    research_loop_active_candidates: int
    research_campaign_hypotheses_rejected: int
    # --- UM-DR-28 (production discovery integration): the campaign-side
    # stateful-discovery summary emitted by the family_execution node —
    # outcomes, per-case provenance, request budgets, scope refusals.
    # Declared so LangGraph channel filtering keeps it (the R2-graph-03
    # lesson: an undeclared key is silently dropped and the campaign
    # report never sees it). Last-write-wins (one node writes it). ---
    stateful_discovery: dict[str, Any]
    # --- UM-DR-30 (Workstream F §8 — campaign-runtime coverage gap map):
    # the advisory gap report emitted by the coverage_gap_report node
    # (production/coverage_gap_report.py — the formerly orphan
    # coverage_map/gap_detector facades, now campaign-wired). Key/status-
    # shaped projection of where the campaign did NOT look (open coverage
    # cells), bounded at 200 gap entries. Advisory only — no finding
    # vocabulary, no promotion, no confirmation authority. Last-write-
    # wins (wired exactly once per campaign pass, between the reporter
    # and reflection nodes). ---
    coverage_gap_report: dict[str, Any]
    # --- UM-DR-30 (Workstream A §3.3 — family execution spine channel
    # contract): the family_execution node's own output block. All nine
    # keys were produced since the spine landed but undeclared, so
    # LangGraph channel filtering silently dropped them (the exact
    # R2-graph-03 miss class, now closed for the whole family at once):
    # the campaign report and every downstream consumer saw ONLY the
    # merged ``findings`` and never the execution status, candidates,
    # plans, validation results, sealed proof bundles, observed
    # capabilities, feed-derivation flag, or the merged-count.
    # Semantics: last-write-wins with NO reducer — the spine is wired
    # exactly once per campaign pass (EXECUTION_SANDBOX →
    # FAMILY_EXECUTION → VALIDATOR), matching the dedup_report
    # precedent. Advisory/auditable data only: none of these channels
    # grants confirmation authority (cqa_v2/causal_guard.py stays the
    # sole authority); they make the non-findings spine output visible
    # to reporting, coverage intelligence, and the operator. Absent
    # from legacy checkpoints by construction (total=False). ---
    family_execution_status: str
    family_observed_capabilities: list[str]
    family_candidates: list[dict[str, Any]]
    family_execution_plans: list[dict[str, Any]]
    family_executed_plans: int
    family_validation_results: list[dict[str, Any]]
    family_proof_bundles: list[dict[str, Any]]
    family_findings_merged: int
    family_feeds_derived: bool
    # --- UM-DR-30 (cont.): the SAME return statement emits eleven more
    # advisory keys — the chained-exploit projections, the adversarial
    # review downgrades, the creative-horizon hypotheses, the expanded
    # surface, the adaptive-defense state, and the self-verify quality
    # summary. Same miss class (silently dropped), same semantics (one
    # graph-node writer — attack_graph_planner's dict is an internal
    # result the node reads, not a graph writer — so last-write-wins,
    # no reducer). Declared together so the spine's full output block
    # is accounted for, not just the family_* vocabulary. ---
    attack_graph_chains_total: int
    attack_graph_chains_confirmed: int
    attack_graph_findings_promoted: int
    goed_feedback_hypotheses: list[dict[str, Any]]
    adversarial_review_downgraded: list[dict[str, Any]]
    creative_hybrid_hypotheses: list[dict[str, Any]]
    expanded_attack_surface: dict[str, Any]
    adaptive_defense: dict[str, Any]
    self_verify_quality: dict[str, Any]
    self_verify_needs_review: list[dict[str, Any]]
    self_verify_learned_rules: list[dict[str, Any]]
