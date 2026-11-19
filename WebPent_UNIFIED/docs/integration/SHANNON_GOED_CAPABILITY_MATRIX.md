# Shannon × GOED Capability Matrix

**Document ID:** SHANNON-GOED-MATRIX-1.0
**Date:** 2026-09-10
**Rule set:** Protected migration protocol §5–§7, §10–§15.
**Decision vocabulary:** `KEEP` (GOED already adequate/better) · `PORT` (reusable Shannon implementation safely integrated) · `ADAPT` (useful but must be changed to fit GOED) · `BUILD` (GOED needs it, Shannon has no suitable implementation) · `REJECT` (unsafe / incompatible / redundant / legally unsuitable / architecturally harmful).
**License gate (see SHANNON_LICENSE_AUDIT.md):** Shannon is AGPL-3.0 → **`PORT` is impossible for any Shannon artifact** (zero-copy policy). Every Shannon-derived capability is therefore realized as `KEEP`, `ADAPT` (original Python re-implementation of the pattern), `BUILD`, or `REJECT`.

Evidence key: Shannon paths are relative to `shannon-main/` (read-only reference); GOED paths relative to repo root. "Verified" = implementation read at the pristine commit; hypotheses without located implementations are explicitly marked.

---

## A. High-Value Capability Investigation (protocol §10)

### A1. Source-aware analysis

| Field | Content |
|---|---|
| Capability | Read/parse target application source code to ground vulnerability reasoning |
| Shannon implementation | **Verified.** Capella agentic SAST: `apps/worker/src/ai/sast/capella/temporal/workflow.ts` (10 stages: architecture→threat-model→plan→research→dedupe→review→critic→confirm→calibrate→export); confined repo tools `ai/sast/capella/tools/repository-tools.ts` (path confinement, 64KB read / 2MB grep budgets, regex subset); SARIF export `sarif-exporter.ts`; stage prompts `prompts/sast/capella/*.prompt.hbs` (Mantis-derived, Apache-2.0); pre-recon agent `prompts/pre-recon-code.txt` + collector `collectors/pre-recon-collector.ts` |
| GOED implementation | **None.** GOED is runtime/surface-oriented; `intelligence/` models the target from runtime observation only. No source-reading module exists (verified: no semgrep/tree-sitter/source-scan under `src/webpent`) |
| Evidence | Shannon files above read at pristine commit; GOED absence verified by search (`rg -i "semgrep\|tree-sitter\|source_scan" src/webpent` → no matches) |
| Decision | **ADAPT** |
| Integration strategy | Port the *pattern*, not the code: (1) `src/webpent/integration/source_mapping.py` — deterministic `CodeLocation(file, line, role∈{sink,source,guard}, symbol)` + `SourceMappingRecord` linking source locations ↔ hypotheses ↔ runtime endpoints ↔ attack-graph nodes, with join function; (2) `src/webpent/integration/surface_dossier.py` accepts source-derived endpoint/authz-candidate/injection-source intel as *untrusted advisory input*; (3) the full LLM-driven staged SAST pipeline is **left as a proposal-only scaffold** (`AGENDA_SOURCE_TASK` signals) — real LLM SAST runs require provider keys → `PENDING_TEAM2` |
| Risk | LOW for deterministic contracts (offline-tested). MEDIUM for future LLM SAST: must never bypass CausalGuard — enforced because source findings enter GOED only as hypotheses/signals, never verdicts |

### A2. Attack-surface discovery

| Field | Content |
|---|---|
| Capability | Enumerate endpoints, parameters, roles, authz candidates, injection points |
| Shannon implementation | **Verified.** Recon agent collector `collectors/recon-collector.ts` (9 typed `set_*` tools: executive_summary, technology_stack, authentication, add_endpoints, input_vectors, network_map, role_architecture, authz_candidates, injection_sources) rendered to `recon_deliverable.md` via `services/recon-renderer.ts`; discovery happens inside the LLM loop (no standalone crawler) |
| GOED implementation | **Verified, deeper.** `agents/recon*`, crawler with feature flags, `src/webpent/v29`-era `surface security` module (`test_v29_surface_security.py`), target understanding v17 (`test_v17_target_understanding.py`), `intelligence/endpoint_intelligence` + `contracts.ApplicationKnowledgeGraph`, `shared/attack_graph.py` projection, authorization matrix flag |
| Evidence | Both sides verified by file reads + tests present |
| Decision | **KEEP** GOED runtime discovery + **ADAPT** a consolidation artifact |
| Integration strategy | New `src/webpent/integration/surface_dossier.py`: deterministic `SurfaceDossier` that consolidates GOED's existing surface signals (crawled endpoints, auth state, authz candidates, injection-source signals) into one evidence-referenced dossier the research agenda can consume. No GOED discovery behavior is altered |
| Risk | LOW (pure additive projection; no I/O) |

### A3. Source → runtime attack-path mapping

| Field | Content |
|---|---|
| Capability | Correlate code locations (sinks/sources/guards) with live endpoints and candidate attack paths |
| Shannon implementation | **Verified.** `analysisCodeLocationSchema` in `ai/queue-schemas.ts` (`file, start_line, end_line, role: sink\|source\|guard, symbol`); `sast_source_location` minted by `ai/reconciliation/sast/enrichment/policy.ts::sourceLocationFromContext`; join into report by `services/code-location-join.ts::attachQueueCodeLocations`; stable renumbering via `services/renumber-core.ts::remapSastProvenance` |
| GOED implementation | **None** (no source-location concept anywhere in `src/webpent`) |
| Evidence | Shannon files verified; GOED absence verified by search |
| Decision | **ADAPT** |
| Integration strategy | `source_mapping.py`: `CodeLocation`, `SourceMappingRecord` (source location ↔ endpoint ↔ hypothesis id ↔ evidence refs), `join_source_locations()` producing mapping rows; designed to attach to `shared/attack_graph.py` projections as advisory annotations. Deterministic, offline-testable |
| Risk | LOW |

### A4. Authentication / session handling

| Field | Content |
|---|---|
| Capability | Validate login, persist session state, share authenticated state with downstream research |
| Shannon implementation | **Verified.** `services/validate-authentication.ts`: real browser drive + `submit_auth_result` tool contract `{login_success, failure_point ∈ {username_or_password, totp_secret, out_of_band}, failure_detail}`; `verifySavedAuthState()` validates Playwright storageState; shared session file `prompts/shared/_shared-session.txt` (state-load, fallback full login, never overwrite); TOTP script `scripts/generate-totp.ts` |
| GOED implementation | **Verified.** Graph auth stage nodes, `state.session_cookies` (+ `merge_auth_state` reducer), `shared_reauth_vault` (alembic 0003, `test_vip_shared_reauth_vault.py`), `vip_auth_posture` tests, `auth/` package, credentials handling in CLI `scan` |
| Evidence | Both verified |
| Decision | **KEEP** GOED's session/auth machinery (deeper, integrated with safety gates) + **ADAPT** Shannon's *verdict contract* |
| Integration strategy | `src/webpent/integration/auth_session_contract.py`: typed `AuthValidationVerdict` (tri-state with failure taxonomy) + `AuthSessionRecord`; consumes/produces GOED state dicts (no new transport, no browser code, no credential storage — redaction preserved). Browser-automated validation flow itself stays with GOED's existing playwright stack → real-runtime exercise `PENDING_TEAM2` |
| Risk | LOW (contract only) |

### A5. Browser automation

| Field | Content |
|---|---|
| Capability | Drive a real browser for discovery/exploitation |
| Shannon implementation | **Verified.** `@playwright/cli@0.1.1` skill injected only for `BROWSER_AGENTS` (`utils/browser-agents.ts`), stealth config writer `ai/playwright-config-writer.ts` (navigator.webdriver deletion), session mapping `session-manager.ts::PLAYWRIGHT_SESSION_MAPPING`, screenshots under `.playwright-cli` |
| GOED implementation | **Verified.** Native `playwright>=1.48,<1.49` dependency, Playwright base image (`Dockerfile.base` mcr playwright python v1.48), `test_browser_readiness.py`, active validators (P0), browser-based exploitation paths in `agents/validator/active_checks.py` |
| Evidence | Both verified |
| Decision | **KEEP** (GOED's stack is deeper-integrated with `ActionAuthority`/safety gates; Shannon's is a CLI skill for its pi agent loop and AGPL) |
| Integration strategy | None needed. No Shannon browser artifact enters GOED |
| Risk | NONE |

### A6. HTTP / API interaction

| Field | Content |
|---|---|
| Capability | HTTP client layer, request templating, fuzzing helpers |
| Shannon implementation | **Verified ABSENT.** No HTTP wrapper exists; agents use `bash` (curl) via pi tool; only preflight reachability check `services/preflight.ts` (DNS pinning + metadata blocklist) |
| GOED implementation | **Verified, deep.** `httpx` throughout, `tools/` adapters, `tools/recon/ffuf.py`, request/response canonical evidence v16, validators |
| Evidence | Shannon absence verified by search; GOED presence verified |
| Decision | **KEEP** — Shannon provides nothing to take |
| Integration strategy | None |
| Risk | NONE |

### A7. Exploitation loops

| Field | Content |
|---|---|
| Capability | Decide when/how exploitation runs; record exploit outcomes with proof |
| Shannon implementation | **Verified.** Queue-gated design: `services/exploitation-checker.ts::checkQueue` (pure logic) + `services/queue-validation.ts::validateQueueSafe`; queue files `{class}_exploitation_queue.json` published by reconciliation; exploit agent validates every `vulnerability_id` against `validIds` (`temporal/activities.ts::runExploitAgentWithCollector`) — agent cannot invent targets; `collectors/exploit-collector.ts::add_exploit` strict union `exploited{severity, severity_rationale, impact, exploitation_steps[], proof_of_impact}` vs `blocked{current_blocker, potential_impact, evidence_of_vulnerability, what_we_tried[], how_this_would_be_exploited[]}`; "Proof by Construction" prompts (NOT copied) |
| GOED implementation | **Verified partial.** `agents/` exploit_chainer, PoC policy (`test_v30_evidence_poc_contracts.py`: destructive fail-closed, high-risk needs approval), execution sandbox + HITL, CausalGuard flow; **but no validated exploitation planning queue artifact** linking hypotheses→planned exploit attempts with deduped ids |
| Evidence | Both verified |
| Decision | **ADAPT** |
| Integration strategy | `src/webpent/integration/exploitation_queue.py`: `ExploitationQueue` + `QueueEntry` (id namespace-validated, dedup, hypothesis+evidence refs required), `gate()` returning `RUN/SKIP` decisions with reasons, `ExploitAttemptRecord` strict union (`attempted` requires observation+evidence refs → always routed to CausalGuard via existing deterministic evaluation; `blocked` requires blocker+what_was_tried). **Queue never confirms anything; verdict authority untouched** |
| Risk | MEDIUM→mitigated: gating is additive; every record explicitly non-authoritative; offline-tested |

### A8. Attack planning

| Field | Content |
|---|---|
| Capability | Plan and order attack/research work |
| Shannon implementation | **Verified.** Fixed Temporal pipeline `temporal/workflows.ts::pentestPipeline` (preflight→auth→capella→pre-recon→recon→5 parallel vuln/reconcile/exploit lanes→report); retry policies; NO dynamic priority (verified absence in §14 of Shannon report) |
| GOED implementation | **Verified.** LangGraph 31-node topology with conditional routing, planner nodes, `research_engine/` (orchestrator, priority_engine, ResearchBudget, scheduler), `research/` (ResearchQueue.ordered, decision_loop), `smart/` prioritizer |
| Evidence | Both verified |
| Decision | **KEEP** GOED planning + **BUILD** the missing dynamic agenda (see §B) |
| Integration strategy | No Shannon adoption for planning itself; Shannon's *queue discipline* (validated ids, skip-when-empty) is folded into the ADAPT items above |
| Risk | NONE |

### A9. Finding reconciliation

| Field | Content |
|---|---|
| Capability | Merge/dedupe observations into stable, validated exploitation/reporting tasks |
| Shannon implementation | **Verified.** 4 stages under `ai/reconciliation/`: `prepare.ts` (admit producer observations, re-validate JSON field-by-field, scrub `FORBIDDEN_PUBLISHED_KEYS` so exploit agents never see internal provenance), `enrich.ts` (SARIF intake + CWE mapping), `form.ts` (task formation with singleton fallback on model failure, source jail), `materialize.ts`+`publish.ts` (stable refs `INJ-01…`, schema-versioned idempotent git commit) |
| GOED implementation | **Verified partial.** `state/reducers.py::merge_findings`, `test_finding_aggregation.py`, `test_finding_reducer_strength.py`, `validators/` merge-back (`test_validator_merge_back.py`); no staged reconciliation with stable task refs |
| Evidence | Both verified |
| Decision | **ADAPT** |
| Integration strategy | `src/webpent/integration/reconciliation.py`: deterministic 3-stage (prepare→form→materialize) reconciliation: input validation per-field, dedupe by typed identity, **scrub of internal-only keys before downstream use** (GOED analog of Shannon's forbidden keys: ground-truth labels, hidden oracles), stable refs `REC-###`, idempotent (same inputs → same refs). Output is *tasks for the agenda*, never findings/verdicts |
| Risk | LOW (pure functions, offline-tested) |

### A10. Workspace / resume capabilities

| Field | Content |
|---|---|
| Capability | Durable workspace; resume without redoing completed work |
| Shannon implementation | **Verified.** Git-as-database: `services/git-manager.ts` (`createGitCheckpoint`, `commitGitSuccess`, path-scoped commits, `readCommittedFile`), resume block in `workflows.ts` (`loadResumeState`, `checkpointProvider.shouldSkipAgent()`, `restoreGitCheckpoint`), `DurableScanState`/`ReportProgress` (`types/run-state.ts`), invalid-draft git rollback |
| GOED implementation | **Verified.** LangGraph `SqliteSaver` checkpointer with secret redaction (`graph/checkpoints.py`), `shared/resume_capability.py` (HMAC-signed), `research_engine/research_state.py` (`ResearchTask`/`ResearchState` serializable), `workers/pentest_worker.py` resume, `test_vip_workflow_replay.py` |
| Evidence | Both verified |
| Decision | **KEEP** GOED checkpointing + **ADAPT** skip-completed semantics at agenda level |
| Integration strategy | `research_agenda.py` checkpoint: `save_agenda()`/`load_agenda()` of agenda state (branches, budgets, completed markers) as plain JSON dict; `resume` marks completed branches `done` so they are not blindly re-run (Rabbit-hole Case F). Does not replace LangGraph checkpointer — complements it at research-policy level |
| Risk | LOW |

### A11. Security reporting

| Field | Content |
|---|---|
| Capability | Render final security reports |
| Shannon implementation | **Verified.** `services/report-renderer.ts` (MD), `report-json-adapter.ts`+`report-output-schema.ts` (JSON), `sarif-renderer.ts` (SARIF), `pdf-renderer.ts` (Typst), `renumber-core.ts`/`compaction-core.ts` (deterministic compaction), `report-finalization.ts` (manifest sha256, integrity) |
| GOED implementation | **Verified, deeper for this project's purpose.** `reporter/export.py` (JSON/HTML/PDF + per-finding/master hashes + ProofBundle validation + redaction + quality gate), Jinja templates, `agents/reporter` nodes, `test_report_hash_integrity.py` |
| Evidence | Both verified |
| Decision | **KEEP** (SARIF/Typst renderers are redundant here; AGPL) |
| Integration strategy | None. Gap note: SARIF export is a possible future GOED-side BUILD item — explicitly **NOT** done in this migration (kept scope zero-risk; recorded in "still missing") |
| Risk | NONE |

---

## B. Researcher-Brain Requirements (protocol §11–§13, §23)

| Field | Content |
|---|---|
| Capability | Adaptive research brain: agenda, hypothesis/evidence tracking, dynamic deterministic prioritization, bounded rabbit-hole exploration, branch management, memory, checkpoint/resume |
| Shannon implementation | **Verified ABSENT as a mechanism.** Shannon has: fixed lanes + queue gating (no dynamic priority), `todo_write` + in-memory session with compaction, queue-schemas carrying `exploitation_hypothesis` strings, budget caps only as turn/time limits (Capella 1000 turns, research 200/100), git checkpoint/resume. **No hypothesis graph, no evidence-strength-driven budget reallocation, no deterministic priority policy** |
| GOED implementation | **Verified partial.** `intelligence/target_brain.py` (TargetBrain ✓ advisory), `models/hypothesis.py` + `llm_researcher/interface.py::Hypothesis` (hypothesis tracking ✓), canonical evidence store (evidence tracking ✓), `shared/prioritization.py` (997 loc, primitives ✓), `research_engine/{priority_engine,research_budget,research_state}.py` (✓ planning-only), `RabbitHolePolicy` + `route_after_rabbit_hole` (bounded rabbit-hole ✓ at graph level), `agents/rabbit_hole/` (branch management ✓), `memory/lessons.py` (research memory ✓), SQLite checkpointer (✓). **Missing: a unified `ResearchAgenda` that (a) ingests signals, (b) converts LLM priority *suggestions* into a deterministic bounded policy decision, (c) dynamically reallocates budget, (d) persists checkpoint/resume with skip-completed, (e) is unit-provable for Cases A–F** |
| Evidence | Searches for `ResearchAgenda` (0 hits), `priority` (planning-only modules), Shannon side verified as above |
| Decision | **BUILD** (GOED needs it; Shannon does not provide it) |
| Integration strategy | New `src/webpent/integration/research_agenda.py` + `src/webpent/integration/priority_policy.py`: deterministic, bounded, auditable, reproducible agenda over GOED-native concepts (Hypothesis ids, evidence refs, RabbitHolePolicy-compatible bounds). LLM may only *propose* priorities through `PriorityProposal` (bounded suggestions); actual priority/budget computed deterministically from factors (severity potential, evidence strength, exploitability, asset criticality, confidence, novelty, dependency depth, cost) with integer weights, clamped scores, auditable `PriorityDecision` records, hard caps (max branch depth, max experiments per branch, max active branches, branch timeout, research budget, termination conditions). Checkpoint/resume via plain serializable dict. **No LLM in the loop at runtime; no ground truth; no verdict authority** |
| Risk | MEDIUM (new logic) → mitigated by exhaustive deterministic tests incl. protocol §23 Cases A–F and property-style invariants |

### Source + Runtime Research Graph (protocol §13)

| Field | Content |
|---|---|
| Capability | Combine source info + recon + runtime observations + auth state + hypotheses + evidence into a coherent attack graph of *executable* attack paths |
| Shannon implementation | Pattern-level only (code_locations joined onto findings; no graph model) |
| GOED implementation | `attack_graph/` engine projects `TargetKnowledgeV2` into typed graph; `shared/attack_graph.py` projects from MentalModel; **in-memory, no source lane** |
| Decision | **ADAPT** — feed the new `SourceMappingRecord` rows + `SurfaceDossier` into GOED's existing graph as advisory annotations (no change to `attack_graph/` models; annotations live in `integration/` and reference graph node ids) |
| Risk | LOW |

---

## C. Rejected Shannon Items (with reasons)

| Shannon item | Decision | Reason |
|---|---|---|
| Temporal workflow orchestration (`temporal/workflows.ts`, worker, retry machinery) | **REJECT** | Architecturally harmful to GOED (would duplicate LangGraph+Celery); AGPL; heavy external infra |
| Pi agent framework / pi-executor / task sub-agents | **REJECT** | AGPL vendor code; GOED's LLM containment (`llm_researcher/`) already enforces a stricter model than pi's free agent loop |
| Agent catalog + prompts (`prompts/**`, `session-manager.ts` AGENTS map) | **REJECT** | Prompt text is copyrighted (AGPL / Apache-2.0 Mantis); GOED prompt engineering unchanged; prompt-driven fixed pipeline contradicts §11 (no bigger fixed pipeline) |
| Git-as-database deliverable substrate (`git-manager.ts`, exact-path commits) | **REJECT** | GOED has SQLite checkpointer + audit artifacts; introducing git-mutation into GOED runtime would be an invasive parallel persistence authority |
| Typst/SARIF/Markdown renderers | **REJECT** | Redundant with `reporter/export.py`; AGPL |
| Stealth browser config (`playwright-config-writer.ts`) | **REJECT** | Tied to Shannon's CLI skill; GOED has its own stealth pacing; AGPL |
| Node 22/pnpm/turbo toolchain, Docker compose, CLI launcher | **REJECT** | Language/runtime incompatibility; no value for a Python project |
| Dollar-cost/turn budgets (`MAX_TURNS_PER_SESSION` etc.) | **REJECT as-is; superseded** | GOED's `ResearchBudget` + new agenda caps cover this deterministically |
| Exploitation prompt doctrine ("Proof by Construction") | **REJECT (text); idea folded in** | No prompt text copied; the evidence-gated `attempted/blocked` record union is re-implemented as data contracts |

---

## D. Decisions Requiring Explicit Justification (protocol §7 per-component record)

For every ADAPT/BUILD component the destination module records: original Shannon path (architectural reference only), destination GOED path, reason, dependencies introduced (none beyond stdlib+pydantic), behavior changes (additive only), GOED interfaces affected (none semantically), tests added (listed in §E), license implications (none — zero-copy). See `SHANNON_LICENSE_AUDIT.md` §3 table.

## E. Planned Verification

| New module | New test file | Covers |
|---|---|---|
| `src/webpent/integration/research_agenda.py` (+`priority_policy.py`) | `tests/test_integration_research_agenda.py` | Protocol §23 Cases A–F + bounds + checkpoint/resume + determinism/reproducibility |
| `src/webpent/integration/source_mapping.py` | `tests/test_integration_source_mapping.py` | CodeLocation validation, join semantics, redaction of file content, attack-graph annotation shape |
| `src/webpent/integration/surface_dossier.py` | `tests/test_integration_surface_dossier.py` | Consolidation from GOED-style state dicts, evidence refs, no-finding guarantee |
| `src/webpent/integration/exploitation_queue.py` | `tests/test_integration_exploitation_queue.py` | Queue validation (id namespace, dedup, unknown-id rejection), gate decisions, attempted/blocked union, non-authority |
| `src/webpent/integration/reconciliation.py` | `tests/test_integration_reconciliation.py` | Stage semantics, dedupe, forbidden-key scrub, stable refs, idempotence |
| `src/webpent/integration/auth_session_contract.py` | `tests/test_integration_auth_session_contract.py` | Verdict tri-state, failure taxonomy, state merge without secrets, no verdict authority |

**Rule applied to every row:** if GOED already handles the capability adequately or better → KEEP and do not touch the GOED implementation. Integration is realized exclusively as new additive modules + new tests. No existing GOED file is modified (verified by `git status` at final audit; only `docs/integration/*`, `src/webpent/integration/*`, `tests/test_integration_*.py`, `.gitignore` additions, and this migration's artifacts are added).
