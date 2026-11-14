# UM-DR-34 Scope Architecture Map

**Phase 1 deliverable — the complete scope-authority and egress
inventory, mapped BEFORE any behavior change.** Every route below was
inspected with exact file:line evidence on the baseline
(`features/v0.39.0-umdr33` @ `4795f02`); line numbers are baseline
references.

Legend: **safe client** = `make_safe_httpx_client` /
`make_safe_httpx_async_client` (`shared/http.py`); **raw client** = any
direct `httpx`/`socket`/`urllib` construction.

---

## 1. Network-capable execution routes (13 mapped)

| # | Route | Entry point | Transport | Scope validation at the boundary (baseline) | Verdict |
|---|---|---|---|---|---|
| 1 | Celery worker campaign | `workers/pentest_worker.py:475` `run_pentest_task`, `:1408` `resume_pentest_task` | safe client (in-graph nodes) | admission gate `admission_target_check` (`api/app.py:1139`); scope-file fail-closed parse (`pentest_worker.py:614`); `set_engagement_target_hosts` (`:692`); in-graph `scope_enforcer_node` state filter; **origin policy fail-OPEN when empty** | ENFORCED (context lifecycle defects fixed in Phase 3) |
| 2 | CLI campaign | `cli/unified_hunt.py:191` `run_unified_hunt` | safe client | `--authorization` mandatory (`:133`); tamper-evident manifest (`:70`); scope-file contract (`:101`); `set_engagement_target_hosts` (`:446`) | ENFORCED (as above) |
| 3 | Direct HunterRunner | `agents/hunter_runner.py:657` `run_hunter_campaign` | delegates to AVI → safe client | `scope_policy` OPTIONAL (`:676`); `ScopeEnforcer` optional (`:707`); pre-exec `check_url()` only (`:887`) — never `acquire()`; `scope_policy=None` ⇒ only self-derived ScopeLaw (`production_spine.py:462`, operator-approval timestamp hard-coded `:466`) | PARTIAL → fixed §4.6 |
| 4 | LangGraph campaign | `graph/builder.py:2121` wildcard-scope node; `:2018` scope-enforcer node; `:1997` research-campaign node | safe client | anchored `in_scope_regex` compile (`shared/wildcard_scope.py:192`, malformed ⇒ deny-all `(?!)` + reroute); post-crawler state filtering; transport OriginPolicy | ENFORCED |
| 5 | AVI execution | `production/autonomous_validation_v1.py:840` | safe client (`modern_spine.py:758`, `follow_redirects=False`) | `ToolBoundary().authorize` (`:701`); ScopeLaw `authorize_execution` (`:714`); M4 identity binding fail-closed (`:923`); parallel bursts still per-request through the executor (`production/parallel_orchestrator.py:27`) | ENFORCED (ScopeLaw self-derived from the passed target — residual documented) |
| 6 | HTTPX sync | `shared/http.py:585` `SSRFPinningTransport.handle_request` | pinned transport | origin check (`:711`) — **fail-OPEN when no policy**; blocklist + engagement-target exemption; DNS pinning fail-closed | PARTIAL → fixed §3.1/§4.1 |
| 7 | HTTPX async | `shared/http.py:887` `AsyncSSRFPinningTransport.handle_async_request` | pinned transport | origin check (`:905`) fail-OPEN; **NO rate gate at all**; **NO loopback-trusted exemption** (sync had it); **latent crash**: sync `_redirect_guard` registered as an async response hook (`:1279`) — `await None` TypeError on every successful async response | PARTIAL → fixed §4.2 |
| 8 | Redirect follow-up | `shared/http.py:471` `_redirect_guard` (response hook) | hook | origin-ONLY check (`:508`), **method not considered**; fail-OPEN when no policy | PARTIAL → fixed §4.3 |
| 9 | Playwright navigation/fetch/XHR | `install_playwright_ssrf_guard` (`shared/http.py:1317`), per-request OriginPolicy (`:1501`) + blocklist (`:1515`) + WebSocket guard (`route_web_socket`) | browser | all navigation-capable surfaces install the guard (validator `agent.py:1070`, authentication `:303`, execution_sandbox `:377`, playwright_adapter `:199`, browser_farm `:44`, poc_recorder `:168`); launch-time DNS pinning via `--host-resolver-rules` in 3 of 6 callers | ENFORCED (residual: 3 callers rely on the documented block-or-allow backstop) |
| 10 | External tools | `tools/utils/subprocess.py:206` (frozen manifest, list-only argv, `shell=False`) | subprocess | per-tool scope preflights: sqlmap `:434` + `--scope` regex `:301`; dalfox `:102` + conditional redirect follow `:148`; nuclei `:214`; katana `:115` + field pinning `:141`; ffuf `:25`; httpx(Go) stdin filtering `:175`; nmap double-gated `:154`; gau `:147`; arjun `:133`; subfinder passive `:23` | ENFORCED (tools/); APEX PARTIAL (optional `scope=None` `apex/executor.py:95`, un-isolated LocalSandbox `apex/sandbox.py:283`, documented `ScopeGuard.allow_all()` bypass — out of the live campaign path) |
| 11 | Business-logic fuzzing | `agents/business_logic_fuzzer/agent.py:389` `_send_concurrent_burst` | safe client (`:355`) | per-thread `contextvars.copy_context()` (`:462`, correct); rate governor per host (`:347`); **forms channel has no per-URL engagement-scope check** (scope_enforcer filters endpoints, not forms — `agents/scope_enforcer/agent.py:96`) | PARTIAL (transport boundary now fail-closed; forms-channel state filtering remains a documented residual) |
| 12 | Raw HTTP clients | see §2 below | raw | — | see §2 |
| 13 | h2 race (raw socket) | `shared/h2_race.py:164` `_connect` — `socket.create_connection`, TLS `CERT_NONE` (`:118`) | raw socket | **NO scope check**; reached from `workflow_fuzzing/agent.py:216` under `enable_h2_race`, rate-governed only | NOT ENFORCED → fixed §4.8 |

## 2. Raw-client inventory (§4.8)

| Site | Posture on baseline | Disposition in this window |
|---|---|---|
| `production/modern_spine.py:650/:777` raw `httpx.Client` | literal-loopback origins only (`:53` `:647` `:774`), SSRF errors never fall through | CONTAINED (unchanged; documented) |
| `families/execution_node.py:71` bare pinning transport | pinning transport WITHOUT the response-hook layer (no redirect guard, no untrusted-content mask) | **FIXED** — full safe factory (§4.8); the raw `httpx` identities are REMOVED from the direct-I/O inventory (34→29 unapproved records) |
| `shared/h2_race.py:116` raw socket, `CERT_NONE` | no scope check | **FIXED** — origin decision before connect (§4.8) |
| `agents/request_smuggling/agent.py:95` raw socket | engagement-scope gate `:81` + pinned IP `:87` | ENFORCED (unchanged) |
| `adapters/controlled_target/adapter.py:768` `urllib` | loopback-only lab fixture | CONTROL-PLANE (unchanged) |
| Control-plane (legitimately separate): LLM provider `llm_researcher/providers/openai_compatible.py:61`; in-process ASGI benchmark `irta/v3/campaign.py:64`; Celery/Redis broker; OAST polling + webhooks + retests all via the SAFE client | | separated explicitly by the new CONTROL_PLANE egress mode (§3.1) |

Everything else — **179 safe-factory references across 51 files** — goes
through the hardened factories.

## 3. The scope engines on the baseline (the overlap §2.1 described)

1. `OriginPolicy` + engagement ContextVars (`shared/engagement_scope.py`) — exact-origin policies; **two separate ContextVars, one token returned, cleanup force-empties policies; `is_engagement_origin_allowed` fail-OPEN** (`:413`).
2. `ScopeFileSpec` + strict wildcard compiler (`shared/scope_file.py`, `shared/wildcard_scope.py`) — anchored `*.root` regexes, apex excluded, non-default ports rejected.
3. `ScopePolicy`/`ScopeRule`/`ScopeEnforcer` (`scope/`) — typed rules; **`_host_match` used `fnmatch`** (`scope/enforcer.py:58-60`) — glob metacharacter hazard; **`parsed.port or default`** treats port 0 as omitted (`:69`).
4. `ScopeLaw` + `AuthorizedLabProfile` + `ToolBoundary` (`live_hunter/tool_scope.py`, `llm_researcher/tool_boundary.py`) — tool capability + poison-argument authority; target authorization SELF-DERIVED from the passed target (`production_spine.py:462-479`, hard-coded approval timestamp).
5. `Target.is_in_scope` behavior (in_scope_regex consumer).

**Post-window architecture (one canonical authority):**
`webpent.scope.authority.EngagementScopeAuthority` is the single
request-decision contract; the strict wildcard compiler semantics moved
into it; `ScopeEnforcer` delegates host matching to it; the transports
consult the engagement context (now atomic and fail-closed) through
`is_engagement_origin_allowed`; ScopeLaw/ToolBoundary keep tool-capability
duties and delegate target authorization. See
`UMDR34_CANONICAL_SCOPE_CONTRACT.md`.

## 4. Rate-governance posture on the baseline (§5 charter)

* `rate_limit_enabled` default **False** (`config/settings.py:2807`).
* Sync transport gate only (`http.py:599-650`); async had none.
* Governor internal failure ⇒ **fail-OPEN** (`granted = True`, `:640`).
* `get_global_rate_governor()` never injects Redis (`global_rate_governor.py:501`) — in-process only, undisclosed.
* `ScopeEnforcer.acquire()` existed but no caller used it (HunterRunner used `check_url` only).
* Playwright: no transport governor (browser-level pacing only).
* Global campaign budget existed at the LLM layer (the governor was built for LLM requests originally).

All addressed in Phase 5 — see `UMDR34_RATE_GOVERNANCE_REPORT.md`.
