# M1_READINESS_REVIEW.md — Engineering Checkpoint Before M1 Implementation

**Phase:** M1 Readiness (Stage One of the Autonomous Engineering Execution Mandate)
**Date:** 2026-11-05 (UTC) · **Baseline:** git checkpoint `7386c40` (pristine tree, frozen manifest 659/659 verified, gate 661 passed)
**Method:** first-hand re-verification of every M0 finding against source (paths, symbols, call chains) before any code change. No finding was accepted on the M0 report's word alone.

**Verification verdicts:** VERIFIED = reproduced from source in this session · CONFIRMED-DEAD = the risk path cannot execute today · REFINED = M0 characterization needed correction (documented below).

---

## 0. Executive Summary

All 22 M0 findings (H-1..H-3, M-1..M-5, L-1..L-7, E-1..E-7) were re-verified. **21 VERIFIED, 1 REFINED (H-3 — see §2.3: the LLM involvement is broader than M0 stated).** The review also surfaced **three new facts** (§6) that change the fix design. The frozen-tree constraint applies to 15 of the 19 files to be modified — the Nov-4 refreeze protocol (DR-009 pattern, one documented window, changed-entries-only rehash, DRIFT_REGISTER entry) will be followed. Git checkpoint `7386c40` is the rollback point; every fix lands as its own commit with focused regression tests run before and after.

---

## 1. HIGH Findings

### 1.1 H-1 — API without authentication by default + cloudflared tunnel publishes the whole surface — **VERIFIED**

1. **Paths/symbols:** `src/webpent/config/settings.py:1880-1887` (`Settings.auth_enabled: bool = Field(default=False)`) · `src/webpent/api/auth.py:493-508` (`get_current_user` → stub admin when `auth_enabled=False`) · `docker-compose.dev.yml:52-62` (api service: `--host 0.0.0.0`, `ports: 8000:8000`, `AUTH_ENABLED=false`) and `:105-118` (worker, same) · `scripts/start_tunnel.sh:132` (`cloudflared tunnel --url "$API_URL"` — whole API, not an OOB-only listener), `:166-169` (tunnel URL printed for OOB callbacks).
2. **Reproducible evidence:** read directly this session. The stub: `if not settings.auth_enabled: return User(username="admin", hashed_password="", role="admin", is_global_admin=True)`.
3. **Runtime call chain:** any HTTP client → `api/app.py` endpoints → `get_current_user` dependency → stub admin (no token) → `POST /api/v1/scans` (with `auto_approve=true`) → Celery → live campaign. Mitigations that DO fire: `shared/preflight.py:502-521` blocks non-local binds with auth off (unless `I_UNDERSTAND_THIS_IS_INSECURE`); `settings.py:2195-2204` blocks qualification/staging/production profiles without auth. **The tunnel defeats the bind check**: server binds 127.0.0.1 → preflight passes → cloudflared republishes publicly.
4. **Impact:** unauthenticated scan launch against arbitrary targets with HITL bypass (`auto_approve`), result disclosure, approve/halt control. Realistic operator path: run `docker-compose.dev.yml` (documented dev flow) or `start_tunnel.sh` for OOB callbacks.
5. **Root cause:** defense-in-depth gaps at three layers that each assume another layer is the guard: (a) dev compose publishes 0.0.0.0 with auth off; (b) tunnel script has no scope restriction; (c) app trusts `X-Forwarded-*` presence without treating "tunnel exposure + auth off" as a forbidden combination.
6. **Minimal safe fix (fail-closed, preserving local dev):** (i) `api/app.py` middleware: when `auth_enabled=False`, reject any request carrying proxy/tunnel indicators (`X-Forwarded-Host`, `X-Forwarded-For`, `Cf-Ray`, `Cf-Visitor`) with 401 — the API answers only direct loopback connections when auth is off; (ii) `start_tunnel.sh`: refuse to start when `AUTH_ENABLED` is false/unset unless `I_UNDERSTAND_THIS_IS_INSECURE=1`; (iii) dev compose: bind `127.0.0.1:8000:8000` instead of `0.0.0.0`. (ii) and (iii) do not touch Python; (i) is an app-level change to a frozen file (refreeze window).
7. **Regression tests:** positive: with auth on + valid JWT + forwarded headers → 200; negative: auth off + `X-Forwarded-Host` → 401 on `/api/v1/scans` and `/api/v1/me` (test name from M0: `test_preflight_tunnel_exposure`); auth off + direct loopback request (no proxy headers) → still 200 (dev flow preserved).
8. **Impact on existing capabilities:** legitimate reverse-proxy deployments with `AUTH_ENABLED=true` are unaffected (forwarded headers only checked when auth is off). Local dev unaffected (no proxy headers on direct requests). OOB endpoints (`/api/oob/*`) are by-design unauthenticated with their own token checks — middleware must exempt them.
9. **Dependencies/order:** standalone; first of M1-A (with H-2).
10. **Acceptance criteria:** all three regression tests pass; `python -c` import check of `api.app` clean; existing api tests green.
11. **Rollback:** git revert of the fix commit; manifest refreeze entry reversed in the same revert.

### 1.2 H-2 — `.env.example` CHANGE-ME placeholders pass every secret gate — **VERIFIED**

1. **Paths/symbols:** `.env.example:125-127,131` (`JWT_SECRET_KEY=CHANGE-ME-generate-a-random-secret`, same for `AUDIT_SECRET_KEY`, `CELERY_PAYLOAD_KEY`; `WEBPENT_USERS=CHANGE-ME:CHANGE-ME:admin`) vs `settings.py:2110-2116` (`_INSECURE_JWT_DEFAULTS = {"webpent-dev-secret-key-change-in-production", "change-me-in-production", ""}`), `:2131-2139` (`_INSECURE_AUDIT_DEFAULTS`), `:2145-2150` (`_INSECURE_CELERY_PAYLOAD_DEFAULTS`), `:2227-2244/2246-2261/2299-2314` (the three hard-stop checks), `shared/preflight.py:523-537` (length-only check — placeholder is 34 chars ≥ 32, passes).
2. **Reproducible evidence:** placeholder string `CHANGE-ME-generate-a-random-secret` (35 chars incl. prefix) is absent from all three frozensets; length checks pass. Constructing `Settings(AUTH_ENABLED=true, JWT_SECRET_KEY="CHANGE-ME-generate-a-random-secret", ...)` succeeds today.
3. **Runtime call chain:** operator copies `.env.example` → `.env`, sets `AUTH_ENABLED=true` (as the file's own comments instruct) → `Settings()` constructs cleanly → JWTs/HMAC/Fernet keys are publicly known (repo-readable) → forgeable admin tokens, forgeable evidence-bundle HMACs, decryptable Celery credentials.
4. **Impact:** full admin compromise "in a seemingly hardened posture"; evidence-integrity keys (audit HMAC) forgeable — poisons the proof chain.
5. **Root cause:** the reject-sets enumerate legacy dev defaults, never the placeholders actually shipped in `.env.example`; the two files evolved independently.
6. **Minimal safe fix:** (i) normalize and reject any secret whose value starts with `CHANGE-ME` (case-insensitive) across all three keys when `auth_enabled=True` or strict profile — implement as a `_looks_like_placeholder()` helper added to the three checks; (ii) same rejection for `WEBPENT_USERS` entries with placeholder username/password at seed time (`api/auth.py` `_ensure_seeded` refuses placeholder-credential entries when auth on); (iii) update `.env.example` comments to state the gate. settings.py and api/auth.py are frozen → refreeze window.
7. **Regression tests:** `test_settings_placeholder_rejection` — parametrized over the three keys × (placeholder, empty, legacy default) with auth on → `ValueError` expected; strong random 43-char secret → passes; `WEBPENT_USERS=CHANGE-ME:CHANGE-ME:admin` + auth on → seeding refused.
8. **Impact on existing capabilities:** none for operators with real secrets; tests that construct Settings with auth on already use strong secrets. Dev mode (auth off) untouched.
9. **Dependencies/order:** none; parallel with H-1.
10. **Acceptance criteria:** new tests pass; existing settings/auth suites green; no test constructs Settings with auth on + placeholder (verify by run).
11. **Rollback:** git revert + refreeze reversal.

### 1.3 H-3 — Evidence-integrity defects (fabricated preconditions, missing negative controls, LLM co-gating) — **VERIFIED and REFINED**

M0 bundled four defects under H-3; each verified individually:

#### 1.3a ب1 — Fabricated composite preconditions in the chain analyzer — **VERIFIED**
1. **Path/symbol:** `src/webpent/chained_exploits/analyzer.py:53-79`, esp. `:62-64` — `if cls == "ssrf": observed.add("ssrf_finding"); observed.add("cloud_metadata_reachable")`. Same fabrication pattern for `sensitive_token_in_response` (:58), `oauth_flow_present` (:61), `role_field_accepted`/`admin_endpoint_present` (:66-68), `short_numeric_otp` (:71), `credentials_allowed`/`sensitive_data_endpoint` (:74-75), `csrf_token_in_dom`/`admin_views_surface` (:78-79).
2. **Evidence:** direct read; `cloud_metadata_reachable` asserted from a single SSRF finding class with no probe of 169.254.169.254 anywhere in the function.
3. **Call chain today:** `PreconditionGraphBuilder.analyze` ← families spine — **`wire_family_execution()` has no caller in `graph/builder.py`** (M0 CAPABILITY_WIRING §3) → TEST-ONLY today; becomes live the moment the families spine is wired (planned M3/M6 work). `exploit_chainer` (the LIVE chain node) uses deterministic patterns and emits Pending only.
4. **Impact:** on wiring, chains would be "confirmed" on invented preconditions — poisons Tool-Confirmed from inside.
5. **Root cause:** the analyzer treats "class exists" as "precondition observed" — a modeling shortcut.
6. **Minimal safe fix:** emit composite preconditions only as *hypothesis fuel* explicitly labeled unverified: each fabricated condition becomes `<name>:unverified_precondition` and `applicable_scenarios` must see a real probe observation (from state observations) before a candidate can carry `SUBSTANTIAL` confidence; candidates built on any unverified precondition are capped at `CandidateConfidence.WEAK` and can never reach a chain-validation call. Add a module-level guard: `cloud_metadata_reachable` must be backed by a probe result in the findings/observations passed in.
7. **Regression tests:** negative: SSRF finding without metadata probe → scenario candidate exists but flagged `unverified_precondition`, confidence WEAK, and `validate_exploit_chain` refuses it (test from M0: chain without real probe must be rejected). Positive: SSRF finding + probe observation `cloud_metadata_reachable=True` → candidate allowed to progress.
8. **Impact:** none on live path today (test-only module); tests updated to the new contract.
9. **Order:** with M1-B bundle.
10. **Acceptance:** both tests pass; grep proves no unconditional `observed.add("cloud_metadata_reachable")` remains.
11. **Rollback:** revert commit.

#### 1.3b — `validate_exploit_chain` confirms without a negative control — **VERIFIED**
1. **Path/symbol:** `src/webpent/agents/validator/family_checks.py:248-286` — CONFIRMED on 2xx composed replay + ≥2 feeder artifacts, `negative_control_digest=""` (:276).
2. **Evidence:** direct read; compare `validate_business_logic` (:292-332) which requires tampered-vs-baseline differential — the chain check has no such pair.
3. **Call chain:** family checks are invoked from the (currently unwired) families spine + tests (`test_five_families.py`).
4. **Impact:** a chain "confirmed" on a single 2xx — a compose request that would 2xx anyway (e.g., unauthenticated GET) confirms theft chains.
5. **Root cause:** missing baseline/control replay requirement in the spec construction.
6. **Minimal safe fix:** require a `control_replay` argument (the same composed request with the feeder artifact neutralized); CONFIRMED only if `composed_replay` is 2xx AND `control_replay` is non-2xx-or-materially-different (digest differs from candidate and matches failure/sanitized shape); otherwise NEEDS_HUMAN_REVIEW with reason. `negative_control_digest` must be non-empty for CONFIRMED. Default `control_replay=None` → fail-closed NEEDS_HUMAN_REVIEW (backward-compatible signature).
7. **Regression tests:** negative: 2xx composed + 2xx control (artifact irrelevant) → NOT CONFIRMED; positive: 2xx composed + 403 control → CONFIRMED with non-empty negative_control_digest; missing control → NEEDS_HUMAN_REVIEW.
8. **Impact:** existing tests that confirm chains with no control now expect NEEDS_HUMAN_REVIEW — test contract updated (they cover an unwired spine; no production behavior change).
9. **Order:** M1-B.
10. **Acceptance:** tests above pass; every CONFIRMED path in the function constructs a non-empty `negative_control_digest`.
11. **Rollback:** revert.

#### 1.3c — `validate_oauth` confirms on weak derived booleans — **VERIFIED**
1. **Path/symbol:** `family_checks.py:338-372` — CONFIRMED if `code_delivered_to_attacker or token_misuse_confirmed` (:354), both caller-supplied booleans with no replay substantiation; `negative_control_digest=""` (:358).
2. **Evidence:** direct read; the booleans are asserted by the caller with no digest/marker contract.
3. **Call chain:** same unwired spine + tests.
4. **Impact:** an optimistic caller boolean = confirmed OAuth finding with a proof bundle that looks sealed.
5. **Root cause:** trust boundary not expressed in the API — booleans trusted like verified observations.
6. **Minimal safe fix:** require a delivered-artifact marker: `code_delivered_to_attacker` counts only when `attacker_redirect_replay` body/label contains the delivered code/token fragment (parameter `delivered_artifact_marker: str = ""`); without a non-empty marker that appears in the replay → NEEDS_HUMAN_REVIEW. Same for `token_misuse_confirmed` (require `misuse_replay` 2xx evidence). `negative_control_digest` = digest of `legitimate_callback_baseline` when present, else the check degrades to NEEDS_HUMAN_REVIEW (fail-closed).
7. **Regression tests:** negative: bare `code_delivered_to_attacker=True` with no marker in replay → NEEDS_HUMAN_REVIEW; positive: marker present in attacker replay body → CONFIRMED with digests.
8. **Impact:** unwired spine + tests only; test contract updated.
9. **Order:** M1-B (after 1.3b, same file).
10. **Acceptance:** tests pass; no CONFIRMED path with empty marker/negative digest.
11. **Rollback:** revert.

#### 1.3d — SQLi reauth promotion path: LLM co-gate + replay bypass — **VERIFIED and REFINED (see §6)**
1. **Path/symbol:** `src/webpent/agents/validator/agent.py:3538-3575` — promotion when `session_reauth AND det_confirmed AND llm_confirmed` (:3543), no `differential_observation` (the branch condition), no negative control, no ProofBundle; evidence records `supervisor_verdict` (:3524). **REFINED:** the `llm_confirmed` term is dead code in this branch (see §6.1) — the live defect is (a) the promotion text still declares LLM a gate, (b) the promotion bypasses `verify_replay_evidence`, and (c) the GENERAL path (:3458) and `causal_signal` (:3618) carry live LLM gating M0 did not flag.
2. **Evidence:** control-flow analysis this session (documented §6.1); code's own comment admits "narrow, deliberate bypass of verify_replay_evidence" (:3548-3555).
3. **Call chain:** `validate_finding` → `_validate_with_tool` → (sqli, no differential) → reauth branch → writes `confidence_level="Tool-Confirmed"` → memory/db persist. **LIVE path** (validator is the architectural Tool-Confirmed writer).
4. **Impact:** (today) an SQLi finding with a fresh re-login + sqlmap marker promotes with no replay evidence and the LLM nominally in the gate; violates LLM Charter §3.1/§3.2 ("البوابة الوحيدة للتأكيد هي validators الـ baseline/candidate/negative-control"؛ "قرار الترقية يبقى حتمياً 100%") and the mandate's M1-B invariants.
5. **Root cause:** recovery-path pragmatism (V9 P0-B) predating the approved Charter (2026-11-03).
6. **Minimal safe fix:** (i) remove `llm_confirmed` from :3543 (dead term — deletion is behavior-neutral, verified by §6.1 analysis); (ii) keep the deterministic reauth gate (session_reauth + det marker = tool-native re-execution on fresh session) with `promotion_guard.reason` rewritten to "deterministic_tool_native_reauth" and the LLM verdict recorded advisory-only; (iii) fix the general path and causal_signal per §6.2/§6.3; (iv) full sqlmap-internal differential extraction is M6 scope (documented deferral with reason — not silently dropped).
7. **Regression tests:** new guard test `test_no_llm_in_promotion_decisions` (charter gate, M0 TEST_QUALITY §4): construct findings with a stub LLM that answers NO vs YES vs None — the resulting `confidence_level`/`promotion` decision must be IDENTICAL across all three (deterministic-only gating); plus focused reauth tests: session_reauth+det → Tool-Confirmed (no LLM consulted), no-reauth → Needs Human Review.
8. **Impact:** offline mode (LLM_ENABLED=false) can now confirm dalfox-XSS on deterministic marker (previously impossible — §6.2); LLM veto removed for det-confirmed findings (devils_advocate + CQA still review downstream). sqlmap behavior unchanged (det was already authoritative).
9. **Order:** M1-B, first (this file anchors the charter guard test).
10. **Acceptance:** charter guard test passes; existing validator suites green (offline-mode behavior for XSS changes intentionally — tests asserting LLM-veto are updated with justification).
11. **Rollback:** revert commit (validator/agent.py + tests).

---

## 2. MEDIUM Findings

### 2.1 M-1 — `webpent-cli.sh` auto-approves the HITL sandbox gate, unauthenticated — **VERIFIED**
1. **Path/symbol:** `webpent-cli.sh:25-38` — polls `is_paused_at_sandbox` then `POST /api/v1/scans/$THREAD_ID/approve` with no Authorization header and no human interaction.
2. **Evidence:** direct read (this session): `curl -sf -X POST "$API_URL/api/v1/scans/$THREAD_ID/approve"`.
3. **Call chain:** script → API stub admin (auth off) → resume task — HITL becomes decorative when driven by this script.
4. **Impact:** automated approval of active-exploitation phase without a human; combined with H-1's tunnel, a remote party can drive approvals.
5. **Root cause:** script written for pre-auth API era; never updated for the HITL contract.
6. **Minimal safe fix:** interactive `read -r -p` confirmation before approve (default: refuse), `--yes` flag for explicit opt-in, `WEBPENT_API_TOKEN` support (Bearer header) when set, and refusal to approve when the API reports auth disabled (unauthenticated approve attempt returns 401 once H-1 middleware lands → script surfaces the error instead of swallowing it).
7. **Regression tests:** shell-level test harness (bats-style or pytest subprocess): (a) with no TTY and no `--yes` → script must NOT reach the approve call (mock server counts calls); (b) `--yes` → approve called once with Bearer when `WEBPENT_API_TOKEN` set.
8. **Impact:** operator workflow gains one keystroke; automation must pass `--yes`.
9. **Order:** after H-1 (relies on its 401 behavior for the auth-off refusal message).
10. **Acceptance:** both tests pass; `bash -n webpent-cli.sh` clean.
11. **Rollback:** revert.

### 2.2 M-2 — katana crawls cross-origin URLs from target content; mitigation is post-hoc — **VERIFIED (nuanced)**
1. **Path/symbol:** `src/webpent/tools/recon/katana.py:105-158` (pre-spawn seed-host allowlist check — good, V10 P3-11), command build `:140-158` (no field-scope switch), post-filter `:235-250` (results filtered after connections happened).
2. **Evidence:** direct read. The seed gate fails closed when the seed host is not in the engagement allowlist. The command relies on katana's *default* field scope (`-fs rdn` — registrable domain of the seed); no explicit scope is passed.
3. **Call chain:** recon node → katana adapter → subprocess. **LIVE.**
4. **Impact:** (a) reliance on tool defaults across katana versions — a default change silently widens crawl scope; (b) same-RDN drift: engagement scoped to `app.example.com` still lets katana *contact* sibling hosts (`blog.example.com`) before the post-filter drops results — connections outside the engagement allowlist but inside the RDN; (c) IPs like 169.254.169.254 are outside rdn scope (not crawled) — the M0 worst case is mitigated by defaults, not by us.
5. **Root cause:** no explicit scope pinning in the argv contract.
6. **Minimal safe fix:** pass explicit `-fs fqdn` (crawl exactly the seed host) — the engagement allowlist already governs which hosts get seeded (each engagement host is crawled separately via its own invocation through the allowlist gate); keep the post-filter; keep the seed gate. Add a comment documenting the choice. Alternative considered: `-fs rdn` preserves subdomain crawling but re-opens (b); subdomain discovery is subfinder's pipeline, not katana's.
7. **Regression tests:** argv-contract test: built command contains `-fs fqdn` and does not contain `-ns`/`-no-scope`; existing seed-gate and post-filter tests stay green.
8. **Impact:** katana no longer discovers same-RDN sibling endpoints — that discovery moves to subfinder+allowlist (existing pipeline). Documented behavior change.
9. **Order:** M1-A bundle.
10. **Acceptance:** tests pass; no scope-widening switch present in any katana invocation.
11. **Rollback:** revert (restores rdn default).

### 2.3 M-3 — `GlobalRateGovernor` is dead code: no central rate ceiling on the default hunt path — **VERIFIED**
1. **Path/symbol:** `src/webpent/shared/global_rate_governor.py` (zero importers outside the module — re-confirmed by grep this session); `SSRFPinningTransport.handle_request` in `src/webpent/shared/http.py` (the chokepoint wrapping every safe client); per-tool RPS caps in `scope/enforcer.py:134-148` apply only when a ScopePolicy file is loaded (worker path, not CLI).
2. **Evidence:** `rg -l GlobalRateGovernor src/` → the module itself only.
3. **Call chain (after fix):** every request through `make_safe_httpx_client` → `SSRFPinningTransport.handle_request` → `GlobalRateGovernor.try_acquire` → block/deny past ceiling.
4. **Impact:** a hostile target or a runaway loop hits the target without a central ceiling on the CLI hunt path.
5. **Root cause:** governor built (V-era) but never wired at the transport chokepoint.
6. **Minimal safe fix:** wire an opt-out-safe default in `SSRFPinningTransport.handle_request`: acquire from a process-global governor when `settings.global_rate_limit_rps > 0` (new setting, default ON at a conservative 10 rps, override via env; 0 = off for tests that assert request timing). The governor's existing semantics (fail-open on internal error? — verify: must fail-open with a logged warning, never break requests on governor bugs). Tests unaffected by default get the ceiling via the shared fixture overriding to 0 where needed… — **decision:** default ON breaks ~timing-sensitive tests; instead default matches `rate_limit_enabled` (existing setting, default False) times a fixed ceiling — the operator posture already declares intent. Fix: `if settings.rate_limit_enabled: try_acquire(...) or raise RateLimitExceeded`. Fail-open on governor internal errors with CRITICAL log. This preserves all existing test behavior (rate_limit_enabled=False by default) while giving the enforcement path M0 asked for.
7. **Regression tests:** transport-level test with `rate_limit_enabled=True`, ceiling 2 rps, 5 rapid loopback requests → ≥1 blocked with RateLimitExceeded; governor error → request still proceeds (fail-open) + CRITICAL logged.
8. **Impact:** no default-path change (rate_limit_enabled=False today); operators flipping the existing switch gain a real ceiling.
9. **Order:** M1-A.
10. **Acceptance:** tests pass; existing http/transport suites green.
11. **Rollback:** revert.

### 2.4 M-4 — `ContainedHTTPClient` imports a nonexistent symbol, falls back to raw httpx — **VERIFIED**
1. **Path/symbol:** `src/webpent/shared/legacy_containment.py:172-181` — `from webpent.shared.http import bounded_http_request` → ImportError → raw `httpx.Client(...)` (no SSRFPinningTransport).
2. **Evidence:** `rg "def bounded_http_request" src/webpent/shared/http.py` → no match (re-confirmed this session). `make_safe_httpx_client` exists at `http.py:898`.
3. **Call chain:** ContainedHTTPClient users (test-only today) → raw httpx — private-IP/DNS-rebind protections silently absent.
4. **Impact:** latent: any future wiring of legacy containment looks "contained" but is not.
5. **Root cause:** refactor renamed the API; the legacy shim's import was never updated.
6. **Minimal safe fix:** replace the import with `make_safe_httpx_client` (single authority): `_delegate` builds a safe client with the passed bounds (timeout, follow_redirects=False) and delegates; **remove the raw-httpx fallback entirely** — ImportError of the authoritative module must fail loud, not silently degrade (fail-closed per mandate). 
7. **Regression tests:** `test_legacy_containment_uses_safe_transport`: monkeypatch `webpent.shared.http.make_safe_httpx_client` with a recorder raising on raw httpx.Client construction; assert delegation goes through the factory; assert raw `httpx.Client` is never constructed in-module.
8. **Impact:** contained clients gain SSRF pinning; none on live path (test-only consumers).
9. **Order:** M1-A.
10. **Acceptance:** test passes; `rg "httpx.Client" legacy_containment.py` → zero.
11. **Rollback:** revert.

### 2.5 M-5 — raw `urlopen` on environment-shaped URLs (OOB poll + notifications) — **VERIFIED**
1. **Path/symbol:** `src/webpent/shared/oob.py:440-450` (`urlopen(collector_url…)` with `# noqa: S310`) · `src/webpent/integrations/notifications/dispatch.py:149-172` (scheme/loopback guard exists, then raw `urlopen`).
2. **Evidence:** direct read both sites.
3. **Call chain:** OOB poll loop (worker/live hunt OOB mode) and notification dispatch (operator-configured endpoints).
4. **Impact:** a hostile/mistyped env value makes the framework fetch internal URLs without blocklists; contrast `integrations/webhook.py` which correctly uses the safe factory.
5. **Root cause:** pre-factory code never migrated.
6. **Minimal safe fix:** both sites switch to `make_safe_httpx_client` (oob.py: GET with timeout, fail-open semantics preserved — poll failure = no data; dispatch.py: POST JSON, keep https/loopback rule, fail-open on error). Remove the S310 noqa.
7. **Regression tests:** loopback test: safe factory invoked (recorder) on both paths; blocklist test: URL resolving to private IP outside allowlist → blocked by transport (oob → empty list; dispatch → False).
8. **Impact:** none beyond gaining protections; env-configured https collectors unaffected.
9. **Order:** M1-A.
10. **Acceptance:** tests pass; no `urlopen` remains in either file.
11. **Rollback:** revert.

---

## 3. LOW Findings (disposition in M1)

| ID | Verdict | M1 disposition |
|---|---|---|
| L-1 Playwright surfaces without route guard (`recon/browser_farm.py:28`, `reporter/poc_recorder.py:149-167`) | VERIFIED (M0 paths) | Fix in M1-A tail: reuse `install_playwright_ssrf_guard` + host pinning on both — same pattern as execution_sandbox/validator |
| L-2 `SMART_AUTO_APPROVE` lifts approval for active actions | VERIFIED (`action_authority.py:259`) | Keep behavior (operator opt-in), add test asserting `interrupt_before` HITL unaffected + document in .env.example |
| L-3 CLI hunt never declares engagement hosts → recon tools fail closed | **VERIFIED — top functional gap** | Fix in M1-A: `cli/unified_hunt.py` `_invoke_with_progress` wraps `graph.stream(...)` with `set_engagement_target_hosts(url…)` + `finally: clear` (mirror worker `:692`); regression: unit test on `_invoke_with_progress` asserting the token is set/cleared around the stream call |
| L-4 OAST DNS responder binds 0.0.0.0 default | VERIFIED (`oast/server.py:274`) | Default → `127.0.0.1` (explicit bind_host still available); test asserts default |
| L-5 `decision_log` metadata written without enforced redaction | VERIFIED (`:248`) | Enforce `redact_sensitive` on metadata at append; existing callers send ids only — no behavior change |
| L-6 OOB endpoints unauthenticated by design + compensations | VERIFIED (M0) | Monitor only; note in risk register as accepted |
| L-7 `WEBPENT_ALLOWED_EXECUTABLES` PATH-order nuance | VERIFIED | Document in `.env.example` + SECURITY.md note (first PATH match wins) |

## 4. Evidence-Integrity Supplementary Findings

| ID | Verdict | M1 disposition |
|---|---|---|
| E-1 Tool-Confirmed writers not architectural (~7 families; model accepts the string without proof; `service/cost_alerts.py:109` writes it ungated) | VERIFIED (model validator `findings.py:512-569` is a literal whitelist; cost_alerts constructs a notification Finding with `"Tool-Confirmed" if status=="promoted"`) | M1-B: (a) `cost_alerts.py` stops writing `Tool-Confirmed` on notification objects — use `"Pending"` + `lifecycle_status=promoted` in evidence (it is a notification, not an evidence finding); (b) add module-level `assert_tool_confirmed_writer()` decorator/gate in `models/findings.py` — a registry of approved writer modules; Finding construction with `confidence_level="Tool-Confirmed"` outside the registry raises (fail-closed) — registry seeded with the 7 legitimate writers from M0 CAPABILITY_WIRING §2; (c) regression: unregistered module constructing a Tool-Confirmed Finding → ValueError; all legit writers still construct |
| E-2 IDOR still listed in `_DETERMINISTIC_STRUCTURAL_CLASSES` (`prioritization.py:643`), guarded only by early-return `:661-662` | VERIFIED | Remove the dead entry + guard test `test_idor_never_deterministically_promotable` that fails if the early-return is reordered away |
| E-3 `enable_report_quality_gate` default OFF; strict gate reachable only via `reporter/agent.py:1079` | VERIFIED | Policy decision implemented: default stays OFF for the CLI hunt (evidence-first demotion at export already always-on), BUT strict gate becomes ON for platform/bounty exports (`reporter/export.py` platform path) where a downstream consumer trusts the artifact — bounded, justified hardening; documented in registry + risk register |
| E-4 OAuth analyzer dead fields (ب6) | VERIFIED (M0) | Fill from identity_discovery outputs in M1-C wiring (data exists); fields no one writes → wire the writers |
| E-5 118 `except: pass` in src (107 live) | VERIFIED (M0 AST scan) | M1-D: ruff S110 rule enabled for live paths with noqa budget documented; not a code sweep in M1 (churn risk) — registered |
| E-6 10 `NotImplementedError` | VERIFIED (M0) | Documented; deferred to owning phases (dojo/families/goed are opt-in/test-only) |
| E-7 LLM payload strings into state without schema | VERIFIED (M0) | Payloads already flow through HITL + sandbox; schema-validated payload proposal contract is M3 scope (registered) |

---

## 5. Special Investigations (mandate §2)

### 5.1 Missing Ledger files
`docs/legacy_migration_ledger.json` / `docs/LEGACY_MIGRATION_LEDGER.md` (cited by the audit report with numbers 752/188/283 and ~300 red) **do not exist anywhere in the tree** (re-verified this session). No DRIFT_REGISTER entry records their deletion. **Recovery:** impossible from this tree — no VCS history exists (zip export; git initialized only now, after the fact). The audit's claims that referenced them are treated as **unverifiable-by-artifact**; the numbers that matter today are the independently reproduced ones (M0 BASELINE + UM-DR-06 residuals). **Decision:** mark the ledger claims "source artifact absent" in the registry; do not propagate 752/188/283 into any living document.

### 5.2 Report Quality Gate behavior
Wired exactly once: `agents/reporter/agent.py:1079` passes `strict_quality_gate=bool(settings.enable_report_quality_gate)` (default False → `evaluate_report_quality` advisory). Always-on compensations verified: `normalize_report_finding` demotion at export (`reporter/export.py:217`) applies in every mode. **Disposition:** E-3 above.

### 5.3 November 4 archival window
Re-verified: mtimes 2026-11-04 04:53–05:39, `EXECUTION_REPORT.md` + `DRIFT_REGISTER.md` UM-DR-09 document ق5–ق11 (7 modules, 112 tests — re-run green in M0 and again this session: frozen gate 661 passed), refreeze with exactly one entry (settings.py), floors 8,003→8,115, coverage ratchet 4.07% (re-measured by M0). The window's deliverables exist and are internally consistent; its modules have **zero production importers** (re-verified this session: cve_advisory 0, api_surface_shadow 0, identity_orchestrator 0, bounty_pipeline 0, self_benchmark 0, portfolio/manager 0, legacy_disposition 0 — the "portfolio" hits in cli/ops.py are the *production* portfolio_manager, a different module). **Reconstruction evidence is sufficient**; the window is trustworthy as a feature-add window, not as a fix window (none of H/M/E findings touched — verified: 20 audit items stand at the same lines).

### 5.4 Phase numbering conflicts
Confirmed from DOCUMENT_RECONCILIATION §1.1–1.2 (re-read this session): Part 4 section headings define M0–M12 (13 phases, incl. M6=Deception-Resistance, M9=HITL) while its §15 execution-order table renumbers and drops M6/M9; five phase-numbering systems coexist across parts. **Resolution:** Canonical registry (Stage Two deliverable) adopts the Part 4 *heading* numbering as canonical (13 phases), records every alias table, and preserves all strategic objectives (deception-resistance and HITL live as full phases M6/M9, not deleted).

### 5.5 Proposed integrations — runtime wiring status (all re-verified this session)
| Capability | Production importers | Verdict for M1-C |
|---|---|---|
| ق5 cve_advisory | 0 | Wire into target_understanding (opt-in phase OFF today) — **deferred to M3** with the phase; do not force-wire now (would edit frozen target_understanding node without its phase contract) |
| ق8 api_surface_shadow | 0 | Feeds hypotheses (planner) — M3 scope (same reason) |
| ق7 identity_orchestrator | 0 | Needs runner session_factory injection — M3 |
| ق10 bounty_pipeline | 0 | Operator-surface (CLI) — M1-C: expose as `webpent bounty` subcommand (safe: sends nothing without approval cage) |
| ق5 self_benchmark | 0 | M1-C: add to nightly CI (workflow step; no frozen-tree edit) |
| ق11 portfolio manager | 0 | M1-C: CLI surface `webpent ops portfolio` already exists for production manager — wire ق11 into its own subcommand `webpent portfolio wave` (safe, no graph edits) |
| ق9 legacy_disposition | 0 | M1-D: RUN it (operator script invocation, documented window) over the dead clusters |
| coverage ratchet | 0 (CI) | M1-C: wire `scripts/coverage_ratchet.py` into CI workflow + Makefile target |
| OAST (754 lines) | flag undeclared | M1-C: declare `enable_oast` (default False) + declare `enable_campaign_resume` etc. as declared-and-False so the modules are at least *constructible*; full bridge wiring per fix-plan 2.2 is M3 (needs node pattern outside builder) |
| api/live_stream.py (SSE) | 0 | M1-D disposition: archive (superseded by polling endpoints + dashboard) — documented decision |

**Do-not-wire list (M1):** families/execution_node + chain_planner (blocked by ب1/M6 decision), engines 3+4 (archive candidates), deep/ bridge (M3), EGAIE (declared research library).

---

## 6. New Facts Discovered During This Review (beyond M0)

### 6.1 The `llm_confirmed` term in the SQLi-reauth gate is dead code
Control-flow: for `vuln_class == "sqli"`, stage 3 (`:3439-3449`) sets `confirmed=True, llm_confirmed=True` (LLM skipped) iff `det_confirmed`; if `det_confirmed=False`, `confirmed=False` → early return at `:3501`. Therefore the reauth branch (`:3543`) is only ever reached with `det_confirmed=True ∧ llm_confirmed=True`. The LLM never actually gates this path today — but the code *declares* it does (evidence field, comments, condition), which is itself an integrity defect (the charter gate test would fail on the *declared* contract) and a landmine (reordering stage 3 would silently activate LLM gating). Fix (1.3d) removes the term and rewrites the contract text.

### 6.2 The general path makes the LLM a live VETO over deterministic confirmations (and kills offline XSS confirmation)
`:3458` `confirmed = det_confirmed and llm_confirmed` for all non-SQLi tool classes (dalfox/XSS today). `_llm_supervisor_verdict` returns False when `llm is None` (`:486-491`) — i.e., **with `LLM_ENABLED=false` (the documented default operating mode), no dalfox-confirmed XSS can ever reach Tool-Confirmed**. This violates Charter §2 ("الـ LLM غائباً… أبطأ وأقل ذكاءً فقط، وليس أبداً أقل نزاهة" — here it silently removes a whole confirmation class) and §3 (LLM output participates in the decision field). Fix: `confirmed = det_confirmed`; LLM verdict recorded advisory-only in evidence (`supervisor_verdict` stays, renamed semantics documented); `_classify_validator_failure` retains llm signal for retry-strategy classification only (not decisions).

### 6.3 `causal_signal` feeds the LLM term into `verify_replay_evidence`
`:3618` `causal_signal=bool(differential_observation and det_confirmed and llm_confirmed)` — after fix 6.2 a det-confirmed + LLM-dissenting finding with a differential observation would compute `causal_signal=False` and be wrongly blocked. Fix: `causal_signal=bool(differential_observation and det_confirmed)` (deterministic-only); `replay_metadata.supervisor_verdict` keeps the advisory record.

---

## 7. Implementation Order, Acceptance and Rollback (M1 execution plan)

**Order (dependency-driven):**
1. **M1-B first** (evidence integrity — it anchors the charter guard test and touches validator/agent.py which M1-A's tests will rely on): 1.3d → 1.3a → 1.3b → 1.3c → E-1 → E-2 → charter guard test.
2. **M1-A** (security/config): H-2 → H-1 → M-1 → M-2 → M-3 → M-4 → M-5 → L-3 → L-1/L-4/L-5/L-2-doc.
3. **M1-C** (wiring): ratchet→CI, self-benchmark→nightly, bounty/portfolio CLI surfaces, OAST/flag declarations, E-4 wiring where data exists.
4. **M1-D** (disposition): run ق9 engine over dead clusters, .orig deletion (verified outside frozen manifest), root debris archive, engine ownership decision, live_stream disposition, CHANGELOG/CURRENT_RELEASE sync.

**Frozen-tree protocol:** one refreeze window (`scripts/refreeze_manifest_m1_recovery.py`, DR-009 pattern: changed-entries-only, self-check before write, no removals) + DRIFT_REGISTER entry `UM-DR-10` listing every changed frozen path with its fix ID. Gate re-run (661) must pass after refreeze.

**Per-fix discipline (mandate §8):** pre-change focused test run → smallest safe change → focused tests → affected integration tests → broader regression (validator + api + shared suites) → static check (`python -m compileall`-equivalent via ast.parse; ruff if available) → commit with fix ID → next.

**Acceptance (M1 complete when):** every finding above has disposition fixed/mitigated/deferred-with-reason/blocked-with-dependency; the 10 named regression tests from M0 TEST_QUALITY §6 exist and pass; frozen gate 661 green post-refreeze; broader suites green or environment-blocked (documented); CANONICAL_PHASE_REGISTRY updated; M1 phase report written.

**Rollback:** per-fix git revert (each fix = one commit); refreeze reversal included in the revert of the last frozen-file fix; global rollback = `git reset 7386c40`.

**Known limits of this environment:** no Docker (compose/tunnel behavior verified by config inspection + TestClient, not live containers); no external targets ever contacted; full 8,115-suite not runnable here (partial environment, documented in M0 BASELINE §4 — unchanged); ruff/bandit/coverage-full unavailable (pip partial environment).

— End of M1_READINESS_REVIEW.md —
