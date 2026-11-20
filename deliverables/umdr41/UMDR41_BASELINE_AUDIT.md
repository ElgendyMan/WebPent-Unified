# UMDR41 — Baseline Audit (recalculated from the current checkout)

**Verified starting HEAD:** `86e5861ae0f24d40f8f9c1ef9c6ae84fafd026cc` (matches remote main; ZIP identical to git tree modulo untracked artifacts)
**Working branch:** `security/umdr41-foundation-and-discovery` (commits c0bd56a, 50516af, e674da2)
**CI state:** run 44438324258 FAILED; **all 13 runs in repo history FAILED**.

## 1. Codebase measurements (recomputed; historical figures in parentheses)

| Metric | Measured (UMDR41) | Historical |
|---|---|---|
| src Python files | **1,124** | ~1,120 |
| src lines | **306,488** | ~306,000 |
| test Python files | **754** | — |
| repo-wide .py (tracked) | **2,619** | — |
| packages (src) | **162** | 87 |
| files > 1,500 lines | **15** (top: validator/agent.py 4,948; egaie/differential.py 4,048; settings.py 3,324; builder.py 2,661; api/app.py 2,527) | 15 |
| longest functions | _validate_with_tool 1,393; hypothesis_node 1,236; build_graph 944; run_pentest_task 929 | — |
| broad `except Exception` | **919** (60 `pass`) | ~290 (47 pass) |
| `global` statements | **34** | 47 |
| unused imports (AST, src) | **952** | 124 |
| lazy (function-level) imports | **977** | — |
| mutable default args | **0** | — |
| `sqlite3.connect` | **26** | 27 |
| `shell=True` real code sites | **0** (5 textual hits are string literals in remediation knowledge bases / docs) | 5 |
| `eval`/`exec` real | **0** (hits are remediation-db string examples) | 5 |
| `pickle.load` real | **0** (hits are remediation-db string examples) | 2 |
| `os.system` real | **0** | — |
| f-string SQL `execute(f"...")` | **6** (all identifier-position or PRAGMA/ALTER from internal constants; values parameterized — analyzed, none attacker-controlled) | — |
| dynamic `import_module`/`__import__` sites | **11** (9 stdlib-name literals like 'json'/'hashlib'; 2 governed: tools/registry auto-discovery hardcoded catalog, cli/ingest fixed loader map — both in the G-08 dynamic allowlist) | — |
| possible orphan modules | **95** (after exact/descendant import matching + entrypoint + tool-catalog exclusion) | 299 |
| annotation-resolution failures (`get_type_hints`) | **20 found; 6 fixed in WebPent code; 14 upstream pydantic** | — |

Notes: the historical 290-`except` figure under-counted (my sweep counts every `except Exception` handler via AST). The unused-import count is AST-based and intentionally conservative (counts `__all__`-re-exported names too); ruff is not installed in this sandbox. **95 orphans vs 299 historical** reflects exact-match semantics: importing a package's parent does not mark a child reachable (and conversely `scope.registry` looked orphaned to naive grep but is consumed via the package `__init__` — the directive's exact warning).

## 2. Import and reachability analysis

- Method: AST import graph (exact + descendant matching), entrypoints from pyproject (`webpent`, `webpent-poc`, `webpent-ingest`), tool auto-discovery hardcoded catalog (registry.py:206-232), CLI `__main__`, test imports.
- Dynamic-import governance: only tools/registry.py and cli/ingest.py have non-constant loaders; both are in the G-08 `DYNAMIC_IMPORT_ALLOWLIST` with approved line ranges.
- Classification summary: 1,029 ACTIVE (imported or entrypoint/tool-catalog reachable), **95 POSSIBLE_ORPHAN** (list in `_metrics/possible_orphans_net.json`; full version-sprawl trees: webpent.irta.* (16), dom_xss (4), sourcemap_analysis (3), role_matrix (2), plus 70 single modules). Zero deletions performed (directive §4.2).
- Version sprawl confirmed: causal_reasoning vs causal_reasoning_v2, cqa_v2, autonomous_validation_v1, irta.v3, goed_v1_8_* archives — authoritative-path determination recorded in the ARCHITECTURE_MAP.

## 3. Architecture inventory (production path)

- Entrypoints: `webpent.cli:main` (typer), API `webpent.api.app:app` (FastAPI, 20 routes), Celery worker `workers/pentest_worker.py:run_pentest_task`.
- Graph: `graph/builder.py` build_graph (944 lines) — nodes incl. scope_enforcer, hypothesis (wrapped by RC-5 dedup at line 2055), validator, strategist (RC-6/7 measurement), rabbit-hole.
- Scope enforcement chain: API `/scope/load` -> GLOBAL_SCOPE_REGISTRY (pre-fix: per-process memory; post-fix: optional durable store) **plus** the independent worker-side chain: ScanRequest.scope_entries (encrypted transit via celery_payload_key) -> parse_scope_file fail-closed -> RuntimeContext ScopeRuntimeHandle(compile_wildcard_scope) -> graph runtime.scope_matcher.allows() at every active-research handler. Both chains verified; the registry channel was the cross-process gap (F-006, fixed opt-in).
- CausalGuard: cqa_v2/causal_guard.py (frozen) remains sole confirmation authority; ProofBundle models frozen; RC-5 dedup wrapper is generation-time only and does not touch frozen files.
- OOB callbacks: advisory-only by contract (never seals, never alters confidence) — verified in app.py route handlers.

## 4. Security posture findings (summary; details in SECURITY_REVIEW)

- Auth: profile model EXISTS and is enforced (settings hard-stops for staging/qualification/production: auth_enabled, JWT secret strength/placeholders, rediss://, no-wildcard CORS, no allow_insecure_tls; preflight blocks non-local unauth binds unless explicit override; /token mints nothing while auth off). Residual documented gap: default `lab` profile + loopback = unauthenticated stub admin (dev boundary; effective route matrix produced).
- Route matrix (20 routes): 4 scope mgmt (admin/service), recon+scans+halt+resume (admin/service), approve (admin), status/findings/dashboard/reports/estimate/me (any authenticated), health+token+2×OOB (unauthenticated by design — OOB secret-gated, constant-time).
- Secrets: 30 pattern hits, ALL intentional fixtures (AKIAABCDEFGHIJKLMNOP, ghp_abcdef..., JWT test payloads); git history .env deletions: 0. No real credentials.
- Subprocess/eval/pickle: no real unsafe sites (all textual hits are remediation knowledge-base examples). Docker: gosu privilege-drop preserved; Dockerfile.base has 3 unpinned `@latest` Go tools (F-010).

## 5. Test evidence for this mission

Commands run (exact):
1. `python3 -m pytest tests/test_umdr41_p0_correctness.py -q` → **22 passed**
2. `python3 -m pytest tests/test_umdr41_scope_registry.py -q` → **8 passed**
3. `python3 -m pytest tests/test_umdr41_rc6_rc7.py -q` → **4 passed**
4. `python3 -m pytest tests/test_umdr41_p0_correctness.py tests/test_umdr41_scope_registry.py tests/test_umdr41_rc6_rc7.py tests/test_repair_recon.py tests/test_five_families.py tests/test_principal_provisioning_completion.py tests/test_m1d_legacy_disposition_overmatch.py tests/test_m3_research_wiring.py tests/test_umdr34_canonical_scope_authority.py tests/test_scope_program_policy.py tests/test_hardening_0330_b1.py -q` → **298 passed, 2 skipped (pre-existing goed_v1 archive skips), exit 0**
5. `python3 -m pytest tests/test_umdr34_canonical_scope_authority.py tests/test_scope_program_policy.py tests/test_repair_recon.py tests/test_campaign_pack_contract.py -q` → 69 passed, 1 failed — `test_python_dash_m_webpent_cli_is_executable` **pre-existing environment failure** (webpent not pip-installed in this sandbox venv; verified failing identically on the pristine baseline via `git stash`).

Environment: Python 3.12.16, /home/z/.venv; langgraph==1.2.10 + langgraph-checkpoint-sqlite==3.1.1 + langchain-core==1.6.7 + bcrypt==5.0.0 installed to match the lockfile's exact pins for the affected suites. The FULL 9,365-test suite was NOT run in this sandbox (torch/chromadb/sentence-transformers and the full dev extra are not installable here within the time budget); affected-module batches above are the honest scope of local validation. Remote CI evidence for the branch commits: NOT_AVAILABLE (no push authorization — per directive, no push without owner authorization).

## 6. Release-integrity baseline (verified, not assumed)

- `git cat-file -t fe92f178.../ccb4aea/bafe618` → **not found** in main, all remote branches, and the umdr38 bundle (fetched and verified reachable set). BUILD_INFO honesty gate reproduces exactly 5 failures locally.
- Mission branch refs in the bundle: only `mission/umdr38-closure` (8f43e88).
- Accounting: executed(9366) = collected(9365) + 1 collection-phase skip; v3 hook accounting authoritative and internally consistent; BUILD_INFO's `accounting_consistent: 1` contradicts the evidence record's `0` (inconsistent copy, F-012).
