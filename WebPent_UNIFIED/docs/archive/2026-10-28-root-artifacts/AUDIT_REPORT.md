# AUDIT_REPORT.md — WebPent REPAIRED_FINAL (2026-10-07) — TEAM-AUDIT-FIX

## Executive Verdict

**Posture: heavily hardened, one confirmed P1 defect family fixed, zero authority gates weakened.**

The entire `src/webpent/` tree (708 files) is byte-sealed by `frozen_modules.sha256` and enforced by `tests/test_frozen_module_gate.py` (708 parametrized cases). Verification: **708/708 match, 0 drift**. All six NON-NEGOTIABLE authority modules (CausalGuard, ProofBundle, ReplayVerifier, ToolBoundary, ScopeLaw, PromotionPipeline) reside in frozen files and were verified byte-identical post-edit. No src file was modified.

One real, fixable P1 defect family was found in the non-frozen root launch surface `webpent-cli.sh` (JSON injection, silent `--stealth` no-op, missing auth wiring, cross-engagement findings bleed, shell-string interpolation). Fixed with a minimal patch. All other findings are either test fixtures, synthetic secrets, documented residuals, or blocked by the freeze.

**Canonical root chosen:** `extracted/project/` → source tree `src/webpent/`. The `goed_v1_8*` directories at repo root are small reference snapshots (5–22 py files each, 34K–201K) and were excluded from the audit surface (not imported by any entrypoint).

## Method / Commands Run

| # | Command | Outcome |
|---|---------|---------|
| 1 | `unzip -o WebPent_REPAIRED_FINAL_20261007.zip` | extracted `project/` |
| 2 | `python3 -m compileall -q src tests scripts main.py server.py worker.py verify_all.py viewer.py` | **exit 0, zero syntax errors** |
| 3 | `sha256sum -c` loop over `frozen_modules.sha256` (708 entries) | **708/708 MATCH, 0 mismatch** |
| 4 | stdlib-AST hostile scanner (448 non-frozen .py files) + grep sweeps | 94 raw hits → triaged (most false positives in tests/benchmarks) |
| 5 | `bash -n webpent-cli.sh` (pre + post) | pass |
| 6 | Payload JSON-validity + empty-array safety tests (post-fix) | pass |
| 7 | Re-verify 14 ruff-excluded authority files post-edit | **all byte-identical** |
| 8 | CI-referenced script existence check (8 scripts + floor file) | all present |

**Not run (environment constraint, no network install permitted):** full pytest suite (deps: torch/chromadb/playwright/langgraph not installed), ruff, mypy, bandit, pip-audit. CI documents ruff (3,750 findings, report-only) and pip-audit (12 known CVEs in pinned langgraph line, report-only).

## Defect Register

| ID | Sev | File:Line | Type | Impact | Evidence | Status |
|----|-----|-----------|------|--------|----------|--------|
| D-01 | P1 | `webpent-cli.sh` (orig ~L34) | Logic/security — JSON injection | `TARGET_URL` interpolated into `curl -d "{\"url\": \"$TARGET_URL\"…}"`; a URL containing `"` or `\` breaks out of the JSON string, can inject arbitrary scan fields (e.g. force `auto_approve:true`) | original line: `-d "{\"url\": \"$TARGET_URL\", \"auto_approve\": $AUTO}"` | **FIXED** — payload built via `python3 json.dumps` with env-passed values |
| D-02 | P1 | `webpent-cli.sh` (orig `EXTRA="$EXTRA --stealth"`) | Dead/unreachable critical path — silent no-op | `--stealth` parsed into `$EXTRA` but `$EXTRA` never referenced in any `curl` call; operator believes stealth is on, server never receives it | `EXTRA="$EXTRA --stealth"; shift` but no later use of `$EXTRA`; `ScanRequest` (api/app.py:470-495, frozen) has no `stealth` field, so sending it is also silently ignored | **FIXED (v2)** — field not sent; passing `--stealth` now emits an explicit WARNING to stderr (no silent no-op). Adding a real stealth field would require thawing frozen src. |
| D-03 | P1 | `webpent-cli.sh` (all curl calls) | Contract/wiring break | API defaults `AUTH_ENABLED=true` (`.env.example`); CLI sends no `Authorization` header → every call returns 401, script reports "API unreachable". No documented token path | no `-H "Authorization: …"` in any of the 4 curl invocations | **FIXED** — `WEBPENT_API_TOKEN` env → Bearer header; clear error message if unauthorized |
| D-04 | P1 | `webpent-cli.sh` (final sqlite block) | Reliability/data-leak — cross-engagement bleed | Final findings query `SELECT … FROM findings ORDER BY created_at DESC` has no `thread_id` filter; prints **every finding in the DB** regardless of which scan was just run | `conn.execute('SELECT title,severity,… FROM findings ORDER BY created_at DESC')` | **FIXED** — parameterized `WHERE thread_id = ?` scoped to `$THREAD_ID` (column confirmed in `src/webpent/models/findings.py:416`, V9 P0 Fix 3) |
| D-05 | P2 | `webpent-cli.sh` (final `python3 -c`) | Weak/fragile — shell-string interpolation into Python source | `DB_PATH` interpolated into `python3 -c "…sqlite3.connect('$DB_PATH')…"`; a path containing `'` breaks or injects into the Python literal | `sqlite3.connect('$DB_PATH')` | **FIXED** — `DB_PATH`/`THREAD_ID` passed via environment, read with `os.environ` |
| D-06 | P2 | `build_sprint_a_zip.py:82-88` | Weak code — `assert` for validation | Stripped under `python -O`; one-off sprint build script, never invoked under optimized mode | 6 consecutive `assert` statements | RESIDUAL (low risk; build-script surface; minimal-patch principle) |
| D-07 | P3 | `docker-compose.test.yml:66,77,108` | Hygiene — hardcoded test secrets | `WEBPENT_OOB_CALLBACK_SECRET=ground-truth-test-secret`, `ADMIN_PASSWORD=live-parity-lab-credential-not-for-production` | literal values; explicitly labeled not-for-production, test-only profile | RESIDUAL (acceptable; test profile only) |
| D-08 | P2 | `scripts/dep_closure_audit.py:97`, `scripts/team2_*.py` (6 sites), `scripts/m2a_p7_repro/fake_llm_server.py:36` | Reliability — bare `except: pass` | Swallows failures in eval/audit helper scripts; not on production execution path | `except Exception: pass` blocks | RESIDUAL (helper/eval scripts, not main flow) |
| D-09 | P2 | `tests/test_r2_spine_authority_contracts.py:213` | Test quality — `xfail(strict=True)` | Ratified B-06 residual: entrypoint naming (`campaign_worker` vs `worker`), unfreeze denied by R3 Ruling R3-002 §3.5. Honest strict xfail, not a hidden skip | `@pytest.mark.xfail(reason="B-06 residual … DENIED for R3 …", strict=True)` | RESIDUAL (documented, strict — will fail if it unexpectedly passes) |
| D-10 | — | `src/webpent/**` (708 files) | Coverage gap — freeze blocks src fixes | Any defect inside the sealed tree cannot be patched without breaking the fail-closed byte-identity gate (708 pytest cases). Pattern scan of src found **no** `eval(`, `exec(`, `shell=True`, `os.system`, `pickle.load`, `yaml.load(`, `verify=False`, `debug=True`, or hardcoded JWT secret. Line-by-line logic audit of 708 frozen files was not performed | `frozen_modules.sha256` (708 entries) + `tests/test_frozen_module_gate.py` | RESIDUAL — BLOCKED BY FREEZE (by design; gate is an authority mechanism) |
| D-11 | P3 | CI (`.github/workflows/ci.yml` header) | Documented backlog — ruff + pip-audit non-blocking | 3,750 ruff findings; 12 known CVEs in pinned langgraph/langgraph-checkpoint*/langgraph-sdk line (fixed only by 0.x→1.x major bump). Both run report-only, `|| true` | CI comment + `run: uv run ruff check . \|\| true` | RESIDUAL (documented escalation path) |
| D-12 | P3 | `benchmarks/goed_v1_5/target_template.py` | Not a defect — intentional template | Contains `@@PORT@@` substitution placeholders; not valid Python; explicitly ruff-excluded | pyproject `extend-exclude` | NOT A DEFECT |

## Wiring / Main-Flow Findings

| Surface | Verdict | Evidence |
|---------|---------|----------|
| Entrypoints (`main.py`, `server.py`, `worker.py`) | OK | delegate to `webpent.cli` / `webpent.api.app:app` / `webpent.workers.pentest_worker:celery_app`; `server.py` binds loopback by default and runs `run_preflight` before socket; `WEBPENT_ENTRYPOINT` label set via `setdefault` |
| CI workflow | OK | 8 referenced gate scripts all exist; static gates REQUIRED (state-contract, orchestrator-construction authority, isolation denylist, vault-import authority, test-count floor, G-08 direct-I/O); test-evidence required; artifact upload `if-no-files-found: error` |
| docker-compose.yml | OK | secrets fail-closed via `${VAR:?…}` required substitution (JWT/AUDIT/CELERY_PAYLOAD/OOB); no hardcoded production secrets |
| `entrypoint.sh` | OK | root startup → `chown` bind-mount paths → `gosu` drop-privilege → `exec` (signal-forwarding); `set -euo pipefail` |
| `pyproject.toml` | OK | langgraph pair exact-pinned (1.2.10 / 3.1.1) with documented rationale; `[tool.pytest.ini_options]` `--strict-markers --strict-config`; frozen files ruff-excluded |
| `config/isolation_denylist.yaml` | OK | D-01..D-05 denylist populated, contract versioned, amendment log present; enforced by `scripts/check_isolation_denylist.py` |
| `alembic/versions/` (0001–0005) | OK | no string-concatenated SQL (`f"…"`, `%s`, `.format`, `+`) found in migration `execute()` calls |

## Secrets / Logging Findings

- **No real hardcoded secrets found** in `src/`, `config/`, `scripts/`, root `.py`, or compose production profile. All matches were synthetic test fixtures (`sk_live_abcdef…`, `password_a`/`password_b`, `super-secret-value`, smoke tokens) in tests/benchmarks, or placeholders (`REPLACE_ME`, empty `.env.example`).
- `scripts/evaluate_ground_truth.py` scanner hits at L242/244/250 were **false positives**: logs the string `"Auth token acquired"` and the HTTP status code, never the token value.
- `scripts/run_recall_gap_llm_campaign.py:147-148` `password="bearer:" + owner_token` is **intentional** (sealing a bearer token as the principal credential), not a bug.
- `docker-compose.test.yml` test secrets labeled `not-for-production` (D-07).

## Test Results — Before / After

| Check | Before | After |
|-------|--------|-------|
| `compileall` (1068 py files) | exit 0 | exit 0 (no .py changed) |
| Frozen manifest 708/708 | PASS | PASS (edited file not in manifest) |
| 14 authority files byte-identical | PASS | PASS |
| `bash -n webpent-cli.sh` | pass | pass |
| JSON payload validity (malicious URL) | — injection possible — | **PASS** (quotes escaped) |
| `--stealth` behavior | silent no-op (dropped) | **WARNING to stderr; field not sent** (API ScanRequest has no stealth field; adding it would require thawing frozen src) |
| Auth header support | NONE | Bearer via `WEBPENT_API_TOKEN` |
| Findings scoped to thread | NO (all findings) | YES (`WHERE thread_id=?`) |

Full pytest suite **not executed** (deps not installed; network install prohibited). The frozen-gate test (`tests/test_frozen_module_gate.py`) is stdlib-only and was replicated manually with identical semantics (708/708).

## Residuals and Risks

1. **src freeze (D-10)** is the dominant residual: any latent logic defect in 708 sealed files cannot be patched without a manifest regen + documented review. Recommend: thaw-and-refreeze process for any future src fix, never direct edit.
2. **CI report-only gates (D-11)**: ruff (3,750) and pip-audit (12 CVEs) do not block. CVE exposure is in the pinned langgraph line; remediation requires a major-version bump with full re-test.
3. **Test-suite execution gap**: full suite not run in this environment. The shipped `FULL_SUITE_POSTFIX_RESULT.txt` (380KB) claims green; this audit did not independently re-run it.
4. **D-06/D-08** low-severity hygiene items left in place to honor minimal-patch / no-drive-by-refactor rule.

## Coverage Gaps (explicit)

- Line-by-line logic audit of 708 frozen src files: **NOT performed** (pattern-scan only; freeze blocks fixes anyway).
- Full pytest / ruff / mypy / bandit / pip-audit: **NOT run** (tools/deps absent; no network).
- Runtime behavior of API/worker/Celery/Redis stack: **NOT exercised** (no local services).
- `goed_v1_8*` reference snapshots: **excluded** (not imported).

---

## Hostile-Review Amendments (TEAM-RED self-audit, 2026-10-07)

A hostile self-audit of the first delivery found three defects in the delivered `webpent-cli.sh` patch. All three are fixed in this revision. Full detail in `HOSTILE_REVIEW_FIXES.md`.

| id | sev | defect in v1 patch | status in this revision |
|----|-----|-------------------|--------------------------|
| R-01 | P0 | Findings-block f-string used `f"…{r[\"severity\"]}…"` inside a single-quoted bash wrapper → backslash reached Python → `SyntaxError` on all CPython versions; D-04/D-05 never executed | **FIXED** — outer f-string now single-quoted, inner dict keys double-quoted, no backslash. Verified by executing the verbatim snippet against a real sqlite DB (thread scoping returns exactly 1 row). |
| R-02 | P1 | Bare `"${AUTH_HEADER[@]}"` with `set -u` aborts on bash <4.4 (macOS stock bash 3.2); patch introduced a silent bash-version dependency | **FIXED** — all four uses now `${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"}` (portable to bash 3.2). Header comment documents the 3.2+ guarantee. |
| R-03 | P1 | `--stealth` sent as JSON field but `ScanRequest` (api/app.py:470-495, frozen) has no `stealth` field → Pydantic silently ignores it; flag remained a no-op and the v1 report falsely claimed "server receives it" | **FIXED** — field removed from payload; when `--stealth` is passed a clear WARNING is printed to stderr and execution continues. Adding the field to ScanRequest would require thawing a frozen src file (out of scope). |
| R-04 | P2 | `compileall` claim overbroad (omitted production/verification/release) | AMENDED — re-run on all dirs; omitted dirs compile clean (`target_template.py` is an intentional template). |
| R-05..R-07 | P2 | Gate scripts / verify_all.py / auth.py fail-open paths not examined | **AUDITED** — 6 CI gate scripts and verify_all.py are fail-closed (`sys.exit(1)`); auth.py raises 401 on invalid tokens. One residual P2 found: `scripts/verify_campaign.sh:33` — missing required JWT/AUDIT/CELERY secrets → WARN only, script exits 0 (section header mislabeled "fail-closed posture"). Non-frozen; fixable with a 2-line patch (warn→bad). Left RESIDUAL per minimal-patch scope. |
| R-08 | P3 | v1 ZIP dropped 13 files (egg-info, .ruff_cache) vs original | **FIXED** — both dirs restored from original ZIP; v2 ZIP is a strict superset (only webpent-cli.sh modified + reports added). |
| R-09 | P3 | Inbound webhook verify path not checked | **AUDITED** — outbound push fails closed on empty secret (webhook.py:241-243); inbound path uses same SecretStr settings gate. |

**Re-verification (v2):** `bash -n` pass; PAYLOAD snippet executed verbatim with quote-injecting URL (valid JSON, no stealth field); findings snippet executed verbatim against real sqlite (thread scoping returns exactly 1 row); empty-array expansion under `set -u` pass (portable form); `--stealth` emits warning to stderr; frozen gate **708/708, 0 drift**; 14 authority files byte-identical.
