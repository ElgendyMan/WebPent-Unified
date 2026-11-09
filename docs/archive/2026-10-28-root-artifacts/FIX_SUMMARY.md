# FIX_SUMMARY.md — mapped to defect ids

## D-01 (P1) — JSON injection in scan payload
**File:** `webpent-cli.sh`
**Before:** `curl … -d "{\"url\": \"$TARGET_URL\", \"auto_approve\": $AUTO}"` — shell interpolation of `TARGET_URL` into a JSON string literal. A URL containing `"` or `\` breaks out of the string and can inject arbitrary JSON fields (e.g. force `auto_approve:true`).
**Fix:** payload is now built by `python3 -c 'json.dumps({…})'` with `TARGET_URL`/`AUTO`/`STEALTH` passed via environment variables. `json.dumps` escapes all special characters. Verified: malicious URL `http://evil.example/?q="><script>…` produces valid JSON with the quote escaped.

## D-02 (P1) — `--stealth` silently dropped
**File:** `webpent-cli.sh`
**Before:** `--stealth` was parsed into `$EXTRA="$EXTRA --stealth"` but `$EXTRA` was never referenced by any `curl` call — a silent no-op.
**Fix (v2, after hostile review):** `ScanRequest` (api/app.py:470-495, frozen) has NO `stealth` field, so sending one is silently ignored. The `stealth` field has been removed from the payload; passing `--stealth` now prints an explicit WARNING to stderr and continues. Adding a real stealth field would require thawing frozen src.

## D-03 (P1) — no authentication wiring (contract break)
**File:** `webpent-cli.sh`
**Before:** none of the four `curl` calls sent an `Authorization` header; with the default `AUTH_ENABLED=true` posture every call returns 401 and the script misreports "API unreachable".
**Fix:** reads `WEBPENT_API_TOKEN` from the environment; when set, sends `Authorization: Bearer <token>` on all four calls; failure message now explicitly suggests setting the token if `AUTH_ENABLED=true`.

## D-04 (P1) — cross-engagement findings bleed
**File:** `webpent-cli.sh`
**Before:** final findings query was `SELECT … FROM findings ORDER BY created_at DESC` with no thread filter — printed every finding in the DB, not just the just-run scan.
**Fix:** parameterized `WHERE thread_id = ?` bound to `$THREAD_ID` (column confirmed at `src/webpent/models/findings.py:416`, the V9 P0 Fix 3 isolation field). Falls back to `LIMIT 50` only if thread_id is empty.

## D-05 (P2) — shell interpolation into Python source
**File:** `webpent-cli.sh`
**Before:** `DB_PATH` was interpolated into the `python3 -c "…sqlite3.connect('$DB_PATH')…"` source string; a path containing a quote broke or injected into the Python literal.
**Fix:** `DB_PATH` and `THREAD_ID` are passed via environment variables and read with `os.environ` inside the Python snippet.

## What was NOT changed (and why)
- **No file under `src/`** — the entire 708-file tree is byte-sealed (`frozen_modules.sha256`, enforced by `tests/test_frozen_module_gate.py`). All six NON-NEGOTIABLE authority modules (CausalGuard, ProofBundle, ReplayVerifier, ToolBoundary, ScopeLaw, PromotionPipeline) are in frozen files and were verified byte-identical after the edit.
- `build_sprint_a_zip.py` asserts (D-06), `scripts/*` swallowed-excepts (D-08), `docker-compose.test.yml` test secrets (D-07): low-severity, non-main-flow; left in place to honor minimal-patch / no-drive-by-refactor. Documented as residuals in AUDIT_REPORT.md.

## Verification
- `bash -n webpent-cli.sh` — pass (pre and post).
- JSON payload validity test with quote-injecting URL — pass.
- Empty bash-array expansion under `set -u` (bash 5.1) — pass.
- Frozen manifest re-verified: 708/708 match; 14 authority-critical files byte-identical.

---

## CORRECTION (hostile-review round 2, 2026-10-07)

The v1 patch contained three defects found by hostile self-audit; all fixed in v2. Full detail in `HOSTILE_REVIEW_FIXES.md`:

- **R-01 (P0):** findings-block f-string used `\"` inside a single-quoted bash wrapper → SyntaxError, block never ran. Fixed: single-quoted outer f-string, double-quoted inner keys, no backslash. Verified against real sqlite (thread scoping returns exactly 1 row).
- **R-02 (P1):** bare `"${AUTH_HEADER[@]}"` fails on bash <4.4 (macOS 3.2). Fixed: portable `${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"}` guard at all four sites; script now bash 3.2+ compatible.
- **R-03 (P1):** `stealth` field sent but `ScanRequest` (frozen) has no such field → silently ignored; v1 claim "server receives it" was false. Fixed: field removed; `--stealth` now emits explicit WARNING to stderr.
- **R-08 (P3):** v1 ZIP dropped egg-info/.ruff_cache. Restored from original; v2 ZIP is a strict superset.
- Re-verified (v2): both embedded Python snippets executed verbatim; frozen gate 708/708, 0 drift.
