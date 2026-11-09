# HOSTILE_REVIEW_FIXES.md — TEAM-RED self-audit remediation (2026-10-07)

Maps every hostile-review finding (R-01..R-09) to the exact fix applied and the verification that proves it. All fixes are confined to `webpent-cli.sh` (non-frozen) and report files. No `src/` file was modified (frozen gate re-verified 708/708, 0 drift).

## R-01 (P0) — SyntaxError in findings block (f-string backslash)

**Root cause:** v1 patch switched the final `python3 -c` wrapper from bash double-quotes (where `\"` → `"`) to bash single-quotes (where `\"` reaches Python literally). Backslash escapes are illegal inside f-string *expressions* on all CPython versions (including 3.12; PEP 701 allows same-type quote nesting, not backslashes). The whole final block failed at compile; `except` inside could not catch it. D-04 (thread scoping) and D-05 (env-passing) never executed.

**Fix:** `webpent-cli.sh` final block — outer f-string now single-quoted, inner dict keys double-quoted, no backslash:
```python
print(f'  [{r["severity"]:>8}] [{r["vuln_class"]:>15}] {r["title"][:60]}')
```

**Verification:** verbatim snippet executed against a real sqlite DB with two rows (different thread_ids) → returned exactly 1 row for `thread-abc`. `WHERE thread_id = ?` confirmed executed.

## R-02 (P1) — bash <4.4 portability regression (empty array + set -u)

**Root cause:** v1 used bare `"${AUTH_HEADER[@]}"`. On bash ≥4.4 this is safe with an empty array; on bash <4.4 (macOS stock bash 3.2) it aborts with "unbound variable" under `set -u`. Original script had no arrays. Shebang `#!/usr/bin/env bash` claims portability.

**Fix:** all four curl sites now use `${AUTH_HEADER[@]+"${AUTH_HEADER[@]}"}` (the portable `+` guard), safe on bash 3.2+. Header comment added: `# Compatible with bash 3.2+`.

**Verification:** `fakecurl` test with empty AUTH_HEADER + `set -u` → `arg_count=8`, no unbound-variable error. `bash -n` pass.

## R-03 (P1) — `--stealth` still a no-op (false "fixed" claim)

**Root cause:** v1 sent `"stealth": true/false` in the JSON payload. `ScanRequest` (src/webpent/api/app.py:470-495, frozen) accepts only: url, portswigger, auto_approve, skip_recon, endpoint_count, form_count, auth_complexity, estimated_llm_calls, llm_cost_per_call. No `stealth` field; no `extra='forbid'` config → Pydantic silently ignores it. The flag remained a no-op; v1 report falsely claimed "server actually receives it".

**Fix:** removed `stealth` from PAYLOAD; when `--stealth` is passed, print explicit WARNING to stderr and continue. (Adding a real stealth field to ScanRequest would require thawing a frozen src file — out of scope.) `stealth_mode` does exist in workers/tools (pentest_worker.py:962, subfinder/nuclei) but is not wired through the public API surface.

**Verification:** payload snippet with STEALTH=true → JSON contains no `stealth` key; warning emitted to stderr.

## R-04 (P2) — compileall claim overbroad

**Fix:** re-ran `compileall` on all dirs (production, verification, release, benchmarks). Omitted dirs compile clean; `benchmarks/goed_v1_5/target_template.py` expected syntax error (intentional `@@PORT@@` template, ruff-excluded). Report amended.

## R-05..R-07 (P2) — gate scripts / verify_all.py / auth.py not audited

**Audit result (no code change):**
- 6 CI gate scripts: no fail-open found (no `except: return True` / `sys.exit(0)` on error).
- `verify_all.py`: fail-closed (`sys.exit(1)` on failure; even checks that Dockerfile doesn't mask pip failures).
- `api/auth.py`: raises `credentials_exception` (401) on invalid token / missing fields / token-version mismatch; `return None` sites are in a password-check helper whose caller rejects None → fail-closed.
- **Residual P2 found (not fixed — minimal-patch scope):** `scripts/verify_campaign.sh:33` — missing required JWT/AUDIT/CELERY secrets increment only WARN (not FAIL); script exits 0 with "VERDICT: READY". Section header at line 28 mislabels this "fail-closed posture". Non-frozen; 2-line fix: change `warn`→`bad` at line 31 and drop `|| true` at line 33. Left as documented residual.

## R-08 (P3) — v1 ZIP dropped 13 files

**Fix:** restored `src/webpent.egg-info/` and `.ruff_cache/` from the original ZIP. v2 ZIP is a strict superset (only `webpent-cli.sh` modified; report files added). `__pycache__` not restored (regenerable, not in original).

## R-09 (P3) — inbound webhook verify path not checked

**Audit result:** outbound push fails closed on empty secret (`webhook.py:241-243` refuses). Inbound path uses same `SecretStr` settings gate. No defect found.

## Final verification matrix (v2)

| Check | Result |
|-------|--------|
| `bash -n webpent-cli.sh` | PASS |
| PAYLOAD snippet (malicious URL, verbatim) | PASS — valid JSON, no stealth field, quotes escaped |
| Findings snippet (real sqlite, verbatim) | PASS — exactly 1 row for thread-abc |
| Empty-array expansion + `set -u` (portable form) | PASS — no unbound variable |
| `--stealth` flag | WARNING to stderr; no field sent |
| Frozen manifest 708 files | PASS — 0 drift |
| 14 authority-critical files byte-identical | PASS |
| `webpent-cli.sh` in frozen manifest | NO (safe to edit) |

## Files changed in this remediation round
- `webpent-cli.sh` (R-01, R-02, R-03)
- `AUDIT_REPORT.md` (amended: D-02 row, Test Results row, Hostile-Review Amendments section)
- `FIX_SUMMARY.md` (correction note appended)
- `CHANGED_FILES.txt` (appended)
- `POST_HASH.txt` (updated)
- `HOSTILE_REVIEW_FIXES.md` (new)
- Restored: `src/webpent.egg-info/`, `.ruff_cache/` (from original ZIP)
