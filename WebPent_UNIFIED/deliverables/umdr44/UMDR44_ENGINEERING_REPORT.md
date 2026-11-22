# UM-DR-44 ENGINEERING REPORT — Security Hotfixes Window (Partial Delivery)

**Branch:** `feature/umdr44-security-and-identity-closure` (base: d638af9)
**Window:** 2026-11-22
**Status:** PARTIALLY_COMPLETE — Track B security core delivered (A0, B1, B2, B3, B5, B6, B8); remaining items descoped with reasons below (honesty before completeness).

## Delivered items (RED→GREEN, evidence in `deliverables/umdr44/evidence/`)

### A0 — CI patch applied inside the branch (commit e055ff7)
The original `ci_fixes_umdr43c.patch` file was corrupt at line 45 (truncated hunk), so the three documented changes were applied manually: SBOM `--no-emit-project` + removal of `|| true`, and evidence upload `include-hidden-files: true`.

### B1 — scope path rules bound to first allow entry only (commit f45f1c6) — P0
**Defect (verified):** `authority_from_scope_file_spec` built exclude-path deny rules with `value=allow_entries[0]` and the include constraint used only `include_paths[0]`, while its own comment claimed "apply as constraints on every allow rule". `["a.com","b.com"]` + `exclude_paths:["/admin"]` denied `a.com/admin` but allowed `b.com/admin`.
**Fix:** one deny rule per (allow entry × exclude prefix) under deny-first evaluation; include constraint is any-of per origin.
**Evidence:** RED 4 failures (`B1_red.txt`) → GREEN 12/12 (`B1_green.txt`). Scope wing 67 passed, zero regression.

### B2 — merge zeroes promotion-critical fields (commit 371f097) — P0
**Defect (verified):** the merge base field list omitted `deterministic_match`, `evidence_contract`, `novelty_score`, `preconditions_satisfied`, `info_gain` → `model_validate` reset them to defaults on every re-emission merge (deterministic_match=False), silently stripping promotion eligibility.
**Fix (per-field policy):** deterministic_match sticky True; evidence_contract dict merge (new keys win); novelty_score/info_gain keep last DECLARED value (model_fields_set distinguishes declaration from default); preconditions_satisfied non-None wins. Lifecycle transitions untouched.
**Evidence:** RED 7 (`B2_red.txt`) → GREEN 8/8 (`B2_green.txt`). Merge wing 64 passed.

### B3 — 307/308 pass via GET fallback (commit 58a2a16) — P0
**Defect (verified):** the redirect guard's second fallback allowed a redirect when the target origin allowed GET, without checking the status code — for 307/308 httpx re-issues the ORIGINAL method (POST), executing it outside method constraints.
**Fix:** GET fallback legitimate only for 301/302/303 (genuine downgrades); 307/308 must pass under the original method or be refused.
**Evidence:** RED 3 (`B3_red.txt`) → GREEN 11/11 (`B3_green.txt`). Redirect wing 65 passed.

### B8 — TE.CL status-line split (commit e346ccb) — P0
**Defect (verified, byte-level):** line 295 contained the 6 file bytes `5c 5c 72 5c 5c 6e` (double-escaped) — the split on 4 LITERAL bytes `backslash-r-backslash-n` never separated status lines, so only the FIRST response's first line was scanned; a poisoned SECOND response (first 200, second 4xx — the exact connection-poisoning shape) fell through to "inconclusive". Note: the mission described the branch as "unreachable"; the verified operational truth is narrower (first-line-shaped misses), documented here per the honesty rules.
**Fix:** single-escaped `b"\r\n"` (real CRLF), identical to the CL.TE twin at line 178. Verified end-to-end against a local loopback TCP server through the real `_send_raw_http`.
**Evidence:** RED 1 (`B8_red.txt`) → GREEN 5/5 (`B8_green.txt`). Smuggling wing 17 passed 1 skipped.

### B5 — funnel accepts fake ProofBundle + copy-paste entities branch (commit 7fe9394) — P1
**Defects (verified):** (1) `bundle_ok` accepted ANY truthy non-Mapping — the string `"pending"` counted as a valid ProofBundle; (2) the entities branch checked `isinstance(raw_relations, ...)` (copy-paste), so list-shaped entities were never read.
**Fix:** a bundle counts only as a Mapping carrying the verifier contract keys (replay_metadata / promotion_guard / bundle_id); entities branch now checks `raw_entities`.
**Evidence:** RED 3 → GREEN 6/6 (`B5_green.txt`). Funnel wing 44 passed.

### B6 — four structural fail-open gaps (commits 68cea6c + 661159c) — P1
- **(a)** `EngagementThread` (contextvars.copy_context wrapper) + process-wide active-engagement registry: a context-less caller during an ACTIVE campaign now DENIES (context lost ≠ absent); legacy behavior outside campaigns unchanged. CI-style gate `tests/test_umdr44_b6_thread_gate.py` blocks NEW raw `threading.Thread(` in src/ against the documented 20-file window baseline.
- **(b)** `h2_race._connect` now passes the engagement origin decision, DNS pinning (`_resolve_first_ip`), and TLS verification per the engagement policy (blanket CERT_NONE only when target TLS verification is explicitly disabled in settings).
- **(c)** the request-smuggling raw sender binds the port to the engagement origin policy (previously a free caller parameter).
- **(d)** `rate_limit_enabled` default False → True — the ONE default change authorized by the mission (security exception, rule 9). **Migration note:** deployments that intentionally ran unthrottled must now set `rate_limit_enabled=false` explicitly.
**Evidence:** RED 4 (`B6_red.txt`) → GREEN 8/8 (`B6_green.txt`). Regression wings 79 passed.

## Frozen-modules protocol (zero manifest movement)
`frozen_modules.sha256` itself is byte-identical to d638af9 (verified: `git diff d638af9 HEAD -- frozen_modules.sha256` is empty). All frozen-file changes run under the established declared-window convention: `UMDR44_20261122_THAW_PATHS` in `tests/test_frozen_module_gate.py` (same pattern as the UM-DR-43C window), covering: `shared/http.py` (B3), `agents/request_smuggling/agent.py` (B6c+B8), `production/discovery_funnel.py` (B5), `shared/engagement_scope.py` (B6a), `config/settings.py` (B6d), `state/reducers.py` (B2, under the pre-existing UM-DR-43C thaw). Gate result: 641 passed, 7 documented skips. Byte-identity is restored at window close by the UM-DR-44 re-freeze.

## Descoped items (honest record, per mission §0 rule 8)

| Item | Status | Reason |
|---|---|---|
| B4 (confirmation tightening) | NOT_STARTED | Window step budget exhausted before Track B completion order reached it; no code written, nothing to regress. |
| B7 (GraphQL oracle) | NOT_STARTED | Same. |
| B9 (LLM redaction + doctor) | NOT_STARTED | Same. |
| B10 (dead agents decision) | NOT_STARTED | Same. |
| A1–A7 (Track A body) | NOT_STARTED | Track B consumed the window (the mission's own drop order deprioritizes Track A below B5). |
| Full regression wing + ruff + compileall + honesty gate | PARTIAL | Per-item wings all green (scope 67, merge 64, redirect 65, funnel 44, engagement 79, smuggling 17+1skip, frozen gate 641+7); the FULL 9.4k suite and ruff/compileall were not run in this window. |

## Commits (one per item, per the delivery contract)
```
661159c fix(tests): B6 — construct EngagementThread after the engagement context is set
68cea6c fix(security): B6 — close four structural fail-open gaps
7fe9394 fix(funnel): B5 — stop counting fake ProofBundles; read list-shaped entities
e346ccb fix(smuggling): B8 — TE.CL status-line split used a double-escaped literal
58a2a16 fix(http): B3 — 307/308 redirects no longer pass via the GET fallback
371f097 fix(state): B2 — preserve promotion-critical fields through hypothesis merges
f45f1c6 fix(scope): B1 — path rules apply across ALL allow entries, not just the first
e055ff7 fix(ci): apply UM-DR-43C CI fixes inside the branch (A0)
```

## Residual risks
- The 20 pre-existing raw `threading.Thread` uses in src/ (documented baseline in the thread gate) still run context-less; during active campaigns they are now DENIED (fail-closed) rather than allowed, which is safe but may surface as new refusals in those code paths until migrated to `EngagementThread`.
- `h2_race` TLS hardening changes behavior for self-signed targets that previously "worked" under blanket CERT_NONE: such targets must now explicitly disable target TLS verification in settings.
- B4 (confirmation granted_full on superficial indicators) remains the highest-risk open security item from the mission; it is unstarted, not partially applied.
