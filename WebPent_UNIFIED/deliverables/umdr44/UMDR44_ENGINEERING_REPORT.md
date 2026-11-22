# UM-DR-44 ENGINEERING REPORT — Security Hotfixes Window (Partial Delivery)

**Branch:** `feature/umdr44-security-and-identity-closure` (base: d638af9)
**Window:** 2026-11-22
**Status:** FULLY COMPLETE — B-track: A0 + B1–B10; A-track: A1–A4 + A7, and the DEFERRED BATCH now CLOSED on top of 6f3dc7c (A5a–A5d, A6, registry-leak §7, gates §6 — commits e0e5d33..de9a376, 8 commits). Full suite on the final tree: **9609 passed / 20 skipped / 3 xfailed / 0 failed** (evidence/FULL_VERIFICATION.txt). Honesty gate PASS (pyproject 0.40.1 == BUILD_INFO package_version).

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
| B4 | **DELIVERED (9372eb4)** | RED 6→GREEN 15; CQA wing 277. |
| B7 | **DELIVERED (2918166)** | RED 1→GREEN 3; GraphQL wing 69. |
| B9 | **DELIVERED (8e28d4e)** | RED→GREEN 12 (9 redaction + 3 slug-sync, 9/9 provider drift closed); wing 206. |
| B10 | **DELIVERED (7bb5f48)** | Documented RETAIN decision + structural gate (5/5). |
| A1 | **DELIVERED (471e57a)** | RED 4→GREEN 6 + 20 43C preserved; wing 337. |
| A2 | **DELIVERED (0e4b565)** | RED 6→GREEN 11; emitter wings 149. |
| A3 | **DELIVERED (f2ebab0 + fc21a6e fix)** | RED 2→GREEN 5; critical wing 82. |
| A4 | **DELIVERED (fc21a6e)** | 2/2 end-to-end; caught+fixed the A3 None-context gap. |
| A5a | **DELIVERED (e0e5d33)** | Endpoint identity is the canonical (scheme, host, effective_port, path) tuple — SSOT _endpoint_tuple_key/_endpoint_id_of shared by BOTH build paths and apply_observation; no-scheme/bare-host URLs ABSTAIN (no invented identity); methods_seen accumulates (set semantics, provenance-winner independent); status_code keeps the latest; metadata carries scheme/port/host/path. RED 10 -> GREEN 12. |
| A5b | **DELIVERED (dc92dcf)** | The merge path now increments revision (the documented "every add/contradiction increments it" contract was violated — delta_since was blind to re-observation); metadata merges additively (extras from either side survive). RED 5 -> GREEN 11. |
| A5c | **DELIVERED (3c8825c)** | Path-equivalence contracts: same URL mints the same id from rebuild and incremental (verified against the SSOT minter, no hardcoded strings); observation-on-rebuild merges in place with a revision bump; double-apply idempotent at the entity/relation level. 3/3. |
| A5d | **DELIVERED (0fc08bc)** | Every research hint carries model_revision at derivation time — a stale hint is recognizable (model_revision < model.revision); ownership locators resolve to real entities; advisory_only and the 128 bound unchanged. RED 2 -> GREEN 4. |
| A6 | **DELIVERED (d10ea9b)** | canonical_target_key: IPv6 brackets preserved (the base produced the INVALID https://::1:8443 netloc), literals unified through ipaddress.IPv6Address (hex case AND zero-compression), IDN punycoded (münchen.de == xn--mnchen-3ya.de), domains/IPv4 byte-identical, docstring corrected to match the actual trailing-slash strip. RED 5 -> GREEN 19; critical wing 696 passed. |
| §7 registry leak | **DELIVERED (3d1f6c2)** | clear(None) now empties _ACTIVE_ENGAGEMENTS (the force path left every entry alive -> _any_engagement_active() True forever -> every context-less check DENIED: fail-closed masquerading as security, ~15 order-dependent suite failures); EngagementToken carries registry_key and teardown unregisters with the EXACT key registered under (the previous-context-key mismatch was guaranteed leakage on every real authority engagement). RED 3 -> GREEN 4; B6/34/41 wings 63/63. |
| §6 gates | **DELIVERED (56393e3)** | 43C incremental tests derive ids from the SSOT (documented contract change); h2_race.py broad handler registered (REGISTERED_FILES + ACCEPTED_EXCEPTIONS_REGISTER.md) and pinned in frozen_modules.sha256 as a scope completion (not a thaw) in the undocumented_current subtraction; G-02 inventory regenerated by the NEW official tool scripts/regen_direct_io_inventory_umdr44.py (1223 -> 1225: exactly the two reviewed dynamic_resolution additions — h2_race.py B6-b, state/reducers.py B2 — zero removals, refuse-gates enforced). umdr34 ceiling-parity default aligned to the B6(d) contract (mission rule 9). |
| A7 | **VERIFIED PASS** | pyproject 0.40.1 == BUILD_INFO package_version; check_build_info_honesty.py: PASS. |
| Full 9.6k suite + ruff parity + compileall | **RUN + GREEN** | 9609 passed / 20 skipped / 3 xfailed / 0 failed in 879.89s — first clean run (the §7 fix eliminated the pollution class). Ruff parity exact on every modified file (4/2/3/3 base == current); new files totally clean. compileall RC=0. evidence/FULL_VERIFICATION.txt + RUFF_COMPILEALL.txt. |

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

---

# DEFERRED BATCH CLOSURE (2026-11-22, commits e0e5d33..de9a376 on 6f3dc7c)

Executed per the batch prompt (option (b): fresh re-implementation from the pushed base 6f3dc7c). Every defect below was RED-proven on the base tree before its fix; RED/GREEN outputs are saved per item under evidence/.

## Root causes found and fixed

1. **A5a — endpoint identity dropped scheme and port** (P0 semantic). All three id-construction sites (builder.ensure_endpoint ~201, builder observation-link ~337, models.apply_observation ~356) minted f"{host}{path}": https/http on the same path collapsed into ONE entity (evidence merged across different trust boundaries), implicit/explicit ports collapsed, and the add_entity provenance tie-break discarded the newer methods_seen (a POST observation erased a recorded GET). Fix: the SSOT pair _endpoint_tuple_key/_endpoint_id_of; abstention for URLs without scheme+host.

2. **A5b — the merge path did not increment revision** (P1, documented-contract violation). delta_since was blind to evidence accumulation (revision_to == revision_from for pure re-observation). Fix: merge increments; metadata merges additively.

3. **A5d — hints carried no derivation revision.** A stale hint was indistinguishable from current truth. Fix: model_revision on every hint.

4. **A6 — canonical_target_key broken on IPv6 and IDN** (P1). parts.hostname strips brackets -> the rebuilt netloc was INVALID (https://::1:8443); hex-case and zero-compression spellings of one literal produced different keys; IDN hosts were not punycoded; the docstring lied about trailing-slash preservation (corrected to match the code — never the reverse). Fix: brackets + ipaddress.IPv6Address unification + IDNA with verbatim fallback.

5. **§7 — the engagement registry leaked on every force-clear** (found by the full suite as ~15 order-dependent failures). clear(None) emptied the contextvars but never the registry -> _any_engagement_active() stayed True forever -> every later context-less origin check was DENIED: fail-closed masquerading as security. Additionally the token teardown unregistered with the PREVIOUS context's key while registration used the NEW context's key — identical only via the "default" coincidence; real authority contexts (scope_fingerprint) leaked GUARANTEED. Fix: force path wipes the registry under the lock; EngagementToken carries registry_key and unregisters exactly its own entry.

## Gates (§6)

* 43C incremental tests: ids derived from the SSOT (contract change documented in-file).
* h2_race.py broad handler (B6-b fail-closed settings read): registered + manifest-pinned as a scope completion.
* G-02: official regen tool scripts/regen_direct_io_inventory_umdr44.py (refuses removals; refuses unreviewed additions; regen_reason recorded) — 1223 -> 1225, the two reviewed dynamic_resolution additions only.
* umdr34 ceiling-parity default assertion aligned to B6(d) (mission rule 9 — the ONE authorized default change; the ceiling itself is unchanged).

## Verification numbers (all automated, saved)

* Full suite: 9609 passed / 20 skipped / 3 xfailed / 0 failed (879.89s).
* Ruff parity: builder 4->4, models 2->2, hypothesis_identity 3->3, engagement_scope 3->3; all NEW files clean.
* compileall: RC=0.
* Wings: A5 26/26; identity 696 passed; B6/34/41 63/63; gates 641 passed; G-02 4/4.

## Delivery

8 commits on feature/umdr44-security-and-identity-closure (e0e5d33, dc92dcf, 3c8825c, 0fc08bc, d10ea9b, 3d1f6c2, 56393e3, de9a376) + format-patch series + ZIP carrying the full .git. Push status: see the honesty note in the delivery section — no push is claimed that did not happen.
