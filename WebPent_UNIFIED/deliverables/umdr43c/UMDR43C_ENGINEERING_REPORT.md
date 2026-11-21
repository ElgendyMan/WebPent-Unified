# UMDR43C ENGINEERING REPORT

**Mission:** UM-DR-43C — Identity-Safe Hypothesis Intelligence & Lifecycle Integrity
**Branch:** `feature/umdr43c-identity-safe-hypothesis-lifecycle` (from published main `ce20de8`)
**Date:** 2026-11-21

---

## 1. Existing architecture (as audited, not as documented)

Four components governed hypothesis identity before this mission:

| Component | Role | Identity convention | State |
|---|---|---|---|
| `production/hypothesis_dedup.py` (RC-5) | wraps the production `hypothesis_node` at `graph/builder.py` NODE_HYPOTHESIS; rewrites emitted ids | `uuid5(NAMESPACE_URL, "webpent:umdr40:" + sha256(normalized URL + class))`, whole-URL lower-cased | **not frozen** — the designated extension point |
| `production/identity_workflow.py` (UMDR-32) | identity/composite-workflow hypotheses with a richer fingerprint (target, class, objective, principals, preconditions, state keys) | `uuid5(NAMESPACE_URL, "webpent:umdr31:" + …)` | frozen |
| `production/adaptive_research.py` (UMDR-31) | coverage-gap/invariant hypotheses, same `umdr31` namespace | as above | frozen |
| `egaie/identity_scope.py` (UMDR-43) | pure, explainable IdentityContext + scope key + merge decisions | operates on the **EGAIE** `HypothesisRecord`, not the production `Hypothesis` | frozen, isolated |

The reducer `state/reducers.py::merge_hypotheses` upserts by id — and a
same-id re-emission **replaced** the existing record wholesale.

## 2. Root cause

1. **Split identity namespaces.** The same investigation arriving from the
   generic producer (umdr40 id) and the identity workflow (umdr31 id) could
   never merge — cross-producer dedup was impossible by construction.
2. **Identity-blind RC-5 fingerprint.** `(lower-cased URL, class)` merged
   case-sensitive paths (`/Reports` ≡ `/reports`) and query-order
   differences, and never distinguished principal/tenant/object/operation
   contexts — exactly the §5 matrix's security distinctions.
3. **Lifecycle loss on re-entry.** The upsert replace meant a regenerated
   stale copy (`status=unexplored`) reset an `investigating`/`promoted`
   hypothesis and wiped its `evidence_refs`, `origin_detail`, parent links.
4. **A real checkpoint bug found while testing:** `_extract_id` returned a
   `UUID` for models but a uuid **string** for checkpointed dicts —
   `UUID(x) != "x"` in dict lookups, so a live model never met its own
   checkpointed record; both accumulated across resume.
5. `egaie/identity_scope.py`'s good logic was never wired to the production
   hunt path.

## 3. The identity contract (v2, `umdr43c:v1`)

New module `production/hypothesis_identity.py` (pure functions; no I/O, no
network, no LLM, no egaie/graph imports — layering preserved):

- **`canonical_target_key`** — HTTP-semantics URL canonicalization:
  scheme/host case-insensitive, default ports stripped, fragment dropped;
  **path case and query order preserved** (behaviorally significant);
  lone-trailing-slash normalized; non-http and relative inputs returned
  trimmed (honest fallback). Verified: 13 §5.4 semantics cases.
- **`HypothesisIdentityContext`** — the twelve §5.1 dimensions (actor, role,
  tenant, namespace, resource_owner, object_id, operation, workflow_state,
  session, auth_strength, http_method, preconditions), each with a
  provenance tier: `observed > declared > inferred > unknown`. **Unknown
  never upgrades**; absence is itself a distinction (empty context ≠ known
  context).
- **`identity_from_hypothesis`** — extraction from structured channels
  ONLY: hypothesis `request_data` identity keys (representation-only keys —
  request_id/nonce/trace_id/… — stripped), `origin_detail` structured
  lines, `request_method`, and (parameters ready for the hunt path)
  `identity_profiles` / `object_identity_registry` observed evidence.
  **Never** from the free-text statement, never URL-substring guesses.
- **`identity_fingerprint`** — versioned sha256 over (canonical target,
  class, objective_key, full identity scope). **`legacy_fingerprint`** —
  byte-compatible RC-5 re-implementation: context-free hypotheses keep
  their historical ids (§13 — old checkpoints, `Finding.hypothesis_id`
  links and decision-ledger references never churn).
- **`decide`** — the §5.3 merge policy as one explainable call:
  merge / keep_separate / legacy_merge, each with a reason and the exact
  differing dimensions. Known+known differs → separate (explained);
  known vs unknown → **never** silently equal; unknown vs unknown → legacy
  pair under the compatibility contract, explicitly flagged as not proving
  security-identity equality. The legacy fallback compares fingerprints OF
  THE CANONICAL v2 KEYS — closing RC-5's false merges (case-sensitive
  paths) and false splits (default-port spellings) in one rule.
- **`IdentityTelemetry`** — bounded §8 counters (no text, no URLs, no
  principals; ≤32 separation-dimension keys; JSON-serializable).

## 4. The lifecycle contract (reducer)

`merge_hypotheses` same-id re-entry now merges field-wise
(`_merge_hypothesis_records`):

- **Transition table, not a rank:** `_LEGITIMATE_HYPOTHESIS_TRANSITIONS`
  enumerates the one-way-per-branch machine (unexplored→investigating→
  promoted→resolved_*, →abandoned, →learned; explicit
  abandoned→investigating reopen; self-transitions). Anything else is
  **refused** — and the refusal is RECORDED in `origin_detail` as a bounded
  `lifecycle-conflict[…]` note, never silent.
- **Terminal verdicts survive:** a stale or contradictory update on
  `resolved_true/false/learned` keeps the verdict; the contradiction is
  recorded (§6 case 6).
- **Preservation:** `evidence_refs` / `preconditions` / `alternatives` /
  `hint_provenance` union (bounded 64/32); `parent_hypothesis_id` and
  `created_at` kept; `origin_detail` grows by bounded `re-emitted[…]`
  appends (audit trail, original producer first); numeric measured values
  kept unless absent; request-context fields fill only where missing.
- **Shape-agnostic:** dict-shaped checkpoint state stays dict-shaped;
  model instances revalidate; `status` normalizes enum-or-str.

Frozen-window discipline: `reducers.py` thawed under the declared
`UMDR43C_20261121_THAW_PATHS` convention (delta-mode gate entry, regression
proof = the lifecycle suite), re-pinned by
`scripts/refreeze_manifest_umdr43c.py`, which also pins the NEW
trust-chain file `hypothesis_identity.py`. Same pattern as UM-DR-40b/42.

## 5. Production wiring (§7)

**The graph wiring did not change at all** — `graph/builder.py` still binds
`NODE_HYPOTHESIS` to `deduplicated_hypothesis_node`; the entire evolution
is inside the (unfrozen) dedup module the builder already calls. No
parallel hunt path, no new flags, no changed defaults:

- Context-free hypotheses → exact legacy RC-5 ids (feature-off behavior
  is byte-identical to before — Scenario A proves it).
- Identity-carrying hypotheses (identity workflow, any producer that sets
  structured `request_data` identity keys) → v2 ids under one contract, so
  **cross-producer duplicates now collapse** while security-distinct
  contexts stay separate (Scenario B proves it).
- No circular dependency: `hypothesis_identity` imports nothing from
  egaie/graph/models at module scope; the EGAIE `identity_scope` module is
  untouched (its own contracts stay green).

## 6. Before / After behavior (measured on the executed fixtures)

| Behavior | Before | After |
|---|---|---|
| Same investigation, two producers | two ids, both retained forever | one id, merged |
| `/Reports` vs `/reports` hypotheses | merged (lower-cased URL) | kept separate, reason recorded |
| Same URL, different principal | merged (identity-blind) | kept separate (`actor` cited) |
| `:443` vs no-port spelling | split (RC-5 kept ports) | merged (canonical keys) |
| Re-emitted `unexplored` copy of an `investigating` hypothesis | status reset, evidence wiped | status kept, evidence unioned, re-emission appended to provenance |
| Contradictory terminal verdict | last writer won silently | first verdict kept, conflict recorded |
| Model vs its checkpointed dict | two pool entries (UUID≠str bug) | one entry (id keys normalized) |
| Pool after two identical passes | stable by RC-5 (generic path) | stable on both paths (replay digest equal) |
| Requests emitted for this feature | — | **zero** (pure in-process computation; no network, no LLM, no embeddings) |

## 7. Files changed

| File | Change |
|---|---|
| `src/webpent/production/hypothesis_identity.py` | NEW — the v2 identity contract (§5) |
| `src/webpent/production/hypothesis_dedup.py` | upgraded to the v2 contract + telemetry (legacy API preserved) |
| `src/webpent/state/reducers.py` | lifecycle merge contract + id-key normalization fix (declared thaw, re-pinned) |
| `tests/test_frozen_module_gate.py` | UMDR43C thaw set + manifest-scope entry |
| `tests/test_umdr43c_identity_matrix.py` | NEW — §9.1 matrix (19 tests) |
| `tests/test_umdr43c_lifecycle.py` | NEW — §9.2/9.3/9.4 (26 tests) |
| `scripts/refreeze_manifest_umdr43c.py` | NEW — declared window re-freeze |
| `scripts/umdr43c_archive_manifest.py` | NEW — §3 recovery + manifest |
| `scripts/umdr43c_buildinfo_rebaseline.py` | NEW — §2.4 truthful re-baseline |
| `scripts/check_build_info_honesty.py` | `Publish v…` publication convention (not frozen) |
| `BUILD_INFO.json` | declared re-baseline (only BUILD_INFO touched) |
| `frozen_modules.sha256` | window re-pin (reducers.py + new file) |
| `ci_fixes_umdr43c.patch` | NEW — §2.2/§2.3 CI fixes (apply manually) |
| `deliverables/umdr43c/*` | closure report, archive manifest + recovered artifacts, executed-matrix JSONs |

No test was deleted, skipped or weakened for this window (the two
`pytest.skip`s in the frozen gate are the declared delta-mode entries the
convention itself defines, restored by the re-freeze).

## 8. Tests performed

- Identity matrix: **19/19** (every §9.1 row, reason asserted; executed
  results exported to `IDENTITY_MATRIX_EXECUTED.json` by the tests
  themselves).
- Lifecycle + graph integration + replay: **26/26** (L1–L10; Scenario A
  identity-off legacy path intact; Scenario B identity-on separation +
  representation-only merge + strategist pool stability; `build_graph()`
  constructs; replay digests identical across runs; all 7 statuses
  round-trip).
- Regression neighborhood: RC-5 dedup, UMDR32 identity workflow, UMDR43
  EGAIE identity scope, frozen gate — **210/210** together with the new
  suites in the same run.
- Provenance adversarial suite: **24/24** (including the two tests that
  failed on published main).
- Honesty gate: **PASS**.
- Full regression suite under the exact CI environment: see the delivery
  report (§17E) for the final counts on the branch tip.

## 9. Performance observations

- Fingerprint computation is sha256 over ≤ ~1 KB canonical JSON —
  microseconds per hypothesis; no O(n²): the reducer is keyed by id
  (hash lookup per re-entry), and `decide` compares two fingerprints.
- Telemetry counters are O(1) per hypothesis with a 32-key bound.
- No new dependency, no embedding model, no database, no agent/scanner.

## 10. Remaining limitations

1. `identity_profiles` / `object_identity_registry` are contract-ready
   parameters but the hunt path does not yet populate them at runtime —
   today's context comes from producer-declared structured fields
   (request_data, origin_detail, method). Wiring observation feeds into
   those channels is follow-up work (it changes producers, all frozen).
2. The `objective_key` bridge reads `origin_detail` structured lines; the
   frozen identity_workflow does not yet emit `objective=` lines — its
   hypotheses still carry umdr31 ids (they merge among themselves exactly
   as before; they merge with generic ones only when both sides carry
   matching context).
3. ci.yml fixes are a patch file until the owner applies them (token
   scope); until then CI's evidence-upload step stays red on any branch.
4. PR creation is blocked by the token; the owner opens and merges it
   (merge commit, not squash).
