# UM-DR-32 Security Regression Report

**Window:** UM-DR-32 — §10 (Phase Eight) + §10.1 measured here
**Report date:** 2026-11-09
**Evidence:** `tests/test_umdr32_security_regressions.py` (32 tests),
`tests/test_umdr32_scope_admission.py` (17 tests), the evaluation lab,
and the full-suite run (8,903 → 8,894/0/6/3).

---

## 1. Scope preservation — VERIFIED

- The hypothesis-admission filter, the executor scope gates, the
  engagement-scope allowlist, request budgets, time limits, rate
  limits, kill switches and HITL requirements are untouched; the full
  suite (which encodes their contracts) passes 8,894/0.
- The evaluation lab's out-of-scope area (`/internal/*`) is refused
  before any request in every arm (the pre-existing scope gate).
- All new network I/O flows through injected clients under the
  authorized executor (direct-I/O inventory: +0 transport sites).

## 2. Origin validation (§10.1) — DEFECT FOUND AND FIXED

**Defect:** `_admit_endpoint()` (production/adaptive_research.py)
unpacked the campaign origin scheme and then compared only host and
effective port — `https://lab.example:443` admitted
`http://lab.example:443/api/x` (identical host + numeric port, different
origin).

**Fix:** the complete normalized origin (scheme + host + effective
port) must match; `scheme_mismatch:{scheme}_vs_{origin_scheme}` is the
new rejection reason.

**Test matrix (all green, 17 tests):** HTTPS-origin-vs-HTTP-endpoint and
the reverse (same port and default-port forms), explicit default ports,
missing default ports, port mismatches, host case normalization, invalid
schemes, malformed URLs, missing origin (fail-closed), relative
resolution through the base scheme, scheme-like relative references
joined as safe paths, and the inventory-path integration (the production
caller). The 61 pre-existing admission tests are unchanged and green.

The admission filter remains defense in depth; the executor's
authoritative scope enforcement is unchanged.

## 3. Identity safety (§10.2) — VERIFIED

Cross-tenant non-merging, cross-type non-merging, ambiguous abstention,
no promotion from weak evidence, no merge from path similarity alone:
all directly tested, all green. The lab fixture's same-id-across-tenant
pair stays two identities in every arm.

## 4. Alias safety (§10.3) — VERIFIED

Query-value distinctness (`?account=1` ≠ `?account=2`), duplicate query
parameters preserved at the fingerprint layer (F10/F11
non-regression), same numeric id across tenants/types distinct, false
aliases rejected, weak candidates remain candidates. Zero false merges
across every evaluation arm.

## 5. Session / principal isolation (§6.6) — VERIFIED

- Principal records are pseudonymous by construction; the public
  projection is checked to contain no credential-shaped vocabulary.
- `SessionBindingError` fires BEFORE any request when owner and foreign
  principals share a session reference.
- Every differential probe binds principal → its own session reference;
  the lab's executor sends per-principal headers end-to-end.
- The lab's cross-representation differentials reuse one owner positive
  control per pair and per-principal probes — no owner-session reuse
  for foreign probes.

## 6. Workflow safety (§10.4) — VERIFIED

Invalid preconditions produce no workflow; correctly-rejecting clients
never yield violation candidates; destructive steps blocked under all
three insufficient contracts (not resettable / not isolated / not
operator-authorized); budget enforcement is a hard ceiling with the
exhaustion visible in the trace; partial failures produce honest
telemetry (INCONCLUSIVE, never a fabricated confirmation).

## 7. Causal confirmation integrity (§10.5) — VERIFIED

- CausalGuard's authority is UNCHANGED (its source is untouched this
  window; the guard's own tests pass).
- No alternate confirmation path: the five new modules expose no
  promotion/confirmation vocabulary (mechanically tested across all
  public names).
- A response-only difference (no authorization context) cannot confirm
  — tested at the guard AND through the engine (varying bodies with no
  auth context never produce a violation candidate).
- Identity/alias similarity alone cannot promote: the full pipeline
  over a similar-paths-only state produces zero confirmed aliases and
  zero hypotheses.
- Findings promoted in the lab run carry the validator/guard authority
  stamps; ProofBundle + replay contracts are untouched (their tests are
  part of the 8,894).

## 8. Fault injection (§10.6) — ALL FAIL-SAFE

Missing identity fields, malformed object references, conflicting alias
evidence, unknown tenant, missing principal, expired session context,
duplicate observations (idempotent), malformed workflow state, missing
validator class (fail-closed ValidatorError), empty execution
inventory, budget exhaustion (honest stop + visible trace), and total
garbage state into the node (honest telemetry, zero fabricated
output) — every mode degrades safely with honest telemetry; none
crashes, none fabricates, none confirms.

## 9. Observed security regressions

**None.** The full regression suite (8,903 tests including every
security gate: frozen modules, direct-I/O, broad exceptions, scope
laws, SSRF guards, hygiene) passes with 0 failures.

## 10. Residual risk statement

- The scheme-admission fix narrows admission; the executor scope gate
  remains the authoritative second gate (defense in depth preserved).
- The privilege-differential route now makes cross-principal
  experiments executable; they remain bounded (3 requests, replay
  required) and fail-closed on missing controls — the added capability
  is detection, not authority.
- The composite engine can execute state-mutating sequences ONLY under
  the fixture safety contract; on production targets without an
  operator-authorized resettable fixture, state-mutating sequences
  BLOCK (tested).
