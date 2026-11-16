# UM-DR-36.2 + UM-DR-37 — Verification Round Report

Generated 2026-11-16T05:24:44.949432+00:00 from live artifacts. Head `609da8ade4bc`.

## A. Execution summary

This round independently verified the previous execution's claims and
closed the refined mission's gaps: all seven remaining full-suite
failures investigated INDIVIDUALLY and fixed at the smallest correct
level; the runner v2/v3 contract resolved at the contract level; the
12-state hypothesis lifecycle, the structured failure taxonomy, and
the 8-family security profiles implemented as reuse-layer extensions;
the full-loop learning proof delivered through the real production
research path; and the extended lab (decoy + out-of-scope origin)
EXPOSED AND CLOSED a real false-positive class — the ownership
heuristic confirmed a public resource as an IDOR (measured in
artifacts/umdr37_decoy_exposure.json).

NOTE: this verification round was executed twice — a sandbox recycle
mid-delivery wiped the first execution's working tree and git objects;
the entire round (fixes, modules, proofs, campaigns, surgery, suite)
was rebuilt and re-executed from scratch. Every artifact in this
delivery comes from the SECOND, completed execution.

## B. Repository identity

- branch `mission/umdr36.2-umdr37`, head `609da8ade4bc`
- version 0.40.1 (SSOT-aligned; BUILD_INFO provenance protocol
  extended for mission re-baselines, ONE declared re-baseline, history
  surgically rebuilt tree-identically)
- source of truth: the public GitHub main (64a5bea content) + the
  delivered 36.1 bundle

## C. Root-cause results (§4 verification)

RC-1..RC-4 re-verified with the §4 sub-checks (nested traversal, dedup,
size limits, free-text rejection, same-origin; checkpointer-enabled
branch; the guard's context mapping — normalization, never
manufacture). The decoy route added a FIFTH finding: a real
false-positive class in the ownership heuristic, closed this round
(UMDR37_DECOY_CLOSURE.json, exposure measured before the closure).

## D. Discovery intelligence

- Application Understanding: appmodel provenance vocabulary
  (UNKNOWN/CONTRADICTED), timestamps, revisions/deltas.
- Security Reasoning: 8 family profiles x 10 aspects, honest statuses
  (exactly one PRODUCTION_PATH_VERIFIED).
- Experimental Discovery: info-gain selection with adversarial
  repetition/exhaustion pins.
- Hypothesis Lifecycle: the 12-state registry with evidence-gated
  reopening, merging, supersession (9/9 adversarial).
- Root-Cause Learning: 16-stage taxonomy, closed reason codes,
  evidence-gated influence (8/8).
- Full-loop learning: PROVEN (see E).

## E. Production results

3/3 campaigns through `run_unified_hunt` against lab v1.6.0: exactly
the two real boundary violations confirm through CausalGuard ->
ProofBundle -> replay; the decoy stays unconfirmed; the out-of-scope
origin received ZERO requests; all invariants green (artifacts/
umdr37_production_campaigns.json). Full-loop learning: the six-step
chain held under an identical 36-request budget (docs/
UMDR37_FULL_LOOP_LEARNING.json).

## F. Test results

Final full-suite run (v3 hook accounting): collected 9228, outcomes {'passed': 9217, 'failed': 0, 'skipped': 8, 'xfailed': 3, 'xpassed': 0}, errors 0, exit 0 — evidence commit 1386d5707296. the final full-suite run executed at 1386d5707296; any commits after it are the protocol BUILD_INFO re-freeze and deliverables regeneration only — no source changes (verifiable via git log --stat)

New suites this round: {
  "lifecycle_registry": "tests/test_umdr37_lifecycle_registry.py (9)",
  "failure_taxonomy": "tests/test_umdr37_failure_taxonomy.py (8)",
  "family_profiles": "tests/test_umdr37_family_profiles.py (8)",
  "component_influence": "tests/test_umdr37_component_influence.py (12)",
  "decoy_closure": "tests/test_umdr37_decoy_closure.py (4)",
  "full_loop_proof": "docs/UMDR37_FULL_LOOP_LEARNING.json (PROVEN)"
}

## G. Security guarantees

Explicit authorization, scope validation, same-origin + SSRF
enforcement (out-of-scope origin: zero requests, proven), negative
controls never promoted (admin 403, missing 404, decoy public — all
unconfirmed in all runs), CausalGuard sole authority, no LLM-only
confirmation, no automatic promotion without sealed evidence.

## H. Unverified items

- Remote CI (no credentials — bundle provided).
- Full-suite freshness: see F and full_suite.note in
  UMDR37_READINESS.json.
- Families beyond access control: integrated/implemented, not
  production-confirmed.

## I. Deliverables

This file + the Part-20 set + the git bundle + the final ZIP with a
complete file index (every project file listed).

## J. Final status

**PARTIALLY_VERIFIED** — production discovery/confirmation verified
and reproducible (3/3), full-loop learning proven, seven failures
closed, decoy class exposed and closed; remote CI and the in-flight
suite freshness remain.
