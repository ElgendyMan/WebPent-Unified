# TEAM-1 — TEAM-2 HOSTILE ACCEPTANCE FIXES REPORT
## B — PARTIALLY ACCEPTED (82%) → CRITICAL FIXES APPLIED

**Status:** CRITICAL findings fixed. **249 tests pass, 1 skipped (API deps). 0 failures.**

---

## CRITICAL FINDING 1: `verify_seal()` survives semantic tampering — FIXED

### Root cause
`_seal_payload()` did NOT cover: `created_at`/chronology, execution identity, negative-control identity, evidence origin, target-backed. Caller could mutate these after sealing and `verify_seal()` still passed.

### Fix: Canonical semantic digest bound to seal
- `canonical_semantic_representation(bundle)` — deterministic, covers ALL 25 security-critical fields (engagement_id, finding_id, hypothesis_id, vulnerability_class, target_identity, evidence_origin, target_backed, negative_control_independent, oracle_decision, causal_oracle_digest, scope_context_digest, identity_context_digest, replay_metadata_digest, baseline_digest, negative_control_digest, evidence_refs, evidence_digests, request/response digests, baseline/candidate/negative_control evidence refs, validator_id/version, run_id, campaign_id, cleanup_status, bundle_id).
- `canonical_semantic_digest(bundle)` — SHA-256 of canonical representation, stored in `validator_config_digest` which IS in `_seal_payload()`.
- `promotion_valid()` Layer 2.5: re-derives digest; mismatch → `semantic_digest_mismatch:post_seal_tampering_detected`.
- Any post-seal semantic tampering breaks either the crypto seal OR the re-derived semantic digest.

### Chronology/execution identity (Part 3-4)
- Timestamps across causal/session/replay >1 year apart → rejected (fixed bug: SemanticValidationError(ValueError) was being caught by except).
- `execution_identity` required; `experiment_id` mismatch across contexts → rejected.
- baseline/candidate/negative_control execution IDs must be DISTINCT; reuse → rejected ("Execution identity violation").

### Negative-control authenticity (Part 5)
- `negative_control_independent` DERIVED from digest comparison (NC ≠ baseline AND ≠ candidate). Caller assertion ignored.
- Duplicate positive as negative → SemanticValidationError.
- Independence metadata alteration ignored (derived from trusted execution identities).

### Evidence origin + target-backed (Part 6-7)
- `evidence_origin=target_runtime` required for promotion. Caller forging `target_backed=True` with `offline_fixture` → rejected.
- `oracle_decision=CONFIRMED` requires `causal_signal=True`.

---

## CRITICAL FINDING 2: `legacy_recon_advisory_only` regressed to False — FIXED

### Root cause
Flag was set AFTER `recon_node(state)` ran; legacy node could overwrite.

### Fix: Structural enforcement in `_combined_recon_node`
- Modern spine runs FIRST; modern authoritative state preserved (legacy cannot overwrite `modern_spine_active`, `_modern_orchestrator`, `_modern_spine_trace`, `modern_spine_version`, `legacy_recon_advisory_only`).
- Flag set BEFORE and AFTER legacy runs (structural invariant).
- Additional flags: `legacy_recon_cannot_confirm=True`, `legacy_recon_requires_modern_evidence_path=True`.
- Legacy findings forced `confirmed=False, advisory_only=True` via decorator.
- Legacy proof construction structurally denied.

---

## 17-CASE ADVERSARIAL MUTATION MATRIX (Part 15) — ALL REJECTED

created_at, event chronology, execution ID, experiment ID, target identity, evidence origin, target-backed, negative-control removal, negative-control replacement, negative-control execution reuse, negative-control identity, causal relation, lifecycle state, evidence-reference, cross-engagement injection, cross-target injection, cross-experiment injection → ALL fail promotion AND fail replay.

---

## REAL E2E PROOF (Part 16)
Loopback HTTP server → modern spine → real execution → observation → ProofBundle (semantics DERIVED from execution, not manually populated) → seal → promotion_valid=True → mutate → rejection.

---

## SINGLE-AUTHORITY AUDIT (Part 14)
- ONE `build_promotion_grade_bundle` → delegates to canonical `build_proof_bundle` (no direct ProofBundle construction).
- ONE ScopeLaw: `ContainedHTTPClient._scope_law is scope` (same instance).
- No duplicate CausalGuard/PromotionFirewall/ToolBoundary.

---

## REGRESSION: 249 passed, 1 skipped (API app extra deps). 0 failures.

## REMAINING UNPROVEN (HALF 2 — not in scope)
- operational memory retrieval + causal influence
- real process-restart persistence
- 3+ cycle longer-horizon campaign
- cross-target structural generalization
- complete regression validation
