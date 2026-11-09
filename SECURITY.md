# WebPent Security Model

This document is the ONE canonical source for WebPent security invariants.

## Core Principle
**AUTHENTIC PROOF != MERELY VALID SEAL.** Promotion requires:
TRUSTED EXECUTION + CANONICAL SEMANTICS + HMAC AUTHENTICITY + CAUSAL SUPPORT + AUTHORIZED SCOPE.

## Security Invariants

### 1. Scope Authority (ScopeLaw)
- Every evidentiary request evaluated at final execution boundary.
- External/unauthorized targets → fail closed.
- No legacy path may bypass ScopeLaw.

### 2. Execution Authorization (ToolBoundary)
- Only allowed tools (discover, request, replay, compare, inspect_state, inspect_response, enumerate_entity, run_workflow_step, summarize_memory).
- Every tool call must be associated with a research hypothesis (≥5 chars).
- Forbidden tools: shell_exec, file_write, modify_detector, set_confirmed, override_verdict, bypass_causal_guard, mutate_evidence, modify_ground_truth, system, exec, eval.
- M1-A (L-7) — external-tool governance is BASENAME-based: `WEBPENT_ALLOWED_EXECUTABLES` registers basenames and the spawn resolves them via `PATH`, where the FIRST match wins. A shadowing binary with an allowed basename in an earlier `PATH` directory is the one that executes. Operators must pin tool paths (`NMAP_PATH=...`, absolute) on multi-tenant hosts and keep the runtime `PATH` minimal.

### 3. CausalGuard
- Causal signal must be True for CONFIRMED oracle decision.
- Negative control must be complete.
- Caller-asserted booleans (target_backed, negative_control_independent, oracle_decision) are DERIVED from evidence, never trusted.

### 4. ProofBundle Authenticity (dual-layer)
- SHA-256 integrity (seal_digest) covers canonical semantic representation.
- HMAC-SHA256 authenticity (authenticity_tag) computed over seal_digest using trusted secret.
- Secret from WEBPENT_AUDIT_SECRET_KEY env var or Settings.audit_secret_key (≥32 chars).
- Missing/weak secret → fail closed (authenticity_tag=None → verify_seal=False).
- verify_seal() checks BOTH SHA integrity AND HMAC authenticity.
- verify_seal_integrity_only() exists for advisory use — NOT for promotion.

### 5. Semantic Proof Integrity
- Canonical semantic digest covers 25 security-critical fields.
- Stored in validator_config_digest (which IS in seal payload).
- Post-seal semantic tampering → seal broken OR semantic digest mismatch.
- Negative control independence DERIVED from digest comparison (NC ≠ baseline AND ≠ candidate).
- Execution identity: baseline/candidate/negative_control must reference DISTINCT executions.
- Chronology: timestamps across contexts >1 year apart → rejected.

### 6. PromotionFirewall
- promotion_valid() requires: cryptographic_seal AND semantic_completeness AND semantic_digest_match AND promotion_contract AND replay_consistency.
- Layers: CRYPTO_FAIL → SEMANTIC_FAIL → SEMANTIC_DIGEST_MISMATCH → PROMOTION_FAIL → REPLAY_FAIL.

### 7. Replay Binding
- Replay uses same canonical verify_seal() (HMAC + SHA).
- Replay context must match proof identity (campaign, target, run).
- Tampered proof → rejected at replay, same as promotion.

### 8. Modern/Legacy Authority
- Modern Spine is production default (MODERN_SPINE_MODE=PRODUCTION_MODERN).
- COMPATIBILITY_LEGACY mode: explicit, auditable, legacy_authority_blocked=True.
- UNSUPPORTED_LEGACY_ONLY: blocked for production authority.
- Legacy findings forced confirmed=False, advisory_only=True.
- Legacy proof construction structurally denied.
- Legacy cannot overwrite: scope authority, confirmation state, proof authority, vulnerability class, target binding, execution authorization, promotion state.

### 9. Schema Trust Boundary
- All schema descriptions/summaries/parameter descriptions/GraphQL descriptions = UNTRUSTED.
- Marked with UNTRUSTED_DESCRIPTION_MARKER.
- Cannot influence: authorization, scope, confirmation, promotion, proof status.
- Authority derived only from authoritative structured state.

### 10. Advisory Memory
- Memory is advisory-only (trust_level=untrusted_advisory).
- usage_constraint=may_influence_ranking_only.
- Cannot authorize, bypass ScopeLaw/ToolBoundary/CausalGuard, create promotion authority, or manufacture proof.
- Cross-target isolation: target-specific memory does not leak authority across targets.

### 11. Fail-Closed Behavior
- Missing authority → fail closed.
- Missing proof → fail closed.
- Invalid scope → fail closed.
- Unverifiable evidence → fail closed.
- Configuration drift → fail closed.
- Unknown state version → fail safe (no silent reinterpretation).

## Trust Boundary for HMAC Secret
1. WEBPENT_AUDIT_SECRET_KEY env var (explicit dev/test override, ≥32 chars).
2. Settings.audit_secret_key (production trusted config, ≥32 chars).
Secret never stored in or exposed by ProofBundle.
