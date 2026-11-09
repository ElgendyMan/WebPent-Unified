# TEAM-1 — PROOF AUTHORITY CONSOLIDATION + HMAC PROMOTION INTEGRATION REPORT

**Status:** IMPLEMENTATION COMPLETE. **268 tests pass, 1 skipped (API deps). 0 failures.**

---

## PART 1 — PROOFBUNDLE AUTHORITY MAP (CALLER → FUNCTION → FINAL AUTHORITY)

| Module | Role | Classification | Final Authority |
|--------|------|---------------|-----------------|
| `models/proof_bundle.py` | Constructor, serializer, seal, verify_seal | **CANONICAL** | `ProofBundle.seal()` / `verify_seal()` |
| `models/proof_semantics.py` | Semantic validator, promotion_valid | **CANONICAL** (semantic layer) | `ProofSemanticValidator` + `promotion_valid()` |
| `utils/crypto.py` | HMAC-SHA256 + audit_secret_key | **AUTH SOURCE** (delegated) | `_compute_hmac()` + `_get_audit_key()` |
| `irta/v3/proof.py` | Legacy builder wrapper | **DELEGATING WRAPPER** → canonical | `build_proof_bundle()` |
| `shared/proof_bundle_store.py` | Persistence adapter | **PERSISTENCE ONLY** (reads → canonical verify) | canonical `verify_seal()` |

**ONE canonical proof authority.** No duplicate seal/HMAC/promotion logic.

---

## PART 4 — CRYPTOGRAPHIC MODEL: C (DUAL-LAYER SHA-256 + HMAC-SHA256)

- **SHA-256 integrity** (`seal_digest`): covers `_seal_payload()` (all semantic fields, evidence digests, chain of custody). Detects tampering.
- **HMAC-SHA256 authenticity** (`authenticity_tag`): computed over `seal_digest` using trusted secret. Proves the bundle was sealed by a trusted runtime. Attacker cannot forge without the secret.
- **New fields**: `authenticity_tag`, `authenticity_algorithm` (hmac_sha256_v1), `authenticity_key_version`.

---

## PART 5/6 — HMAC TRUST BOUNDARY

Secret retrieval (ordered, explicit):
1. `WEBPENT_AUDIT_SECRET_KEY` env var — explicit dev/test override (visible, requires ≥32 chars, cannot silently become production).
2. `Settings.audit_secret_key` — production trusted config.

**Fail-closed**: missing/weak key (<32 chars) → `authenticity_tag=None` → `verify_seal()=False` → promotion BLOCKED. Secret never stored in or exposed by bundle.

---

## PART 7 — PROMOTION PATH INTEGRATION

```
execution → evidence → canonical semantics → seal_digest (SHA) → authenticity_tag (HMAC)
  → verify_seal() [SHA match + HMAC match]  ← authenticity checked HERE
  → semantic_validation
  → CausalGuard
  → PromotionFirewall
  → promotion_valid()=True
```

`verify_seal_integrity_only()` (SHA only) exists for advisory use — promotion requires full `verify_seal()` (dual-layer).

---

## PART 8 — AUTHENTICITY VS SEMANTICS MATRIX (4 CASES)

| Case | Authenticity | Semantics | Result | Rejected By |
|------|-------------|-----------|--------|-------------|
| A | ✅ HMAC valid | ✅ Valid | **Eligible** | — |
| B | ✅ HMAC valid | ❌ Tampered | REJECT | verify_seal (SHA mismatch) |
| C | ❌ Wrong key | ✅ Valid-looking | REJECT | **HMAC verification** |
| D | ❌ No tag | ❌ Invalid | REJECT | HMAC verification |

---

## PART 9/10 — POST-SEAL TAMPERING + SEMANTIC DIGEST ATTACK (ALL REJECTED)

- **Attack A**: mutate semantic field + recompute SHA + leave HMAC → **HMAC mismatch → REJECT**
- **Attack B**: mutate + recompute SHA + forge HMAC (no secret) → **HMAC mismatch → REJECT**
- **Attack C**: valid proof + different runtime key → **HMAC mismatch → REJECT**
- **Semantic digest attack**: caller recomputes canonical semantic digest + plain seal → still **REJECTED** (HMAC requires trusted secret)

---

## PART 12 — REPLAY AUTHORITY CONSISTENCY

Replay uses same canonical `verify_seal()` (HMAC + SHA). Tampered proof → rejected at replay, same as promotion. No separate replay validator.

---

## PART 14 — VERSIONING

- `authenticity_algorithm = "hmac_sha256_v1"` — explicit algorithm version
- `authenticity_key_version` — key identifier (env_override_v1 / settings_audit_key_v1)
- `canonical_semantic_digest` schema = `semantic_v1:` prefix

---

## PART 15 — KEY ROTATION: SINGLE-KEY TRUST MODEL

Documented single-key model. No rotation complexity built. Boundary: key version field present for future rotation; unknown versions fail closed.

---

## PART 16 — REAL E2E AUTHENTIC PROOF

Loopback HTTP server → modern spine → real execution → observation → ProofBundle (HMAC sealed) → verify_seal (dual-layer pass) → promotion_valid=True → 3 attacks (A/B/C) all rejected.

---

## PART 17 — AUTHORITY DUPLICATION AUDIT

- Seal: ONE implementation (`ProofBundle.seal`)
- HMAC: ONE helper (`_compute_authenticity_tag`) → delegates to `utils.crypto._compute_hmac`
- Semantic validation: ONE (`ProofSemanticValidator`)
- Promotion: ONE (`promotion_valid`)
- Replay: ONE (`replay_semantic_consistent` → canonical verify_seal)
- Legacy `irta/v3/proof.py`: delegates to canonical `build_proof_bundle`

**No dangerous duplicates.**

---

## PART 18 — REGRESSION: 268 passed, 1 skipped (API app extra deps). 0 failures.

---

## HALF-2 REMAINING GATES (not in scope)
- operational memory improvements
- process-restart persistence
- longer-horizon campaign work
- cross-target generalization
