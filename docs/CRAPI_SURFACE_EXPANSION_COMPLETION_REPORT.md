# CrAPI Surface Expansion Completion Report

**Date:** 2026-10-03  
**Scope:** Authorized local CrAPI gateway at `http://127.0.0.1:8888`, with Juice Shop regression at `http://127.0.0.1:3000`.

## 1. Implementation completed

- Added bounded operator-declared same-origin `route_seeds` support to the generic crawler.
- Allowed runtime-only `surface_paths` in validated principal profiles; no credentials are stored in source or evidence.
- Threaded the route seeds through the hunter runner into the crawler and campaign summary.
- Preserved observed object identifiers when constructing generic IDOR/BOLA request triples; principal IDs are used only for actor identity.
- Added sanitized body-digest propagation into AVI structured observations. This allows independent 200 responses to be distinguished without exposing target bodies to the validator or LLM.
- Kept all execution behind the existing ScopeLaw, ToolBoundary, M4 ContextAuthority, AVI, ProofBundle, replay, and PromotionPipeline path.
- No frozen trust-spine module was changed.

## 2. CrAPI expanded campaign — r4

Campaign: `crapi-workshop-expansion-20261003-r4`

| Metric | Observed result |
|---|---:|
| Configured workshop route seeds | 7 |
| Routes crawled | 32 |
| Candidates generated | 14 |
| Executable candidates | 10 |
| Confirmed validations | 1 |
| Blocked validations | 3 |
| Inconclusive validations | 1 |
| Refuted validations | 0 |
| LLM calls | 12 |
| Observed LLM cost | `$0.049837` |
| Duration | `219.26 s` |
| Vault-bound principals | 2 |
| Discovered identity IDs | 2 |
| Resource templates | 1 |
| Audit chain | **Verified** |

### Promoted result

- **Finding:** `finding_bola_232719982d12688e`
- **Class:** BOLA
- **Request resource:** `/workshop/api/shop/orders/1`
- **Baseline:** owner principal, HTTP 200
- **Candidate:** foreign principal on the owner resource, HTTP 200
- **Negative control:** `/workshop/api/shop/orders/2`, foreign principal, HTTP 200 with a different redacted body digest
- **Response digests:** baseline/candidate `3aa8caa7b4f80c88`; negative control `890cffef9245261e`
- **Validator:** `CONFIRMED`
- **ProofBundle:** sealed; `proof_bundle_80b9c9f45374444e85e012696dcecf16`
- **Replay:** verified
- **Promotion:** all 8 anti-fake gates passed

The response bodies and credentials were not copied into the report or release archive.

## 3. Community exploration result

The expanded campaign also queued and crawled community routes. The initial generic seed `/community/api/v2/community/posts/1` returned HTTP 400 for both principals in this deployment, so it was correctly not promoted. This is recorded as an observed limitation, not a fabricated BOLA.

## 4. Juice Shop regression — r1

Campaign: `juice-surface-regression-20261003-r1`

- Routes crawled: 35
- Candidates generated: 14
- Executable candidates: 10
- Vault-bound principals: 2
- Discovered identity IDs: 2
- Confirmed validations: 3
- Audit chain: **Verified**
- Promotions included IDOR/BOLA findings through ProofBundle, replay, and all 8 gates.
- Runtime credential values were absent from the campaign artifacts.

## 5. Independent validation

- Full suite: **2131 passed, 0 failed**.
- Acceptance input: **20 passed in round 1, 20 passed in round 2, 20 passed in round 3**.
- Direct-I/O inventory contract: **4 passed** after canonical regeneration; current scan contains 622 records and 20 pinned unapproved records.
- Frozen manifest: **13/13 OK**.
- State-contract gate: **PASS**.
- Orchestrator construction authority gate: **PASS**.
- Isolation denylist gate: **PASS**.
- Vault import authority gate: **PASS**.
- Test-count gate: **PASS**, 2131 collected against a 1940 floor.
- Changed-module compilation: **PASS**.

The first full-suite attempt had one expected inventory-drift failure after source edits; the inventory was regenerated canonically and the complete suite then passed with zero failures.

## 6. Security and honesty constraints

- No hardcoded operator credentials were added to source.
- No raw credentials, bearer tokens, cookies, or target response bodies are included in the evidence projections.
- A promotion is reported only when runtime observations, causal validation, sealed ProofBundle, replay, semantic identity binding, and all other gates pass.
- The CrAPI result is a genuine promoted non–Juice-Shop finding; no result was inferred from HTTP status alone.
