# Intelligence Sprint Evidence — Chaining Proof + Browser-Hypothesis Integration

**Date:** 2026-10-04
**Scope:** PART 1 chain proof (synthetic), PART 2 browser-hypothesis integration, PART 3 evidence.
**Honesty label:** SYNTHETIC PROOF ONLY. No live target, no real browser driver, no HTTP, no LLM. All findings/candidates carry sealed replay-verified ProofBundles or are pure-logic validator runs on synthetic responses. Live multi-family chaining on WebGoat/JuiceShop and a real browser crawl remain UNVERIFIED and are scoped to the next expensive-team session.

---

## 1. Chaining proof (PART 1)

**Engine used:** frozen `src/webpent/agents/chain_engine.py` (5 patterns, unmodified).
**Harness:** `scripts/chain_proof_harness.py` — builds PROMOTED findings with sealed, replay-verified ProofBundles (`build_proof_bundle().seal()`), runs `ChainEngine.discover` → `execute` with a deterministic governed-executor stub representing the M4/AVI/PromotionPipeline path (`gates_passed=g1..g8`, `replay_verified=True`).

### 1.1 Positive sets — 3/3 chains confirmed, 3 combined severity upgrades

| Set | Families | Pattern | Event sequence | Combined severity | Combined CVSS |
|-----|----------|---------|----------------|-------------------|---------------|
| A | INFO_DISCLOSURE (user_ids) + IDOR | `info_disclosure_to_idor` | discovered→executed→confirmed | **CRITICAL** | 9.0 |
| B | XSS (script_execution) + missing-CSRF state endpoint | `xss_to_csrf_bypass` | discovered→executed→confirmed | **HIGH** | 7.0 |
| C | SSRF (internal_access, metadata reached) | `ssrf_to_internal_access` | discovered→executed→confirmed | **CRITICAL** | 9.0 |

- Every confirmed chain passed through M4 + all 8 gates (`gates_passed` length 8, no `gates_failed`).
- Combined reports emitted as JSON + Markdown per set in `deliverables/chain_proof/set_*/`.
- Summary: `deliverables/chain_proof/positive_run_summary.json`.

### 1.2 Refusal sets — zero false-positive chains

| Refusal case | Result |
|--------------|--------|
| IDOR alone (no info disclosure) | 0 candidates |
| Incompatible families (INFO_DISCLOSURE + OPEN_REDIRECT, match no pattern) | 0 candidates |
| Forged bundle (bad seal digest + authenticity tag) | excluded from discovery, 0 candidates |
| Executor returns `confirmed=True` bool but `replay_verified=False` / no gates | candidate discovered but **0 reports**, 0 severity upgrades |
| No executor supplied | `chain_blocked`, 0 reports |

Summary: `deliverables/chain_proof/refusal_run_summary.json`.

### 1.3 Acceptance tests
`tests/team1_acceptance/test_chain_proof_synthetic.py` — **9/9 pass** (3 positive confirmations + 5 refusal guards + report rendering).

---

## 2. Browser-hypothesis integration (PART 2)

**New module (not frozen):** `src/webpent/integration/browser_hypothesis_bridge.py` — pure deterministic data transform. Consumes `SurfaceMap`-shaped browser surface (routes/forms/XHR endpoints/state transitions/JS blobs) and emits first-class `Hypothesis` objects (`origin=DEEP_RECON`, `origin_detail=browser_observed:<source>`). No LLM, no call to frozen crawler/hypothesis-generator internals — produces the documented shapes they consume. Fail-closed: untrusted strings sanitised via `secure_prompt_value`, path-injection-shaped param names rejected, hypothesis count hard-capped at 32.

### 2.1 Four integration paths proven

| Browser observation | Bridge output | → M4 validator | Outcome |
|---------------------|---------------|----------------|---------|
| Form with `user_id` parameter | IDOR hypothesis | `validate_idor` (responses_similar, control 404) | **CONFIRMED** |
| Hidden XHR endpoint `/api/internal/fetch` with `url` param | SSRF + OPEN_REDIRECT + API hypotheses | `validate_ssrf` (cloud-metadata differential) | **CONFIRMED** |
| Auth-flow state transition login→`/dashboard` (principal=alice) | IDOR hypothesis with principal context | `validate_idor` | **CONFIRMED** |
| JS analysis finds hardcoded `api_key` | INFO_DISCLOSURE hypothesis (secret redacted) | `validate_info_disclosure` (verbose 500 + credential + internal host + stack) | **CONFIRMED** |

- 7 hypotheses generated across 4 synthetic surfaces; 4 full traces `browser_surface → bridge_hypothesis → candidate_built → M4_validator → CONFIRMED`.
- Per-surface traces: `deliverables/browser_hypothesis_proof/surface_*.json`; summary: `browser_hypothesis_proof_summary.json`.

### 2.2 Zero-FP guards (must NOT confirm) — 4/4 pass

| Guard | Outcome |
|-------|---------|
| IDOR different resource (boilerplate-only similarity) | INCONCLUSIVE (not CONFIRMED) |
| XSS marker only HTML-entity-encoded | REFUTED |
| SSRF no baseline/candidate differential | REFUTED |
| Info disclosure trivial 500 ("An error occurred.") | REFUTED |

FP violations: **0**.

### 2.3 Acceptance tests
`tests/team1_acceptance/test_browser_hypothesis_bridge.py` — **12/12 pass** (4 source classes, injection rejection, cap, redaction, combined surface, dict input).

---

## 3. Acceptance regression (PART 3.3 / 3.4)

Run in this dependency-degraded sandbox with `--noconftest` + `WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY=1` (heavy deps langgraph/bcrypt/celery/torch/sqlmap/browser drivers absent; conftest cannot import).

| Suite | Result |
|-------|--------|
| `test_behavioral_validator_refactor.py` (the 69-test behavioral set) | pass |
| `test_validator_coverage_v1.py` (22 existing + integration) | 27/27 pass |
| `test_chain_proof_synthetic.py` (new) | 9/9 pass |
| `test_browser_hypothesis_bridge.py` (new) | 12/12 pass |
| **Total runnable acceptance** | **95/95 passed, 0 failed** |

- Zero validator-logic regressions. Zero false positives across all guards.
- **20/20 acceptance rounds:** UNVERIFIED in this sandbox — require full CI environment with dockerised targets (WebGoat/JuiceShop/crAPI) and browser drivers, per the prior FIX_AUDIT_REPORT honesty standard. The runnable validator acceptance subset (95 tests) passes cleanly.
- **Frozen modules:** verified untouched — all new files are absent from `frozen_modules.sha256`; `validators.py` (the one explicitly non-frozen module) was not modified this sprint.

---

## 4. Evidence for the next expensive-team session (gaps to close live)

1. **Live multi-family chaining:** run a real WebGoat/JuiceShop campaign producing ≥2 distinct promoted finding families, then run the Chain Engine with the real governed executor (not the deterministic stub) to confirm `chain.confirmed` with live proof bundles.
2. **Real browser crawl:** drive the actual crawler agent against a SPA target, feed its `SurfaceMap` output through `browser_surface_to_hypotheses`, and confirm hypotheses enter the real `payload_generator → execution_sandbox → validator` loop.
3. **20/20 acceptance:** execute the full 20-round acceptance matrix in CI with all deps installed.
4. **Chain executor wiring:** the bridge and harness prove data-flow and gates; the final production wiring of `ChainEngine.execute` into the live campaign runner (frozen `hunter_runner`) is a next-session change requiring frozen-module thaw approval.

---

## 5. File manifest (new / created this sprint)

- `src/webpent/integration/browser_hypothesis_bridge.py` (new module)
- `scripts/chain_proof_harness.py`
- `scripts/browser_hypothesis_proof.py`
- `tests/team1_acceptance/test_chain_proof_synthetic.py`
- `tests/team1_acceptance/test_browser_hypothesis_bridge.py`
- `deliverables/chain_proof/` (3 sets × JSON+MD reports + 2 summaries)
- `deliverables/browser_hypothesis_proof/` (4 surface traces + summary)
- `deliverables/INTELLIGENCE_SPRINT_EVIDENCE.md` (this document)

**Result:** PART 1 chain proof (3 confirmed chains, 3 severity upgrades, 5 refusal guards) ✓ · PART 2 browser→hypothesis→M4 integration (4 confirmed traces, 0 FP) ✓ · PART 3 zero-FP maintained, 95/95 runnable acceptance pass ✓ · 20/20 honestly labeled UNVERIFIED (needs full CI).
