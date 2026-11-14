# M6_PHASE_REPORT.md — M6 (Target-Deception Resistance & Evidence Quality)

**Phase:** M6 of the CANONICAL_PHASE_REGISTRY (Part 4 §8 — P1).
**Date closed:** 2026-11-06 (UTC).
**Window:** DRIFT_REGISTER UM-DR-19.
**Baseline entering:** post-M5 tree (UM-DR-18); frozen authority manifest untouched; frozen-module gate 661 green.
**Refreeze:** NONE REQUIRED — the entire phase is a NEW package (`src/webpent/deception/`) outside the frozen gate, plus a published benchmark report. Zero frozen-file changes.

---

## 1. What was delivered

### 1.1 — The deception fixture corpus (`deception/fixtures.py`)

The registry's eight named classes, 3 deterministic variants each (24 fixtures), every one with recorded ground truth **not vulnerable**:

| Class | Deceptive behavior |
|---|---|
| generic_200 | identical friendly 200 for every payload |
| reflected_uninterpreted | payload reflected verbatim in a `text/plain` `<pre>` (never interpreted) |
| catch_all | SPA shell 200 for any path/payload |
| decoy | convincing fake admin data page |
| waf_page | 403 WAF block page full of security vocabulary |
| cached_stale | same cached body + ETag for every payload |
| randomized | seeded per-token random body (diff-defeating) |
| delayed | constant artificial delay marker on every request |

Pure in-process responders — no network, no state; the randomized class is token-seeded so runs are reproducible.

### 1.2 — The deception-resistant causal verifier (`deception/verifier.py`)

The three-response causal protocol — `baseline` (payload-free), `candidate` (payload), `control` (a SECOND payload-free request) — plus `candidate_repeat` for repeatability. The causal fields are mandatory and recorded on every outcome: precondition / action / effect / baseline / control / repeatability.

The control's causal semantics (the review-hardened version): a target whose **payload-free responses already vary** cannot attribute the candidate difference to the payload — `response_varies_without_payload:effect_unattributable` REFUTES (this is what catches the randomized class: the first-draft semantics compared the control to the CANDIDATE and let all 3 randomized fixtures through as false positives; comparing the control to the BASELINE — two payload-free requests — closed it: **24/24 rejected, 0 FP**).

Named deception signatures recognized structurally from the response PAIR (never from keywords): identical responses, cache-frozen ETags, delay-only marker "effects", uninterpreted reflection contexts, control-reproduced effects, payload-free variance.

Verdicts are one-way by construction: `refuted_deceptive` / `inconclusive` / `confirmed_candidate` — and `confirmed_candidate` is an EVIDENCE verdict ("the differential is real and attributable"), never a Finding. **No inconclusive→confirmed transition exists**: the verdict is computed once by a pure function (idempotence test-pinned). A genuine differential with a sound control still CONFIRMS (true-positive sanity test — the verifier is not a refuse-everything gate).

### 1.3 — The declared evidence contracts (`deception/validator_contracts.py`)

`webpent-evidence-contracts-v1`: per-vuln-class (xss, sqli, idor_bola, ssrf, cache_poisoning, tenant_isolation) — `required_evidence` fields, `negative_control_required`, declared `limitations` (what the contract does NOT prove), `replay_required`. `validate_evidence_bundle` enforces fail-closed per class; unknown classes refuse (`unknown_vuln_class_contract`), never a silent default-allow.

### 1.4 — The sqlmap internal differential (`deception/sqlmap_differential.py`)

The M0-documented, M1-deferred residual, closed: `extract_sqlmap_differential(baseline_stdout, candidate_stdout)` — confirmation evidence ONLY when the candidate run carries a marker AND the baseline run does NOT (the internal pair); **both-runs markers ⇒ `deceptive_both_runs` refused** (ambient text — the exact evidence-integrity defect a single-run `parse_sqlmap_confirmation` cannot catch); candidate-only ⇒ `differential_confirmed` with the extracted injection facts (type lines, parameter, payload). The module never launches sqlmap — it extracts from the stdout pair the frozen runner already captured.

### 1.5 — The benchmark (`deception/benchmark.py` + `reports/deception/benchmark_v1.json`)

ATOBench-inspired: runs the corpus through the verifier with the full four-request protocol; per-class counts with sample sizes; a deterministic hash-split **blind set** (8 fixtures) scored separately; false-positive fixture ids listed. **Published report: 24 fixtures, 24 rejected, 0 false positives, 0 inconclusive; blind set 8/8 rejected** (regenerated after the control-semantics hardening; the first run's 3 randomized false positives are recorded in the DRIFT_REGISTER as the found-and-fixed defect).

## 2. Acceptance vs the registry

| Registry acceptance (Part 4 §8) | Status |
|---|---|
| misleading fixtures rejected | **delivered + measured** — 24/24, 0 FP, blind set 8/8 |
| evidence replay preserved | **delivered** — contracts require `replay_spec`; the M5 replay specs satisfy them |
| no inconclusive→confirmed transitions | **delivered** — one-way pure verdict (idempotence test-pinned) |
| deception benchmark reports published with sample sizes | **delivered** — `reports/deception/benchmark_v1.json` (per-class + blind set + sizes) |
| deception fixtures (8 classes) | **delivered** (§1.1) |
| causal verification fields mandatory | **delivered** (§1.2 — recorded on every outcome) |
| validator contracts declared | **delivered** (§1.3) |
| sqlmap differential extraction from internal baseline/candidate pairs | **delivered** (§1.4 — the M1 deferral closed) |

Deferred with owners: wiring the verifier into the frozen validator chain's response-pair paths → a dedicated thaw window when the validator's response-pair seam is next opened (the contracts module is the declared interface); live corpus expansion (more variants, real-world captures) → M11's benchmark scope.

## 3. Gate evidence at closure

- **Tests:** `tests/test_m6_deception_resistance.py` — 16 passed.
- **Frozen-module gate:** 661 passed (no frozen changes — nothing to refreeze).
- **Test-count gate:** 8,452 ≥ floor 8,115.
- **Coverage ratchet:** 4.27% ≥ 4.07% (scoped; unchanged).
- **Authority manifest:** untouched (13 files).

— End of M6_PHASE_REPORT.md —
