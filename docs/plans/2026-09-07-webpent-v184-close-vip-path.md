# WebPent GOED v1.8.4 — Close VIP Qualification Path Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Close out GOED v1.8.4 LLM validation milestone, produce measured evidence of LLM-layer capability (or honest no-gain), and prepare P10 Authorization Request v2 for human governance decision.

**Architecture:** Execute Phase 6-16 with real LLM APIs against local synthetic benchmark targets (differential_v2 on port 9210). Phase 11 (LLM_OFF vs LLM_ON differential) is the critical measurement. Phase 18 regression gate validates no governance invariants were violated. Phase 19 final truth audit ties every claim to a runnable JSON artifact.

**Tech Stack:** Python 3.10+, httpx, Groq OpenAI-compatible API (primary), OpenRouter API (secondary model comparison), hashlib, json, zipfile

**Governance Hard Rules (never violate):**
- `vip_qualified` = **false** everywhere
- `qualification_state` = **CONDITIONAL**
- P10 = **NOT_OPEN** / **CLOSED**
- No mock reported as VERIFIED — label ENGINEERING_MOCK_VERIFICATION explicitly
- `blind_v3_executor.py` must NEVER read `ground_truth.json`
- Phase 15: report both models independently, no averaging
- If Phase 11 `delta_recall <= 0`, report `REAL_LLM_INTEGRATED_NO_MEASURED_GAIN`

---

## Pre-Execution: Environment Setup

### Task 0: API Keys & Environment

**Files:**
- Environment variables only (no files created)

**Step 1: Verify API keys are available**

Required environment variables for primary provider (Groq):
```bash
LLM_PROVIDER=openai_compatible
LLM_API_KEY="gsk_<REDACTED>"
LLM_BASE_URL="https://api.groq.com/openai/v1"
LLM_MODEL="qwen/qwen3.8-27b"
```

For Phase 15 secondary provider (OpenRouter):
```bash
LLM_PROVIDER_2=openai_compatible
LLM_API_KEY_2="sk-or-v1-<REDACTED>"
LLM_BASE_URL_2="https://openrouter.ai/api/v1"
LLM_MODEL_2="anthropic/claude-3.5-sonnet"
```

**Step 2: Test API connectivity**

Run:
```python
import httpx
headers = {"Authorization": f"Bearer {LLM_API_KEY}"}
r = httpx.get(f"{LLM_BASE_URL}/models", headers=headers, timeout=15)
assert r.status_code == 200, "Groq API unreachable"
```
Expected: Status 200, model list includes `qwen/qwen3.8-27b`

**Step 3: Clear Python cache**
```bash
find src -name "__pycache__" -type d -exec rm -rf {} +
find . -name "*.pyc" -delete
```

---

## Part A.1: Resolve Freeze Contradiction (Governance Decision)

### Task A.1: Create Decision Record & Re-Freeze Manifest

**Files:**
- Create: `docs/decisions/DECISION-2026-09-06-phase18-freeze-contradiction.md`
- Create: `docs/archive/goed-v1.8.4/GOED_V1_8_4_FREEZE_MANIFEST.json`
- Reference: `docs/archive/goed-v1.8.3/freeze_manifest.json`

**Step 1: Compute current hashes of the 4 changed files**

```python
import hashlib, json
files = [
    "src/webpent/cqa_v2/replay_verifier.py",
    "src/webpent/llm_researcher/tool_boundary.py",
    "src/webpent/llm_researcher/providers/__init__.py",
    "src/webpent/llm_researcher/providers/factory.py",
]
for f in files:
    with open(f, "rb") as fh:
        h = hashlib.sha256(fh.read()).hexdigest()
    print(f"{f}: {h} ({os.path.getsize(f)} bytes)")
```

**Step 2: Write decision record**

Document option (a) Re-freeze as the recommended choice, with one-line reason per file:
- `replay_verifier.py`: v1.8.4 STRICT replay protocol upgrade
- `tool_boundary.py`: SSRF guard added (Phase 14 security fix)
- `providers/__init__.py`: Exports ProviderPool for multi-provider failover
- `providers/factory.py`: Adds `get_provider_status()` for failover health

**Step 3: Write v1.8.4 freeze manifest**

JSON structure with `artifacts` dict keyed by category, each entry containing `sha256`, `bytes`, `status: "superseded"`, `reason`.

---

## Part A.2: Phase 16 — Learning Experiment

### Task A.2: Create & Run Learning Experiment

**Files:**
- Create: `goed_v1_8_4/learning_experiment_v184.py`
- Report: `reports/goed_v1_8_4/learning_experiment_v184.json`
- Reference: `benchmarks/differential_v2/manifest.json` (20 reasoning/novel cases)

**Step 1: Write the experiment script**

Key design:
- COLD run: `LLMResearcher` with no learned weights
- LEARNED run: same researcher with `apply_hypothesis_weights()` called first
- Both runs against same 20 cases from differential_v2 (reasoning + novel families)
- Acceptance: ONLY hypothesis ordering may differ; verdict matches must be identical
- If verdicts differ → FAIL (leak, not learning)

**Step 2: Run with real API**
```bash
LLM_PROVIDER=openai_compatible \
LLM_API_KEY="gsk_<REDACTED>" \
LLM_BASE_URL="https://api.groq.com/openai/v1" \
LLM_MODEL="qwen/qwen3.8-27b" \
python3 goed_v1_8_4/learning_experiment_v184.py
```

**Step 3: Verify expected output**
```
Result: PASS — NO_MEASURABLE_LEARNING
  Cold recall: 1.0, Learned recall: 1.0
  Verdict matches: 20/20
  Ordering changed: False
```

---

## Part A.3: Phase 6 — Real Contract Trace

### Task A.3: Create & Run Contract Trace

**Files:**
- Create: `goed_v1_8_4/contract_trace_v184.py`
- Report: `reports/goed_v1_8_4/contract_trace_v184.json`
- Target: `benchmarks/differential_v2/differential_target_v2.py` (port 9210)

**Step 1: Write contract trace script**

Key design:
- Select 1 case from reasoning family with `expected_label=vulnerable` (e.g., dv2_031)
- Start target server, make HTTP requests for baseline/candidate/control
- Build observations, pass through `CausalFeedbackBridge.run_research_loop()`
- Verify: verdict matches expected, loops_run > 0 confirms LLM path taken

**Step 2: Run with real API**
```bash
LLM_PROVIDER=openai_compatible \
LLM_API_KEY="gsk_<REDACTED>" \
LLM_BASE_URL="https://api.groq.com/openai/v1" \
LLM_MODEL="qwen/qwen3.8-27b" \
python3 goed_v1_8_4/contract_trace_v184.py
```

**Step 3: Verify expected output**
```
Result: OK
  Case: dv2_031 (reasoning)
  Verdict: CONFIRMED
  Expected: vulnerable
  Loops: 1
```

---

## Part A.4: Phases 7-9 — Blind Benchmark v3

### Task A.4.1: Create Blind v3 Executor (Phase 7-8)

**Files:**
- Create: `goed_v1_8_4/blind_v3_executor.py`
- Input: `benchmarks/blind_v3/manifest.json` ONLY (never ground_truth.json)
- Report: `reports/goed_v1_8_4/blind_v3_execution.json`

**CRITICAL SAFETY CHECK:** The script must NOT import, read, or reference `benchmarks/blind_v3/ground_truth.json`. Add a safety assertion that verifies the file is NOT loaded.

**Step 1: Write executor script**

Key design:
- Load manifest.json, normalize cases list to dict keyed by case_id
- Start differential_v2 target on port 9210 (hardcoded in server)
- For each case: GET baseline/candidate/control paths with `X-Actor: attacker` header
- Build observations, run through `CausalFeedbackBridge`
- Record: verdict, loops_run, confidence, trajectory
- Report field: `"ground_truth_loaded_by_executor": False`

**Step 2: Run with real API**
```bash
LLM_PROVIDER=openai_compatible \
LLM_API_KEY="gsk_<REDACTED>" \
LLM_BASE_URL="https://api.groq.com/openai/v1" \
LLM_MODEL="qwen/qwen3.8-27b" \
python3 goed_v1_8_4/blind_v3_executor.py
```

Expected: 120 cases processed, no errors.

### Task A.4.2: Create Blind v3 Scorer (Phase 9)

**Files:**
- Create: `goed_v1_8_4/blind_v3_scorer.py`
- Input: `reports/goed_v1_8_4/blind_v3_execution.json` + `benchmarks/blind_v3/ground_truth.json`
- Report: `reports/goed_v1_8_4/blind_v3_score.json`

**Step 1: Write scorer script**

Key design:
- Load execution results and ground truth (separate step, AFTER execution)
- Compute: precision, recall, F1, TP/FP/FN/TN against `expected_label`
- Leakage audit: grep execution report for forbidden terms (expected_label, mechanism, vulnerability_class, etc.)
- By-family breakdown: simple, reasoning, compositional

**Step 2: Run scorer**
```bash
python3 goed_v1_8_4/blind_v3_scorer.py
```

Expected metrics: P≈0.56, R≈0.34, F1≈0.42

---

## Part A.5-A.8: Phases 11 → 10 → 12 → 13 (Strict Order)

### Task A.5: Phase 11 — LLM_OFF vs LLM_ON Differential

**Files:**
- Create: `goed_v1_8_4/differential_v184.py`
- Report: `reports/goed_v1_8_4/differential_v184.json`

**Step 1: Write differential script**

Key design:
- **Mode A (LLM_OFF):** Direct `guarded_causal_evaluate(baseline, candidate, control)` — deterministic only
- **Mode B (LLM_ON):** Full pipeline through `CausalFeedbackBridge.run_research_loop()`
- Same 120 blind_v3 cases for both modes
- Compute delta: Mode B metrics - Mode A metrics
- Classification: `MEASURED_GAIN` if delta_recall > 0, else `NO_MEASURED_GAIN`
- Count recovered (Mode A=FN, Mode B=TP) and lost (Mode A=TP, Mode B=FN)

**CRITICAL:** `guarded_causal_evaluate` takes 3 SEPARATE observation dicts (not a list) and returns `GuardedCausalResult` with `.verdict.value` and `.confidence`.

**Step 2: Run with real API**
```bash
LLM_PROVIDER=openai_compatible \
LLM_API_KEY="gsk_<REDACTED>" \
LLM_BASE_URL="https://api.groq.com/openai/v1" \
LLM_MODEL="qwen/qwen3.8-27b" \
python3 goed_v1_8_4/differential_v184.py
```

**Step 3: Verify expected output**
```
Mode A (LLM_OFF): P=0.6667 R=0.137 TP=10 FN=63
Mode B (LLM_ON):  P=0.5556 R=0.3425 TP=25 FN=48
Delta Recall: +0.2055 — MEASURED_GAIN
Recovered: 15, Lost: 0
```

### Task A.6: Phase 10 — Independent Hypothesis Evaluation

**Files:**
- Create: `goed_v1_8_4/hypothesis_evaluation_v184.py`
- Depends on: `reports/goed_v1_8_4/differential_v184.json`
- Report: `reports/goed_v1_8_4/hypothesis_evaluation_v184.json`

**Step 1: Write hypothesis evaluation script**
- Load Phase 11 results, identify up to 10 recovered cases
- For each, extract LLM-generated hypotheses from trajectory
- Evaluate: hypothesis quality, citation of observations, confidence calibration

**Step 2: Run**
```bash
python3 goed_v1_8_4/hypothesis_evaluation_v184.py
```

### Task A.7: Phase 12 — Recovery Rule Verification

**Files:**
- Create: `goed_v1_8_4/recovery_rule_v184.py`
- Depends on: `reports/goed_v1_8_4/differential_v184.json`
- Report: `reports/goed_v1_8_4/recovery_rule_v184.json`

**Step 1: Write recovery rule script**

A "genuine recovery" requires ALL 7 checks to pass:
1. LLM_OFF verdict = FN (INCONCLUSIVE/CLEAN but ground truth = vulnerable)
2. LLM_ON verdict = TP (CONFIRMED)
3. LLM actually selected the experiment (not just fallback)
4. New evidence reached CausalGuard
5. ProofBundle valid
6. Replay valid
7. No metadata leakage

**Step 2: Run**
```bash
python3 goed_v1_8_4/recovery_rule_v184.py
```

Expected: 15 candidates, genuine recoveries may be 0 (strict criteria) — this is honest, not a failure.

### Task A.8: Phase 13 — Generative vs Pattern-Recognition Split

**Files:**
- Create: `goed_v1_8_4/generative_split_v184.py`
- Depends on: `reports/goed_v1_8_4/recovery_rule_v184.json`
- Report: `reports/goed_v1_8_4/generative_split_v184.json`

**Step 1: Write split script**
- Load Phase 12 genuine recoveries as candidate set
- Classify each as GENERATIVE (requires novel strategy) or PATTERN (matches known pattern)
- If candidate set is empty, report 0/0 honestly

**Step 2: Run**
```bash
python3 goed_v1_8_4/generative_split_v184.py
```

---

## Part A.9: Phase 15 — Two Real Models Comparison

### Task A.9: Create & Run Two-Model Comparison

**Files:**
- Create: `goed_v1_8_4/two_model_comparison_v184.py`
- Report: `reports/goed_v1_8_4/two_model_comparison_v184.json`

**Step 1: Write comparison script**

Key design (HARD RULES):
- Model 1: Groq + `qwen/qwen3.8-27b` (reads LLM_API_KEY, LLM_BASE_URL, LLM_MODEL)
- Model 2: OpenRouter + `anthropic/claude-3.5-sonnet` (reads LLM_API_KEY_2, LLM_BASE_URL_2, LLM_MODEL_2)
- Both run on SAME 30 reasoning-family cases from blind_v3
- **Report BOTH independently** — no averaging, no picking "better" one
- Agreement analysis: same_verdict, different_verdict, model1_only_tp, model2_only_tp
- Helper `get_provider_from_env_vars()` temporarily swaps env vars to reuse `get_provider_from_env()`

**Step 2: Run with both APIs**
```bash
LLM_PROVIDER=openai_compatible \
LLM_API_KEY="gsk_<REDACTED>" \
LLM_BASE_URL="https://api.groq.com/openai/v1" \
LLM_MODEL="qwen/qwen3.8-27b" \
LLM_PROVIDER_2=openai_compatible \
LLM_API_KEY_2="sk-or-v1-<REDACTED>" \
LLM_BASE_URL_2="https://openrouter.ai/api/v1" \
LLM_MODEL_2="anthropic/claude-3.5-sonnet" \
python3 goed_v1_8_4/two_model_comparison_v184.py
```

**Step 3: Verify expected output**
```
Overall: OK
Model 1: P=0.5333 R=0.4444 TP=8 FN=10
Model 2: P=0.5333 R=0.4444 TP=8 FN=10
Agreement: same=30 different=0
Model1-only TP: 0, Model2-only TP: 0
```

Interpretation: Both completely different models give identical results → CausalGuard deterministic engine is the real decision authority.

---

## Part A.10-A.12: Final Gates & Delivery

### Task A.10: Re-run Phase 18 — Full Regression

**Files:**
- Existing: `goed_v1_8_4/full_regression_v184.py`
- Report: `reports/goed_v1_8_4/full_regression_v184.json`
- Reference: `docs/archive/goed-v1.8.3/freeze_manifest.json`

**Step 1: Run regression**
```bash
python3 goed_v1_8_4/full_regression_v184.py
```

**Expected results:**
- `compileall_pass: True`
- `v183_historical_manifest_untouched: True`
- `changed_count: 6` (4 original + 2 new for LLM enablement)
- `superseded_documented_count: 6`
- `unresolved_violation_count: 0`
- `missing_count: 1` (WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip — open item)
- `causalguard_unchanged: True`
- `proofbundle_unchanged: True`
- `audit_pass: False` (due to missing delivery artifact — DOCUMENT as OPEN ITEM, do not silently ignore)

### Task A.11: Phase 19 — Generate Final Truth Audit

**Files:**
- Create: `goed_v1_8_4/final_truth_audit_v184.py`
- Output: `reports/goed_v1_8_4/GOED-V1.8.4-PHASE19-FINAL-TRUTH-AUDIT.md`

**Step 1: Write audit generator**

Key design:
- Reads ALL phase report JSONs from `reports/goed_v1_8_4/`
- Produces markdown table with 3 sections:
  1. Deterministic & Governance Foundation (Phases 14, 17, 18)
  2. Real LLM Integration (Phases 6, 7-9, 10, 11, 12, 13, 15, 16)
  3. Gate Summary
- Every row backed by a runnable JSON artifact — no VERIFIED on narrative alone
- Explicit OPEN ITEMS section:
  1. Missing v1.8.3 delivery artifact (causes audit_pass=false)
  2. Scope limitation (narrow slice of wider project)
- **VIP Qualification Status:** `vip_qualified=false`, `qualification_state=CONDITIONAL`, `P10=NOT_OPEN`

**Step 2: Run generator**
```bash
python3 goed_v1_8_4/final_truth_audit_v184.py
```

### Task A.12: Build Delivery Zip

**Files:**
- Create: `goed_v1_8_4/build_delivery_v184.py`
- Output: `WebPent-GOED-v1.8.4-BlindRealLLM-GAIN.zip` (or -NOGAIN.zip if delta ≤ 0)

**Step 1: Write build script**

Include in zip:
- All `goed_v1_8_4/*.py` phase scripts
- All `reports/goed_v1_8_4/*` reports (JSON + Phase 19 markdown)
- v1.8.4 modified source files (replay_verifier, tool_boundary, providers/__init__, factory, base, interface, pool)
- Freeze manifests and decision records from `docs/archive/` and `docs/decisions/`
- `benchmarks/blind_v3/manifest.json` ONLY (NEVER ground_truth.json)

**Step 2: Build zip**
```bash
python3 goed_v1_8_4/build_delivery_v184.py
```

**Step 3: Verify no ground truth leak**
```python
import zipfile, glob
z = zipfile.ZipFile(glob.glob('WebPent-GOED-v1.8.4-BlindRealLLM*.zip')[0])
assert 'ground_truth' not in str(z.namelist()).lower()
```

---

## Part B.1: P10 Authorization Request v2

### Task B.1: Write P10 Authorization Request v2

**Files:**
- Create: `docs/authorization/P10_AUTHORIZATION_REQUEST_v2.md`
- References: `docs/authorization/P10_AUTHORIZATION_REQUEST.md` (v1), `reports/goed_v1_6/VIP_ROADMAP.md`, `reports/reviews/JUICE-SHOP-P10-RE-AUDIT-v4.md`

**Step 1: Write the document**

Required structure:
1. **Header:** Date, requester, supersedes v1, current state: `vip_qualified=false`, `qualification_state=CONDITIONAL`, `P10=NOT_OPEN`
2. **Executive Summary:** Engineering readiness demonstrated TWICE (v1.6 deterministic + v1.8.4 LLM-augmented). Sole remaining blocker: real independent human governance sign-off.
3. **Evidence Base (Clearly Separated):**
   - v1.6 Deterministic Core table (P=1.00, R=0.83, Proof=1.00)
   - v1.8.4 LLM-Augmented table (Phase 6-17 results)
4. **The Pattern:** Table showing v1.6→v1.7→v1.8→v1.8.1→v1.8.2→v1.8.3→v1.8.4 all engineering-complete but governance pending
5. **Requested Authorization:** Open P10 = VIP Qualification Campaign under constraints (no external targets, vip_qualified stays false until Phase 5 decision)
6. **Decision Requested:** Authorize OR Decline to open P10 — either outcome moves project forward
7. **Footer:** `vip_qualified: false`, `qualification_state: CONDITIONAL`, `P10: NOT_OPEN`

**CRITICAL:** Document must NOT:
- Claim VIP qualification anywhere
- Self-certify or perform independent review
- Use language like "based on the evidence, qualification can now be considered..."

---

## Source Code Fixes (Required for Real LLM Execution)

### Task SC.1: Fix CausalFeedbackBridge Mock Detection

**File:** Modify: `src/webpent/llm_researcher/causal_feedback_bridge.py`

**Problem:** Bridge checks `getattr(llm_client, 'mock_provider', True)` but `mock_provider` exists only in `get_provider_metadata()` dict, not as direct attribute. Real providers are misdetected as mock.

**Fix:** Change to `llm_client.is_mock` property check.

### Task SC.2: Add mock_provider Property to BaseLLMProvider

**File:** Modify: `src/webpent/llm_researcher/providers/base.py`

**Problem:** Scripts check `getattr(provider, 'mock_provider', True)` to decide REAL_API_UNAVAILABLE vs proceed. Real providers fail this check.

**Fix:** Add `mock_provider` property as alias for `is_mock`:
```python
@property
def mock_provider(self) -> bool:
    return self.is_mock
```

### Task SC.3: Add Required Methods to LLMResearcher (interface.py)

**File:** Modify: `src/webpent/llm_researcher/interface.py`

**Problem:** Scripts call `get_policy_hash()` and `apply_hypothesis_weights()` which don't exist on the real LLMResearcher class.

**Fix:**
1. Add `_hypothesis_weights: Dict[str, float] = {}` to `__init__`
2. Add `get_policy_hash()` returning `self.system_prompt_hash`
3. Add `apply_hypothesis_weights(weights)` storing weights

### Task SC.4: Fix start_target Port Handling

**Files:** Modify: `goed_v1_8_4/blind_v3_executor.py`, `goed_v1_8_4/differential_v184.py`, `goed_v1_8_4/two_model_comparison_v184.py`

**Problem:** `differential_target_v2.py` hardcodes `PORT = 9210`. Scripts try ports 9211/9212/9213 → Connection refused.

**Fix:** `start_target()` always returns `actual_port = 9210` regardless of requested port.

### Task SC.5: Fix guarded_causal_evaluate Call Signature

**File:** Modify: `goed_v1_8_4/differential_v184.py` (run_llm_off function)

**Problem:** Script calls `guarded_causal_evaluate([b, c, ctrl])` with a list. Real function takes 3 separate args and returns `GuardedCausalResult` object.

**Fix:** Call as `guarded_causal_evaluate(b, c, ctrl)`, access `.verdict.value` and `.confidence`.

---

## Final Checklist (Task F.1)

### Task F.1: Verify All Artifacts & Compliance

**Step 1: All artifacts present**
- 14 report JSON files in `reports/goed_v1_8_4/`
- 15 phase scripts in `goed_v1_8_4/`
- 3 docs (P10 auth, decision record, freeze manifest)
- Delivery zip present

**Step 2: No improper ground_truth reads**
- Verify `blind_v3_executor.py` never opens/reads `ground_truth.json` (comments only OK)

**Step 3: Phase 18 open item documented**
- `audit_pass=false` explicitly documented in Phase 19 audit

**Step 4: No vip_qualified=true anywhere**
- Grep all docs/reports for `vip_qualified.*true`

**Step 5: Delivery zip integrity**
- No ground truth leaked
- All expected files present

---

## Execution Sequence Summary

```
0. Environment setup + API test
├─ A.1 Decision record + re-freeze manifest
├─ A.2 Phase 16 Learning (fast, 20 cases × 2)
├─ A.3 Phase 6 Contract Trace (1 case)
├─ A.4 Phase 7-8 Blind v3 Execution (120 cases, LLM)
│   └─ A.4 Phase 9 Blind v3 Scoring (no LLM)
├─ A.5 Phase 11 Differential (120 × 2 modes) ⭐ CRITICAL
├─ A.6 Phase 10 Hypothesis Evaluation
├─ A.7 Phase 12 Recovery Rule
├─ A.8 Phase 13 Generative Split
├─ A.9 Phase 15 Two Models (30 × 2 providers)
├─ A.10 Phase 18 Regression Re-run
├─ A.11 Phase 19 Final Truth Audit
├─ A.12 Build Delivery Zip
└─ B.1 Write P10 Authorization Request v2
```

**Estimated API calls:** ~500-800 (Groq primary) + ~60 (OpenRouter secondary)
**Critical path:** Phase 11 determines MEASURED_GAIN vs NO_MEASURED_GAIN
**Governance gate:** Phase 18 audit_pass=false is documented open item, not a silent failure
