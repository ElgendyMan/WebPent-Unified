# GOED v1.7 — Regression Audit (Phase 1)
**Date:** 2026-09-04T09:48:22.137410+00:00

## File Inventory
- Python source files under `src/`: **572**

## Compilation
- `compileall.compile_dir("src/")`: **PASS**
- `hidden_generator.py` syntax: **FIXED**

## Import Smoke Test

### Scope
**CORE MODULES TESTED:** `webpent.goed_v1`, `webpent.cqa_v2`, `webpent.models`, `webpent.smart`

**OPTIONAL LAYERS EXCLUDED** (lazy import pattern):
`agents`, `api`, `cli`, `graph`, `shared`, `state`, `workers`
(require: langchain_core, langgraph, bcrypt, celery)

### Results
- Core modules tested: 47
- Core successes: **47**
- Core failures: **0**
- Status: **PASS**

## Key Exports Verified
- `goed_v1`: StatefulExecutor, IntegratedEvaluator, 7 invariant strategies, 3 governance dicts
- `cqa_v2`: guarded_causal_evaluate, Verdict, build_complete_proof_bundle, verify_replay
- `models`: ProofBundle, validate_proof_bundle
- `smart`: SmartMemory, SmartStrategyEngine, SmartPrioritizer, SmartReporter, VIPSmartHunter

## Fixes Applied
1. Fixed `hidden_generator.py` raw string syntax error
2. Converted 7 optional layer `__init__.py` files to lazy import pattern
3. Scoped import smoke test to CORE modules only

## Overall Status: **PASS**
