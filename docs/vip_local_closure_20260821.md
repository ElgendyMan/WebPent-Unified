# WebPent VIP — Local Closure Record

**Date:** 2026-08-21  
**Scope:** Local, offline-safe implementation and verification only.  
**Target policy:** WAPTLab and Juice Shop were not started, contacted, modified, or used during this closure pass.

## Result

The local VIP closure pass completed without changing the confirmation policy. The project still requires a causal signal, a negative control, and a valid ProofBundle before any finding can be treated as confirmed. LLM telemetry is diagnostic only and cannot create, promote, or confirm findings.

## Implemented in this pass

| Area | Local result | Evidence |
| --- | --- | --- |
| Per-provider usage capture | Added a bounded, scope-aware trace around guarded synchronous and asynchronous provider invocations. | `src/webpent/shared/llm.py` and deterministic contract tests in `tests/test_llm_provider_compatibility.py` |
| Per-node attribution | Uses explicit LangChain metadata when supplied and a bounded legacy call-site label otherwise. Prompt text and exception bodies are never copied into telemetry. | `llm_usage_trace` records and tests |
| Cost semantics | Token fields are recorded when the provider exposes them. Unknown prices remain `unpriced` and `estimated_cost_usd` remains `null`; no cost is guessed. | `llm_usage_trace` schema |
| State compatibility | Added `llm_usage_trace` as an additive list reducer with an empty initial value. Older checkpoints may omit it. | `state.py`, `initial_state.py` |
| Report visibility | Actual usage is exported as a separate redacted field in the canonical report data and campaign ledger. Existing `llm_budget_trace` remains unchanged. | `reporter/agent.py`, `reporter/export.py` |
| Worker/CLI isolation | CLI and worker executions collect usage in a per-execution context, preventing process-global mixing between concurrent engagements. | `cli/__init__.py`, `workers/pentest_worker.py` |
| Prompt-injection boundary | Existing adversarial tests remain active; telemetry does not trust prompt-controlled node labels unless explicitly supplied through runtime metadata. | `tests/test_llm_provider_compatibility.py` |

## Verification evidence

The final local gate after the implementation pass was:

| Gate | Result |
| --- | ---: |
| Pytest | **1167 passed** |
| Ruff (`src/`, `scripts/`, `tests/`) | **0 errors** |
| Direct-I/O inventory (G-02) | **64 records generated successfully** |
| Python compilation of modified modules | **passed** |
| Live WAPTLab/ Juice Shop qualification | **not run by policy** |

The test suite emitted dependency/runtime warnings from existing third-party packages. Those warnings did not fail the gate and were not converted into false security claims.

## Deferred items

**VIP item 3.1–3.3, WAPTLab qualification, remains deferred.** It needs an explicitly permitted live lab run. No live finding count or qualification claim is made here.

**VIP item 4.3, Celery/Redis multi-worker qualification, remains deferred.** It needs a live broker/worker environment and concurrency verification. The local worker code remains fail-closed and bounded, but this document does not claim distributed-runtime qualification.

**External release signing remains operator-controlled.** The generated manifest can carry SHA-256 integrity hashes, but no private signing key was used or claimed in the sandbox.

## Confirmation boundary

A candidate, heuristic, static match, LLM suggestion, or usage record is not a confirmation. Confirmation remains blocked unless the evidence pipeline produces the required causal signal, negative control, and ProofBundle under the existing authorization and scope rules.
