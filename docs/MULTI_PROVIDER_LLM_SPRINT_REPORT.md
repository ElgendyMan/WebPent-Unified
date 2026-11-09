# Multi-Provider LLM Setup — Final Report

**Run date:** 2026-10-01  
**Project:** WebPent  
**Target used for live verification:** official OWASP Juice Shop v20.2.0 at `http://127.0.0.1:3000`

## Executive result

The secure multi-provider foundation is implemented and verified. The sandbox had **one enabled provider credential: OpenAI through the Manus OpenAI-compatible proxy**. No OpenRouter, Groq, Anthropic, Gemini, Mistral, Cohere, Cerebras, Z.ai, Cloudflare, or GitHub provider credential was present, so this run does **not** claim a multi-provider failover event or fabricate usage for unavailable providers.

The configured provider was exercised through the guarded WebPent LLM path and through a real Juice Shop hunting campaign. The campaign completed with five promoted findings and eight validator-refuted candidates. The trust/promotion path was not bypassed.

**Feature verdict:** PASS for the enabled single-provider configuration; **multi-provider failover demonstration: NOT DEMONSTRATED** because additional authorized provider keys were unavailable.

## Implementation delivered

- `src/webpent/llm_researcher/key_pool.py`
  - Environment-over-file precedence.
  - Provider/model credential records with fingerprint-only status output.
  - Rotation, bounded cooldown, 401/403 authentication failure classification, 429 rate-limit classification, and success/failure usage accounting.
  - No secret values in status, diagnostics, or error metadata.
- `src/webpent/llm_researcher/task_router.py`
  - Task-based routing for recon, extraction, hypothesis, payload selection, analysis, code, and repair tasks.
  - Preferred/fallback route structure.
  - Explicit OpenAI-compatible compatibility fallback when that is the only configured provider.
  - Free-provider routes are only advertised when their credentials are actually configured.
- `src/webpent/shared/llm.py`
  - Key-pool fallback for application settings.
  - Guarded execution updates the process-local pool with real request success/failure and token telemetry.
  - Explicitly constructed `Settings(...)` objects remain hermetic and cannot inherit ambient provider secrets.
  - Existing redaction, usage accounting, fallback, and circuit-breaker behavior remains intact.
- `src/webpent/cli/commands.py`
  - `webpent llm keys status --json`
  - `webpent llm keys add <provider> <key> [--model ...]`
  - `webpent llm keys remove <provider> [--model ...]`
  - `webpent llm keys test`
- `.llm_keys.example.json`, `.env.llm.example`, and `.gitignore` entries for local-only key material.
- Numeric token telemetry is retained in campaign evidence; credentials, bearer tokens, raw target content, and sensitive response fields remain redacted.
- Direct-I/O inventory was regenerated from the canonical scanner after the CLI changes.

## Provider verification

The redacted status artifact reported:

- Configured providers: `openai`
- Model: `gpt-5-mini`
- Status: `AVAILABLE`
- Fingerprint only: `key_403540bf1f5c`
- No key material was emitted.

The live CLI probe returned `status=ok`, `response_received=true`, provider `openai`, model `gpt-5-mini`, 11 input tokens, 10 output tokens, and 21 total tokens. The provider usage layer intentionally reports its catalog price as `unpriced`; campaign cost accounting used the independently captured live catalog rates.

## Live Juice Shop campaign

**Canonical source-matched run:** `recall-gap-llm-20261001t135458z`

| Metric | Observed value |
|---|---:|
| Crawled routes | 33 |
| Crawl events | 50 |
| Generated hypotheses | 39 |
| Executable hypotheses | 39 |
| LLM calls | 6 |
| LLM model | `gpt-5-mini` |
| Input tokens | 1,374 |
| Output tokens | 11,763 |
| Total tokens | 18,257 |
| Actual calculated cost | `$0.0238695` |
| Call budget | 100 |
| Dollar budget | `$5.00` |
| Campaign duration | 158.553 seconds |
| Total wall time | 163.331 seconds |
| Promoted findings | 5 |
| Validator-refuted candidates | 8 |
| Rejected decisions | 25 |
| M4 principals | `owner`, `foreign` |
| Owner login | HTTP 200 |
| Foreign login | HTTP 200 |
| Disposable user creation | HTTP 201 |

The six live calls were all provider-backed `openai/gpt-5-mini` calls. Payload prompts were structural/redacted and limited to routes, parameters, statuses, and payload-library IDs. The campaign evidence states that credentials were attached by M4 only and were never placed in LLM prompts.

The campaign result was produced through the existing `ModernOrchestrator/ScopeLaw/AVI/PromotionPipeline` authority path. No deterministic result was relabeled as LLM output, and no unavailable provider was represented as used.

## Cost accounting

The captured model catalog recorded:

- Input: `$0.25 / 1M tokens`
- Output: `$2.00 / 1M tokens`

The campaign cost is calculated as:

```text
(1,374 × 0.25 / 1,000,000) + (11,763 × 2.00 / 1,000,000)
= $0.0238695
```

The run consumed 6% of the 100-call cap and approximately 0.48% of the `$5.00` budget. The raw provider usage records may still show `pricing_status=unpriced`; that is expected and is why the report uses the separately captured live catalog rates.

## Security and regression validation

- Focused multi-provider, LLM, untrusted-content, recall-gap, and routing tests: **59 passed, 0 failed**.
- Full suite: **2,088 passed, 0 failed, 0 skipped**; 10 warnings only; new failures versus baseline: 0.
- Acceptance round 1: **20/20 passed**.
- Acceptance round 2: **20/20 passed**.
- Acceptance round 3: **20/20 passed**.
- Reproducibility: **YES**.
- Security gates:
  - `check_state_contract`: exit 0
  - `check_orchestrator_construction_authority`: exit 0
  - `check_isolation_denylist`: exit 0
  - `check_vault_import_authority`: exit 0
  - `verify_test_count`: exit 0
- Frozen manifest: **MATCH**, exit 0.
- Direct-I/O inventory: canonical regeneration and drift tests passed; current artifact contains 593 records and the pinned 20 unapproved records.
- Credential-shaped scan of final campaign evidence: **PASS**.

Warnings are existing dependency/development warnings and are recorded in the full-suite evidence; they are not test failures.

## Honest limitations and next step

This sprint provides the provider abstraction, routing, credential isolation, redacted diagnostics, CLI controls, real provider execution, and safe fallback behavior. It does **not** prove cross-provider failover because only one provider key was available in this environment. To demonstrate failover, add at least one additional authorized provider key through the local ignored configuration or environment, run `webpent llm keys test`, then execute a bounded failure-injection test that records provider A failure and provider B success without persisting either secret.

No API keys, vault values, bearer tokens, raw Juice Shop bodies, or raw response headers are included in the evidence bundle or release archive.
