# TEAM1 Provider Failover Audit

**Document ID:** TEAM1-PROVIDER-FAILOVER-AUDIT-1.0
**Date:** 2026-09-10
**Rule 14/15:** real API failure fail-closed; no mock reported as real validation; no new agent layer.

## Existing machinery (unchanged, reused — no new layer added)

| Component | Role | Fail-closed behavior |
|---|---|---|
| `llm_researcher/providers/factory.py::get_provider` | real-API gate | missing `LLM_API_KEY` → `RuntimeError("REAL_API_UNAVAILABLE")`; mock only via explicit `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true` + warning |
| `llm_researcher/providers/pool.py::ProviderPool` | slots `LLM_API_KEY`…`LLM_API_KEY_N` | round-robin + failover + health states; redacts keys to 4-char prefix |
| `shared/llm.py` | `_DEAD_PROVIDERS` circuit breaker (600s TTL), `LLM_ENABLED=false` raises | deterministic fallback; no silent switch |

## Failover chain (verified statically + offline test)

`Provider A → retry → Provider B → Provider C → SAFE_DEFER/SAFE_STOP`. All-providers-exhausted never hangs, never retries forever, never fabricates output. `test_provider_missing_key_fails_closed` (new) proves the gate raises `REAL_API_UNAVAILABLE` with no mock downgrade.

## LLM boundary (unchanged)

`LLM → hypothesis (JSON-schema bounded) → experiment proposal → tool execution (ToolBoundary whitelist) → target observation → deterministic validation (CausalGuard)`. LLM cannot: confirm findings, override verdicts, edit evidence, change thresholds, modify governance, bypass safety. `FORBIDDEN_METADATA_FIELDS` strip ground-truth metadata from observations.

## Failure-first tests added (Phase 8, all fail-closed & observable)

provider unavailable / quota / auth failure (gate), malformed LLM output (bounded schema), hallucinated tool (FORBIDDEN_TOOLS whitelist), prompt injection (`_SECRET_KEYS` reject in observation refs), target-capability missing (capability gate → BLOCKED), observation unavailable (evidence gate → pending), replay mismatch (strict 5-condition), corrupted evidence (seal verify), budget exhaustion (SAFE_STOP), kill switch (monotonic), resume after checkpoint (dedup, no duplicate work).

## Unverified (Team-2)

- Live provider failover under real quota/auth/timeout conditions (requires real keys — Team-2's scarce resource).
