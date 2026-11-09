# Multi-Provider LLM Setup — Changelog

## Added

- Added `KeyPool` and typed provider/model credential records.
- Added environment-over-file precedence with ignored local key-file templates.
- Added redacted provider status fingerprints and health states.
- Added cooldown and failure classification for authentication failures, rate limits, transient failures, and budget exhaustion.
- Added `TaskRouter` with task-specific prompt styles and route diagnostics.
- Added a compatibility route for the configured OpenAI-compatible provider when no other provider is available.
- Added `webpent llm keys status`, `add`, `remove`, and `test` commands.
- Added guarded execution telemetry that records actual request success/failure and numeric token usage into the process-local key pool.
- Added explicit Settings-construction isolation so tests and embedded callers cannot inherit ambient provider secrets.
- Added focused tests for precedence, redaction, rotation, cooldown, routing, local fallback visibility, and hermetic Settings behavior.

## Safety decisions

- Key values are never returned by status or diagnostics; only stable fingerprints are emitted.
- Provider fallback is disabled when `LLM_ENABLED=false`.
- A free route is not advertised unless its provider is actually configured.
- The OpenAI-compatible compatibility route is labeled as compatibility, not free.
- Target content and credentials remain outside LLM prompts according to the existing untrusted-content and M4 boundaries.
- Frozen trust-spine modules were not modified.

## Validation

- Focused suite: 59 passed.
- Full suite: 2,088 passed, 0 failed, 0 skipped.
- Acceptance: 20/20 for each of three rounds.
- Security gates: all five exit 0.
- Frozen manifest: exit 0 / MATCH.
- Live provider probe: `openai/gpt-5-mini`, usage reported.
- Live Juice Shop campaign: 6 real LLM calls, 5 promoted findings, 8 validator-refuted candidates, `$0.0238695` calculated cost.
- Additional provider failover was not claimed because no second provider key was enabled.
