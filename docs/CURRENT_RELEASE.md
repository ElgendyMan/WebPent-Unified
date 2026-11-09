# WebPent Current Release Identity

## Canonical identity

This document is the source of truth for the current WebPent release candidate. Historical v55, v60, v61, v63, v70, and v72 reports remain preserved as historical evidence and do not redefine the current release identity.

| Field | Value |
|---|---|
| Package version | `0.34.0` (SSOT: pyproject.toml / CHANGELOG.md — 0.34.0 = unified-merge tree + the M1-A/M1-B/M1-C/M1-D recovery windows of 2026-11-05, documented as DRIFT_REGISTER UM-DR-10/11/12 without a version bump; superseded the stale `0.33.0` row during M1-D per the CHANGELOG/CURRENT_RELEASE sync discipline) |
| Tested Python runtime | `3.12.x` (CI installs 3.12; local qualification captured 3.12.3/3.12.14/3.12.16) |
| Declared Python compatibility | `>=3.12,<3.13` (per pyproject.toml) |
| Resolved LangGraph | `1.2.11` in `uv.lock` |
| Resolved LangGraph checkpoint SQLite | `3.1.1` in `uv.lock` |
| Implementation source revision | unified tree (post-UNIFIED-MERGE, post-M1 recovery windows; git history initialized post-hoc — see the provenance note below) |
| Frozen manifest | `frozen_modules.sha256` — 659/659 verified after the UM-DR-12 refreeze (2026-11-05); gate + M1 guard suites 776 passed |
| Test floor | 8,115 (`scripts/test_count_floor.json`); 8,223 collected, 0 collection errors in the declared pip environment |
| Qualification state | `NOT QUALIFIED` for VIP status |

## What is validated offline

The release candidate is validated through deterministic unit and regression tests, static checks, secret scans, direct-I/O inventory checks, G-02 checks, provider fixture checks, signed-package checks, and the WebPent/bbscout integration contracts. In a clean checkout environment, the complete regression passed **1,622 tests**, skipped 6 optional external-source tests, and emitted 56 warnings. Those optional tests are skipped because the reviewed bbscout source is not vendored in this checkout. Docker Compose dev smoke also passed locally: API health, Redis, Celery worker, Python 3.12.3, Playwright 1.48.0, Nuclei 3.9.0, and Chromium headless. These are offline/runtime checks; live target qualification remains blocked. No optional skip is treated as a live qualification pass. LLM use remains advisory and cannot authorize target actions, promote evidence, or disclose findings automatically.

The final clean regression for implementation revision `e3d4717` completed with **1,622 passed**, 6 skipped optional external-source tests, and 56 warnings. These are offline/source regression results; they do not prove live target contact, complete distributed readiness, or qualification. The local Docker smoke is recorded separately in `docs/PASTED_CONTENT_3_EXECUTION_STATUS.md`. The lock file records resolved dependency versions for reproducibility. This release line intentionally declares Python `==3.12.3` and validates against that interpreter; changing the compatibility range requires a separate compatibility policy and migration test set.

## LLM cost and fallback boundary

Managed graph runs enforce a deterministic per-run provider-attempt cap through `LLM_MAX_CALLS_PER_RUN` (default `32`); fallback attempts count toward the same cap and are blocked before another provider request after exhaustion. Reported token usage is tracked without pricing assumptions, and `LLM_WARNING_TOKENS_PER_RUN` (default `100000`) emits one redaction-safe advisory warning. The runtime summary is appended to `llm_budget_trace` and contains counters only, never API keys, prompts, responses, or authorization.

The router continues to use deterministic fallback behavior when LLM use is disabled, unavailable, or budget-exhausted. Direct library calls made outside the managed `llm_usage_scope` remain backward-compatible and are intentionally not budget-enforced; production workers and the CLI open the managed scope around graph execution.

## Qualification boundary

No provider or target live I/O was performed in the current bbscout/WebPent integration validation. WAPTLab and Juice Shop qualification are therefore fail-closed and remain pending. The repository retains a redacted historical live-smoke artifact, and the release manifest labels it `historical_live_artifact`; its `target_contacted=true` value must not be interpreted as contact made during the current validation. The offline proof/replay simulation observed three reproducible fixture runs with replay agreement, but `live_qualification_proven=false` for that simulation. VIP qualification requires three independent authorized local WAPTLab runs, each meeting all of the following: at least 15 confirmed findings out of 20, precision of at least 90%, reproducibility of at least 95%, complete proof coverage, zero scope violations, and zero duplicates. A cumulative result or fixture-only result cannot satisfy that gate.

## Release identity procedure

The release process records the implementation source revision (`e3d4717`) in this document and regenerates the manifest from that source tree in a final metadata-only commit. The manifest identifies the source tree and its parent revision; the delivery report records the metadata commit separately. Self-referential hashes are not claimed.

## Operator safety

Required secrets are intentionally blank in `.env.example`. Operators must inject secrets at runtime through their deployment secret store. Placeholder strings must not be promoted to staging or production. The production profile continues to require authentication, strong signing/audit/payload secrets, explicit non-wildcard CORS, secure Redis transport where applicable, and trusted-proxy configuration.

**Status:** production-hardened release candidate for offline validation; conditionally usable only for controlled single-node authorized operation. It is not production-qualified for horizontal/multi-tenant deployment and is not a VIP Smart Autonomous Bug Hunter until the independent authorized target-backed qualification gate passes. See [`docs/PASTED_CONTENT_3_EXECUTION_STATUS.md`](PASTED_CONTENT_3_EXECUTION_STATUS.md) for the completed phase matrix.
