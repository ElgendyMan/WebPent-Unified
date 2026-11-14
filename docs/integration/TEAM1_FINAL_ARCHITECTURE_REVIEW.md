# Team 1 Final Architecture Review

**Document ID:** TEAM1-FINAL-ARCH-REVIEW-1.0
**Date:** 2026-09-10
**Rule:** additive-only hardening; no graph-builder rewrite (protocol §15); `FILES_DELETED = 0`.

## A. What was integrated (additive contracts, fully tested offline)
- `src/webpent/integration/` (8 modules): `auth_session_contract`, `exploitation_queue`, `priority_policy`, `reconciliation`, `research_agenda`, `source_mapping`, `surface_dossier`, package init.
- `src/webpent/research_engine/agenda_bridge.py` (`AgendaBridge`, `BridgePlanResult`, `BridgePlannedTask`, `signal_from_auth_verdict`, `signal_from_reconciliation_task`).
- `src/webpent/attack_graph/source_lane.py` (`attach_source_lane`, `source_lane_summary`).
- Tests: `tests/test_integration_*.py` (8 files, 85 tests, all passing).
- Docs: `docs/integration/` capability matrix, integration final, license audit, baseline summaries, protected inventory.

## B. What remains optional (flag-gated, default OFF)
- `Settings.enable_integration_agenda` (default `False`): when OFF, historical execution unchanged; when ON, additive bridge behavior is available.
- `AgendaBridge` and `source_lane` are exported from their packages but have **no live caller** in graph/workers/cli/agents/api. Classification: `OPTIONAL-LIVE` / `PARTIALLY_WIRED` (see `team1_wiring_audit.md`).

## C. What remains historical (immutable, intact)
- `goed_v1_8/`, `goed_v1_8_1/` … `goed_v1_8_4/` (one-way dependency: they import FROM webpent; nothing in src imports them).
- `benchmarks/`, `reports/`, `audit/`, `artifacts/`, `release/`, root baseline manifests (`*.sha256`, `*.log`, `pip-audit-*`, `test-count-*`).
- `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip`, `DELIVERY_NOTES_V55..V61.md`, `FINAL_REVIEW_REPORT.md`, `REVIEW_REPORT_2026-08-15.md`.
- All verified present; `FILES_DELETED = 0` (every canonical file exists in this tree; 39 files added, 0 removed).

## D. What remains R&D (proposal-only, not wired)
- LLM-driven staged SAST pipeline (Shannon Capella pattern): realized only as `AGENDA_SOURCE_TASK` advisory signals + `source_mapping` deterministic join. Real LLM SAST execution requires provider keys → `PENDING_TEAM2`.
- SARIF / Typst report renderers: explicitly REJECTED (redundant, AGPL); not implemented.

## E. What remains Team-2-only (real runtime / real network)
- Real-API provider exercise (openai_compatible/mistral/gemini/cohere/anthropic/cloudflare pool).
- Browser/Playwright-driven auth validation and exploitation paths.
- Live authorized-target campaigns, P9/P10 qualification runs, workflow replay against real targets.
- Docker stack (`make dev-up`) and the 7 `verify_all.py` Dockerfile/tool-registry checks that are environment-specific.

## F. What remains unverified (and why)
- Live execution-path wiring of the integration layer: no live caller exists by design (no graph-builder rewrite permitted). Unverifiable until Team-2 (or an approved additive change) connects it.
- Real provider failover under quota/auth failure in a live network: statically confirmed fail-closed gate exists; live behavior requires Team-2.
- The 6 environment-dependent baseline test failures: not reproduced here (sandbox differences); require Team-2's canonical environment to confirm.

## G. Why those items remain unverified
Protocol §15 forbids forcing modules into the graph to claim wiring; §23 forbids consuming scarce free API keys during hardening; §27 forbids live target campaigns by Team 1. These are intentional stop boundaries, not gaps.
