# TEAM1 FINAL STATUS — Research-Entity Runtime Integration Milestone

**Document ID:** TEAM1-FINAL-STATUS-RESEARCH-ENTITY-1.0
**Date:** 2026-09-10
**STATUS:** `READY_FOR_TEAM2_VALIDATION` (real-API + live-target validation remains Team-2).
**Explicit:** `FILES_DELETED = 0`. No human authorization for deletion requested or granted.

## 1. Baseline
Captured in `docs/integration/TEAM1_BASELINE_MANIFEST.json` (machine-readable): test counts 971P/4F (4 = strict subset of pristine baseline 10), governance values, sha256-16 of 19 canonical-core files + 10 integration-layer files, exact known-failure IDs.

## 2. Final tests
Full regression: see `docs/integration/TEAM1_REGRESSION_REPORT.json` (machine-readable). New tests: `tests/test_team1_research_entity.py` (13 tests: A/B agenda proof, rabbit-hole trace, target-adapter isolation, provider fail-closed, budget SAFE_STOP, resume dedup, scope-mismatch fail-closed, prompt-injection reject, kill-switch monotonic, single-entity lineage). All new tests pass. **NEW_FAILURES = 0** (pre-existing 4 failures unchanged; no unexplained new failure).

## 3. New integration capabilities
Additive agenda hook: `EvidenceAwareAgentLoop.evaluate(agenda_bridge=...)` merges `AgendaBridge`-planned tasks into the SAME canonical `ResearchState` via GOED's own `admit_task` (scope/dedup/budget gates preserved) and deterministically re-orders by priority → real downstream effect on experiment selection. Gated: default `None` → historical behavior byte-identical. New `TargetAdapter`/`RuntimeProfile` (additive, nothing imports by default).

## 4. Verified wiring
Canonical single entity: one graph, one state, one WorldModel, one finding ledger, one evidence chain, one prioritization authority, one safety authority, one verdict authority (CausalGuard). Agenda bridge now OPTIONAL-LIVE with proven downstream effect (A/B test: agenda ON changes selected experiment; OFF preserves historical selection). Cannot bypass scope/budget/evidence/central-proof gates (proven by tests).

## 5. Optional wiring
`source_lane` remains exported but no live graph caller (deliberate, no graph-builder rewrite). `smart/*` opt-in via `--enable-smart`. Agenda hook active only when caller explicitly passes a bridge.

## 6. Historical / R&D components
`goed_v1_8*`, `benchmarks/`, `reports/`, `audit/`, `artifacts/`, `release/` all intact. LLM SAST pipeline remains proposal-only (PENDING_TEAM2). SARIF/Typst REJECTED.

## 7. Security invariants
All INTACT & unmodified: CausalGuard sole verdict authority; ProofBundle seal/promotion/replay; ActionAuthority; safety gates; P9=CLOSED/P10=CLOSED; ground-truth isolation (no src file references ground-truth filenames); secret redaction; SSRF; provider fail-closed `REAL_API_UNAVAILABLE`; governance flags unchanged.

## 8. Shannon-derived capabilities
Zero-copy (AGPL). All ADAPT re-implementations. No Shannon identifier in new source. `SHANNON_LICENSE_AUDIT.md` reference intact.

## 9. Files created
`src/webpent/integration/target_adapter.py`, `tests/test_team1_research_entity.py`, `docs/integration/{TEAM1_BASELINE_MANIFEST.json, TEAM1_WIRING_GRAPH.json, TEAM1_RESEARCH_ENTITY_ARCHITECTURE.md, TEAM1_RABBITHOLE_PROOF.md, TEAM1_TARGET_AGNOSTIC_AUDIT.md, TEAM1_PROVIDER_FAILOVER_AUDIT.md, TEAM1_FINAL_STATUS.md, TEAM1_REGRESSION_REPORT.json, TEAM1_CHANGED_FILES.txt, TEAM1_SHA256_MANIFEST.txt}` + updated `TEAM2_HANDOFF.md`.

## 10. Files modified
**Exactly 1 canonical-core file, additively:** `src/webpent/research_engine/evidence_aware_loop.py` (+ optional `agenda_bridge` param, default `None`, lazy import). No semantic change to any existing path. CausalGuard/ProofBundle/replay/governance/graph-builder/thresholds: **0 modifications**.

## 11. Files deleted
**`FILES_DELETED = 0`.**

## 12. Dependencies changed
**None.** `pyproject.toml` / `uv.lock` unmodified.

## 13. Remaining limitations
Real-API provider failover under live quota/auth/timeout; live-target single-entity trace with `agenda_bridge` enabled; browser/Playwright paths; 6 environment-dependent baseline failures in canonical Docker env; `source_lane` live caller.

## 14. Team-2 requirements
Python 3.12.x, `uv sync --locked`, `LLM_API_KEY`…`LLM_API_KEY_N`, authorized local target only, Playwright stack, exact commands and expected evidence in `docs/integration/TEAM2_HANDOFF.md`. No secrets in any handoff document.

## 15. Governance
`vip_qualified=false` · `qualification_state=CONDITIONAL` · `P10=CLOSED` · `P9=CLOSED` · external targets forbidden · bug bounty blocked. Team 1 stops here. No live campaigns, no P10 opening, no destructive testing, zero real API keys consumed.
