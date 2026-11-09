# Team 1 Wiring Audit

**Document ID:** TEAM1-WIRING-AUDIT-1.0
**Date:** 2026-09-10
**Method:** For every newly integrated component, the full chain `SOURCE → IMPORT → LIVE CALLER → EXECUTION → OUTPUT → DOWNSTREAM EFFECT → TEST` was proven by static import analysis (`grep` across `src/webpent/{graph,workers,cli,agents,api}`) plus the live test run. Where the chain cannot be fully proven, classification is `PARTIALLY_WIRED` per protocol §3 — no full-integration claim is made.

## 1. New components (Team-1 integration surface)

| Component | File | Lines |
|---|---|---|
| `auth_session_contract` | `src/webpent/integration/auth_session_contract.py` | 175 |
| `exploitation_queue` | `src/webpent/integration/exploitation_queue.py` | 261 |
| `priority_policy` | `src/webpent/integration/priority_policy.py` | 222 |
| `reconciliation` | `src/webpent/integration/reconciliation.py` | 265 |
| `research_agenda` | `src/webpent/integration/research_agenda.py` | 625 |
| `source_mapping` | `src/webpent/integration/source_mapping.py` | 190 |
| `surface_dossier` | `src/webpent/integration/surface_dossier.py` | 272 |
| `integration/__init__` | `src/webpent/integration/__init__.py` | 127 |
| `AgendaBridge` | `src/webpent/research_engine/agenda_bridge.py` | 324 |
| `source_lane` | `src/webpent/attack_graph/source_lane.py` | 179 |

## 2. Chain proof per component

### 2.1 `webpent.integration.*` (8 modules)
- **SOURCE:** present, `py_compile` OK.
- **IMPORT:** `agenda_bridge.py` imports `auth_session_contract`, `exploitation_queue`, `priority_policy`, `reconciliation`, `research_agenda`; `source_lane.py` imports `source_mapping.JoinedMapping`. Package `__all__` contract exact-match tested.
- **LIVE CALLER:** `AgendaBridge` is the only in-tree caller. **No** live caller in `graph/`, `workers/`, `cli/`, `agents/`, `api/` (grep for `AgendaBridge(`, `attach_source_lane(`, `enable_integration_agenda` in those trees → empty).
- **EXECUTION / OUTPUT:** exercised only by `tests/test_integration_*.py` (85 tests, all pass): reconciliation→agenda→ResearchState admission, GOED budget gate (`max_requests`, `stop_reason`), scope-mismatch fail-closed, plan determinism + audit records, auth verdict→agenda signal strength (1.0 / 0.2), exploitation full cycle (RUN→consume→re-gate SKIP), source-lane additive/idempotent/unmatched-unchanged + summary.
- **DOWNSTREAM EFFECT in live graph:** none — gated behind `enable_integration_agenda` (default `False`).
- **Classification:** `PARTIALLY_WIRED` / `OPTIONAL-LIVE`.

### 2.2 `AgendaBridge` (`research_engine/agenda_bridge.py`)
- Lazy-exported from `research_engine/__init__.py` (additive `__all__` entries). No live graph-node caller. `OPTIONAL-LIVE`.

### 2.3 `source_lane` (`attack_graph/source_lane.py`)
- Re-exported from `attack_graph/__init__.py` (additive). `attach_source_lane` is additive/idempotent/unmatched-unchanged (tested). No live caller in graph builder. `OPTIONAL-LIVE`. Source annotations are advisory only — never become proven graph edges.

## 3. Activation flag

`Settings.enable_integration_agenda: bool = Field(default=False, ...)` — additive field only. `OFF` preserves historical execution unchanged (no live caller exists, so the flag is currently a no-op guard for future wiring). `ON` makes the additive behavior importable/usable by future callers. Provider-unavailable path: safe degradation via existing `REAL_API_UNAVAILABLE` gate.

## 4. What is NOT wired (deliberate, per protocol §15 — no graph-builder rewrite)
- No research module was forced into the LangGraph topology.
- No new graph node, worker task, CLI command, or API endpoint was added.
- LLM-driven SAST pipeline (Capella pattern) remains **proposal-only** (`AGENDA_SOURCE_TASK` signals); real runs require provider keys → `PENDING_TEAM2`.

## 5. Verdict
- Fully proven chain (in isolation): integration modules ↔ AgendaBridge ↔ source_lane, with deterministic outputs and 85 passing tests.
- Live execution-path wiring: **not present** and not claimed. Components are `OPTIONAL-LIVE`, ready for Team-2 to exercise and, if approved, connect additively.
- `HYPOTHESIZED != OBSERVED != PROVEN` preserved: all integration outputs are advisory signals/tasks; CausalGuard remains the sole verdict authority (untouched, FORBIDDEN).
