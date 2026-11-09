# M1b_CONTRACTS_REPORT.md — M1b (Contracts & Models) — core acceptance record

**Phase:** M1b of the CANONICAL_PHASE_REGISTRY (Part 4 §3 — the Part-4 half of M1; M1a closed separately).
**Date:** 2026-11-05 · **Window:** DRIFT_REGISTER UM-DR-13 · **Refreeze:** `scripts/refreeze_manifest_m1b_contracts_models.py` (exactly 1 declared frozen change, self-check passed, 713 tests green post-refreeze).

## What was delivered

1. **`src/webpent/models/contracts.py`** — the reconciliation layer M1b asked for:
   - `EngagementContract` — the domain's isolation root, previously implicit across thread_ids/engagement_ids/client ids. `client_id` and `engagement_id` are both required and non-empty (`extra="forbid"`): an engagement that does not name its client cannot be CONSTRUCTED, so no caller can create an unscoped engagement and retrofit ownership later.
   - `DOMAIN_CONTRACTS` — 8 entities (Engagement, Target, Finding, Hypothesis, ProofBundle, Observation, ToolExecution, CampaignExecutionContract), each IMPORTING the authoritative class from its owning module. A moved or renamed entity breaks the import loudly; the catalog can never silently diverge from the tree.
   - `DATA_SOURCE_OF_TRUTH` — 9 data types with their one owning store + owner module (findings → sqlite; evidence_bundles → proof-bundle column; hypotheses → graph channel + sqlite; checkpoints → langgraph sqlite; decision_log; retest_ledger → JSONL; embeddings → chroma (derived, rebuildable); reports → workspace filesystem; engagement_registry → scan_registry). The catalog test imports every owner module.
   - `export_contracts()` — deterministic, JSON-serializable, schema-versioned (`webpent-domain-contracts-v1`); checked in as `docs/domain_contracts_export.json` (M1b acceptance: "schema-versioned exported contracts").
2. **State-consistency fix (`state/unified_state.py`, frozen — refrozen in this window):** five channels (`surface_metrics`, `lesson_priority_adjustments`, `consulted_lessons`, `extracted_lessons`, `detector_results`) were re-declared on UnifiedState WITHOUT their `Annotated[..., merge_lists/merge_dicts]` reducers — in unified runs concurrent writes OVERWROTE instead of merging. The duplicates are removed; the channels live once on PentestState with their reducers. Caught by the new superset test, not by review.
3. **`tests/test_m1b_domain_contracts.py`** (8 tests) — the acceptance suite:
   - export determinism + serializability + version presence + importable owners;
   - EngagementContract refuses unscoped construction and round-trips;
   - scoping fields declared for every scoped entity;
   - **isolation proven on the real sqlite store**: engagement A's thread query never returns engagement B's findings;
   - **state consistency**: UnifiedState ⊇ PentestState with reducer-for-reducer annotation equality (ForwardRef-argument comparison), plus legacy-bridge round-trip key preservation.

## Acceptance criteria status

| Criterion (registry) | Status |
|---|---|
| State consistency tests pass | ✅ superset + reducer-equality + bridge round-trip green |
| Isolation tests pass | ✅ real-store thread isolation + constructor-enforced client scoping |
| Schema-versioned exported contracts | ✅ `export_contracts()` + checked-in artifact |

## Residual scope (recorded, owned — not dropped)

- Channel-level checkpoint compatibility sweep across ALL engine families (hunter bridge covers the budget keys; a full per-channel replay matrix is the next window).
- Tenant-isolation scenario engine (`tenant_isolation/` package) wiring into the graph's qualification path — the frozen nodes belong to M3's scope contract.
- Filesystem artifact ownership tests (reports/poc artifacts under the per-target workspace root).

— End of M1b_CONTRACTS_REPORT.md —

---

## Residual closure (UM-DR-14, 2026-11-05) — M1b COMPLETE

The three residual items recorded above are now dispositioned:

1. **PentestState channel-level checkpoint compatibility sweep across engine families — DONE.** `tests/test_m1b_checkpoint_channel_matrix.py` (6 tests): every declared PentestState channel (261) plus the full UnifiedState inventory round-trips through the production `get_checkpointer()` stack (redacting SqliteSaver, loaded back from sqlite); the hunter bridge family round-trips via `hunter_state_to_unified`; the secret-redaction contract is pinned independently (`session_cookies`/`session_headers`/`identity_profiles` → `{}`, `jwt_weak_secret_candidates` → `[]`, `auth_state` secret keys emptied); every reducer channel (≥140) is swept for merge-not-overwrite with per-reducer contracts (`merge_auth_state` upsert-by-name, `merge_retries` overwrite-per-key, `replace_runtime_capability_gaps` replace, findings/hypotheses/messages both-sides survival).
2. **Per-type data-ownership enforcement tests for reports/artifacts — DONE.** `tests/test_m1b_workspace_artifact_ownership.py` (7 tests): distinct deterministic workspace per (client, engagement, origin); layout matches `DATA_SOURCE_OF_TRUTH`; storage overrides bind writes inside the owning root with cross-engagement invisibility on the real filesystem; active-workspace context resolves the decision log and checkpointer to the active workspace and refuses mid-run switching (`target_workspace_switch_blocked`); POC artifact stems cannot traverse paths.
3. **Tenant-isolation scenario engine graph wiring — OWNED BY M3** (frozen nodes; the registry's M3 scope contract covers them). Deferred with an owning phase, not silently dropped.

Gate evidence at closure: frozen authority manifest byte-verified (13 files, no refreeze needed — no production file touched); combined guard run 734 passed; test-count gate 8,255 ≥ 8,115; coverage ratchet 4.27% ≥ 4.07%. Window record: `DRIFT_REGISTER.md` UM-DR-14.

**M1b status: COMPLETE** — acceptance criteria (schema-versioned exported contracts, engagement+client scoping enforced at construction, isolation on the real store, state consistency regression-pinned) plus the recorded residuals closed or explicitly owned. The registry's M1 entry is updated to reflect both halves closed.
