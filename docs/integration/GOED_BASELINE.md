# GOED Baseline (Pre-Integration)

**Document ID:** GOED-BASELINE-1.0
**Date:** 2026-09-10
**Purpose:** Immutable reference state of WebPent-GOED BEFORE any Shannon integration. Any post-integration deviation must be attributable to a documented, tested integration change or it is a regression.

## 1. Version / Checkpoint

| Item | Value |
|---|---|
| Archive source | `webpent-canonical.zip` (uploaded) |
| Git checkpoint (initialized for this migration) | commit `835b36b6aae2185fd593fee9104ea081dd71e000`, branch `main`, tag `pristine-baseline` |
| Git remote / prior history | none existed in the archive (fresh `git init` at migration start; full pristine tree committed before any change) |
| Python | 3.12.14 |
| Package version | `webpent 0.3.0` (pyproject) |
| Declared release line | v60 Smart Hunter + v61 remediation + Knowledge Pack (README / DELIVERY_NOTES_V61) |

## 2. Tree / Counts

| Metric | Value |
|---|---|
| `.py` files under `src/webpent` | 588 files / 139,698 lines |
| Module directories under `src/webpent` | 56 |
| Test files under `tests/` | 119 `test_*.py` (+ `conftest.py` + `tests/ground_truth/`) |
| Test functions | 837 (`scripts/verify_test_count.py --minimum 498` → OK) |
| Total collected test items (incl. parametrized) | 890 (879 passed + 10 failed + 1 skipped at baseline) |
| Historical harness roots | `goed_v1_8/`, `goed_v1_8_1/`, `goed_v1_8_2/`, `goed_v1_8_3/`, `goed_v1_8_4/` + nested `WebPent-GOED-v1.8.3-RealLLM-CausalBridge.zip` (all preserved, all one-way dependencies) |
| Docs | `docs/` incl. 11 pre-existing files under `docs/integration/` |

## 3. Dependency State

| Check | Result |
|---|---|
| Lockfile | `uv.lock` present (248 packages resolved) |
| `uv lock --check` | PASS (lockfile consistent with pyproject) |
| `uv sync --locked --extra dev` | PASS (installed into project `.venv`, Python 3.12.14) |
| `python -m pip check` | PASS ("No broken requirements found") |
| `python -m compileall -q src` | PASS (exit 0) |
| Notable pins | langgraph 0.6.11, langchain-core 0.3.86, playwright >=1.48,<1.49, redis <6.0, torch >=2.2 |
| No Shannon dependency added at baseline | n/a — integration adds none without audit (see SHANNON_LICENSE_AUDIT.md / matrix) |

## 4. Test Execution Environment (used for ALL runs in this migration)

```
PYTHONPATH=src
LLM_ENABLED=false
EMBEDDINGS_OFFLINE=true
DISABLE_RAG=true
AUTH_ENABLED=false
FFUF_ENABLED=false
WEBHOOK_ENABLED=false
```

Runner: `uv run pytest` (pytest 8.x, asyncio_mode=auto, `--strict-markers --strict-config`), project `.venv`, Python 3.12.14, Linux sandbox (4.1 GB RAM, 2 CPUs).

**Sandbox memory caveat:** a single-process full-suite run (837+ tests with torch/chromadb loaded) is killed by the 4.1 GB sandbox at ~64% progress (observed twice at the same point; the suspect file passes in isolation). The canonical baseline is therefore measured with the persisted batch runner `scripts/run_test_batches.py` (8 files per fresh pytest process, 15 batches, deterministic file order). The same runner must be used for post-integration comparison. Logs: `/home/z/my-project/baseline_logs/baseline/batch_001..015.log` + `SUMMARY.txt`.

## 5. Baseline Test Results (CANONICAL)

| Metric | Value |
|---|---|
| Batches | 15 / 15 clean (0 crashes, 0 timeouts) |
| **Passed** | **879** |
| **Failed** | **10** (all pre-existing — list in §6) |
| Skipped | 1 |
| Errors | 0 |
| `verify_test_count.py --minimum 498` | PASS (837 ≥ 498) |

Release-note cross-reference: `release/release_manifest.json` historically recorded "2270 passed, 7 preserved legacy/local-lab failures" for a larger release harness; the 10 failures below are consistent with that class of legacy/local-lab/environment-dependent tests in this canonical snapshot.

## 6. Pre-Existing Baseline Failures (MUST NOT be "fixed" by weakening; recorded for regression comparison)

| # | Test | Failure evidence (baseline log) | Classification |
|---|---|---|---|
| 1 | `test_browser_readiness.py::test_capability_manifest_records_browser_executable_metadata` | `FileNotFoundError: '/home/ubuntu/upload/pasted_content.txt'` (hardcoded path from original author's machine) | Environment-dependent |
| 2 | `test_local_causal_lab_option_b_approval.py::test_option_b_import_validates_and_original_packet_stays_pending` | `ValueError: approval_boundary_failed:approval_source_missing` | Legacy local-lab approval boundary |
| 3 | `test_local_causal_lab_option_b_approval.py::test_option_b_import_rejects_changed_approval_source` | `ValueError: approval_boundary_failed:approval_source_missing` | Legacy local-lab approval boundary |
| 4 | `test_option_b_local_causal_lab_runner.py::test_option_b_runner_emits_only_redacted_blocked_records` | `ValueError: approval_boundary_failed:approval_source_missing` | Legacy local-lab approval boundary |
| 5 | `test_option_b_local_causal_lab_runner.py::test_option_b_runner_records_runtime_digest_blockers_without_sensitive_material` | `ValueError: approval_boundary_failed:approval_source_missing` | Legacy local-lab approval boundary |
| 6 | `test_p1_config_contracts.py::test_production_prefixed_aliases_are_consumed` | `ValueError: Unsupported database URL scheme: 'file:/home/z/my-project/db/custom.db'` + assertion mismatch | Environment/sandbox path interference |
| 7 | `test_v10_p0p1_rca_followup.py::TestEmbeddingsOfflineSettings::test_settings_have_embeddings_offline_field` | assertion/env interaction | Environment-dependent |
| 8 | `test_v28_structure_aware_triage.py::test_crawler_structure_aware_queue_overrides_url_only_llm_bias` | `UnboundLocalError: cannot access local variable 'llm_selected'` (pre-existing source bug on a flag-gated path) | Pre-existing source bug |
| 9 | `test_v62_ingest_and_memory_isolation.py::test_lesson_storage_and_search_require_exact_scope` | `assert [] == [{'client_id': 'eng-a', ...}]` | Legacy/local-lab |
| 10 | `test_v63_vip_security_regression.py::test_jwt_contains_required_claims_and_revocation_is_effective` | `HTTPException: 401 Could not validate credentials` | Environment-dependent (JWT fixture/env) |

Note: these 10 are the reference set. Post-integration runs must produce **exactly this failure set** (same tests, same kinds of errors) and zero additional failures. Any deviation triggers the §16 protocol stop rule.

## 7. Public Interfaces at Baseline (frozen reference)

- **CLI** (`main.py` → Typer `webpent.cli:app`): `scan`, `preflight`, `init`, `scope_add|show|remove`, `hunt`, `graph`, `findings`, `evidence`, `investigate`, `report`; console scripts `webpent`, `webpent-ingest`.
- **API** (`server.py` → uvicorn `webpent.api.app:app`, loopback default): `POST /token`, `POST /api/v1/scans` (202), `GET /api/v1/scans/{thread_id}/status`, `POST /api/v1/scans/{thread_id}/approve`, `GET .../findings`, `GET .../risk-summary`, `POST /api/v1/oob/{finding_id}` (HMAC), `GET /health`; rate-limit middleware; per-user scan authorization.
- **Worker** (`worker.py` → `webpent.workers.pentest_worker:celery_app`).
- **Verification CLIs**: `verify_all.py`, `viewer.py`, `release/verify_proof_bundle.py`, `scripts/verify_test_count.py`.
- **Makefile targets**: `build*`, `dev-*`, `ingest-knowledge*`, `doctor`, `prod-up|down`, `test-count`, `test-unit`, `coverage`, `lint`, `security`, `ci`, `test`, `clean`.

## 8. Security Invariants at Baseline (verified by reading code; re-verified at final audit)

1. `CausalGuard` (`cqa_v2/causal_guard.py::guarded_causal_evaluate`) is the sole CONFIRMED authority; fail-closed; `BLOCKED` never transitions to CONFIRMED/CLEAN.
2. LLM researcher (`llm_researcher/`) is add-only onto `WorldModel`; `FORBIDDEN_METADATA_FIELDS` strips ground-truth leakage; policy hash embeds `vip_qualified=false`, `P10=NOT_OPEN`, `P9=CLOSED`.
3. `ProofBundle` promotion requires `oracle_decision=="CONFIRMED"` AND `evidence_origin=="target_runtime"` AND `target_backed`; offline fixtures can never be promoted.
4. Replay strict rule `verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`.
5. P9 ledger state machine fail-closed; P10 evaluation strict; review mapping can never confer qualification.
6. Real-API gate: `llm_researcher/providers/factory.get_provider()` raises `REAL_API_UNAVAILABLE` without key; mock only via explicit `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION=true` + `RuntimeWarning`, and metadata labels it "NOT real API validation".
7. Rabbit-hole loop is policy-bounded (`config/policies.py::RabbitHolePolicy`, `route_after_rabbit_hole` fail-closed).
8. Ground truth confined to evaluation layer (`benchmark/`, `tests/ground_truth/`, `scripts/evaluate_ground_truth.py`); runtime executor has no access path to it.
9. Safety: `EngagementKillSwitch` monotonic; `EngagementSafetyGate` http/https only; `ActionAuthority` central gate; H9 hard-stops on weak secrets.
10. Bug-bounty execution blocked (`enable_bug_bounty_reporter=False`, bounty-submission policy flags blocked); external targets forbidden for qualification (`external_target_contacted` fails production qualification).

## 9. Configuration Contracts at Baseline

- `Settings` env-file `.env`, case-insensitive; `get_settings()` cached.
- V55 feature flags **all default False**: `enable_target_understanding`, `enable_attack_graph`, `enable_adaptive_hunt`, `enable_workflow_understanding`, `enable_planner_decisions`, `enable_authorization_matrix`, `enable_idor_enumeration`, `enable_js_intelligence`, `enable_report_quality_gate`, `enable_bug_bounty_reporter`, `enable_structure_aware_triage`.
- Bounds: `smart_max_actions`, `smart_action_budget`, `smart_auto_approve=False`, `max_js_assets`, `idor_enumeration_neighbors`.
- `RabbitHolePolicy` / `SandboxPolicy` pydantic-validated.
- Integration additions must be additive flags defaulting to the exact current behavior.

## 10. Baseline Artifact Map (protected references)

- Root audit records: `phase0_*.log`, `baseline-symbols.txt`, `code-symbols.txt`, `combined_plan_baseline.sha256`, `webpent_archive_baseline.sha256`, `doctor-offline.json`, `pip-audit-v63-*.json`, `test-count-v63*.json`, `requirements-audit-v63.txt`.
- `reports/cqa_v2/phase12_checkpoint/SHA256SUMS.txt`, `reports/goed_v1_5/{baseline,validation_baseline}/SHA256SUMS.txt`, `release/cqa_v2/SHA256SUMS`, `release/release_manifest.json`.
- `audit/` (54 provenance files), `artifacts/` (incl. `smart_hunter_review/causal_attack_graph.json`), `benchmarks/**` manifests + ground truth.

**Baseline is FROZEN as of this document. Integration work starts only after the capability matrix is complete.**
