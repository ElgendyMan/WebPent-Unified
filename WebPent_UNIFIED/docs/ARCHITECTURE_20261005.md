# WebPent Architecture (2026-10-05)

This document describes the **verified** production architecture — every chain
below was statically traced with file:line citations during the Milestone-1
call-graph audit (`TEAM_REVIEW_MILESTONE1_CALL_GRAPH_AUDIT.md`) and re-verified
by the 2026-10-05 fix-sprint (3,043-test suite + frozen hash gate).

## 1. Prime invariant: one path to authority

There is exactly one route from "candidate idea" to "authoritative finding":

```
Static HAR/JSON fixture or internal catcher
  → advisory exploration artifact
  → audited external-observation ingress (strips authority claims)
  → ModernOrchestrator (only scheduler)
    → hypothesis/candidate normalization (trusted=False, advisory_only=True)
    → ScopeLaw + ToolBoundary authorization (fail-closed)
    → WebPent executor: baseline / candidate / independent negative control
    → validated observations (append-only, principal-linked)
    → WorldModel (non-verdict evidence state)
    → CausalGuard (BLOCKED / INCONCLUSIVE / CONFIRMED differential)
    → ProofBundle (frozen + sealed, HMAC authenticity tag)
    → ReplayVerifier (re-derives the result)
    → PromotionPipeline (sole persistence/reporting authority)
  → authoritative ledger + report
```

Nothing else may persist an authoritative finding or emit an authoritative
report. Exploration components may propose, rank, deduplicate, and identify
coverage gaps — never confirm, seal, replay, promote, or report.

## 2. Component map

| Layer | Module | Responsibility |
|---|---|---|
| Entrypoints | `main.py`, `src/webpent/cli/commands.py`, `server.py`, `worker.py` | CLI (Typer), FastAPI server, Celery worker |
| Graph runtime | `src/webpent/graph/builder.py` | 45-node LangGraph; checkpointed via `graph/checkpoints.py` (SqliteSaver + secret redaction) |
| Production spine | `src/webpent/production/production_spine.py` | `resolve_production_spine()` — the authoritative orchestrator factory; config-drift registry rejects divergent entrypoint configs |
| Orchestrator | `src/webpent/production/modern_spine.py` | `ModernOrchestrator`: deep recon, research loop, bounded experiments |
| Governance | `shared/engagement_scope.py` (ScopeLaw), `llm_researcher/tool_boundary.py` | Host/method/action authorization; unknown tool or out-of-scope request → denied |
| Execution | `agents/hunter_runner.py`, `recon/login_executor.py`, `shared/http.py` | Bounded real requests; session vault; SSRF-guarded HTTP client |
| Session resilience | `recon/session_recovery.py`, `recon/auth_resilience.py`, `integration/session_recovery_bridge.py` | 3× dead-session → re-login → re-provision → M4 re-bind → resume; exhausted → `CampaignHalted` (fail-closed) |
| Evidence | `models/proof_bundle.py`, `shared/workflow_replay.py` + `cqa_v2/replay_verifier.py` | Sealed proof; deterministic replay verification |
| Validation | `cqa_v2/causal_guard.py`, `production/validators.py` | Causal differential verdicts; per-family fail-closed validators |
| Promotion | `production/autonomous_validation_v1.py` (PromotionPipeline) | Terminal promotion decision; only promotion success persists findings |
| Memory | `memory/db.py`, `memory/vectorstore.py`, `memory/lessons.py` | Findings ledger, RAG store (Chroma), per-client lessons |
| Intelligence | `integration/planner_enrichment_bridge.py`, `integration/learning_ab_contract.py`, `integration/browser_hypothesis_bridge.py` | Advisory enrichment, A/B learning verdicts, browser-surface hypotheses (all default-off) |
| Reporting | `reporter/export.py`, `reporter/bounty_report.py`, `shared/report_quality.py` | JSON/HTML reports; lifecycle stage mapping; redaction |

## 3. Entry chains (verified)

| # | Chain | Classification |
|---|---|---|
| 1 | CLI `scan` → graph → modern spine → orchestrator → … → promotion | THROUGH-SPINE |
| 2 | API `POST /api/v1/scans` → Celery → graph (same as #1) | THROUGH-SPINE |
| 3 | API `/approve` → `resume_pentest_task` → LangGraph checkpoint resume | THROUGH-SPINE |
| 4 | Celery worker console → tasks of #2/#3 | THROUGH-SPINE |
| 5 | API OOB callback → ProofBundle seal + DB confirm | REMEDIATION-TRACKED (BYP-02; documented in docs/API.md) |
| 6 | `webpent-ingest` → RAG vectorstore only | ADVISORY-ONLY |
| 7 | CLI manifest commands (init/scope/findings/report) | ADVISORY-ONLY |
| 9 | `python -m webpent.production.campaign_worker` | DISABLED in production; test-only launcher; latent-risk B-06 pinned |

Known accepted caveats (from the audit, unchanged by this sprint):
- **BYP-01** — the graph recon node constructs `ModernOrchestrator` directly
  instead of via `resolve_production_spine()`; the factory's protections are
  exercised by tests, not the wired path. documented; remediation is a
  deliberate (non-sprint) change because it alters the wired graph.
- **BYP-05** — `MODERN_SPINE_MODE=UNSUPPORTED_LEGACY_ONLY` env var can route
  recon to legacy-only mode (auditable emergency rollback hatch).

## 4. Trust chain and the frozen gate

The frozen manifest `frozen_modules.sha256` pins **695 files** byte-identical,
including the entire trust spine (ProofBundle, PromotionPipeline, CausalGuard,
ScopeLaw, ToolBoundary, M4/ContextAuthority, ReplayVerifier). Enforcement:

- Shell: `sha256sum -c frozen_modules.sha256` → 695/695 OK.
- Pytest (added 2026-10-05): `tests/test_frozen_module_gate.py` — 695
  per-file byte-identical pins + manifest-population check + a baseline-delta
  check asserting the pre-unfreeze baseline differs on exactly the five
  documented unfreeze paths.

The 5 files unfrozen on 2026-10-05 (additive, default-off parameters only):
`agents/hunter_runner.py`, `recon/hypothesis_generator.py`,
`recon/login_executor.py`, `recon/auth_detector.py`,
`recon/principal_provisioning.py`. See
`docs/UNFREEZE_FILES_20261005.md` for the per-file contract.

## 5. Fail-closed conventions

- **Secrets:** `celery_payload_key`, `jwt_secret_key`, `audit_secret_key`
  default to empty → refuse to encrypt/sign rather than use a known key.
  ProofBundle seal HMAC is fail-closed (<32-char key → no tag → not
  promotion-ready).
- **Scope:** unknown host, missing allowlist, exhausted budget → denied; no
  legacy fallback.
- **Recovery:** bounded attempts; exhaustion raises `CampaignHalted`; healthy
  responses pass through untouched (zero-FP invariant).
- **Inventory:** direct-I/O inventory artifact (`docs/direct_io_inventory.json`)
  is drift-enforced by test (`tests/test_g02_direct_io_inventory.py`); the
  20/17 unapproved raw-transport-site pin is fail-closed on the future.

## 6. Verification matrix

| Gate | Command | Current result |
|---|---|---|
| Full suite | `pytest tests/ -q` | 3043/3043 pass |
| Synthetic acceptance | sprint + chain/browser + fix files (80 tests) | 80/80 pass |
| Frozen gate | `sha256sum -c frozen_modules.sha256` | 695/695 OK |
| Frozen gate (pytest) | `pytest tests/test_frozen_module_gate.py` | 697/697 pass |
| Direct-I/O drift | `pytest tests/test_g02_direct_io_inventory.py` | 4/4 pass |
| Bandit | `bandit -r src/` | 0 HIGH (17 MEDIUM triaged, all frozen/by-design) |
| Secret scan | `python3 goed_v1_8_4/secret_scanner.py` | 0 true secrets (2 adjudicated fixture false-positives) |
| pip-audit (project closure) | `pip-audit` + closure filter | 1 residual (chromadb; fixes in breaking 2.x) |
| pip check | `pip check` | clean for project scope |
