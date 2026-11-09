# Team 2 Handoff — Real-API / Real-Runtime Validation

**Document ID:** TEAM2-HANDOFF-1.0
**Date:** 2026-09-10
**From:** Team 1 (offline integration, deterministic validation)
**To:** Team 2 (real API / network validation)
**Project state at handoff:** `READY_FOR_TEAM2_VALIDATION` — all Team 1 work complete; final regression, security-invariant audit, deletion audit, and provenance audit PASS.

---

## 1. Project identity

| Item | Value |
|---|---|
| Pristine GOED checkpoint (recoverable original) | git tag `pristine-baseline` = `835b36b6aae2185fd593fee9104ea081dd71e000` |
| Final Team 1 commit | see `git log -1` in the archive (`WebPent-GOED-Shannon-Integrated-FINAL.zip` ships the full git history incl. the pristine tag) |
| Final archive | `WebPent-GOED-Shannon-Integrated-FINAL.zip` + `WebPent-GOED-Shannon-Integrated-FINAL.zip.sha256` |
| Python | 3.12.x (tested on 3.12.14) |
| Test totals at handoff | 948 passed / 10 pre-existing failures / 1 skipped (identical failure set to pristine baseline — see `docs/integration/test_reports/`) |

## 2. Environment variables required by Team 2 (NO secrets in this document)

GOED strict real-API gate (`llm_researcher/providers/factory.py` — unchanged):

| Variable | Purpose | Notes |
|---|---|---|
| `LLM_API_KEY` | Primary real provider key (openai_compatible) | **Team 2 sets this in the runtime env only.** Its presence flips the provider gate from `REAL_API_UNAVAILABLE` to real calls |
| `LLM_API_KEY_2` … `LLM_API_KEY_N` | Optional additional slots for `ProviderPool` failover | Optional |
| `LLM_BASE_URL` | openai_compatible endpoint base URL | Optional; provider default if unset |
| `LLM_MODEL` | Model id for the provider | Optional; provider default if unset |
| `ALLOW_MOCK_FOR_ENGINEERING_VERIFICATION` | Explicit mock opt-in | **Leave UNSET for real validation.** If set, mock runs are labelled "NOT real API validation" by `get_provider_metadata()` |

Standard GOED runtime secrets (already enforced fail-closed by `config/settings.py` — unchanged): `CELERY_PAYLOAD_KEY`, `JWT_SECRET_KEY` (≥32 chars), Redis URL/TLS, OOB callback HMAC secret. Never commit these; supply at deploy time.

Offline switches used by Team 1's deterministic runs (Team 2 must UNSET/flip the relevant ones for real runs): `LLM_ENABLED`, `EMBEDDINGS_OFFLINE`, `DISABLE_RAG`, `AUTH_ENABLED`, `FFUF_ENABLED`, `WEBHOOK_ENABLED`.

## 3. Exact commands for Team 2

Run from the project root of the extracted FINAL archive.

```bash
# 0) Reproducible environment (locked deps; Python 3.12)
uv sync --locked --extra dev
uv lock --check

# 1) Re-verify Team 1 baseline state offline (must reproduce 948P/10F/1S
#    with the batch runner — the single-process full suite OOMs a 4GB box;
#    the batch runner is canonical):
export PYTHONPATH=src LLM_ENABLED=false EMBEDDINGS_OFFLINE=true DISABLE_RAG=true \
       AUTH_ENABLED=false FFUF_ENABLED=false WEBHOOK_ENABLED=false
python3 scripts/run_test_batches.py team2_offline_check 8   # script ships under /scripts of the migration workspace; equivalent one-liner below
#   (equivalent: for each 8-file chunk of `tests/test_*.py`: uv run pytest -q --tb=line -rf <chunk>)

# 2) Real-API provider gate validation (Team 2 env with LLM_API_KEY set):
uv run python - <<'PY'
from webpent.llm_researcher.providers.factory import get_provider
p = get_provider()
print("provider:", p.name if hasattr(p, "name") else p)
PY

# 3) Real-API research loop smoke (authorized local target ONLY — e.g. the
#    bundled tests/ground_truth lab app or your own authorized fixture):
#    - start the ground-truth lab target (never an external target):
docker compose -f docker-compose.test.yml up ground-truth -d
#    - run the v1.8.4 harness family (historical, one-way dep) or drive
#      CausalFeedbackBridge directly with deterministic_eval_fn wired to
#      CausalGuard.guarded_causal_evaluate.

# 4) Researcher-brain wiring recipe (optional graph-node integration,
#    feature-flagged, default OFF):
#    from webpent.integration import ResearchAgenda, AgendaSignal
#    agenda = ResearchAgenda()                      # bounded, deterministic
#    agenda.ingest_signal(AgendaSignal(...))        # signals from recon/validators
#    # feed agenda.ordered_active()[0] into existing hypothesis probing flow;
#    # every experiment still goes through ActionAuthority → sandbox →
#    # CausalGuard → ProofBundle → replay (NO new authority introduced).

# 5) After every real-runtime step: full regression must remain
#    failure-set-identical to docs/integration/test_reports/BASELINE_SUMMARY.txt
```

**Rule reminder:** real validation ONLY against targets you own or have written authorization to test (GOED scope/safety gates enforce this and Team 2 must not bypass them).

## 4. Expected real-runtime artifacts (Team 2 produces these)

| Artifact | Source | Where it lands |
|---|---|---|
| Real provider session metadata (provider, model, redacted key prefix) | `llm_researcher/providers/pool.get_provider_metadata()` | research session export |
| LLM-generated hypotheses (bounded JSON) | `llm_researcher/interface.py` | world-model observation store |
| `guarded_causal_evaluate` verdicts on real observations | `cqa_v2/causal_guard.py` | CQA v2 pipeline outputs |
| Sealed `ProofBundle`s with `evidence_origin="target_runtime"` | `models/proof_bundle.py` + `build_proof_bundle` | proof bundle store |
| Replay verification results (`verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`) | `cqa_v2/replay_verifier.py` | proof bundle coverage report |
| Agenda audit trail over real signals | `integration/research_agenda.audit_trail()` | engagement artifacts |
| Exploitation queue gate decisions + attempted/blocked records | `integration/exploitation_queue.py` | engagement artifacts |
| Reconciliation task refs (stable `REC-###`) | `integration/reconciliation.py` | engagement artifacts |

Nothing in Team 1's work fabricates or pre-populates any of these; all remain genuinely absent until Team 2 runs real flows.

## 5. PENDING_TEAM2 register (complete list)

| # | Item | Blocking dependency |
|---|---|---|
| 1 | Real-API provider validation (gate flip + metadata correctness) | `LLM_API_KEY` in env |
| 2 | Real-LLM hypothesis generation round-trip through `CausalFeedbackBridge` with CausalGuard evaluation | item 1 + authorized local target |
| 3 | Real sealed ProofBundle + replay verification on target-runtime evidence | item 2 |
| 4 | Browser-automated auth-validation exercise feeding `integration/auth_session_contract.py` verdicts | authorized target + GOED playwright stack |
| 5 | Source-aware lane: feeding real source intel (if the engagement provides target source) through `integration/source_mapping.py` + `surface_dossier.py` | target source tree availability; LLM SAST pipeline design decision |
| 6 | Optional agenda↔LangGraph node wiring (feature flag default False) + regression | Team 2 decision (recipe in §3 step 4) |
| 7 | ResearchAgenda live audit-trail review over real signals (Cases A–F behavior on production data) | items 1–2 |
| 8 | SARIF export decision (future BUILD; not required for qualification path) | product decision |

## 6. Warnings / known caveats for Team 2

1. **Sandbox memory:** single-process full-suite runs OOM a 4.1 GB box at ~64% (torch+chromadb). Use the batch runner pattern (§3 step 1). This is an environment constraint, not a project defect.
2. **Pre-existing failures (10):** documented with root causes in `GOED_BASELINE.md` §6 — including one pre-existing source bug (`test_v28_structure_aware_triage` → `UnboundLocalError: llm_selected` on a flag-gated path) and environment-dependent tests. Do **not** "fix" these by weakening assertions; fix implementation if the owner authorizes.
3. **Stale doc note:** `docs/CURRENT_RELEASE.md` claims "LangGraph 1.2.11 in uv.lock" but the lock resolves 0.6.11 (pre-existing inconsistency, documented in the inventory; left untouched as a historical doc).
4. **Zero-copy license rule stands:** Shannon (AGPL-3.0) content must never be pasted into this MIT project — see `SHANNON_LICENSE_AUDIT.md`.
5. The final state is **READY_FOR_TEAM2_VALIDATION**. Do not represent it as QUALIFIED, production-ready, or real-world validated: `vip_qualified=false`, P9=CLOSED, P10=CLOSED, bug-bounty execution blocked.

## 7. Stop condition confirmation (protocol §32)

Team 1 confirms: final regression run ✔; security/invariant audit ✔ (`SHANNON_GOED_INTEGRATION_FINAL.md` §M); deletion audit ✔ (FILES_DELETED=0); provenance audit ✔ (no Shannon content; no new deps); complete ZIP built ✔; SHA256 generated ✔; this handoff written ✔; remaining PENDING_TEAM2 items listed ✔. **Team 1 stops here. Team 2 validation not started.**

---

## Addendum — Review round (2026-09-11): wiring completed + dead-code sweep

The review pass closed the §D.3 gap from the main report: the integration layer is now **wired additively** into GOED's RESTRICTED integration surfaces (no FORBIDDEN file touched):

- **`webpent.research_engine.AgendaBridge`** (new `research_engine/agenda_bridge.py`, lazy-exported): reconciliation tasks + auth-validation verdicts in → bounded `AgendaSignal`s; active agenda branches out → GOED `ResearchTask` rows admitted through GOED's own budget-aware `ResearchState.admit_task` (scope/dedup/budget gates are GOED's, never bypassed); exploitation planning runs through the evidence-gated `ExploitationQueue` (`pending_entries → gate → record_attempt`, strict attempted/blocked union).
- **`webpent.attack_graph.attach_source_lane` / `source_lane_summary`** (new `attack_graph/source_lane.py`): advisory `metadata["source_lane"]` annotations on ENDPOINT nodes from `JoinedMapping` joins — pure function, idempotent, additive-only.
- **Operator switch**: `Settings.enable_integration_agenda` (additive, default **False** — current behavior unchanged). To activate for live runs: set `ENABLE_INTEGRATION_AGENDA=true` in the Team 2 environment and construct `AgendaBridge(engagement_id=…, target_id=…)` inside the research node (recipe unchanged; graph builder stays untouched).
- **Review regression**: 964 passed / 10 failed / 1 skipped — failure set byte-identical to the pristine baseline (`test_reports/REVIEW_SUMMARY.txt`). Integration-layer tests now 85 (69 + 16 wiring tests in `tests/test_integration_wiring.py`).
- Dead-code sweep of the integration layer: 7 items removed/fixed (details in `SHANNON_GOED_INTEGRATION_FINAL.md` addendum §R.2). No behavior change beyond the auditability additions (proposer + signal provenance now recorded).

---

## Addendum — Final hardening round (2026-09-10): TEAM 1 VERIFIED vs TEAM 2 MUST TEST

Evidence: `docs/integration/team1_final_baseline.md`, `team1_wiring_audit.md`, `team1_priority_audit.md`, `TEAM1_FINAL_SECURITY_REVIEW.md`, `TEAM1_FINAL_ARCHITECTURE_REVIEW.md`, `TEAM1_FINAL_STATUS.md`.

### TEAM 1 VERIFIED (offline, deterministic, zero real API keys consumed)

| Item | Result |
|---|---|
| Full regression (pytest 8.4.2 / Python 3.12.11) | 971 passed / 4 failed / 0 errors. 4 failures = strict subset of pristine baseline (#2–#5, `approval_source_missing`). **NEW_FAILURES = 0.** |
| Integration-layer tests | 85/85 pass. |
| Wiring classification | `OPTIONAL-LIVE` / `PARTIALLY_WIRED`: grep-confirmed **no live caller** in graph/workers/cli/agents/api. Gated behind `enable_integration_agenda=False`. No graph-builder rewrite (protocol §15). |
| Priority / rabbit-hole | LLM bounded to advisory `PriorityProposal`; final priority deterministic. Rabbit-hole cases A–F proven offline (budget SAFE_STOP, checkpoint/resume no-duplicate). |
| Attack-graph semantics | `HYPOTHESIZED != OBSERVED != PROVEN`; source-lane additive/idempotent/unmatched-unchanged. |
| Provider failure | `REAL_API_UNAVAILABLE` fail-closed; no silent mock; pool circuit breaker intact. |
| Secrets | Repository scan clean (only intentional redaction fixture `AKIAABCDEFGHIJKLMNOP`). No secrets in this handoff. |
| Ground-truth isolation | No `src/webpent/` file references `ground_truth.json`/`expected_findings.json` by name. Evaluator ≠ Executor. |
| Governance | `vip_qualified=false`, `qualification_state=CONDITIONAL`, `P10=CLOSED`, `P9=CLOSED`, bug-bounty blocked, external targets forbidden. Zero forbidden-claim matches in src/tests/docs. |
| Shannon provenance | Zero-copy (AGPL). No Shannon identifier in any new source file. |
| Files | `FILES_DELETED = 0` (39 added, 0 removed; 4 existing files modified additively only). `pyproject.toml`/`uv.lock` unchanged. |

### TEAM 2 MUST TEST (not verifiable offline by Team 1)

1. Real-API provider pool under: unavailable, timeout, quota exhausted, auth failure, all-providers-exhausted → confirm `SAFE_DEFER`/`SAFE_STOP`, no hang, no fabrication.
2. Live authorized-target campaign end-to-end with `ENABLE_INTEGRATION_AGENDA=true` → confirm additive agenda bridge produces downstream effect (or explicitly decide to wire it additively).
3. Browser/Playwright auth validation + exploitation paths against local authorized targets.
4. Docker stack (`make dev-up`) + the 7 `verify_all.py` Dockerfile/tool-registry checks that fail in this sandbox (pre-existing, environment-specific).
5. The 6 environment-dependent baseline failures (hardcoded paths, JWT fixture, crawler flag-gated `llm_selected` path, lesson-scope fixture, DB URL scheme, embeddings env) in the canonical environment.
6. P9/P10 qualification runs, workflow replay, proof-bundle promotion against the ground-truth harness (`scripts/evaluate_ground_truth.py`).
7. Confirm `ENABLE_INTEGRATION_AGENDA=false` preserves historical execution byte-for-byte in the real runtime.

**Stop reminder:** Team 1 consumed zero real API keys. Free keys are reserved for Team 2. Never commit `.env`/credentials to the archive.

---

## Addendum — Research-Entity Runtime Integration Milestone (2026-09-10)

### What CHANGED (additive only; exactly 1 canonical-core file)

- `src/webpent/research_engine/evidence_aware_loop.py`: added optional `agenda_bridge: AgendaBridge | None = None` param to `EvidenceAwareAgentLoop.evaluate`. Default `None` → historical behavior **byte-identical**. When supplied: agenda tasks merged into the SAME `ResearchState` via GOED's own `admit_task` (scope/dedup/budget gates preserved); tasks deterministically re-sorted by `(-priority, task_id)` → real downstream effect on experiment selection. All subsequent gates (scope/budget/capability/evidence/central-proof) **unchanged**.
- Added `src/webpent/integration/target_adapter.py` (TargetAdapter/RuntimeProfile; nothing imports it by default).
- Added `tests/test_team1_research_entity.py` (13 tests, all pass).
- Added docs: `TEAM1_BASELINE_MANIFEST.json`, `TEAM1_WIRING_GRAPH.json`, `TEAM1_RESEARCH_ENTITY_ARCHITECTURE.md`, `TEAM1_RABBITHOLE_PROOF.md`, `TEAM1_TARGET_AGNOSTIC_AUDIT.md`, `TEAM1_PROVIDER_FAILOVER_AUDIT.md`, `TEAM1_FINAL_STATUS.md`, `TEAM1_REGRESSION_REPORT.json`, `TEAM1_CHANGED_FILES.txt`, `TEAM1_SHA256_MANIFEST.txt`.

### What did NOT change

CausalGuard, ProofBundle, replay_verifier, ActionAuthority, safety_gate, P9/P10, governance flags, `graph/builder.py` (31 nodes), all thresholds, `pyproject.toml`/`uv.lock`, all historical artifacts. **FILES_DELETED = 0.** Final regression: 984 passed / 4 failed (identical pre-existing subset) / 0 errors → **NEW_FAILURES = 0**.

### What Team 2 MUST execute (exact commands)

```bash
uv sync --locked --extra dev   # Python 3.12.x
export PYTHONPATH=src LLM_ENABLED=false EMBEDDINGS_OFFLINE=true DISABLE_RAG=true AUTH_ENABLED=false FFUF_ENABLED=false WEBHOOK_ENABLED=false
uv run pytest -q tests/                     # expect 984 passed / 4 pre-existing failures / NEW_FAILURES=0
uv run pytest -q tests/test_team1_research_entity.py   # expect 13 passed
# real-API (set LLM_API_KEY): provider failover A fail -> B -> C -> SAFE_DEFER
# authorized LOCAL target ONLY: campaign with agenda_bridge wired -> single engagement lineage trace
# two distinct local targets -> Target-A profile does not alter Target-B behavior
```

### Expected evidence (Team 2 produces)

- One `engagement_id`/`target_id` lineage across: target→discovery→hypothesis→prioritization→rabbit-hole→experiment→new observation→world model→CausalGuard→ProofBundle→replay→finding.
- Provider failover traces (redacted key prefixes); no hang, no fabrication, no mock-as-real.
- Replay: `verdict_match AND evidence_match AND seal_valid AND seal_match AND replay_executed`.
- Governance invariant: `vip_qualified=false`, P9=CLOSED, P10=CLOSED throughout.

### What remains UNVERIFIED (Team-2 only)

Real-API provider failover under live quota/auth/timeout; live-target single-entity trace with agenda enabled; browser/Playwright paths; 6 environment-dependent baseline failures in canonical Docker env; `source_lane` live caller. **No mock may be reported as real API validation.**
