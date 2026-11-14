# TEAM-1 P0 Wiring & Truthfulness Recovery — Master Implementation Record

**Status:** Implemented and independently verified (TEAM-2 audit, ACCEPTED WITH RESIDUALS, 68/100).
**Scope of this document:** backfill the master implementation record for Phases 1–8 of the P0 Wiring & Truthfulness Recovery plan, as required by TEAM-2 residual **R-03**. Every entry is anchored to file/symbol/test evidence; nothing here is claimed without a seam or a test.

**Implementation pass addendum:** residual defects R-01..R-10 from the TEAM-2 report were implemented by the IMPLEMENTATION team on top of this work. See the addendum section at the end.

---

## Phase 1 — OOB + database parity

**Law:** OOB callback ingestion, worker persistence, validator polling, and API findings resolution MUST resolve to one engagement/workspace persistence authority.

| Seam | Evidence |
|---|---|
| OOB callback route resolves the caller's workspace | `src/webpent/api/app.py` `_process_oob_callback` (~line 1674+): callback tokens are mapped to their engagement workspace before persistence |
| Worker activates the target workspace before graph execution | `src/webpent/workers/pentest_worker.py:552` and `:1136` (workspace activation / resume reconstruction) |
| API findings route is workspace-activated | `src/webpent/api/app.py:1319-1343` (`/api/v1/scans/{thread_id}/findings`) |
| Test | `tests/test_team1_oob_database_parity.py` (docstring honestly notes it simulates deployed topology in one process; live proof = residual R-01 → Wave-1 harness `scripts/run_live_parity.py`) |

## Phase 2 — Compose / workspace parity

**Law:** api and worker share workspace/checkpoint/persistence mounts; no hidden per-container default DB.

| Seam | Evidence |
|---|---|
| `docker-compose.yml`, `docker-compose.dev.yml`, `docker-compose.test.yml` | api and worker both set `WEBPENT_DATABASE_URL=sqlite:////app/runtime/webpent.db` (test stack) / equivalent shared-mount URLs and `WEBPENT_TARGET_WORKSPACE_ROOT=/app/runtime/workspaces`, plus the shared `./runtime` bind |
| Test | `tests/test_team1_compose_workspace_parity.py` |

## Phase 3 — Refutation semantics

**Law:** confirmations are refutable only with deterministic evidence; LLM text alone can neither confirm nor refute; REFUTED is terminal; history is preserved.

| Seam | Evidence |
|---|---|
| Monotonic status law `UNCONFIRMED → CONFIRMED → REFUTED` with anti-resurrection guards | `src/webpent/memory/db.py` `mark_refuted` (~line 1328) — later graph-state saves and late OOB callbacks cannot resurrect a retracted confirmation |
| Terminal status vocabulary | `src/webpent/models/findings.py` — `Refuted` allowed only as deterministic terminal state; `Not Scanned` / `Clean` distinct signals |
| Tests | `tests/test_team1_refutation_persistence.py` (6/6 independent pass) |

## Phase 4 — Non-DVWA hypothesis generation

**Law:** no target-specific keyword tables as the primary hypothesis path; generic producers run from params/forms/path/ids/response structure; `skip_recon=true` still classifies the seed URL.

| Seam | Evidence |
|---|---|
| Generic structural producers | `src/webpent/agents/hypothesis_analyzer/` (~line 730+): parameter/form/path/id/response-structure producers |
| Seed-URL classification under `skip_recon` | seed URL placed at `endpoints[0]`; classifier runs on it |
| Test | `tests/test_team1_non_dvwa_hypotheses.py` (non-DVWA-shaped fixtures yield non-empty hypotheses) |

## Phase 5 — State contract repair

**Law:** every node-written state key is declared; writer → declaration → reader → persistence coherence is statically checkable.

| Seam | Evidence |
|---|---|
| Static checker | `scripts/check_state_contract.py` — exit 0 with 165 keys / 51 writers / 0 violations (independently re-run by TEAM-2) |
| `max_rounds` vs `max_replan_rounds` mismatch | fixed in `src/webpent/config/settings.py` / `src/webpent/state/state.py` / `src/webpent/graph/builder.py` |
| Test | `tests/test_team1_state_contract.py` |

## Phase 6 — Post-validation replan (bounded)

**Law:** strategist may re-enter after validation at the existing graph seam, at most 2 replans per run, only with a monotonic evidence-count increase; no second scheduler; no ToolBoundary/CausalGuard bypass.

| Seam | Evidence |
|---|---|
| Evidence-gated re-entry edge | `src/webpent/graph/builder.py:946-994`, registered at `:1187-1191` |
| Bounds | replan cap ≤ 2 enforced in the router gate; budget counters in state |
| Test | `tests/test_team1_post_validation_replan.py` |

## Phase 7 — Knowledge/RAG bootstrap (non-authoritative)

**Law:** offline knowledge pack ingestible; retrieval budgeted and fail-closed; sanitized; RAG influences candidates/payloads but NEVER confirmation; poisoning is isolated per workspace.

| Seam | Evidence |
|---|---|
| Retrieval + budget + fail-closed | `src/webpent/shared/knowledge_retrieval.py`, `src/webpent/memory/vectorstore.py` |
| Preflight exposure | `src/webpent/shared/preflight.py` `_check_knowledge_ready` |
| Ingest | `scripts/ingest_payloads.py --manifest knowledge_pack/manifest.yaml`; `knowledge_pack/` + `knowledge_sources.yaml` shipped |
| Tests | `tests/test_team1_rag_knowledge.py` incl. `test_rag_content_fails_causal_confirmation_gate` (RAG cannot confirm) and poisoning-isolation cases |

## Phase 8 — Tool scope consistency

**Law:** every exploitation tool uses the same fail-closed scope preflight; poisoned/out-of-scope URLs are denied; redirects cannot bypass scope.

| Seam | Evidence |
|---|---|
| sqlmap | scope preflight + `--scope` regex derived from the same model; fail-closed on malformed scope |
| dalfox / ffuf / katana / nuclei | same preflight seam in `src/webpent/tools/` wrappers |
| Test | `tests/test_team1_tool_scope.py` (incl. denial cases) |

---

## Regression honesty (as verified by TEAM-2)

- Full suite at verification time: **1176 passed / 6 failed / 1 skipped**; the 4 Option-B failures exactly matched the declared pre-existing baseline (no new failures from TEAM-1).
- The single TEAM-1 acceptance-test failure in the first pass was proven to be the verifier sandbox's leaked `DATABASE_URL` env var (passes hermetically) — later fixed properly by residual **R-04**.

## Implementation-pass addendum (R-01..R-10 closure)

Implemented on top of the verified TEAM-1 tree; see `IMPLEMENTATION_REPORT.md` in the delivery for full evidence:

- **R-01** — live multi-container acceptance harness `scripts/run_live_parity.py` + contract test `tests/test_live_parity_harness_contract.py` + lab credential in `docker-compose.test.yml`. Honesty gate: exits 2 without Docker, never claims unexecuted proof.
- **R-02 / R-09** — shipped `webpent.db`, `memory/global/*` removed; `.gitignore` extended; conftest redirects global memory (decision log / lessons / sessions / chroma) to tmp.
- **R-03** — this document; `scripts/build_release_manifest.py` exclusions hardened (no run artifacts, caches, or snapshot dirs in manifests).
- **R-04** — `config/settings.py` alias chain now `("WEBPENT_DATABASE_URL", "DATABASE_URL")`; the bare field-name alias was REMOVED because with `case_sensitive=False` it case-insensitively matched the ambient generic var and always won regardless of order (proven by test). Conftest hermeticity fixture added.
- **R-05** — `.env.example` documents namespaced-first DB URL + absolute shared-mount path.
- **R-06** — `scripts/doctor.py` reports `knowledge_ready` by reusing `webpent.shared.preflight._check_knowledge_ready`; the preflight pack-root anchor bug (`parents[2]` → `src/`) was fixed so the check can actually detect the shipped pack.
- **R-07** — reporter surfaces terminal refutations: `refuted_count` + `refuted_findings` in `reporter/export.py`; Refuted stat card, dedicated Refuted Findings section, strike-through styling in the HTML template; Refuted section + `~~title~~` in Markdown; stats extended.
- **R-08** — `.github/workflows/ci.yml` restored to satisfy `test_ci_security_environment_contract_is_explicit` (deterministic/offline env contract + preserved test-count floor).
- **R-10** — the four declared Option-B baseline failures were FIXED (not waived): the approval-artifact location is now operator-configurable (`WEBPENT_OPTION_B_APPROVAL_SOURCE`), `build_result` gained an `approval_source` seam, and the tests are hermetic (synthetic approval + recomputed hash) while pinning the fail-closed laws (`approval_source_missing` / `approval_source_hash_mismatch`).
