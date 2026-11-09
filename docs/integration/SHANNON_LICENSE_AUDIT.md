# Shannon → GOED License Audit

**Document ID:** SHANNON-LICENSE-AUDIT-1.0
**Date:** 2026-09-10
**Auditor:** Team 1
**Verdict:** ⛔ **NO SHANNON SOURCE CODE, PROMPT TEXT, OR TEMPLATE TEXT MAY BE COPIED INTO GOED.** All Shannon-derived capability must be re-implemented natively in Python as original GOED code, using Shannon files as **architectural reference only**. This verdict is enforced throughout the migration: every Shannon-derived GOED module below documents the Shannon *pattern* referenced, and contains zero copied Shannon text.

## 1. Shannon License

| Item | Finding | Evidence |
|---|---|---|
| Shannon top-level license | **GNU Affero General Public License v3.0** (full 662-line text) | `shannon-main/LICENSE` |
| Declared package license | `AGPL-3.0-only` | `apps/cli/package.json` |
| Source headers | 141 of 205 `.ts` files carry `Copyright (C) 2026 Keygraph, Inc. … GNU Affero General Public License version 3` headers | `rg -c "Copyright \(C\) 2026 Keygraph" apps/worker/src` = 141 |
| AGPL implications | Strong copyleft + network-service clause: any work **deriving from** Shannon code and offered as a service must be released under AGPL-3.0 | LICENSE §13 |
| GOED license | MIT (`pyproject.toml`: `license = { text = "MIT" }`) | GOED `pyproject.toml` |
| Compatibility | AGPL-3.0 code **cannot** be relicensed into an MIT project. Copying any Shannon .ts/.hbs/.txt content into GOED would (a) contaminate GOED with AGPL obligations, or (b) constitute a license violation. | — |

## 2. Shannon's Own Third-Party Notices

| Component | License | Use in Shannon | Relevance to GOED |
|---|---|---|---|
| Pi agent framework (earendil-works/pi, © 2025 Mario Zechner) | MIT | Core agent executor (`@earendil-works/pi-*` 0.84.4) | Not copied. GOED uses LangGraph, not pi. |
| Mantis (google/mantis, commit `876a0c8…`, retrieved 2026-08-25) | Apache-2.0 | Capella agentic-SAST **prompt** templates (`apps/worker/prompts/sast/capella/*`, `prompts/partials/capella-*.hbs`) | Prompt text is copyrighted creative content. Even though Apache-2.0 permits derivative use with attribution, Team 1 decision: **do not copy prompt text into GOED at all** — GOED's prompt engineering is its own. Pattern (staged SAST pipeline) referenced only. |
| Temporal SDK / server | MIT / MIT | Workflow orchestration | Not copied; GOED uses LangGraph + Celery. |
| TypeBox, zx, ajv, handlebars, js-yaml, dotenv | MIT/Apache-2.0 | Worker deps | Not imported into GOED (Python project). |
| `@playwright/cli@0.1.1` | Apache-2.0 | Browser skill | GOED already uses Python `playwright>=1.48,<1.49` (its own dependency line) — no Shannon artifact involved. |
| Typst 0.14.2 | Apache-2.0 | PDF rendering | Not imported; GOED has its own reporter. |

## 3. Files Used ONLY as Architectural Reference (no text copied)

Each GOED integration module below was informed by reading the listed Shannon file(s) to understand the **pattern** (ideas, procedures, data-shape concepts), then implemented from scratch in Python against GOED's own contracts. Ideas and procedures are not copyrightable; the expression here is original.

| Shannon reference (read-only) | Pattern taken (idea only) | GOED original implementation | Copied text? |
|---|---|---|---|
| `apps/worker/src/services/exploitation-checker.ts`, `services/queue-validation.ts` | Gate exploitation behind a validated queue; agent cannot invent targets outside the queue | `src/webpent/integration/exploitation_queue.py` (queue schema, validation, gating — new Python code) | NO |
| `apps/worker/src/ai/queue-schemas.ts` | Queue entry carries `exploitation_hypothesis`, `suggested_exploit_technique`, `code_locations[]` with `role: sink\|source\|guard` | `src/webpent/integration/source_mapping.py` (`CodeLocation`, `SourceMappingRecord`) | NO |
| `apps/worker/src/services/code-location-join.ts` | Join source locations onto findings/report | `src/webpent/integration/source_mapping.py::join_source_locations` | NO |
| `apps/worker/src/collectors/recon-collector.ts` (+ `prompts/recon.txt` NOT copied) | Structured attack-surface deliverable: endpoints, authz candidates, injection sources, role architecture | `src/webpent/integration/surface_dossier.py` (`SurfaceDossier`, `AuthzCandidate`, `InjectionSource`) | NO |
| `apps/worker/src/services/validate-authentication.ts` | Auth validation verdict contract: `login_success / failure_point / failure_detail` tri-state + saved-session verification | `src/webpent/integration/auth_session_contract.py` (`AuthValidationVerdict`, `AuthSessionState`) | NO |
| `apps/worker/src/ai/reconciliation/{prepare,enrich,form,materialize}.ts` | Four-stage finding reconciliation with stable task refs and forbidden-internal-keys scrubbing | `src/webpent/integration/reconciliation.py` (`ReconciliationStage`, `reconcile_observations`) | NO |
| `apps/worker/src/types/run-state.ts`, `services/report-checkpoints.ts` | Durable state machine with `partial_reasons` set; skip-completed-work on resume | `src/webpent/integration/research_agenda.py` (agenda checkpoint semantics) | NO |
| `apps/worker/src/services/exploitation-checker.ts` (again) + exploit collector union | Strict evidence-gated `exploited vs blocked` outcome union (`what_we_tried`, `how_this_would_be_exploited`) | `src/webpent/integration/exploitation_queue.py::ExploitAttemptRecord` | NO |
| `apps/worker/prompts/**` | NOT copied — GOED prompt engineering is unchanged | n/a | NO |
| `apps/worker/templates/typst/report.typ` | NOT copied — GOED templates unchanged | n/a | NO |

## 4. Imported Files / Adapted Files

- **Imported (copied) files:** **NONE** (zero bytes of Shannon content enter the GOED tree).
- **Adapted files:** **NONE** in the copyright sense (no Shannon file was modified-and-carried-over). The table in §3 lists original GOED modules whose *design* was informed by Shannon patterns.

## 5. Attribution

- No attribution notice is legally required for reading AGPL code and independently implementing the same ideas (ideas/methods are uncopyrightable); however, to be conservative and transparent, this migration **documents Shannon as architectural reference** in:
  - this audit (§3),
  - `SHANNON_GOED_CAPABILITY_MATRIX.md` (Evidence column),
  - module-level docstrings of each `src/webpent/integration/*` module ("Architectural reference: Shannon <file> (AGPL-3.0) — pattern only, no code copied").
- If the project owner ever wishes to copy Shannon code verbatim, the entire affected work would need to become AGPL-3.0 — an explicit human decision outside Team 1's mandate.

## 6. GOED-side Third-Party Risk Check for New Modules

- All new GOED modules use **stdlib + existing GOED dependencies only** (pydantic v2, stdlib dataclasses/enum/hashlib/json/time). **Zero new third-party dependencies** were introduced by this migration → zero new license surface.
- Shannon's heavyweight infra (Temporal server, Node 22 runtime, pnpm workspace, Typst, Playwright-CLI skill, Chromium) is explicitly **not** added to GOED.

## 7. Compatibility Concerns Register

| Concern | Status |
|---|---|
| AGPL contamination via copied code | Mitigated — zero-copy policy enforced; git-history greppable proof (`rg -l "Keygraph\|earendil\|capella-" src/webpent/integration` returns no Shannon content) |
| AGPL contamination via translated TS→Python near-1:1 port | Mitigated — modules are re-designed around GOED contracts (pydantic, PentestState, CausalGuard flow), not line-by-line translations; each module documents the divergence |
| Mantis Apache-2.0 prompt text | Mitigated — no prompt text copied |
| Patent/other | No patent grants observed in Shannon repo |
| Snapshot discrepancy | Shannon Dockerfile references `LICENSES/` and `assets/` dirs absent from the uploaded snapshot — noted; does not affect the zero-copy decision |

## 8. Audit Method

1. Read `LICENSE`, `THIRD_PARTY_NOTICES.md`, `apps/*/package.json`.
2. Counted and located all copyright headers.
3. Diffed planned integration surface against Shannon sources to confirm only *patterns* are taken.
4. Verified new GOED modules import only stdlib + pydantic (no Shannon deps, no new pip packages).
5. Confirmed `grep` proof that no Shannon-identifying strings (Keygraph, earendil, capella-*, typst, temporal) appear in new GOED modules.
