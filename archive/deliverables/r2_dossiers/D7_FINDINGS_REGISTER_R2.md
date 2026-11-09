# D7 — FINDINGS REGISTER (discovered, out-of-scope) + ESCALATIONS

Sprint R2 rule: anything discovered that is NOT Section 3 goes here. Nothing below was fixed.

| # | Finding (discovered during 6.2 re-anchor on v5) | Severity | Disposition |
|---|---|---|---|
| F-01 | `_combined_recon_node` (builder.py:1338-1370) swallows ALL legacy `recon_node` failures via a broad tuple `except (AttributeError, ImportError, KeyError, OSError, RuntimeError, TypeError, ValueError)` and logs at WARNING — advisory-lane failure invisibility is by design here, but the tuple is wide; candidate for the accepted-exceptions register if not already listed | P3 | REGISTERED — out of scope (not Section 3); candidate for `docs/ACCEPTED_EXCEPTIONS_REGISTER.md` review next register cycle |
| F-02 | `modern_spine_recon_node` has a silent `except Exception: pass` in the admitted-fixture loop (modern_spine_integration.py:143-144) — a malformed fixture is dropped without any counter increment (the rejections register only captures structured rejections); a debug-level log would preserve the existing fail-soft contract while making drops observable | P3 | REGISTERED — out of scope; site is frozen; note for the next touch of this file |
| F-03 | `entrypoint_parity_check` (production_spine.py:403-437) pops the drift registry for the engagement before the parity loop — safe because it re-keyes with per-entrypoint engagement ids (`f"{engagement_id}_{ep}"`), but the pop makes the helper non-reentrant under concurrency; helper is diagnostics-only today (zero production callers) | P3 | REGISTERED — out of scope |
| F-04 | M1's Chain 5 mitigation inventory (`oob_confirm_route_enabled` default-off) means the BYP-02 authority pathway is INERT in every default deployment; the ratified demotion remains required (the pathway exists and one operator flag arms it) — recorded so TEAM-REVIEW weights exposure correctly | P2 (context) | RECORDED — feeds D5 §4.1 operator guidance |
| F-05 | `tests/test_r2_spine_authority_contracts.py::test_t03b` intentionally pins the RESIDUAL "no entrypoint setter in src/"; when D2/R2-01 lands this test fails by design and must be updated in the same commit (its assertion message says so). Tripwire pattern matches the strict-xfail dossiers | P3 (meta) | RECORDED — self-documenting |
| F-06 | v5's `KNOWN_ENTRYPOINTS` excludes `campaign_worker` (D2/R2-04); while true, `ProductionTrace.entrypoint` cannot distinguish the campaign subprocess from the Celery worker in any already-emitted evidence — historical traces are correctly labeled `"worker"`, which is truthful but coarse | P3 | REGISTERED — resolves with D2/R2-04 |

## ESCALATIONS (require Orchestrator action)

| Escalation | Item | Ask |
|---|---|---|
| E-1 | D2/R2-02 (BYP-02, P0) | Unfreeze request: `src/webpent/api/app.py`, `src/webpent/memory/db.py` — apply the ratified advisory-only demotion (proposed diff attached) |
| E-2 | D2/R2-03 (BYP-05, P2) | Unfreeze request: `src/webpent/graph/builder.py` — graph-path fail-closed rejection (proposed diff attached) |
| E-3 | D2/R2-04 (B-06 residual, P3) | Unfreeze request: `production_spine.py` (one-word KNOWN_ENTRYPOINTS addition), `campaign_worker.py` (one-word literal) |
| E-4 | D2/R2-01 residual (P0 lineage) | Unfreeze request: `modern_spine_integration.py` — entrypoint provenance read-side (proposed diff attached); editable wiring follows in the same change |
| E-5 | D2/R2-05 / D2/R2-06 (P1 conditionals) | Ruling on post-unfreeze designs for lane provenance and the Phase-1 smart-profile block (dossier text attached; no diffs by design) |

## Hygiene note-and-park (per dispatch R2-07)

R2-07 resolved as **"nothing to do"**: both cited hygiene sites are already clean on v5
(ruff F811/F401 clean on `graph/builder.py` and `production/modern_spine.py`; all four
smart-campaigns import names in builder.py are used). No parked items.
