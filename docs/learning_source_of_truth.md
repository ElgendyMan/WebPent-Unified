# Learning Loop — Source of Truth Decision (Track 6.1/6.2)

**Date:** 2026-10-29 (RESIDUAL CLOSURE window, v0.26.0)
**Roadmap item:** المسار 6 — حلقة تعلم موحدة ومحكومة، البندان 1 و2.

## Decision

**`src/webpent/memory/` is the single source of truth for the governed
learning loop.** `src/webpent/brain/` is NOT a parallel production
lesson system.

### The evidence (verified 2026-10-29)

| Aspect | `memory/` | `brain/` |
|---|---|---|
| Lesson storage | SQLite via `LessonsManager` (1,235 lines) | in-memory `LessonsLedger` (44 lines) |
| Engine wiring | `graph/builder.py` nodes (consultation after planning, extraction after reflection), `agents/hunter_runner.py`, `service/facade.py`, `production/autonomous_recon.py` | **none** — only its own tests (`tests/test_u15_lessons.py`, `tests/lab/lcs2_sweep_instrument.py`) and one import of `brain/ev_scheduler` by `production/chain_composer.py` (scheduler, not lessons) |
| Provenance | production lineage | v14.1 "restored-rewritten (minified)" restorations (documented in DRIFT_REGISTER) |
| Client isolation | enforced (`get_structured_lessons` refuses without `client_id`; SQL-filtered) | not applicable (no production path) |

The `brain/` lesson ledger is dead code kept only by its own tests. It
is RETIRED from the learning contract effective this decision: no new
code may import `brain/lessons.py`.

**REMOVAL EXECUTED (G-1, v0.29.0, 2026-10-31 — the announced deletion
window promised above):** `src/webpent/brain/lessons.py` and its test
`tests/test_u15_lessons.py` are deleted from the tree. Consumers
updated in the same window: `tests/lab/lcs2_sweep_instrument.py` now
carries a minimal local ledger equivalent (byte-for-byte semantics,
documented in place), and `scripts/resurrect.py` dropped the module
from its `BRAIN_MODULES` list (the live `webpent.memory.lessons` stays
pinned in `SPINE_MODULES`). The frozen manifest was re-frozen by
`scripts/refreeze_manifest_0290_g1_lessons_removal.py` (658 entries).
Nothing imports the deleted module anywhere in the tree.

### Loop coverage status (Track 6.2)

Post-planning advisory consultation (`graph/lesson_nodes.py`, numeric
modifiers in [-0.5, 0.5], never instructions, fail-open) is wired into:

* unified `webpent hunt` (all modes) — consulted AND extracted;
* `webpent scan` — same graph;
* the agent hunter loop — `hunter_runner.py` consults post-crawl and
  persists post-review;
* `service/facade.py` + `production/autonomous_recon.py`.

**Documented exemption:** `webpent hunt-auto` (the deprecated alias)
drives `src/webpent/autonomous/` and does NOT consult the lessons
store. This is deliberate and recorded here rather than hidden: the
alias exists only for backward compatibility, carries its own file-key
memories (`intel`/`deadends`), and is scheduled for removal by a
declared release per Track 4 item 7. Wiring the deprecated alias into
the governed loop would spend integration effort on a surface that is
slated for deletion; the honest statement is "exempt, deprecated, do
not extend".

### Remaining open item (not closed in 0.26.0)

Track 6.5 (shadow/canary A/B measurement of lesson impact) still has
only the schema (`integration/learning_ab_contract.py`) and
observational metrics (`memory/improvement_tracker.py`); a real
control-vs-treatment lab runner remains future work and is recorded in
the residual register of this window.
