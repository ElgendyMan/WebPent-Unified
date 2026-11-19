# EGAIE Regression Report

Date: 2026-10-21. Scope: the EGAIE increment (src/webpent/egaie/) and
its effect on the existing WebPent suite.

## Test counts (monotonic)

| Suite | Before EGAIE | After EGAIE |
|---|---|---|
| Baseline WebPent suite | 4,337 passed | 4,337 passed |
| tests/egaie | (new) | 32 passed |

Full command: `python3 -m pytest tests/ -q`. The egaie increment adds
32 tests (schemas, selection, repetition, orchestrator, persistence,
causal wiring, benchmark, negative controls) and removes none. Suite
count is monotonic. No existing test was modified, reordered, or
skipped.

## Red-first history (each fix preceded by a proven-red test)

1. `c9fc55c` schemas: investigation state schemas.
2. `01c7034` selection + repetition.
3. `83d9dce` causal adapter + controlled fixture target.
4. `4dd2ddf` persistence + orchestrator closed loop.
5. `bf9c38e` benchmark: adaptive vs fixed baseline.
6. `5149214` ruff import sorting (no behavior change).
7. `eba6c2f` negative-control binding fix. Red evidence: with the
   family-match fallback picking the smallest hypothesis_id, the
   baseline run confirmed neg-bola-1 and neg-idor-1 (FP=2); the new
   tests/egaie/test_negative_controls.py failed before the fix and
   passed after. Fix is three edits: explicit `hypothesis_id` on
   ProposedExperiment, seeds bind each experiment to its own
   hypothesis, and `_update_hypothesis` binds explicitly first with
   family matching only as a fallback for unbound experiments.

## Invariants verified after the increment

- modern_spine.py sha256 unchanged: d10783ec422b...
- live_hunter/profile.py sha256 unchanged: 30fd86c61156...
- src/webpent/verdict/, emulator/, rehearsal/: zero diff (untouched).
- Construction-authority gate
  (scripts/check_orchestrator_construction_authority.py): exit 0.
- Hygiene scan of src/webpent/egaie/: zero getattr, zero hasattr,
  zero `except Exception`. Ruff clean (line length 100).
- No live network: the EGAIE loop and benchmark run only against the
  controlled fixture target in-process; no socket use, no external
  dependencies added.

## cqa_v2 untouched

The closed loop composes the existing CausalGuard,
build_complete_proof_bundle, and verify_replay through ports
(causal_adapter.py). Nothing in cqa_v2 was modified; validation was
not weakened for benchmark scores. Negative controls stay negative in
both the adaptive and fixed-order loops (see
02_benchmark_results.json, post-fix: both FP=0).
