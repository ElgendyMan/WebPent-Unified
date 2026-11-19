# D3-A — WP-I SCOPED DIFF REVIEW (conditional thaw, exit-code honesty ONLY)

**File:** src/webpent/cli/commands.py, src/webpent/workers/pentest_worker.py
**Authorization:** Dispatch #009-A WP-I(c) conditional grant — "FOR
EXIT-CODE-HONESTY CHANGES ONLY. All other edits to them remain
prohibited."
**Review mode:** WP-H scoped-file precedent (modern_spine.py
_TEST_ESCAPE_ENV containment) — every hunk enumerated and classified.

## commands.py — hunks

| # | Location | Change | Classification |
|---|---|---|---|
| 1 | helpers (before `_perform_preflight_check`) | ADD `_chain_honesty_verdict()` + `_enforce_chain_honesty()` (pure verdict/error helpers; no I/O, no target interaction) | exit-code honesty |
| 2 | `hunt --target` (after except) | ADD gate call reading `result["summary"]["production_trace"]` → `typer.Exit(1)` on incomplete/absent | exit-code honesty |
| 3 | `scan --adapter-free` (before projection print) | ADD verdict from `no_executable_hypotheses` / `decisions_executed` / trace completeness → `typer.Exit(1)` | exit-code honesty |
| 4 | `scan` graph path (before success panel) | ADD `_chain_honesty_verdict(final_state)` gate → `typer.Exit(1)` | exit-code honesty |
| 5 | `agent-hunt` (before projection print) | ADD gate call (same as #2) | exit-code honesty |

NO other hunks. No changes to argument parsing, scope handling, graph
construction, persistence, or reporting logic.

## pentest_worker.py — hunks

| # | Location | Change | Classification |
|---|---|---|---|
| 1 | module level (before `_check_graph_state`) | ADD `_chain_short_circuit_reason()` (pure marker reader) | exit-code honesty |
| 2 | completed branch (after findings persistence) | ADD marker check → loud error log + return status `completed_incomplete_chain` | exit-code honesty |

NO other hunks. Persistence order preserved (findings saved BEFORE the
status flip — evidence preservation). Pause/resume/recursion/timeout
paths untouched. No changes to task signatures (verified by
tests/test_v14_entrypoint_wiring.py + tests/test_scope_file_contract.py,
both green).

## Verdict

Every hunk implements exactly the WP-I(a) honesty contract. Zero
authority changes, zero transport changes, zero new state keys, zero
target-interaction changes. GRANT NOT EXCEEDED.
