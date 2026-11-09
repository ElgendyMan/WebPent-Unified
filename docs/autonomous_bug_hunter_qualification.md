# Autonomous Bug Hunter — Qualification Report

Date: 2026-10-14. Scope of this report: the transformation of WebPent's
advisory research components into one autonomous hunt loop
(`src/webpent/autonomous/`) plus its one-command CLI entry
(`webpent hunt-auto`). Every claim below is backed by a command that was run
for this report; every limit is stated as a non-claim.

## What was built

The autonomous hunt is a bounded loop,
recon → hypothesis → rank → execute (gated) → observe → prove → learn →
report, implemented in `src/webpent/autonomous/`:

| Component | File | Responsibility |
|---|---|---|
| Contracts | `hunt_contracts.py` | `HuntPhase`, `HuntStopReason`, `HuntOutcome`, `PhaseRecord` |
| State | `hunt_state.py` | Additive, redaction-safe hunt state with `summary()` |
| Orchestrator | `hunt_orchestrator.py` | The loop itself; delegates all execution |
| Runtime wiring | `hunt_runtime.py` | Production `RuntimeContext` via `RuntimeFactory`, canonical G-02 `smart_http` adapter, `run_wired_hunt` |
| Learning memory | `hunt_memory.py` | `ScopedHuntMemory`: hint-only, capped, engagement-scoped, tamper-evident |
| CLI | `cli/commands.py` (`hunt-auto`) | One-command entry with `--dry-run` and typed exit codes |

## Verified claims (with evidence)

1. **Bounded loop with typed stops.** The orchestrator stops with an
   explicit `HuntStopReason` (never silently) and maps the real
   `AutonomousController`'s `stop_decision.reason` 1:1. Evidence:
   `tests/test_autonomous_hunt_orchestrator.py` (17 tests), including
   `test_real_controller_contract_is_understood` and
   `test_stop_decision_beats_top_level_and_replanning_fallback`.
2. **Real, gated execution.** The wired hunt executes through the
   production `ActionExecutor` with the G-02 `smart_http` adapter.
   Out-of-scope tasks are denied before the handler is called; POST is
   denied in `safe-smart` and allowed in `authorized-active` under the
   approval policy; tasks without G-02 metadata are denied. Evidence:
   `tests/test_autonomous_hunt_runtime.py` (10 tests).
3. **Proof-grade promotion only.** A bundle that fails `verify_seal`,
   lacks `negative_control_digest`, or belongs to another engagement is
   refused; verified bundles link into the report deduped by seal digest.
   Evidence: orchestrator refusal/linking tests (3 added in Phase 3).
4. **Hint-only learning.** Hints are capped at ±0.75 at store, at the
   memory boundary, and again at the point of use; an offline replay shows
   the ranking reorders toward the confirmed pattern while a large
   deterministic gap survives; governance stops are never learned from;
   tampered entries are refused. Evidence:
   `tests/test_autonomous_hunt_memory.py` (7 tests).
5. **One-command entry.** `webpent hunt-auto --url ... [--dry-run]` wires
   the real runtime, validates the mode against `ScanMode` before building
   anything, and reports the redaction-safe summary as JSON. A dry run
   executes nothing. Evidence: `tests/test_autonomous_hunt_cli.py` (4
   tests).
6. **Governance tests green.** The direct-IO inventory was regenerated
   deliberately after source changes (624 records); all inventory
   governance tests pass. Evidence: `tests/test_g02_direct_io_inventory.py`
   4/4 after regeneration.
7. **Full regression.** `PYTHONPATH=src python -m pytest tests/ -q` →
   **2161 passed, 0 failed** (128 s, run 2026-10-14 after the final source
   and inventory state). Ruff: clean on all new/touched code
   (`src/webpent/autonomous/`, the `hunt-auto` region of
   `cli/commands.py`, and the four new test modules).

## Non-claims (what this release does not assert)

- **No live-target qualification.** Every test runs against local fixtures
  and example.test-style offline targets. No real external target was
  hunted, and a finding produced here is not a confirmed real-world
  vulnerability.
- **No Docker/worker claim.** Worker-based distributed qualification
  remains blocked in this environment, unchanged from the prior
  traceability matrix.
- **No new execution authority.** The orchestrator and wiring add no
  bypass of scope, authority, rate-limit, SSRF, or evidence gates; the
  fail-closed tests exist precisely to keep that true.
- **LLM-dependent paths unexercised.** Where the smart-campaign handler
  would call an LLM provider, the tests exercise the deterministic paths;
  no provider was configured during qualification.

## Reproducing the evidence

```
PYTHONPATH=src python -m pytest tests/test_autonomous_hunt_orchestrator.py \
    tests/test_autonomous_hunt_runtime.py tests/test_autonomous_hunt_memory.py \
    tests/test_autonomous_hunt_cli.py -q
PYTHONPATH=src python -m pytest tests/ -q            # full regression
ruff check src/webpent/autonomous/ tests/test_autonomous_hunt_*.py
webpent hunt-auto --url https://lab.example/ --dry-run
```
