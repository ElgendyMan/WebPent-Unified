# CAMPAIGN Verification Log — Waves 1+2 (U-CAMPAIGN-1..6)

_Date: 2026-10-19. Spec: user CAMPAIGN document (governing laws L-1..L-11)
and the deep Wave 1+2 specification (schemas, strategist, executor)._

## Scope and standing constraints honored

The campaign layer is a NEW isolated package
(`src/webpent/campaign/` + `tests/campaign/`). The three existing
isolated packages (`verdict/`, `emulator/`, `rehearsal/`) were not
opened. `modern_spine.py` and `profile.py` were not touched. No new
code in the tools' cores. Red-first TDD throughout; suite count
monotonic; advisory-only.

## Red → Green

- **Step 1 (red)**: the 6 test files were written FIRST and confirmed
  red (`ModuleNotFoundError: No module named 'webpent.campaign'`):
  - `tests/campaign/strategist/test_thesis_builder.py` — 10 tests
    (U-CAMPAIGN-1)
  - `tests/campaign/strategist/test_phase_planner.py` — 10 tests
    (U-CAMPAIGN-2)
  - `tests/campaign/strategist/test_handoff.py` — 8 tests
    (U-CAMPAIGN-3)
  - `tests/campaign/executor/test_phase_runner.py` — 10 tests
    (U-CAMPAIGN-4)
  - `tests/campaign/executor/test_pivot_engine.py` — 12 tests
    (U-CAMPAIGN-5)
  - `tests/campaign/executor/test_budget_guard.py` — 10 tests
    (U-CAMPAIGN-6)
- **Step 2 (green)**: implemented `src/webpent/campaign/`:
  `errors.py`, `schemas.py` (frozen dataclasses + enums),
  `strategist/` (`thesis_evidence.py`, `validators.py`,
  `phase_templates.py`, `thesis_builder.py`, `phase_planner.py`,
  `handoff.py`), `executor/` (`budget_guard.py`, `pivot_engine.py`,
  `phase_runner.py`), `storage/` (`campaign_store.py` — JSON files,
  lossless round-trip). Campaign suite: **61/61 green**.

Two honest deviations from the deep spec, driven by the tests and by
mechanical honesty, both documented in code:

1. **BudgetGuard hard caps are REQUESTS** (phase then campaign); time
   and LLM dimensions are tracked and flagged advisively in the
   decision reason (overrun notes + burn-rate advisory), never used to
   rule. Rationale: the request count is the spend the operator
   authorized; clock/LLM figures are estimates the brain reports.
   The burn-rate advisory (100 req/min) is non-blocking, per L-3.
2. **The planner's chain phase carries no hypotheses** (empty list):
   it is the consolidation stage — its "ammunition" is whatever the
   earlier phases confirmed, so there is nothing honest to pre-script.

Plus one test-side fix during bring-up: `test_trigger_success_resets_counter`
constructed `HypothesisResult` without importing it (missing import;
no behavior change).

## Direct-I/O inventory: clean, no regeneration

The campaign package performs ZERO network I/O: storage is JSON files
under the store root, and every executor component takes its transport
via injection (brain, apex, budget guard, pivot engine are all
caller-injected, same rule as the verdict bridge). During bring-up the
strategist briefly used defensive `getattr(...)` duck-typed reads;
every `getattr` call is recorded by the direct-I/O scanner as a
dynamic-resolution site, so all were replaced with direct protocol
reads (the duck-typed contract defines the fields) plus one static
try/except helper for enum-or-string family keys. Final state: zero
`getattr` in `src/webpent/campaign/` → zero new inventory records →
**inventory test 4/4 green, no drift, no regeneration needed**.

## Zero-touch proof

- `modern_spine.py` SHA-256:
  `ef551212eb2a3583f6d7af14b46f58c32afe9b4c67c5da6e08d4f7aece9ade31`
  — UNMOVED from Round 4/5.
- `profile.py` SHA-256 prefix `30fd86c6` — UNMOVED.
- The campaign layer integrates with the existing system only through
  duck-typed protocols (OracleReport, Prism patterns, Economist) at
  its own adapters — no core file grew a touch point.

## Suite state (monotonic)

- Full suite: **3,943 passed, 0 failed** (Round-5 baseline 3,882 + 61
  campaign = 3,943).
- `verify_all.py`: **145/145 PASSED**.
- Isolated package suites unchanged: verdict 60 passed; emulator 17
  passed + 16 skipped; rehearsal 10 passed.
- Direct-I/O inventory: no drift (scanner records 656/21 baseline;
  campaign adds nothing).

### One pre-existing test hardened (environment drift, not campaign)

`tests/test_p0_critical_fixes.py::test_safe_http_executor_attaches_masked_response_projection`
used `https://example.com/target` behind a `MockTransport`. In the
current sandbox, DNS maps `example.com` to 198.51.100.53 — inside
TEST-NET-2 (198.51.100.0/24), which the SSRF guard correctly blocks as
a reserved range. The guard behaved correctly; the test was
DNS-fragile. Fixed by switching the URL to a routable IP literal
(`93.184.216.34`) with an explanatory comment — no guard or core
change, and the test no longer depends on the environment's resolver.

## Construction authority

Waves 1 and 2 added no ModernOrchestrator wiring; the Wave 3 section
below covers the wiring round and its construction-authority action.

## Wave 3 — the bridge and the wiring (2026-10-20)

Wave 3 completes the campaign integration through the documented
procedures. Two layers, both red-first:

**The bridge** (`src/webpent/production/campaign_bridge.py`, 12 tests
in `tests/test_campaign_bridge.py`): a completed AVI campaign result is
adapted into the strategist's oracle protocol (`OracleView`, every
field degrading to empty — the evidence floor belongs to the thesis
builder), built into a thesis, planned into phases, and registered as
a PENDING operator brief. The operator-sovereignty line is structural:
the module holds NO approval code path (enforced by an AST-source test
— no `def approve` and no `.approve(` anywhere), so the machine can
never sanction its own campaign. Off by default: without
`WEBPENT_CAMPAIGN_STORE` (or an explicit store) the bridge is a typed
blocker in the result — no default disk writes during ordinary
dispatches. Thin evidence is a typed blocker, never an exception.
Where the operator HAS ruled APPROVED, `approved_plan_for` surfaces
the plan as fail-open advisory guidance. Zero `getattr`, zero
transport, zero network.

**The wiring** (`tests/test_campaign_wiring.py`, 4 tests): the same
verdict-bridge pattern — two marked touch points in
`run_autonomous_validation_campaign`. Touch point 1/2 (before the AVI
dispatch) attaches the approved plan as advisory guidance and records
trace stage `campaign_advisory_plan`; touch point 2/2 (after the
verdict registration) turns the completed result into a PENDING brief
under `result["campaign_bridge"]["brief"]` with trace stage
`campaign_advisory_brief`. Failures are typed blockers carrying
`BRIDGE_GUARD` (the bridge's enumerated exception tuple — the P-1
hygiene rule forbids a broad `except Exception` in the spine); they
never raise into a completed campaign. The wiring test constructs
`ModernOrchestrator` directly and was added to `TEST_ALLOWLIST` after
deliberate review (gate exit 0, 26 allowlisted files), with the
review comment referencing
`docs/reviews/round7_campaign_wave3_seal_update.md`.

**Seal movement and inventory.** `modern_spine.py` moved deliberately
to
`d10783ec422bf1cfbba8daeb75f574fb6908b48ab793e54b8fde8c05e8fc9e3e`
(recorded in the seal-update document); `profile.py` is untouched at
`30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663`.
The direct-I/O inventory was REGENERATED from the canonical AST scan
(never hand-edited) with a one-record reviewed diff: line 1052 → 1100
on the pre-existing modern_spine record, same kind and symbol; 656
records and all pin counts unchanged, zero new records (the Wave-3
code carries zero `getattr` and zero I/O sites).

### Verification

- Suite: **4,266 passed, 0 failed** (4,250 → 4,266, monotonic:
  +12 bridge, +4 wiring).
- `verify_all.py`: **145/145 PASSED**.
- Construction-authority gate: exit 0.
- Isolated packages unchanged: verdict 60 passed; emulator 17 passed
  + 16 skipped; rehearsal 10 passed.
- ruff clean on every Wave-3 file.

## Waves 3-5 — Storyteller, Historian, War Room (2026-10-20)

U-CAMPAIGN-7..15: the 63 remaining tests of the 15-unit CAMPAIGN
specification, all inside the isolated campaign package. Red first:
all five test files were written before any implementation and
confirmed red with `ModuleNotFoundError` on
`webpent.campaign.storyteller` / `historian` / `warroom` (63 failed
for exactly that reason).

**Wave 3 — storyteller** (`src/webpent/campaign/storyteller/`):
`NarrativeGenerator` (U-7, 8 tests) renders the thesis and phase plan
as a deterministic narrative with two audiences (operator/executive;
unknown audience is a ValueError) and a no-LLM surface enforced by a
source scan; `ReportGenerator` (U-8, 6 tests) projects the recorded
phase results into an execution report — outcome counts per recorded
status, findings counted from results, budget summed from recorded
spend — and never grades (no score, no grade).

**Wave 4 — historian** (`src/webpent/campaign/historian/`):
`CampaignMemory` (U-9, 8 tests) persists completed campaigns as JSON
under its own directory (brief via the CampaignStore serialization,
plus a record file with the report totals and family mix), recalls
read-only by target, family or whole; re-recording a campaign updates
in place; empty memory yields empty answers. `RetrospectiveEngine`
(U-10, 8 tests) compares planned budgets against recorded spend per
phase; unrun phases are reported PENDING with zero spend, never
invented; over-budget phases yield observations that cite the recorded
numbers. `CrossCampaignLearner` (U-11, 6 tests) aggregates the memory:
findings attributed mechanically to each thesis's top recorded family,
deterministic, read-only over the memory.

**Wave 5 — war room** (`src/webpent/campaign/warroom/`):
`CampaignDashboard` (U-12, 5 tests) renders a stable text snapshot of
the brief. `CampaignCLI` (U-13, 6 tests) is the operator's typed
command surface over the store — list / status / approve / reject,
nothing else; unknown commands and unknown campaigns are failed typed
results, never escaping exceptions. `CampaignIntegration` (U-14,
8 tests) composes report → memory → retrospective and imports campaign
components only (source-scanned). `TruthValidator` (U-15, 8 tests)
checks every report claim against the recorded phase results —
inflated/deflated findings, fabricated outcome counts and budget
mismatches are flagged; consistent reports pass silently; inputs are
never mutated.

**Standing constraints honored**: zero `getattr` in the new packages
(inventory test 4/4 — no drift, no regeneration needed), zero network,
zero touch on `modern_spine.py` / `profile.py` (both seals UNMOVED:
`d10783ec…` and `30fd86c6…`), nothing inside the three pre-existing
isolated packages, no auto-exploitation surface (everything here is
recording, rendering and reading).

### Verification (Waves 3-5)

- Suite: **4,329 passed, 0 failed** (4,266 → 4,329, monotonic, +63).
- `verify_all.py`: **145/145 PASSED**.
- Construction-authority gate: exit 0 (no new orchestrator
  construction anywhere).
- Isolated packages unchanged: verdict 60 passed; emulator 17 passed
  + 16 skipped; rehearsal 10 passed.
- ruff clean on every new file (9 auto-fixable import-order findings
  fixed before the green run).

## Deliverable

Rebuilt from a clean tree as `webpent_v89_prism_campaign_w1w5.zip`
(Waves 1-5 complete: U-CAMPAIGN-1..15);
verified from a fresh extraction (full suite green from the extracted
copy).
