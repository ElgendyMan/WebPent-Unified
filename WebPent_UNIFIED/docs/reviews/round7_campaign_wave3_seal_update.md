# Wave-3 Seal Update — CAMPAIGN integration into the modern spine

_Date: 2026-10-20._

Round 3 sealed the core; Round 4 superseded that rule for the verdict
bridge through two marked, commented touch points. Wave 3 of the
CAMPAIGN package follows the same documented procedure, same shape,
same discipline: the operator directive ("كمل wave 3 كله") asked for
exactly this wiring.

## What changed in the core, exactly

Two marked touch points in
`src/webpent/production/modern_spine.py::run_autonomous_validation_campaign`,
both clearly commented `Wave 3 touch point`:

1. **Advisory plan surface** (before the AVI dispatch): calls
   `campaign_bridge.approved_plan_for(target_url)`. Where the operator
   HAS ruled APPROVED on a brief for this target, the approved plan is
   recorded in the spine trace under stage `campaign_advisory_plan`
   and attached to the result under `result["campaign_bridge"]["plan"]`.
   Fail-open by law: no ruling, no store, or any bridge fault is a
   recorded reason, never an error that touches the dispatch.
2. **Advisory brief surface** (after the verdict registration): calls
   `campaign_bridge.campaign_advisory_brief(result, target_url)` — the
   completed campaign's evidence becomes a PENDING operator brief
   (thesis + phases + budgets) and attaches under
   `result["campaign_bridge"]["brief"]` with trace stage
   `campaign_advisory_brief`. The bridge holds no approval code path
   (the machine never sanctions its own campaign) and is OFF unless
   the operator points it at a brief store via `WEBPENT_CAMPAIGN_STORE`
   — otherwise the result carries a typed blocker, with no default
   disk write during ordinary dispatches. Failures are typed blockers
   in the result; they never raise into a completed campaign.

No other core file changed. No code inside `verdict/`, `emulator/` or
`rehearsal/` changed. `src/webpent/live_hunter/profile.py` is untouched.

## New seal register (sha256)

- `src/webpent/production/modern_spine.py`:
  `d10783ec422bf1cfbba8daeb75f574fb6908b48ab793e54b8fde8c05e8fc9e3e`
  (moved from `ef551212eb2a3583f6d7af14b46f58c32afe9b4c67c5da6e08d4f7aece9ade31`
  at the Round-7 baseline — the two touch points above are the whole
  delta). The touch points guard with the bridge's ENUMERATED
  `BRIDGE_GUARD` tuple (OSError, ValueError, TypeError, KeyError,
  IndexError, AttributeError), not a broad `except Exception`: the
  P-1 exception-hygiene rule forbids broad handlers in the spine, and
  the enumeration keeps the advisory surface just as fail-open.
- `src/webpent/live_hunter/profile.py`: unchanged —
  `30fd86c61156e7a5883205b9ce4b2f6c3f856f78e1561676345ad988d9c5b663`.

## Construction-authority gate

`tests/test_campaign_wiring.py` constructs `ModernOrchestrator`
directly (test-only escape, loopback URL `http://127.0.0.1:9/cw3`,
AVI class escape) and was added to `TEST_ALLOWLIST` in
`scripts/check_orchestrator_construction_authority.py` after deliberate
review, with the review comment in the allowlist itself. Gate exit 0:
`ModernOrchestrator(` appears only in `production_spine.py` and the
approved 26-file allowlist.

## Direct-I/O inventory regeneration (deliberate, reviewed)

The Wave-3 touch points shift line numbers in `modern_spine.py`, which
moves one pre-existing `dynamic_resolution` record. The artifact was
REGENERATED from the canonical AST scan
(`webpent.shared.direct_io_inventory.scan_direct_io`), never
hand-edited, with this verified diff:

- exactly ONE record changed: `modern_spine.py` record #396, line
  1052 → 1100 (same kind `dynamic_resolution`, same symbol `getattr`);
- record count unchanged: 656; coverage unchanged
  (92 approved / 538 not_applicable / 24 unapproved pins, 21
  distinct identities); every pin test passes;
- zero NEW records: the Wave-3 code carries zero `getattr` and zero
  transport sites (advisory selection only, no I/O).

Note in `pin_review_note` records this regeneration rationale.

## Test evidence

- Red first: the 4 wiring tests failed with `KeyError: 'campaign_bridge'`
  before the wiring existed; the 12 bridge tests failed with
  `ModuleNotFoundError` before the bridge existed.
- Green after: 12 bridge tests + 4 wiring tests; the full suite moves
  4,250 → 4,266 (monotonic), `verify_all.py` 145/145.
