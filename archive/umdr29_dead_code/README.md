# UM-DR-29 Dead-Code Archive (2026-11-07)

This directory completes two documented dead-code dispositions from the
UM-DR-29 window ("fix all dead code, dead capabilities, weak wiring"):

## 1. Completion of ULTIMATE PLAN 2026-10-27, proposal 4

The 2026-10-27 window archived 17 verified-dead prototype packages to
`archive/pre_v10_prototypes/` and removed their entries from
`frozen_modules.sha256`, but the physical removal from `src/webpent/`
was never executed — identical copies kept living in the source tree
(a copy, not a move). The UM-DR-29 repository-truth audit found the
duplication, and this window deleted the stale `src/` copies:

    abhc abhie abhie_v6 abhip adi asros avde avrip avrp cqa dcvu
    goed_v1 rta vabhfil_v8 vabhfqr_v10 vabhfqr_v9 vabhic_v7

Evidence: import-graph reachability audit (scripts/umdr29_dead_code_audit2.py)
— 0 runtime importers, 0 test importers, 0 script/config references; the
frozen gate test already carries `ULTIMATE_PLAN_20261027_ARCHIVED_PATHS`
documenting the intended removal; `tests/test_five_families.py` already
skips honestly when `goed_v1` is absent; the broad-exceptions register
entries for `goed_v1` were removed with this window (documented in
`tests/test_editable_broad_exceptions_gate.py`).

One src variant differed from its archive copy and was preserved
losslessly:
`archive/pre_v10_prototypes/abhie_v6/agent_core.py.umdr29_src_variant`
(the src tree lacked the `research_memory` parameter; both variants are
retained; neither has any importer).

## 2. Seven frozen-but-dead packages (DR-009 declared thaw + refreeze)

A second dead set was FROZEN (present in `frozen_modules.sha256`) yet had
zero runtime importers, zero test importers, and zero script references:

    contracts copilot experience persistence profiles security_models validation

These were moved here and their 22 manifest entries removed by the
documented refreeze `scripts/refreeze_manifest_umdr29.py` (661 -> 639
entries; the gate floor of >= 630 documented in
`tests/test_frozen_module_gate.py` is respected). Notably
`webpent/validation/` was a frozen dead duplicate of the live
`webpent/validators/` package, and `webpent/contracts/` was a dead
re-export facade.

## What was deliberately NOT removed

`irta/` (frozen, benchmark lineage, partially test-referenced), the
frozen target-adapter inventory (`adapters/{juice_shop,crapi,webgoat,
mock_target,generic_web,local_causal_lab}`), and unwired-but-documented
research subsystems remain in `src/` with honest status records in
`docs/engineering/UMDR29_ARCHITECTURE_AND_GAP_ANALYSIS.md` and the
machine-readable feature qualification matrix
`docs/engineering/UMDR29_FEATURE_QUALIFICATION_MATRIX.json`.
