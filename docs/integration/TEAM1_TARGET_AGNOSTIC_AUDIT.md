# TEAM1 Target-Agnostic Audit

**Document ID:** TEAM1-TARGET-AGNOSTIC-AUDIT-1.0
**Date:** 2026-09-10
**Rule 6/7:** no target-specific routes/IDs/actors/tenants/headers/workflows in generic core.

## Additive abstraction

`src/webpent/integration/target_adapter.py` (new, nothing imports it by default):

- `RuntimeProfile` (frozen, extra-forbid): `route_discovery`, `actor_context`, `resource_representation`, `state_transition_capabilities`, `execution_quirks` — all optional; absent → generic behavior.
- `TargetAdapter`: register-by-neutral-name; `get(name)` returns profile or generic default; `capabilities(name)` returns a neutral capability set the generic core consumes. One profile's registration can never overwrite another (`profile_already_registered`).

## Regression proof

`tests/test_team1_research_entity.py::test_target_adapter_isolation`: registering Target-A profile leaves `capabilities("target-b")` **byte-identical** to before; Target-B resolves to `generic`; Target-A routes do not appear in Target-B capability set; duplicate registration rejected.

## Core-code review result

- No hardcoded target routes/IDs/actors found in `graph/`, `research_engine/`, `cqa_v2/`, `shared/`, `state/`, `llm_researcher/` (grep for common target-specific tokens — none in generic core).
- Existing target-specific fixtures live under `tests/` and `benchmarks/` (fixtures, allowed by Rule 7).
- `Settings` profiles (`EnvironmentProfile`, `ScanMode`) remain the existing runtime-profile mechanism; the new `TargetAdapter` is additive and optional.

## Unverified (Team-2)

- Exercise against two distinct authorized local targets to confirm zero cross-target state leakage at runtime.
