# UM-DR-36.2 Repository Baseline

Generated 2026-11-16T05:24:44.894368+00:00 from live git + committed artifacts. Head `609da8ade4bc` on
branch `mission/umdr36.2-umdr37`.

## Actual state

The build sandbox was fully recycled between missions; the repository
was restored from two public sources and one delivered bundle:

1. GitHub main `64a5bea` — the owner's commit of the UM-DR-36.1 final
   ZIP, nested under `WebPent_UNIFIED/` (this nesting disables GitHub
   Actions: workflows load only from the repo root).
2. The uploaded ZIP (the `1968f63` UMDR35-36 tree).
3. The git bundle inside the delivered tree — 15 commits of full 36.1
   history, `git bundle verify` OK, tip `0d9511f`.

The mission branch was created from the bundle tip, the published
final-state delta applied (19 files), and the environment rebuilt:
`uv lock --check` OK, `uv sync --locked --extra dev` OK,
`pip check` clean, and 48/48 UM-DR-36.1 regression tests passed on the
restored tree before any new work began.

## Closure state

- version identity: 0.40.1 everywhere (pyproject, __init__, uv.lock,
  BUILD_INFO top-level + contract) — `version_consistency` PASS;
- frozen manifest re-pinned via the DR-009 declared-drift ritual;
  `test_frozen_module_gate` 647/647;
- campaign identity: `causal_guard.finding_id` stamped and the
  integrated-campaign artifact regenerated — `campaign_artifact` PASS;
- recovery verifier verdict: **VERIFIED** (all checks PASS).

## Known unresolved

~101 pre-existing environment-dependent suite failures (recorded
per-file since UM-DR-36.1) and remote CI unverified (no GitHub
credentials in this environment — the bundle is provided for push/PR).
