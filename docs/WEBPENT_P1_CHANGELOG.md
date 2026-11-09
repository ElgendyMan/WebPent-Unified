# WebPent P1 Change Changelog

Baseline: `webpent-final-updated.zip` (pre-P1 master).

## Product changes

The release adds cooperative campaign halt/resume with an atomic action-ledger checkpoint, repeated-hypothesis loop detection after three attempts, deterministic preflight cost estimates before dispatch, role-gated halt/resume/estimate API routes, and a read-only evidence dashboard. It adds `webpent campaign halt <campaign-id>` for operators, cheap-model routing for short classify/sort prompts, a provider-neutral prompt-cache adapter, and a structured-output adapter with deterministic fallback.

The dependency set is upgraded to the LangGraph/checkpoint and LangChain provider core-1-compatible generation. `uv.lock` is regenerated and the synchronized uv environment was used for validation. The G-02 direct-I/O artifacts were regenerated after final source changes. The supplied AVI release security report was used to produce the dashboard render.

## Changed files

- `docs/DIRECT_IO_INVENTORY.md`
- `docs/WEBPENT_P1_CHANGELOG.md`
- `docs/direct_io_inventory.json`
- `docs/p1_dashboard_render.html`
- `docs/p1_dashboard_render.txt`
- `pyproject.toml`
- `scripts/capture_vip_baseline.py`
- `src/webpent/api/app.py`
- `src/webpent/api/scan_registry.py`
- `src/webpent/cli/commands.py`
- `src/webpent/config/settings.py`
- `src/webpent/memory/db.py`
- `src/webpent/production/campaign_state.py`
- `src/webpent/production/campaign_worker.py`
- `src/webpent/production/product_layer.py`
- `src/webpent/shared/action_authority.py`
- `src/webpent/shared/action_ledger.py`
- `src/webpent/shared/llm.py`
- `tests/team1_acceptance/_s2_composition_subprocess_body.py`
- `tests/test_local_causal_lab_option_b_approval.py`
- `tests/test_product_p1.py`
- `uv.lock`

## Validation metadata

- Review patch: `docs/webpent_p1.patch`
- Patch size: 354,668 bytes.
- Frozen trust-module manifest: unchanged.
- Full suite: 2017 passed, 11 warnings.
- Acceptance: 20 passed in each of 3 rounds.
- Security gates: all 5 exit code 0.
