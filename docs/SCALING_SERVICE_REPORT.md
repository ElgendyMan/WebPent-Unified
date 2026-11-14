# WebPent Multi-Campaign Service — Remediation Report

## Delivered scope

The additive service layer provides:

- Per-campaign state, ledger root, namespace isolation, budget, and cooperative halt/resume.
- Lifecycle: `PLANNED → RUNNING → OPERATOR_HALTED → COMPLETED`.
- Cost and LLM-usage projections, cache/cheap-model metrics, and idempotent alerts.
- Bounded scheduling/retry hooks and read-only completion-report generation.
- Authenticated service API routes and `webpent campaign` CLI commands.
- Hourly gate and daily authoritative frozen-manifest health entrypoints.

The service layer does **not** promote findings. Promotion remains owned by the existing production spine and `PromotionPipeline`.

## Fresh execution demo

The old artifact-importing fixture runner is no longer the canonical demo. `scripts/run_scaling_demo.py` now delegates to `scripts/run_fresh_two_target_demo.py`.

The fresh demo starts two independent loopback targets and runs both campaigns concurrently through `run_autonomous_recon_campaign` and the existing production spine:

- `fresh-target-a` → `http://127.0.0.1:38101`
- `fresh-target-b` → `http://127.0.0.1:38102`

The targets expose a bounded redirect differential plus negative controls. Each campaign executed **5 real decisions**:

| Campaign | Decisions | Promoted | Refuted | Completion reports |
|---|---:|---:|---:|---:|
| fresh-target-a | 5 | 1 | 4 | 1 JSON + 1 Markdown |
| fresh-target-b | 5 | 1 | 4 | 1 JSON + 1 Markdown |

The promoted decisions passed the full eight-gate promotion record, including sealed ProofBundle, replay verification, causal confirmation, and semantic identity binding. The four non-findings per campaign were rejected/refuted by the canonical validators and were not reported as bounty submissions.

The per-campaign service kill switch was exercised independently for `fresh-target-a`: the campaign entered `OPERATOR_HALTED`, a subsequent action reservation was denied, and resume returned it to `RUNNING`. This is a service action-ledger checkpoint; it does not bypass or replace the production execution authority.

Fresh evidence is stored under:

- `artifacts/fresh_two_target_demo_20261001/demo_summary.json`
- `artifacts/fresh_two_target_demo_20261001/dashboard_render.json`
- `artifacts/fresh_two_target_demo_20261001/reports/`

No historical campaign artifact is used as input to this demo.

## Security and integrity validation

- Compileall: **exit 0**.
- Full suite: **2052 passed, 0 failed**.
- Current acceptance set: **20 passed × 3 rounds**.
- `check_state_contract.py`: **exit 0**.
- `check_orchestrator_construction_authority.py`: **exit 0**.
- `check_isolation_denylist.py`: **exit 0** under the project `uv` environment.
- `check_vault_import_authority.py`: **exit 0**.
- `verify_test_count.py`: **exit 0**; 2052 collected against a 1940 floor.
- `verify_frozen_manifest.py`: **exit 0**; all 13 authoritative trust-spine files matched.
- Direct-I/O inventory: regenerated from the canonical AST scanner; G-02 tests **4 passed**.

The obsolete acceptance filenames from an earlier patch-chain archive are not present in the recovered tree. Validation therefore used the current equivalent I-3 vertical flow plus the current I-2 walking-skeleton and hotfix tests.
