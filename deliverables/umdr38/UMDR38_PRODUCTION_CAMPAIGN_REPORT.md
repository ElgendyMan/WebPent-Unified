# UM-DR-38 — Production Campaign Report

Generated: 2026-11-17T04:55:50.933126+00:00 — from `artifacts/umdr37_production_campaigns.json` (sha256 `55ee1505f025b80c…`), never hand-written.

**Validation:** PASS — all mandatory metrics present, counts consistent, lab versions identical, every confirmed finding carries a sealed ProofBundle and a passing replay verification, every required invariant held in every run.

Lab version: **invoice-lab/1.6.0** (single authoritative constant, Phase 5).

## Per-run results

| Run | Campaign ID | Requests | Confirmed | CausalGuard verdicts | Replay (passed) | Out-of-scope reqs | Final state |
|---|---|---|---|---|---|---|---|
| 1 | `umdr38-campaign-1-136db27f` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 2 | `umdr38-campaign-2-79ecf9c6` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 3 | `umdr38-campaign-3-1fd44ba6` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |

## Confirmed findings (per run)

### Run 1 (umdr38-campaign-1-136db27f)

- **auth_bypass** — `http://127.0.0.1:44023/api/invoices/INV-A-101` — ProofBundle `proof_bundle_9370791c3bd34861bc0f3c58b943e483` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:44023/api/invoices/INV-B-777` — ProofBundle `proof_bundle_830df4e11a40435cb1f95e2c4457eb3c` (replay-verified)

### Run 2 (umdr38-campaign-2-79ecf9c6)

- **auth_bypass** — `http://127.0.0.1:40785/api/invoices/INV-A-101` — ProofBundle `proof_bundle_1818115da19240c5879ee6959ca2b2fb` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:40785/api/invoices/INV-B-777` — ProofBundle `proof_bundle_d6926def1e8d4427aa0c129660df1877` (replay-verified)

### Run 3 (umdr38-campaign-3-1fd44ba6)

- **auth_bypass** — `http://127.0.0.1:40349/api/invoices/INV-A-101` — ProofBundle `proof_bundle_d66ed70462724befb8b09958e01bb870` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:40349/api/invoices/INV-B-777` — ProofBundle `proof_bundle_68a7f6511c6c44dc9c4eea2b80f6f338` (replay-verified)

## Negative controls (must all hold)

Every run enforces the controlled-laboratory expectations, proven from the lab's own request log — never from expectations:

- `enforced_admin_boundary_unconfirmed`: **True**
- `admin_boundary_actually_enforced_in_lab`: **True**
- `missing_resource_unconfirmed`: **True**
- `missing_resource_was_probed_as_404`: **True**
- `public_resource_unconfirmed`: **True**
- `decoy_route_unconfirmed`: **True**
- `decoy_route_was_served`: **True**

## Reproducibility

```json
{
  "same_lab_version": true,
  "same_configuration": true,
  "fresh_state_per_run": true,
  "unique_campaign_ids": [
    "umdr38-campaign-1-136db27f",
    "umdr38-campaign-2-79ecf9c6",
    "umdr38-campaign-3-1fd44ba6"
  ],
  "confirmed_counts": [
    2,
    2,
    2
  ],
  "guard_verdicts_per_run": [
    [
      "CONFIRMED",
      "CONFIRMED"
    ],
    [
      "CONFIRMED",
      "CONFIRMED"
    ],
    [
      "CONFIRMED",
      "CONFIRMED"
    ]
  ],
  "all_runs_confirm_idor": true,
  "all_invariants_hold": true,
  "differences_explained": "finding counts beyond the two boundary violations are advisory api_issue candidates whose exact set depends on crawl ordering; the CONFIRMED set is the invariant being reproduced"
}
```

The three campaigns are comparable: same lab version, same declared configuration, same controlled budget, fresh state and unique campaign IDs per run, instrumentation reset between runs (§7.2.A). Advisory finding differences are explained in the record; the CONFIRMED security conclusions and required invariants are the reproduced invariant.
