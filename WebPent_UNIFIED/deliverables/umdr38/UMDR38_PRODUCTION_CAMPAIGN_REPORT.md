# UM-DR-38 — Production Campaign Report

Generated: 2026-11-16T08:03:54.900486+00:00 — from `artifacts/umdr37_production_campaigns.json` (sha256 `3af07bf6d056475c…`), never hand-written.

**Validation:** PASS — all mandatory metrics present, counts consistent, lab versions identical, every confirmed finding carries a sealed ProofBundle and a passing replay verification, every required invariant held in every run.

Lab version: **invoice-lab/1.6.0** (single authoritative constant, Phase 5).

## Per-run results

| Run | Campaign ID | Requests | Confirmed | CausalGuard verdicts | Replay (passed) | Out-of-scope reqs | Final state |
|---|---|---|---|---|---|---|---|
| 1 | `umdr38-campaign-1-b912fe6b` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 2 | `umdr38-campaign-2-b13989d8` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |
| 3 | `umdr38-campaign-3-5952ca97` | 108 | 2 | CONFIRMED, CONFIRMED | 2 | 0 | authoritative |

## Confirmed findings (per run)

### Run 1 (umdr38-campaign-1-b912fe6b)

- **auth_bypass** — `http://127.0.0.1:40313/api/invoices/INV-A-101` — ProofBundle `proof_bundle_2eafa34b6837455d87b8c70d1c0ea01f` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:40313/api/invoices/INV-B-777` — ProofBundle `proof_bundle_54561d9c23f74c44a1f14ee8189a4247` (replay-verified)

### Run 2 (umdr38-campaign-2-b13989d8)

- **auth_bypass** — `http://127.0.0.1:37051/api/invoices/INV-A-101` — ProofBundle `proof_bundle_b245cc93ecf54896a3239b868e917d24` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:37051/api/invoices/INV-B-777` — ProofBundle `proof_bundle_6f694352cb4e4263bfc1b7fda68bf99b` (replay-verified)

### Run 3 (umdr38-campaign-3-5952ca97)

- **auth_bypass** — `http://127.0.0.1:40931/api/invoices/INV-A-101` — ProofBundle `proof_bundle_fe77440558634da8b93eeaa40f94d3b4` (replay-verified)
- **auth_bypass** — `http://127.0.0.1:40931/api/invoices/INV-B-777` — ProofBundle `proof_bundle_27f01e44f7fe4255ae66404e1fcabfd4` (replay-verified)

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
    "umdr38-campaign-1-b912fe6b",
    "umdr38-campaign-2-b13989d8",
    "umdr38-campaign-3-5952ca97"
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
