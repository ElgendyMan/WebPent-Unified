# UM-DR-40 — Identity Activation Before/After Campaign Report

Generated 2026-11-18T12:28:48.040234+00:00 — production entrypoint, identical lab, identical configuration, the only difference being the per-campaign identity activation.

## The arms

* **Baseline** (2 runs): every identity capability OFF — the shipped fail-closed default.
* **Enabled** (2 runs): the same campaign inside `identity_campaign_activation` (all four capabilities ON; RC-4's per-campaign mechanism).

## Results (per run)

| arm | run | principals (funnel) | differential questions | auth observations | requests | elapsed s | confirmed |
|---|---|---|---|---|---|---|---|
| baseline | umdr38-campaign-1-4d9401 | 0 | 0 | 4 | 108 | 35.4 | 2 |
| baseline | umdr38-campaign-2-e9db95 | 0 | 0 | 4 | 108 | 1.9 | 2 |
| enabled | umdr38-campaign-3-c74652 | 3 | 0 | 4 | 108 | 2.3 | 2 |
| enabled | umdr38-campaign-4-b5f63d | 3 | 0 | 4 | 108 | 2.0 | 2 |

## The RC-4 proof, stated honestly

* Enabled runs demonstrate principals_observed > 0 from the registered node (the register's acceptance, verbatim): **True**
* Baseline runs show the identity channels empty: **True**
* Guard verdicts unchanged across arms (advisory-only contract): **True**
* **RC-4 PROVEN: True**

## Budget impact (recorded per RC-4)

* `umdr38-campaign-1-4d940173` → `umdr38-campaign-3-c74652fc`: {'lab_request_count': 0.0, 'requests_total': None, 'elapsed_s': -33.1, 'duration_seconds': None, 'findings_confirmed': 0.0, 'findings_pending': None} — identity counts: {'principals_observed': 0, 'identities_observed': 2, 'differential_questions': 0} → {'principals_observed': 3, 'identities_observed': 2, 'differential_questions': 0}
* `umdr38-campaign-2-e9db95d4` → `umdr38-campaign-4-b5f63d2f`: {'lab_request_count': 0.0, 'requests_total': None, 'elapsed_s': 0.10000000000000009, 'duration_seconds': None, 'findings_confirmed': 0.0, 'findings_pending': None} — identity counts: {'principals_observed': 0, 'identities_observed': 2, 'differential_questions': 0} → {'principals_observed': 3, 'identities_observed': 2, 'differential_questions': 0}

Machine record: `IDENTITY_CAMPAIGN_RESULTS.json` (full campaign records are retained inside it).
