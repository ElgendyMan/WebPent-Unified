# M2-A EVIDENCE INDEX — reopened window (Dispatch #009-A)

| Item | Artifact |
|---|---|
| D-J root-cause report (WP-J) | `deliverables/DJ_P7_ROOT_CAUSE_20261006.md` |
| P7 reproduction harness | `scripts/m2a_p7_repro/` (target, fake LLM, scope, runner, README) |
| P7 reproduction evidence | `deliverables/m2a_evidence/p7/` (repro log, hunt stdout/stderr + summary trace excerpt, scan short-circuit + full-chain runs pre/post-fix) |
| WP-I contract tests | `tests/team1_acceptance/test_m2a_exit_code_honesty.py` (20) |
| WP-I scoped-diff dossier | `deliverables/m2a_dossiers/D3-A_WP_I_scoped_diff_review.md` |
| WP-K contract suite | `tests/team1_acceptance/test_template_contracts.py` (10) |
| WP-K template guidance | `docs/credentials_template_README.md` |
| NF-009A-02 repair script | `scripts/fix_gate_order.py` (host copy: scripts/ outside tree) |
| g02 linedrift regen | `scripts/regen_direct_io_inventory_m2a_20261006.py` |
| Integration battery v9 | `deliverables/integration_battery_20261006_v9.txt` (153 + floor) |
| Full suite v9 | `deliverables/full_suite_v9_20261006.txt` (3190 passed) |
| Anchor record (reopen + v9) | `scripts/m2a_anchor_record.json` |
| Evidence report | `EVIDENCE_REPORT_20261006_v9.md` |
| Gate | `scripts/gate_frozen_delta_m2.py --phase reopened --baseline c61519a` → GREEN at every commit |
