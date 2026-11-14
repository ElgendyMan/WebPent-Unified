# D3 — WP-F DOSSIER: FLAG CONSUMERS
Ruling item: R6 / NF-M2-02 (five flags, zero consumers).
Files: src/webpent/production/spine_flag_gates.py (NEW — thaw item 7); modern_spine_integration.py (intake gates); builder.py (dispatch gate).
- SpineFlagSnapshot.from_config: factory-bound ONLY (config object; never state; never mid-run env). binding digest = sha256(target_url)[:16].
- Gates: exploration_ingress, static_fixture_source, multi_principal_execution (binding-checked; placeholder 'target_unknown' fingerprint DENIED); live_proxy_source = unconditional Phase-1 refusal; foreign_report_writer consumed (M3 boundary documented).
- Wiring: intake scheduling DENIED unless ingress+fixture gates ALLOW (rejection register reason spine_flag_gate_denied + loud log); advisory candidates gated out of dispatch when multi_principal denied.
- Fixture-cannot-set proven: flag-like fixture keys schedule nothing.
- E-2 composition: UNSUPPORTED_LEGACY_ONLY refuses composition; consumers never run.
Tests: 6 flag tests in test_m2_transport_contract.py.
