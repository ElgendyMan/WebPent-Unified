# D3 — WP-A DOSSIER: SUBSTRATE/AUDIT FIX
Ruling items: R5 (conditional ratification substrate fixes) + NF-M2-06 disposition.
Files (all on Dispatch #009 thaw list):
- src/webpent/production/advisory_registration.py
  - `_audit`: audit_chain.append() -> append_event(event_type=, details=) [NF-R2-04]
  - `_assert_spine_caller`: object-identity token ladder + pytest-contained escape [NF-R2-06]
  - `register_advisory_candidates_inline(..., token=, dedupe_registry=)`: durable dedupe seeding/add [NF-R2-07]; noncanonical identity fields -> rejected+counted (no TypeError: unhashable)
  - `publish_advisory_hypotheses(..., token=)`
- src/webpent/production/modern_spine_integration.py
  - SPINE_CALL_TOKEN (object identity, non-exported)
  - _audit_root + _resolve_audit_chain: REAL EngagementAuditChain produced per engagement; state carries serializable descriptor only (C10/V13)
  - _recheck_fixture_bounds: frozen-layer bound re-check (MAX_SOURCE_BYTES, free-text caps 2048/4096/4096, parameter_names<=64, HAR<=MAX_HAR_ENTRIES) [NF-M2-06]
  - _load_or_create_campaign_state (fail-safe on corrupted durable state)
- src/webpent/production/campaign_state.py
  - schema v1->v2 (fail-safe loud rejection of foreign versions): +dedupe_keys, +registered_candidates, record_dedupe_key, record_registered_candidate, CampaignStateDedupeRegistry (MutableSet; add persists)
Tests: test_m2_transport_contract.py (audit fires/fail-closed, guard refuse/containment, durable dedupe, bounds recheck, noncanonical rejection).
