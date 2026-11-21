# UMDR42 Phase B — Full-Project Audit Findings

Generated 2026-11-19. Total: 108 findings (0 high, 104 medium, 1 low, 3 info).

Categories: dead-code, error, lint, markers, tooling, weak-code

---

## UMDR42-001 [MEDIUM] (dead-code) — 3 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/controlled_target/adapter.py` (line 598))
- **Detail:** supports_operation (FunctionDef, line 598); do_DELETE (FunctionDef, line 136); bind_target_spec (FunctionDef, line 233)

## UMDR42-002 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/crapi/context_provider.py` (line 51))
- **Detail:** evaluate_access (FunctionDef, line 51); get_ownership_model (FunctionDef, line 143)

## UMDR42-003 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/generic_web/adapter.py` (line 77))
- **Detail:** handle_starttag (FunctionDef, line 77); handle_endtag (FunctionDef, line 90)

## UMDR42-004 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/local_causal_lab/fixtures.py` (line 165))
- **Detail:** snapshot_restore_check (FunctionDef, line 165)

## UMDR42-005 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/local_causal_lab/option_b_contract.py` (line 205))
- **Detail:** validate_option_b_preconditions (FunctionDef, line 205)

## UMDR42-006 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/local_causal_lab/runtime_provenance.py` (line 99))
- **Detail:** readiness_check (FunctionDef, line 99)

## UMDR42-007 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/adapters/mock_target/adapter.py` (line 287))
- **Detail:** supports_operation (FunctionDef, line 287)

## UMDR42-008 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/agents/hunter_contracts.py` (line 229))
- **Detail:** state_digest (FunctionDef, line 229)

## UMDR42-009 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/api/scan_registry.py` (line 527))
- **Detail:** lookup_scan_status (FunctionDef, line 527)

## UMDR42-010 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/attack_graph/reasoner.py` (line 21))
- **Detail:** explain_edge (FunctionDef, line 21)

## UMDR42-011 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/benchmark/profiles.py` (line 47))
- **Detail:** as_fixture (FunctionDef, line 47)

## UMDR42-012 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/brain/adaptation.py` (line 43))
- **Detail:** check_scope_invariant (FunctionDef, line 43)

## UMDR42-013 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/business_logic/state_transition.py` (line 82))
- **Detail:** find_candidates (FunctionDef, line 82)

## UMDR42-014 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/causal_reasoning_v2/causal_adapter_v2.py` (line 151))
- **Detail:** pending_count (FunctionDef, line 151)

## UMDR42-015 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/causal_reasoning_v2/integration_layer.py` (line 298))
- **Detail:** conclusion_count (FunctionDef, line 298)

## UMDR42-016 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/config/policies.py` (line 151))
- **Detail:** to_docker_kwargs (FunctionDef, line 151)

## UMDR42-017 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/config/settings.py` (line 3283))
- **Detail:** api_key_for (FunctionDef, line 3283)

## UMDR42-018 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/coverage/coverage_map.py` (line 23))
- **Detail:** tested_keys (FunctionDef, line 23)

## UMDR42-019 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/cqa_v2/execution/actor_context.py` (line 82))
- **Detail:** requires_workflow (FunctionDef, line 82); execute_with_control (FunctionDef, line 121)

## UMDR42-020 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/deep/business_logic.py` (line 157))
- **Detail:** generate_violations (FunctionDef, line 157); test_violation (FunctionDef, line 207)

## UMDR42-021 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/graph/builder.py` (line 1116))
- **Detail:** route_after_pre_auth_identity (FunctionDef, line 1116)

## UMDR42-022 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/integration/target_adapter.py` (line 67))
- **Detail:** is_agnostic (FunctionDef, line 67)

## UMDR42-023 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/intelligence/application_model.py` (line 54))
- **Detail:** add_asset (FunctionDef, line 54)

## UMDR42-024 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/intelligence/state_model.py` (line 64))
- **Detail:** candidate_invariants (FunctionDef, line 64)

## UMDR42-025 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/intelligence/workflow_graph.py` (line 51))
- **Detail:** add_step (FunctionDef, line 51); entry_steps (FunctionDef, line 63)

## UMDR42-026 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/irta/metrics/benchmark.py` (line 34))
- **Detail:** recall_delta (FunctionDef, line 34)

## UMDR42-027 [MEDIUM] (dead-code) — 4 unreferenced public symbol(s)

- **File:** `src/webpent/irta/v3/blind.py` (line 65))
- **Detail:** register_owner_case (FunctionDef, line 65); detector_view (FunctionDef, line 72); accept_observation (FunctionDef, line 79); owner_evaluate (FunctionDef, line 100)

## UMDR42-028 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/jc/chamber.py` (line 187))
- **Detail:** get_session (FunctionDef, line 187)

## UMDR42-029 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/knowledge/auth_model.py` (line 15))
- **Detail:** from_target_knowledge (FunctionDef, line 15)

## UMDR42-030 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/knowledge/data_flow_model.py` (line 15))
- **Detail:** from_target_knowledge (FunctionDef, line 15)

## UMDR42-031 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/knowledge/entity_graph.py` (line 17))
- **Detail:** from_model (FunctionDef, line 17)

## UMDR42-032 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/knowledge/model_v2.py` (line 212))
- **Detail:** to_snapshot_json (FunctionDef, line 212); from_snapshot_json (FunctionDef, line 217)

## UMDR42-033 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/knowledge/workflow_model.py` (line 15))
- **Detail:** from_target_knowledge (FunctionDef, line 15); transition_candidates (FunctionDef, line 21)

## UMDR42-034 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/live_hunter/research_loop.py` (line 151))
- **Detail:** long_horizon_metrics (FunctionDef, line 151)

## UMDR42-035 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/causal_feedback_bridge.py` (line 121))
- **Detail:** run_research_loop (FunctionDef, line 121)

## UMDR42-036 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/experiment_outcome_tracker.py` (line 132))
- **Detail:** evidence_classes_produced (FunctionDef, line 132)

## UMDR42-037 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/interface.py` (line 181))
- **Detail:** apply_hypothesis_weights (FunctionDef, line 181)

## UMDR42-038 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/providers/base.py` (line 117))
- **Detail:** get_usage_stats (FunctionDef, line 117)

## UMDR42-039 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/providers/pool.py` (line 161))
- **Detail:** get_slot_count (FunctionDef, line 161)

## UMDR42-040 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/tool_boundary.py` (line 212))
- **Detail:** get_call_log (FunctionDef, line 212)

## UMDR42-041 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/llm_researcher/world_model.py` (line 77))
- **Detail:** get_stored (FunctionDef, line 77)

## UMDR42-042 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/memory/advisory_memory.py` (line 254))
- **Detail:** retrieval_log (FunctionDef, line 254)

## UMDR42-043 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/memory/decision_log.py` (line 287))
- **Detail:** get_entries_by_type (FunctionDef, line 287)

## UMDR42-044 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/memory/embeddings.py` (line 49))
- **Detail:** rag_enabled_override (FunctionDef, line 49)

## UMDR42-045 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/memory/lessons.py` (line 918))
- **Detail:** search_structured_lessons (FunctionDef, line 918)

## UMDR42-046 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/memory/postmortem.py` (line 416))
- **Detail:** get_records_by_category (FunctionDef, line 416)

## UMDR42-047 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/memory/vectorstore.py` (line 584))
- **Detail:** reset_vector_store_manager (FunctionDef, line 584); add_knowledge (FunctionDef, line 351)

## UMDR42-048 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/models/authorization_matrix.py` (line 76))
- **Detail:** confirmed_differential_count (FunctionDef, line 76)

## UMDR42-049 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/models/goal_tree.py` (line 278))
- **Detail:** create_standard_sweep_goal (FunctionDef, line 278); get_open_leaves (FunctionDef, line 371)

## UMDR42-050 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/models/hypothesis.py` (line 469))
- **Detail:** to_dict_for_logging (FunctionDef, line 469)

## UMDR42-051 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/production/advisory_registration.py` (line 335))
- **Detail:** AdvisoryRegistration (ClassDef, line 335)

## UMDR42-052 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/production/campaign_state.py` (line 157))
- **Detail:** update_agenda (FunctionDef, line 157)

## UMDR42-053 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/production/context_authority.py` (line 76))
- **Detail:** with_lifecycle (FunctionDef, line 76)

## UMDR42-054 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/production/fixture_intake.py` (line 227))
- **Detail:** FixtureIntake (ClassDef, line 227)

## UMDR42-055 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/recon/auth_handler.py` (line 14))
- **Detail:** BrowserAuthHandler (ClassDef, line 14)

## UMDR42-056 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/recon/auth_resilience.py` (line 70))
- **Detail:** build_query (FunctionDef, line 70)

## UMDR42-057 [MEDIUM] (dead-code) — 3 unreferenced public symbol(s)

- **File:** `src/webpent/recon/autonomous_crawler.py` (line 224))
- **Detail:** handle_starttag (FunctionDef, line 224); handle_endtag (FunctionDef, line 257); handle_data (FunctionDef, line 261)

## UMDR42-058 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/recon/login_executor.py` (line 177))
- **Detail:** handle_starttag (FunctionDef, line 177)

## UMDR42-059 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/research/planner.py` (line 52))
- **Detail:** build_queue (FunctionDef, line 52)

## UMDR42-060 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/research_engine/autonomous_scheduler.py` (line 140))
- **Detail:** record_task_outcome (FunctionDef, line 140)

## UMDR42-061 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/research_engine/feedback_loop.py` (line 139))
- **Detail:** apply_to_campaign (FunctionDef, line 139); apply_task_feedback (FunctionDef, line 192)

## UMDR42-062 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/research_engine/orchestrator.py` (line 140))
- **Detail:** plan_from_projections (FunctionDef, line 140)

## UMDR42-063 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/research_engine/projection_adapter.py` (line 76))
- **Detail:** from_sources (FunctionDef, line 76)

## UMDR42-064 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/research_engine/research_state.py` (line 72))
- **Detail:** add_hypothesis_ref (FunctionDef, line 72)

## UMDR42-065 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/scope/enforcer.py` (line 43))
- **Detail:** active_requests (FunctionDef, line 43); check_request (FunctionDef, line 202)

## UMDR42-066 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/service/facade.py` (line 237))
- **Detail:** record_learning_metrics (FunctionDef, line 237); tick_scheduler (FunctionDef, line 272)

## UMDR42-067 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/service/health.py` (line 80))
- **Detail:** verify_manifest (FunctionDef, line 80); run_forever (FunctionDef, line 109)

## UMDR42-068 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/service/manager.py` (line 115))
- **Detail:** list_snapshots (FunctionDef, line 115)

## UMDR42-069 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/agent_harness.py` (line 446))
- **Detail:** prompt_context (FunctionDef, line 446)

## UMDR42-070 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/autopentestx_adapter.py` (line 249))
- **Detail:** surface_data_from_autopentestx (FunctionDef, line 249); autopentestx_adapter_manifest (FunctionDef, line 293)

## UMDR42-071 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/cognitive_components.py` (line 468))
- **Detail:** ForcedHITLCategories (ClassDef, line 468)

## UMDR42-072 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/confidence.py` (line 346))
- **Detail:** recompute_hypothesis_confidence (FunctionDef, line 346)

## UMDR42-073 [MEDIUM] (dead-code) — 5 unreferenced public symbol(s)

- **File:** `src/webpent/shared/console.py` (line 77))
- **Detail:** print_phase_start (FunctionDef, line 77); print_phase_end (FunctionDef, line 86); create_progress (FunctionDef, line 99); print_info (FunctionDef, line 356); print_success (FunctionDef, line 361)

## UMDR42-074 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/control_plane_runtime.py` (line 581))
- **Detail:** read_correlated (FunctionDef, line 581)

## UMDR42-075 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/control_plane_spine.py` (line 226))
- **Detail:** start_workflow (FunctionDef, line 226); apply_workflow_step (FunctionDef, line 249)

## UMDR42-076 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/direct_io_inventory.py` (line 740))
- **Detail:** inventory_contract_errors (FunctionDef, line 740)

## UMDR42-077 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/engagement_scope.py` (line 141))
- **Detail:** is_engagement (FunctionDef, line 141)

## UMDR42-078 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/fixture_store.py` (line 255))
- **Detail:** read_quarantined_bytes (FunctionDef, line 255)

## UMDR42-079 [MEDIUM] (dead-code) — 3 unreferenced public symbol(s)

- **File:** `src/webpent/shared/http_discovery.py` (line 140))
- **Detail:** handle_starttag (FunctionDef, line 140); handle_endtag (FunctionDef, line 186); handle_data (FunctionDef, line 182)

## UMDR42-080 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/identity_provisioning.py` (line 83))
- **Detail:** reject_raw_material (FunctionDef, line 83)

## UMDR42-081 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/llm.py` (line 209))
- **Detail:** clear_llm_usage_trace (FunctionDef, line 209); reset_dead_providers (FunctionDef, line 417)

## UMDR42-082 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/nettacker_adapter.py` (line 304))
- **Detail:** surface_data_from_nettacker (FunctionDef, line 304); nettacker_adapter_manifest (FunctionDef, line 347)

## UMDR42-083 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/oob_provider.py` (line 256))
- **Detail:** redact_provider_command (FunctionDef, line 256)

## UMDR42-084 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/p9_qualification.py` (line 221))
- **Detail:** get_dead_letter (FunctionDef, line 221)

## UMDR42-085 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/persistent_finding_ledger.py` (line 292))
- **Detail:** export_digest (FunctionDef, line 292)

## UMDR42-086 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/provider_boundary.py` (line 27))
- **Detail:** safe_descriptor (FunctionDef, line 27)

## UMDR42-087 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/rate_governor.py` (line 286))
- **Detail:** is_aborted (FunctionDef, line 286)

## UMDR42-088 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/recovery.py` (line 183))
- **Detail:** request_stop (FunctionDef, line 183); should_execute (FunctionDef, line 186)

## UMDR42-089 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/reference_lookup.py` (line 140))
- **Detail:** reset_lookup_budget (FunctionDef, line 140)

## UMDR42-090 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/runtime.py` (line 363))
- **Detail:** require_capability (FunctionDef, line 363); execute_registered_case (FunctionDef, line 380)

## UMDR42-091 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/scope_file.py` (line 268))
- **Detail:** build_runtime_handle (FunctionDef, line 268); spec_from_state (FunctionDef, line 273)

## UMDR42-092 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/secondary_io_scanner.py` (line 226))
- **Detail:** cross_check_primary (FunctionDef, line 226)

## UMDR42-093 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/secret_vault.py` (line 130))
- **Detail:** purge_expired (FunctionDef, line 130)

## UMDR42-094 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/security_reasoning_memory.py` (line 172))
- **Detail:** remember_research (FunctionDef, line 172); researcher_summary (FunctionDef, line 209)

## UMDR42-095 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/stealth.py` (line 227))
- **Detail:** async_enforce_min_interval (AsyncFunctionDef, line 227); reset_rate_limits (FunctionDef, line 278)

## UMDR42-096 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/target_package_context.py` (line 268))
- **Detail:** assert_package_continuity (FunctionDef, line 268)

## UMDR42-097 [MEDIUM] (dead-code) — 10 unreferenced public symbol(s)

- **File:** `src/webpent/shared/target_spec.py` (line 224))
- **Detail:** RequestBudget (ClassDef, line 224); load_target_spec (FunctionDef, line 247); validate_window (FunctionDef, line 37); validate_hosts (FunctionDef, line 82); validate_ports (FunctionDef, line 100); validate_schemes (FunctionDef, line 107); validate_paths (FunctionDef, line 115); validate_base (FunctionDef, line 127); validate_redirect (FunctionDef, line 208); validate_resolved_addresses (FunctionDef, line 211)

## UMDR42-098 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/shared/tool_adapters.py` (line 295))
- **Detail:** get_tool_adapter (FunctionDef, line 295)

## UMDR42-099 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/shared/untrusted_content.py` (line 63))
- **Detail:** handle_starttag (FunctionDef, line 63); handle_data (FunctionDef, line 75)

## UMDR42-100 [MEDIUM] (dead-code) — 2 unreferenced public symbol(s)

- **File:** `src/webpent/smart/integration.py` (line 119))
- **Detail:** get_memory_hint (FunctionDef, line 119); audit_snapshot (FunctionDef, line 123)

## UMDR42-101 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/tools/exploitation/phpggc.py` (line 205))
- **Detail:** run_phpggc (FunctionDef, line 205)

## UMDR42-102 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/utils/compliance.py` (line 160))
- **Detail:** apply_compliance_tags (FunctionDef, line 160)

## UMDR42-103 [MEDIUM] (dead-code) — 1 unreferenced public symbol(s)

- **File:** `src/webpent/utils/crypto.py` (line 175))
- **Detail:** verify_evidence_bundle (FunctionDef, line 175)

## UMDR42-104 [MEDIUM] (weak-code) — silent except-pass: 6 occurrences

- **File:** `src/`
- **Detail:** pattern scan across src/; see audit .md for per-file detail

## UMDR42-105 [LOW] (markers) — 0 TODO/FIXME/XXX/HACK markers in 0 files

- **File:** `src/`
- **Detail:** tracked backlog markers

## UMDR42-106 [INFO] (error) — compileall clean

- **File:** `src/`
- **Detail:** all modules compile

## UMDR42-107 [INFO] (lint) — ruff findings: 3314

- **File:** `src/`
- **Detail:** Full list in ruff output; categorized counts in detail. This is pre-existing tracked debt (ruff ratchet baseline in scripts/quality/ruff_baseline.json governs CI); recorded for the audit, fix handled via the ratchet, not one-by-one here. | top codes: E501=2205, E702=302, E701=168, UP037=85, I001=77, B008=32, `Mapping`=31, UP045=30, `Iterable`,=26, SIM105=22

## UMDR42-108 [INFO] (tooling) — bandit not installed in sandbox

- **File:** `-`
- **Detail:** -

