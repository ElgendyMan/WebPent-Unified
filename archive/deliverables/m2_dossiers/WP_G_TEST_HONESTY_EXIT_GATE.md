# D3 — WP-G DOSSIER: TEST HONESTY + EXIT GATE
Ruling item: R8.
Files: tests/team1_acceptance/test_i_official_entrypoint.py (R8 rewrite); tests/team1_acceptance/test_sprint_i1_part1_regressions.py (fake removed); NEW tests/team1_acceptance/test_m2_graph_chain_gate.py; NEW tests/team1_acceptance/test_m2_transport_contract.py; tests/conftest.py (per-test WEBPENT_AUDIT_ROOT isolation — durable-store cross-test contamination + repo-residue prevention).
Modified pre-existing tests (C5 ledger — all pre-authorized by R2/R8):
1. test_i_official_entrypoint.py::test_graph_invoke_activates_modern_spine — no exception swallowing, no direct-node proof; real graph.stream bounded probe; asserts prohibited transport absent.
2. test_sprint_i1_part1_regressions.py::test_legacy_cannot_clobber_hypotheses_or_candidate_hypotheses — fake modern/legacy nodes REMOVED (honest real-node invocation preserved; same protected-key contract).
3-7. test_half2_production_dataflow.py, test_a_modern_production_path.py, test_production_research_loop_activation.py, test_h_integrated_run.py, test_half1_behavioral.py — `_modern_orchestrator in state` assertions updated to the R2 contract (prohibited transport absent; markers/counters assert the same production properties).
8. test_sprint_i3_e2e_flow_vertical.py::Test56... — operator flag authorization env added (R6 gating; the fixture path now requires operator-enabled flags).
9. tests/conftest.py — autouse isolation fixture (documented in fixture docstring).
EXIT GATE: test_exit_gate_nonempty_research_loop_through_graph — through-graph chain green (see file docstring for the full chain).
