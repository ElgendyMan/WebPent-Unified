# Architecture map — WebPent-Unified (UM-DR-45, M4 inventory)

Trunk: `feature/umdr44-security-and-identity-closure` @ `f5af4969b80c`. Package root: `WebPent_UNIFIED/` (1128 Python files under `src/webpent`, 752 test files).
This map is an inventory produced by `scripts/umdr45_inventory.py`; it changes no code.

## 1. Package layout

| Package | Python files | Importer files (outside itself) | Classification |
| --- | ---: | ---: | --- |
| `src/webpent/adapters/` | 24 | 3 | WIRED |
| `src/webpent/adaptive/` | 5 | 1 | WIRED |
| `src/webpent/agents/` | 113 | 18 | WIRED |
| `src/webpent/apex/` | 13 | 2 | WIRED |
| `src/webpent/api/` | 6 | 9 | WIRED |
| `src/webpent/appmodel/` | 3 | 1 | WIRED |
| `src/webpent/approvals/` | 3 | 0 | ORPHAN_PACKAGE |
| `src/webpent/appsuite/` | 12 | 0 | ORPHAN_PACKAGE |
| `src/webpent/attack_graph/` | 7 | 5 | WIRED |
| `src/webpent/auth/` | 5 | 8 | WIRED |
| `src/webpent/autonomous/` | 43 | 17 | WIRED |
| `src/webpent/benchmark/` | 24 | 0 | ORPHAN_PACKAGE |
| `src/webpent/brain/` | 9 | 1 | WIRED |
| `src/webpent/business_logic/` | 7 | 3 | WIRED |
| `src/webpent/campaign/` | 28 | 2 | WIRED |
| `src/webpent/causal_reasoning/` | 6 | 0 | ORPHAN_PACKAGE |
| `src/webpent/causal_reasoning_v2/` | 17 | 1 | WIRED |
| `src/webpent/chained_exploits/` | 6 | 2 | WIRED |
| `src/webpent/cli/` | 20 | 3 | ENTRY_POINT |
| `src/webpent/config/` | 4 | 120 | WIRED |
| `src/webpent/core/` | 3 | 0 | ORPHAN_PACKAGE |
| `src/webpent/coverage/` | 5 | 3 | WIRED |
| `src/webpent/cqa_v2/` | 10 | 19 | WIRED |
| `src/webpent/dashboard/` | 0 | 0 | ORPHAN_PACKAGE |
| `src/webpent/deception/` | 6 | 1 | WIRED |
| `src/webpent/deep/` | 16 | 0 | ORPHAN_PACKAGE |
| `src/webpent/dojo/` | 16 | 1 | WIRED |
| `src/webpent/econ/` | 13 | 1 | WIRED |
| `src/webpent/egaie/` | 33 | 6 | WIRED |
| `src/webpent/ekg/` | 4 | 0 | ORPHAN_PACKAGE |
| `src/webpent/evalsuite/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/explorer/` | 2 | 1 | WIRED |
| `src/webpent/families/` | 6 | 19 | WIRED |
| `src/webpent/forge/` | 21 | 0 | ORPHAN_PACKAGE |
| `src/webpent/graph/` | 10 | 6 | WIRED |
| `src/webpent/graphql_testing/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/integration/` | 16 | 4 | WIRED |
| `src/webpent/integrations/` | 9 | 3 | WIRED |
| `src/webpent/intelligence/` | 9 | 4 | WIRED |
| `src/webpent/irta/` | 21 | 1 | WIRED |
| `src/webpent/jc/` | 15 | 1 | WIRED |
| `src/webpent/jsintel/` | 3 | 1 | WIRED |
| `src/webpent/knowledge/` | 9 | 8 | WIRED |
| `src/webpent/labsuite/` | 4 | 0 | ORPHAN_PACKAGE |
| `src/webpent/learning/` | 7 | 8 | WIRED |
| `src/webpent/live_hunter/` | 6 | 5 | WIRED |
| `src/webpent/llm_researcher/` | 19 | 8 | WIRED |
| `src/webpent/memory/` | 18 | 37 | WIRED |
| `src/webpent/models/` | 29 | 201 | WIRED |
| `src/webpent/monitor/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/multi_step_auth/` | 3 | 2 | WIRED |
| `src/webpent/oast/` | 4 | 1 | WIRED |
| `src/webpent/oauth/` | 3 | 2 | WIRED |
| `src/webpent/oracle/` | 14 | 4 | WIRED |
| `src/webpent/portfolio/` | 2 | 1 | WIRED |
| `src/webpent/prism/` | 17 | 2 | WIRED |
| `src/webpent/production/` | 61 | 35 | WIRED |
| `src/webpent/qualification/` | 4 | 0 | ORPHAN_PACKAGE |
| `src/webpent/race_conditions/` | 3 | 1 | WIRED |
| `src/webpent/recon/` | 20 | 6 | WIRED |
| `src/webpent/remediation/` | 14 | 1 | WIRED |
| `src/webpent/reporter/` | 10 | 5 | WIRED |
| `src/webpent/reporting/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/research/` | 11 | 4 | WIRED |
| `src/webpent/research_engine/` | 16 | 2 | WIRED |
| `src/webpent/resume/` | 2 | 1 | WIRED |
| `src/webpent/safety/` | 7 | 6 | WIRED |
| `src/webpent/scheduler/` | 2 | 2 | WIRED |
| `src/webpent/scope/` | 8 | 9 | WIRED |
| `src/webpent/secrets_scanner/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/service/` | 11 | 2 | WIRED |
| `src/webpent/shared/` | 164 | 159 | WIRED |
| `src/webpent/smart/` | 6 | 11 | WIRED |
| `src/webpent/state/` | 5 | 49 | WIRED |
| `src/webpent/stateful_api/` | 4 | 1 | WIRED |
| `src/webpent/targeting/` | 3 | 1 | WIRED |
| `src/webpent/templates/` | 0 | 0 | ORPHAN_PACKAGE |
| `src/webpent/tenant_isolation/` | 3 | 2 | WIRED |
| `src/webpent/tools/` | 19 | 12 | WIRED |
| `src/webpent/utils/` | 4 | 8 | WIRED |
| `src/webpent/validators/` | 6 | 7 | WIRED |
| `src/webpent/verification/` | 5 | 1 | WIRED |
| `src/webpent/vip/` | 5 | 7 | WIRED |
| `src/webpent/vulns/` | 6 | 2 | WIRED |
| `src/webpent/waf_evasion/` | 2 | 0 | ORPHAN_PACKAGE |
| `src/webpent/workers/` | 4 | 1 | WIRED |
| `src/webpent/workflow_fuzzing/` | 3 | 0 | ORPHAN_PACKAGE |

Packages with no importer are listed in `orphan_inventory.json`. `ENTRY_POINT` means the package is started by a launcher (`cli`, `api`, `__main__`) rather than imported.

## 2. Graph wiring (LangGraph `add_node` / `add_edge` call sites)

| File | Nodes | Edges |
| --- | ---: | ---: |
| `src/webpent/agents/hunter_graph.py` | 4 | 0 |
| `src/webpent/shared/surface_evidence_graph.py` | 1 | 0 |

## 4. Agent decision register (D5)

54 agent units under `src/webpent/agents/` (46 folders + 8 root modules), each with exactly one decision: KEEP 44, KEEP-DORMANT 8, RETIRE-CANDIDATE 2.

| Agent unit | Kind | `agent.py` | Production importers | Test importers | Graph node | Decision |
| --- | --- | :-: | ---: | ---: | --- | --- |
| `access_control` | folder | yes | 2 | 9 | — | KEEP — reachable from production code |
| `advanced_web_vulns` | folder | yes | 1 | 1 | — | KEEP — reachable from production code |
| `api_testing` | folder | yes | 3 | 2 | — | KEEP — reachable from production code |
| `attack_graph` | folder | yes | 1 | 0 | — | KEEP — reachable from production code |
| `authentication` | folder | yes | 5 | 10 | — | KEEP — reachable from production code |
| `business_impact` | folder | yes | 1 | 0 | — | KEEP — reachable from production code |
| `business_logic_fuzzer` | folder | yes | 2 | 6 | — | KEEP — reachable from production code |
| `cache_poisoning` | folder | yes | 1 | 2 | — | KEEP — reachable from production code |
| `chain_planner` | folder | yes | 0 | 2 | — | KEEP-DORMANT — imported only by tests |
| `cloud_storage` | folder | yes | 3 | 2 | — | KEEP — reachable from production code |
| `crawler` | folder | yes | 1 | 7 | — | KEEP — reachable from production code |
| `cross_reasoning` | folder | yes | 1 | 0 | — | KEEP — reachable from production code |
| `cvss_engine` | folder | yes | 1 | 2 | — | KEEP — reachable from production code |
| `devils_advocate` | folder | yes | 2 | 3 | — | KEEP — reachable from production code |
| `disclosed_report_intel` | folder | yes | 1 | 1 | — | KEEP — reachable from production code |
| `dom_xss` | folder | yes | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `execution_sandbox` | folder | yes | 1 | 6 | — | KEEP — reachable from production code |
| `executive_summary` | folder | yes | 1 | 1 | — | KEEP — reachable from production code |
| `exploit_chainer` | folder | yes | 3 | 3 | — | KEEP — reachable from production code |
| `graphql_testing` | folder | yes | 1 | 1 | — | KEEP — reachable from production code |
| `hypothesis_analyzer` | folder | yes | 3 | 16 | — | KEEP — reachable from production code |
| `javascript_intelligence` | folder | yes | 1 | 2 | — | KEEP — reachable from production code |
| `js_discovery` | folder | yes | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `multi_step_auth` | folder | yes | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `oauth_hunter` | folder | yes | 0 | 2 | — | KEEP-DORMANT — imported only by tests |
| `payload_generator` | folder | yes | 1 | 5 | — | KEEP — reachable from production code |
| `payload_optimizer` | folder | yes | 1 | 2 | — | KEEP — reachable from production code |
| `planner` | folder | yes | 2 | 6 | planner | KEEP — reachable from production code |
| `post_exploit` | folder | yes | 2 | 2 | — | KEEP — reachable from production code |
| `prototype_pollution` | folder | yes | 1 | 2 | — | KEEP — reachable from production code |
| `rabbit_hole` | folder | yes | 1 | 4 | — | KEEP — reachable from production code |
| `recon` | folder | yes | 3 | 4 | — | KEEP — reachable from production code |
| `reflection` | folder | yes | 1 | 0 | — | KEEP — reachable from production code |
| `reporter` | folder | yes | 2 | 7 | — | KEEP — reachable from production code |
| `request_smuggling` | folder | yes | 3 | 6 | — | KEEP — reachable from production code |
| `role_matrix` | folder | no | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `scope_enforcer` | folder | yes | 3 | 1 | — | KEEP — reachable from production code |
| `smart_campaigns` | folder | yes | 4 | 5 | — | KEEP — reachable from production code |
| `sourcemap_analysis` | folder | yes | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `specialists` | folder | no | 0 | 0 | — | RETIRE-CANDIDATE — no importer anywhere |
| `strategist` | folder | yes | 2 | 6 | — | KEEP — reachable from production code |
| `subdomain_takeover` | folder | yes | 3 | 3 | — | KEEP — reachable from production code |
| `target_understanding` | folder | yes | 2 | 3 | — | KEEP — reachable from production code |
| `tenant_isolation` | folder | yes | 0 | 1 | — | KEEP-DORMANT — imported only by tests |
| `validator` | folder | yes | 13 | 34 | validator | KEEP — reachable from production code |
| `waf_detector` | folder | yes | 1 | 0 | — | KEEP — reachable from production code |
| `chain_engine` | root module | yes | 1 | 2 | — | KEEP — reachable from production code |
| `curiosity_engine` | root module | yes | 1 | 1 | — | KEEP — reachable from production code |
| `hunter_contracts` | root module | yes | 4 | 7 | — | KEEP — reachable from production code |
| `hunter_graph` | root module | yes | 1 | 5 | — | KEEP — reachable from production code |
| `hunter_runner` | root module | yes | 1 | 10 | — | KEEP — reachable from production code |
| `note_taker` | root module | yes | 1 | 1 | — | KEEP — reachable from production code |
| `personas` | root module | yes | 1 | 2 | — | KEEP — reachable from production code |
| `team` | root module | yes | 0 | 0 | — | RETIRE-CANDIDATE — no importer anywhere |

## 4. Version identity

```json
{
  "pyproject.toml": "0.40.1",
  "src/webpent/__init__.py": "0.40.1",
  "WebPent_UNIFIED/BUILD_INFO.json": null,
  "api/app.py version literals": [
    "1.0.0"
  ],
  "consistent": false
}
```

## 5. Reading the map

`WIRED` packages are imported by at least one other package. An agent counted as `KEEP-DORMANT` has tests but no production importer: it is retained and documented, not silently reachable. A `RETIRE-CANDIDATE` has no importer under `src/` or `tests/` at all; it is listed for the owner and is not deleted here.
