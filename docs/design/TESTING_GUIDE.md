# WebPent Family Coverage — Testing & Integration Guide

## Running the tests

```bash
# Full project (CI — has all deps: langgraph, httpx, pydantic)
PYTHONPATH=src python3 -m pytest tests/test_five_families.py -q

# Minimal environment (no langgraph/httpx) — skips the autouse conftest fixture
PYTHONPATH=src python3 -m pytest tests/test_five_families.py -q -c /dev/null --noconftest
```

The `--noconftest` flag is only needed when `langchain_core`/`langgraph` are not
installed (the project-wide `conftest.py` autouse fixture imports the production
spine). In CI with full deps, run normally.

## Injecting a real HTTP executor

The `family_execution_node` does NOT own an HTTP client (separation of
concerns). Inject one via state:

```python
state["http_executor"] = lambda request_plan: httpx_client.request(
    request_plan.method, request_plan.url, headers=request_plan.headers,
    content=request_plan.body,
)
```

A default SSRF-pinned executor is built automatically via
`get_default_http_executor()` when `httpx` and `webpent.shared.http` are
available. If unavailable, the node emits `plans_pending_execution` and never
fakes replays (fail-closed).

## Enabling deeper modes

- `state["goed_max_iterations"] = 3` — run the GOED generative loop up to 3
  deeper iterations (default 1, max 5). Stops early when no new chains appear.
- `state["deep_exploration"] = True` — treat detected anomalies as capabilities
  for the creative hypothesis generator (more hypotheses, slightly more noise).
- `state["allowed_endpoints"] = ["/api/..."]` — scope-filter candidates.
- `state["action_authority"] = ...` — full ActionAuthority permit check.

## What the node outputs

- `family_execution_status`: `ok` | `plans_pending_execution` | `executed_and_validated`
- `family_candidates`, `family_execution_plans`, `family_executed_plans`
- `family_validation_results`, `family_proof_bundles`, `family_findings_merged`
- `attack_graph_chains_total/confirmed`, `goed_feedback_hypotheses`
- `adversarial_review_downgraded` (findings downgraded by the skeptic)
- `creative_hybrid_hypotheses`, `expanded_attack_surface`

## Known limitations (honest)

1. Tests use a mock executor — real-target testing requires a safe authorized
   target and scope approval.
2. Single-artifact chains do NOT confirm (validator requires >=2 feeders) —
   correct by design; multi-artifact composition requires endpoint grouping.
3. `business_logic` scenarios load via direct-file import to avoid the
   langchain-heavy `__init__.py` — if the file moves, `business_logic_unavailable`
   appears in notes.
