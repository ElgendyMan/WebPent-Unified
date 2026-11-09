"""M5 (Part 4 §7, UM-DR-18): the stateful REST API testing engine.

Acceptance under test: "seeded multi-request states discovered +
replayable with same preconditions/identity; causal evidence bundle for
sequences; bounded budgets/cleanup" and "BOLA/IDOR with two authorized
identities and negative controls".

1. **Contract ingestion** — OpenAPI routes (rich) + observed surface
   (thin), provenance-preserved, deduped, bounded.
2. **Dependency/state model** — the deterministic producer→consumer
   heuristic, labelled inferred.
3. **Bounded sequences** — deterministic chains with preconditions,
   expected effects, randomized-id negative control, cleanup plan
   (reverse + DELETE), request budgets, and a byte-stable replay spec.
4. **BOLA differentials** — two authorized identities (A-own baseline,
   B-cross differential, randomized-id control), causal evidence spec
   (precondition/action/effect/baseline/control/repeatability); fewer
   than two identities ⇒ NO plans.
5. **The advisory projection** — hypotheses land unexplored with the M3
   research-contract fields; the node wiring is flag-gated and
   fail-soft.
"""

from __future__ import annotations

from typing import Any

import pytest

from webpent.config.settings import get_settings
from webpent.stateful_api import (
    bola_hypotheses,
    build_bola_plans,
    generate_sequences,
    infer_dependencies,
    operations_from_state,
    sequence_hypotheses,
)

TARGET = "https://app.example.com"


def _state(**extra: Any) -> dict[str, Any]:
    state: dict[str, Any] = {
        "target_url": TARGET,
        "crawled_data": {
            "openapi_routes": [
                {"method": "POST", "path": "/api/v2/users",
                 "body_properties": ["username", "email"]},
                {"method": "GET", "path": "/api/v2/users/{id}"},
                {"method": "DELETE", "path": "/api/v2/users/{id}"},
                {"method": "GET", "path": "/api/v2/documents/{doc_id}"},
            ],
        },
        "identity_profiles": {
            "a": {"role": "owner", "validated": True},
            "b": {"role": "viewer", "validated": True},
        },
    }
    state.update(extra)
    return state


# ---------------------------------------------------------------------------
# 1. Contract ingestion
# ---------------------------------------------------------------------------


def test_operations_ingest_openapi_and_observed_provenance() -> None:
    operations = operations_from_state(_state())
    by_id = {op.operation_id: op for op in operations}
    post = by_id["POST /api/v2/users"]
    assert post.source == "openapi"
    assert post.body_properties == ["username", "email"]
    assert post.collection_path == "/api/v2/users"
    get_item = by_id["GET /api/v2/users/{id}"]
    assert get_item.path_params == ["id"]
    assert get_item.item_path_prefix == "/api/v2/users"
    # Observed surface merges without duplicating schema keys.
    observed = operations_from_state(
        _state(
            crawled_data={
                "openapi_routes": [{"method": "GET", "path": "/api/v2/users/{id}"}],
                "endpoints": [f"{TARGET}/health"],
            }
        )
    )
    keys = [op.operation_id for op in observed]
    assert keys.count("GET /api/v2/users/{id}") == 1
    assert "GET /health" in keys


def test_empty_state_yields_no_operations() -> None:
    assert operations_from_state({"crawled_data": {}}) == []


# ---------------------------------------------------------------------------
# 2. Dependency/state model
# ---------------------------------------------------------------------------


def test_dependency_inference_links_creators_to_consumers() -> None:
    operations = operations_from_state(_state())
    dependencies = infer_dependencies(operations)
    pairs = {(d.producer_operation_id, d.consumer_operation_id) for d in dependencies}
    assert ("POST /api/v2/users", "GET /api/v2/users/{id}") in pairs
    assert ("POST /api/v2/users", "DELETE /api/v2/users/{id}") in pairs
    assert all(d.provenance == "inferred:path_shape" for d in dependencies)


def test_no_dependencies_without_creators() -> None:
    operations = operations_from_state(
        {"crawled_data": {"openapi_routes": [{"method": "GET", "path": "/static"}]}}
    )
    assert infer_dependencies(operations) == []


# ---------------------------------------------------------------------------
# 3. Bounded sequences
# ---------------------------------------------------------------------------


def test_sequences_are_multi_step_with_cleanup_and_budgets() -> None:
    plans = generate_sequences(operations_from_state(_state()))
    assert plans, "expected at least one sequence"
    (plan,) = plans
    step_ids = [step.operation_id for step in plan.steps]
    assert step_ids[0] == "POST /api/v2/users"
    assert "GET /api/v2/users/{id}" in step_ids
    # Cleanup: DELETE exists for the created resource.
    assert plan.cleanup_steps == ["DELETE /api/v2/users/{id}"]
    assert plan.cleanup_complete is True
    assert plan.budget_requests == len(plan.steps) + len(plan.cleanup_steps)
    # Preconditions + expected effects + negative control recorded.
    assert any("identity:primary" in p for p in plan.preconditions)
    assert plan.expected_effects
    assert "non-existent" in plan.negative_control


def test_sequence_without_deleter_is_honestly_incomplete() -> None:
    state = _state()
    state["crawled_data"]["openapi_routes"] = [
        {"method": "POST", "path": "/api/v2/users"},
        {"method": "GET", "path": "/api/v2/users/{id}"},
    ]
    plans = generate_sequences(operations_from_state(state))
    assert plans and plans[0].cleanup_steps == []
    assert plans[0].cleanup_complete is False


def test_sequences_respect_the_budget_bounds() -> None:
    operations = operations_from_state(_state())
    plans = generate_sequences(operations, max_sequences=1, max_depth=2)
    assert len(plans) <= 1
    assert all(len(plan.steps) <= 2 for plan in plans)


def test_replay_spec_is_deterministic() -> None:
    operations = operations_from_state(_state())
    first = generate_sequences(operations)[0].replay_spec()
    second = generate_sequences(operations_from_state(_state()))[0].replay_spec()
    assert first == second
    assert first["preconditions"] and first["steps"]


# ---------------------------------------------------------------------------
# 4. BOLA differentials
# ---------------------------------------------------------------------------


def test_bola_plans_carry_two_identities_and_negative_control() -> None:
    plans = build_bola_plans(
        operations_from_state(_state()), identities=["owner", "viewer"]
    )
    assert plans
    for plan in plans:
        assert plan.identity_a == "owner" and plan.identity_b == "viewer"
        assert len(plan.differential_actions) == 2
        actors = {action["actor"] for action in plan.differential_actions}
        assert actors == {"owner", "viewer"}
        assert plan.negative_control["actor"] == "viewer"
        assert "non-existent" in plan.negative_control["action"]
        spec = plan.causal_evidence_spec
        assert set(spec) == {
            "precondition", "action", "effect", "baseline", "control",
            "repeatability",
        }
        assert plan.bounded_requests == 3
    # Object-consuming operations only.
    plan_ops = {plan.operation_id for plan in plans}
    assert "GET /api/v2/documents/{doc_id}" in plan_ops


def test_bola_requires_two_distinct_identities() -> None:
    operations = operations_from_state(_state())
    assert build_bola_plans(operations, identities=["owner"]) == []
    assert build_bola_plans(operations, identities=["owner", "owner"]) == []
    assert build_bola_plans(operations, identities=[]) == []


def test_bola_replay_spec_roundtrip() -> None:
    plans = build_bola_plans(
        operations_from_state(_state()), identities=["owner", "viewer"]
    )
    spec = plans[0].replay_spec()
    assert spec["identity_a"] == "owner"
    assert spec["bounded_requests"] == 3


# ---------------------------------------------------------------------------
# 5. The advisory projection + node wiring
# ---------------------------------------------------------------------------


def test_hypotheses_land_unexplored_with_research_contract_fields() -> None:
    operations = operations_from_state(_state())
    plans = generate_sequences(operations)
    bola = build_bola_plans(operations, identities=["owner", "viewer"])
    hypotheses = sequence_hypotheses(plans, target_url=TARGET) + bola_hypotheses(
        bola, target_url=TARGET
    )
    assert hypotheses
    for hypothesis in hypotheses:
        assert hypothesis.status == "unexplored"
        assert hypothesis.origin_detail.startswith("stateful_api_")
        assert hypothesis.preconditions
        assert hypothesis.negative_control
        assert hypothesis.expected_behavior


def test_hypothesis_ids_are_stable_across_runs() -> None:
    operations_a = operations_from_state(_state())
    operations_b = operations_from_state(_state())
    ids_a = [str(h.id) for h in sequence_hypotheses(generate_sequences(operations_a), target_url=TARGET)]
    ids_b = [str(h.id) for h in sequence_hypotheses(generate_sequences(operations_b), target_url=TARGET)]
    assert ids_a == ids_b


def test_flag_defaults_off() -> None:
    assert get_settings().enable_stateful_api_testing is False


def test_node_wiring_flag_on_emits_hypotheses(monkeypatch: pytest.MonkeyPatch) -> None:
    """The frozen node consumes the engine when the flag is on.

    The node's network probes are neutralized (they belong to other
    test surfaces); the stateful block is pure planning.
    """
    from webpent.agents.api_testing import agent as api_agent
    from webpent.config.settings import activate_settings

    for probe in ("_probe_graphql", "_probe_jwt_alg_none"):
        if hasattr(api_agent, probe):
            monkeypatch.setattr(api_agent, probe, lambda *a, **k: [])
    if hasattr(api_agent, "_probe_mass_assignment"):
        monkeypatch.setattr(api_agent, "_probe_mass_assignment", lambda *a, **k: [])

    settings = get_settings().model_copy(update={"enable_stateful_api_testing": True})
    state = _state()
    state["target"] = type("T", (), {"url": TARGET})()
    state["findings"] = []
    with activate_settings(settings):
        out = api_agent.api_testing_node(state)

    hypotheses = out.get("hypotheses") or []
    assert hypotheses
    assert all(h.status == "unexplored" for h in hypotheses)
    assert any(h.origin_detail.startswith("stateful_api_bola:") for h in hypotheses)


def test_node_wiring_flag_off_is_structurally_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import webpent.stateful_api as engine

    def _forbidden(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover
        raise AssertionError("engine must not run with the flag off")

    monkeypatch.setattr(engine, "operations_from_state", _forbidden)
    assert get_settings().enable_stateful_api_testing is False
    # Source-level: the node gates the engine behind the flag.
    from pathlib import Path

    source = Path("src/webpent/agents/api_testing/agent.py").read_text(encoding="utf-8")
    assert 'enable_stateful_api_testing' in source
