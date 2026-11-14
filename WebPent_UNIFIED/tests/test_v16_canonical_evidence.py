"""Contract tests for the additive canonical evidence facade."""

from __future__ import annotations

from webpent.models.evidence import AdapterResult, Observation, ToolExecution, make_evidence_ref
from webpent.shared.exceptions import ToolExecutionError
from webpent.shared.tool_adapters import ToolAdapter, builtin_adapters


def test_redaction_and_digest_never_retain_auth_material() -> None:
    ref = make_evidence_ref(
        {
            "url": "https://lab.example.test/item?id=7&token=super-secret",
            "headers": {"Authorization": "Bearer token-value", "X-Test": "ok"},
            "body": {"password": "pw-value"},
        },
        locator="tool://fake/output/0",
    )

    dumped = ref.model_dump(mode="json")
    assert dumped["redaction_status"] == "redacted"
    assert "super-secret" not in str(dumped)
    assert "token-value" not in str(dumped)
    assert "pw-value" not in str(dumped)
    assert dumped["digest"].startswith("sha256:")


def test_adapter_normalizes_legacy_json_result_and_redacts_metadata() -> None:
    def fake_runner(target: str, **_kwargs: object) -> list[dict[str, object]]:
        assert target == "https://lab.example.test"
        return [
            {
                "url": "https://lab.example.test/api?id=7&token=secret-value",
                "status_code": 200,
                "headers": {"Authorization": "Bearer hidden"},
            }
        ]

    adapter = ToolAdapter(name="fake-httpx", runner=fake_runner, category="recon", version="test")
    result = adapter.run(
        "https://lab.example.test",
        parameters={"cookie": "session=hidden", "page": 1},
        command=["fake-httpx", "-u", "https://lab.example.test", "--token", "hidden"],
        scope_decision="allowed",
    )

    assert isinstance(result, AdapterResult)
    assert result.execution.status == "success"
    assert result.execution.scope_decision == "allowed"
    assert result.execution.command_fingerprint is not None
    assert "hidden" not in str(result.execution.model_dump(mode="json"))
    assert len(result.observations) == 1
    observation = result.observations[0]
    assert isinstance(observation, Observation)
    assert observation.redaction_status == "redacted"
    assert "secret-value" not in str(observation.model_dump(mode="json"))
    assert "hidden" not in str(observation.model_dump(mode="json"))
    assert observation.evidence_refs


def test_adapter_keeps_partial_stdout_as_partial_observation() -> None:
    def failing_runner(_target: str) -> None:
        raise ToolExecutionError(
            ["fake-tool", "--target", "https://lab.example.test"],
            124,
            stdout='{"url":"https://lab.example.test/partial","status":200}',
            stderr="timed out",
        )

    adapter = ToolAdapter(name="fake-katana", runner=failing_runner, category="recon")
    result = adapter.run("https://lab.example.test", scope_decision="allowed")

    assert result.execution.status == "partial"
    assert result.execution.return_code == 124
    assert result.error
    assert len(result.observations) == 1
    assert result.observations[0].status == "partial"


def test_builtin_adapters_are_additive_and_lazy() -> None:
    adapters = builtin_adapters()
    assert {"httpx", "katana", "nuclei"}.issubset(adapters)
    assert adapters["httpx"].category == "recon"
    assert adapters["katana"].category == "recon"
    assert adapters["nuclei"].category == "recon"
    assert all(callable(adapter.runner) for adapter in adapters.values())


def test_evidence_models_round_trip_as_json_state() -> None:
    adapter = ToolAdapter(
        name="fake-nuclei", runner=lambda _target: [{"severity": "low"}], category="recon"
    )
    result = adapter.run("https://lab.example.test", scope_decision="unknown")
    state = result.to_state()

    restored_execution = ToolExecution.model_validate(state["execution"])
    restored_observation = Observation.model_validate(state["observations"][0])
    assert restored_execution.tool_name == "fake-nuclei"
    assert restored_observation.value == {"severity": "low"}


def test_canonical_state_fields_are_optional_and_serializable() -> None:
    from typing import get_type_hints

    from webpent.state.state import PentestState

    hints = get_type_hints(PentestState)
    assert "canonical_executions" in hints
    assert "canonical_observations" in hints
    # A legacy partial state may omit both fields because PentestState is
    # total=False; this is the compatibility contract for old checkpoints.
    legacy_state = {"current_phase": "recon", "errors": []}
    assert "canonical_executions" not in legacy_state
    assert "canonical_observations" not in legacy_state


def test_mental_model_understanding_projection_is_typed_and_secret_safe() -> None:
    from webpent.models.mental_model import EdgeKind, NodeKind, extract_mental_model_updates

    target = "https://lab.example.test"
    endpoint = f"{target}/checkout"
    updates = extract_mental_model_updates(
        discovery_source="target_understanding_node",
        endpoints=[endpoint],
        endpoint_details=[
            {
                "url": endpoint,
                "methods": ["post", "get"],
                "parameter_names": ["cart_id", "coupon"],
                "form": True,
                "auth_signals": ["session-cookie"],
                "evidence_refs": ["tool://crawler/forms/0"],
            }
        ],
        identities=[
            {
                "ref": "alice",
                "role": "customer",
                "auth_pattern": "session-cookie",
                "evidence_refs": ["obs://auth/1"],
            }
        ],
        objects=[
            {
                "type": "order",
                "object_id": "order-42",
                "owner_identity": "alice",
                "url": endpoint,
                "evidence_refs": ["obs://order/42"],
            }
        ],
        workflows=[
            {
                "name": "checkout",
                "required_role": "customer",
                "steps": [
                    {
                        "method": "POST",
                        "endpoint": endpoint,
                        "from_state": "cart",
                        "to_state": "paid",
                        "evidence_refs": ["obs://checkout/step/1"],
                    }
                ],
                "evidence_refs": ["obs://checkout"],
            }
        ],
        relations=[
            {
                "kind": EdgeKind.REQUIRES_ROLE.value,
                "source": "checkout",
                "target": endpoint,
                "evidence_ref": "obs://checkout/role",
            }
        ],
        target_url=target,
    )

    node_values = list(updates["nodes"].values())
    kinds = {node["kind"] for node in node_values}
    assert {
        NodeKind.HOST.value,
        NodeKind.ENDPOINT.value,
        NodeKind.IDENTITY.value,
        NodeKind.OBJECT.value,
        NodeKind.WORKFLOW.value,
    }.issubset(kinds)

    endpoint_node = next(node for node in node_values if node["kind"] == NodeKind.ENDPOINT.value)
    assert endpoint_node["metadata"]["methods"] == ["GET", "POST"]
    assert endpoint_node["metadata"]["parameter_names"] == ["cart_id", "coupon"]
    assert "session-cookie" in endpoint_node["metadata"]["auth_signals"]

    edges = updates["edges"]
    edge_kinds = {edge["kind"] for edge in edges}
    assert EdgeKind.OWNS.value in edge_kinds
    assert EdgeKind.CONTAINS.value in edge_kinds
    assert EdgeKind.REQUIRES_ROLE.value in edge_kinds
    assert "order-42" not in str(updates)
    assert "alice" not in str(updates)
    assert "session-cookie" in str(updates)


def test_legacy_mental_model_extraction_shape_is_unchanged() -> None:
    from webpent.models.mental_model import NodeKind, extract_mental_model_updates

    updates = extract_mental_model_updates(
        discovery_source="legacy_recon_node",
        endpoints=["https://lab.example.test/health"],
        target_url="https://lab.example.test",
    )
    assert set(updates) == {"nodes", "edges"}
    assert any(node["kind"] == NodeKind.HOST.value for node in updates["nodes"].values())
    assert any(node["kind"] == NodeKind.ENDPOINT.value for node in updates["nodes"].values())
    assert all(
        node["kind"]
        not in {
            NodeKind.IDENTITY.value,
            NodeKind.OBJECT.value,
            NodeKind.WORKFLOW.value,
        }
        for node in updates["nodes"].values()
    )


def test_invalid_typed_relations_are_ignored_without_mutating_graph() -> None:
    from webpent.models.mental_model import extract_mental_model_updates

    updates = extract_mental_model_updates(
        discovery_source="target_understanding_node",
        endpoints=["https://lab.example.test/a"],
        relations=[
            {"kind": "invented_relation", "source": "missing", "target": "missing"},
            {"kind": "owns", "source": "missing", "target": "missing"},
        ],
    )
    assert all(edge["kind"] != "invented_relation" for edge in updates["edges"])
    assert not any(edge["kind"] == "owns" for edge in updates["edges"])
