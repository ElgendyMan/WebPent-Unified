"""UM-DR-46 Phase J — multi-protocol depth (SKG-driven targets).

The SKG tells the researcher WHERE deeper PROTOCOL-LEVEL work is
warranted, deterministically:

* ``workflow_protocol``  — a workflow with ≥2 observed transitions: the
  full sequence-replay candidate (not single-request testing);
* ``object_id_space``    — a parameter entity with observed numeric
  values: an enumerable object-id space worth systematic probing;
* ``cross_origin``       — a workflow whose observed transitions cross
  more than one trust boundary: cross-origin depth work.

Pure, bounded (32), advisory — targets, never requests.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.protocol_depth import protocol_depth_targets

BASE = "https://shop.example"


def _state() -> dict[str, Any]:
    from tests.test_umdr46_phase_b_brain import _brain_state

    return _brain_state()


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


class TestProtocolDepth:
    def test_workflow_sequence_targets(self) -> None:
        model = _model_of(_state())
        targets = protocol_depth_targets(model)
        seqs = [t for t in targets if t["kind"] == "workflow_protocol"]
        assert seqs, "order-approval (3 transitions) must be a sequence target"
        assert all(t["transition_count"] >= 2 for t in seqs)
        assert all(t["evidence_refs"] for t in seqs)

    def test_object_id_space_targets(self) -> None:
        model = _model_of(_state())
        targets = protocol_depth_targets(model)
        spaces = [t for t in targets if t["kind"] == "object_id_space"]
        assert spaces, "the orders {param} (123/456) is an id space"
        assert all(t["numeric_values"] for t in spaces)

    def test_single_origin_workflows_not_cross_origin(self) -> None:
        model = _model_of(_state())
        targets = protocol_depth_targets(model)
        assert not any(
            t["kind"] == "cross_origin" for t in targets
        ), "the lab workflow spans ONE origin — no cross-origin target"

    def test_deterministic_and_bounded(self) -> None:
        model = _model_of(_state())
        assert protocol_depth_targets(model) == protocol_depth_targets(model)
        assert len(protocol_depth_targets(model)) <= 32


class TestDepthNode:
    def test_node_emits_channel(self) -> None:
        import json

        from webpent.production.protocol_depth_node import (
            protocol_depth_node,
        )

        update = protocol_depth_node(_state())
        assert update["protocol_depth"]["built"] is True
        assert update["protocol_depth"]["advisory_only"] is True
        assert update["protocol_depth"]["target_count"] >= 2
        json.dumps(update["protocol_depth"])

    def test_empty_state_yields_noop(self) -> None:
        from webpent.production.protocol_depth_node import (
            protocol_depth_node,
        )

        update = protocol_depth_node({"engagement_id": "empty"})
        assert update["protocol_depth"]["target_count"] == 0
