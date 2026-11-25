"""UM-DR-46 Phase E — advanced discovery intelligence (SKG-mined).

The mission's Phase E: the SKG itself points at WHAT TO DISCOVER NEXT
— deterministic mining of the model for discovery targets no scanner
enumerate: unobserved workflow-transition pairs, parameter sibling
values, single-path resources, and unmarked state-trigger endpoints.
All pure, bounded, advisory — never a request, never an authorization.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.discovery_intel import (
    discovery_intel_summary,
    mine_discovery_targets,
)

BASE = "https://shop.example"


def _intel_state() -> dict[str, Any]:
    """Phase E fixture = the Phase B brain fixture (same evidence)."""
    from tests.test_umdr46_phase_b_brain import _brain_state

    return _brain_state()


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


class TestDiscoveryTargets:
    """أهداف الاكتشاف المستخرجة من النموذج — deterministic mining."""

    def test_unobserved_transition_pairs_mined(self) -> None:
        model = _model_of(_intel_state())
        targets = mine_discovery_targets(model)
        unobserved = [t for t in targets if t["kind"] == "unobserved_transition"]
        assert unobserved, "pending→review→approved must imply candidates"
        pair = {
            (t["from_state"], t["to_state"]) for t in unobserved}
        assert ("approved", "pending") in pair or (
            "review", "pending") in pair
        for t in unobserved:
            assert t["workflow_key"] == "order-approval"
            assert t["evidence_refs"]

    def test_parameter_sibling_values(self) -> None:
        model = _model_of(_intel_state())
        targets = mine_discovery_targets(model)
        siblings = [t for t in targets if t["kind"] == "parameter_sibling"]
        assert siblings, "orders {param} with values 123/456 must yield one"
        sib = siblings[0]
        assert sib["pattern"]
        assert sib["candidate_values"], "deterministic sibling candidates"
        assert sib["observed_values"] in (["123", "456"], ["123", "456", "789"])

    def test_single_path_resources_mined(self) -> None:
        # a resource reached ONLY by its actor's accesses relation (no
        # endpoint, no owner record) has exactly one evidence path —
        # the spine multiplies paths for endpoint-reached resources,
        # so this case needs a purpose-built minimal state
        minimal = {
            "engagement_id": "umdr46-single-path",
            "authorization_observations": [
                {"finding_id": "f-9", "vuln_class": "idor",
                 "source_node": "test", "guard_verdict": "confirmed",
                 "actor_id": "bob", "resource_id": "widgets:1",
                 "resource_owner": "", "ownership_basis": "lab"},
            ],
        }
        model = _model_of(minimal)
        targets = mine_discovery_targets(model)
        single = [t for t in targets if t["kind"] == "single_path_resource"]
        assert single, "a resource with exactly one path must be mined"
        assert all(t["path_count"] == 1 for t in single)
        assert any(t["resource_label"] == "resource:widgets:1" for t in single)

    def test_unmarked_state_triggers_mined(self) -> None:
        model = _model_of(_intel_state())
        targets = mine_discovery_targets(model)
        triggers = [t for t in targets if t["kind"] == "unmarked_state_trigger"]
        paths = {t["path"] for t in triggers}
        assert "/api/orders/123/submit" in paths
        assert "/api/orders/123/fasttrack" in paths
        assert all(t["evidence_refs"] for t in targets)

    def test_mining_is_bounded_and_deterministic(self) -> None:
        model = _model_of(_intel_state())
        one = mine_discovery_targets(model)
        two = mine_discovery_targets(model)
        assert one == two
        assert len(one) <= 64


class TestIntelNode:
    """The production node writes the advisory channel."""

    def test_node_emits_channel(self) -> None:
        from webpent.production.discovery_intel_node import (
            discovery_intel_node,
        )

        update = discovery_intel_node(_intel_state())
        assert update["discovery_intel"]["built"] is True
        assert update["discovery_intel"]["advisory_only"] is True
        assert update["discovery_intel"]["target_count"] > 0
        import json

        json.dumps(update["discovery_intel"])

    def test_empty_state_yields_noop(self) -> None:
        from webpent.production.discovery_intel_node import (
            discovery_intel_node,
        )

        update = discovery_intel_node({"engagement_id": "empty"})
        assert update["discovery_intel"]["target_count"] == 0


class TestSummary:
    def test_summary_counts_by_kind(self) -> None:
        model = _model_of(_intel_state())
        summary = discovery_intel_summary(model)
        assert summary["advisory_only"] is True
        assert summary["unmarked_state_trigger_count"] >= 2
