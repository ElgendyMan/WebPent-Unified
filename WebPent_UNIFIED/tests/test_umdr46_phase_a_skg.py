"""UM-DR-46 Phase A — the Security Knowledge Graph (SKG).

The lab fixture below declares its ground truth up front (the A4
Alice/Bob pattern): a synthetic campaign state whose entities,
relations, provenance and query answers are KNOWN. Every test asserts
the deterministic SKG builder and the five discriminating-question
queries against that declared truth.

Contract under test (mission Phase A):
* the AppModel grows the 9 security entity classes — Users (identity),
  Roles, Resources, Endpoints, Sessions, Workflows, Parameters, Trust
  Boundaries, State-before-after — every entity AND relation carrying
  provenance + evidence refs (the A5a/A5d discipline extended);
* the deterministic query API: ``get_all_paths_to``,
  ``ownership_changers``, ``reads_without_authz_marker``,
  ``workflow_skip_candidates``, ``ui_vs_api_permission_diff`` — pure
  functions, same model in ⇒ same answer out;
* negative guarantees: no invented relations, no secret values in the
  model, no rule without evidence.
"""

from __future__ import annotations

from typing import Any

from webpent.appmodel.skg import (
    build_security_knowledge_graph,
    build_skg_research_hints,
)
from webpent.appmodel.skg_queries import (
    get_all_paths_to,
    ownership_changers,
    reads_without_authz_marker,
    summarize_skg,
    ui_vs_api_permission_diff,
    workflow_skip_candidates,
)

BASE = "https://shop.example"


def _lab_state() -> dict[str, Any]:
    """The SKG lab fixture — ground truth declared in SKG_GROUND_TRUTH."""
    return {
        "engagement_id": "umdr46-skg-lab",
        "target_url": BASE,
        "base_url": BASE,
        "crawled_data": {
            "openapi_routes": [
                # marked endpoints (declared security requirement)
                {"method": "GET", "path": "/api/orders/123",
                 "security": [{"sessionAuth": []}]},
                {"method": "GET", "path": "/api/orders/456",
                 "security": [{"sessionAuth": []}]},
                {"method": "POST", "path": "/api/orders/789/transfer",
                 "security": [{"sessionAuth": []}]},
                # the UI/API pair with a marker only on the API side
                {"method": "GET", "path": "/api/v1/orders"},
                {"method": "GET", "path": "/orders"},
                # an admin read endpoint with NO authz marker at all
                {"method": "GET", "path": "/api/admin/invoices/900"},
                # workflow trigger endpoints
                {"method": "POST", "path": "/api/orders/123/submit"},
                {"method": "POST", "path": "/api/orders/123/approve"},
                {"method": "POST", "path": "/api/orders/123/fasttrack"},
            ],
        },
        "identity_profiles": {
            "alice": {"role": "owner", "tenant": "t1", "validated": True},
            "bob": {"role": "viewer", "tenant": "t1", "validated": True},
            "root": {"role": "admin", "tenant": "t1", "validated": True},
        },
        # values are secret material — they must NEVER enter the model
        "session_cookies": {"alice": "REDACTED-COOKIE-A", "bob": "REDACTED-COOKIE-B"},
        "object_identity_observations": [
            {"endpoint": "/api/orders/123", "resource_type": "orders",
             "object_id": "123", "tenant": "t1", "observation_ref": "ob-1"},
        ],
        "authorization_observations": [
            # production shape (UM-DR-39 RC-2 finding projection): bob
            # accessed orders:123 owned by alice — Tool-Confirmed.
            {"finding_id": "f-1", "vuln_class": "idor", "source_node": "test",
             "guard_verdict": "confirmed", "actor_id": "bob",
             "resource_id": "orders:123", "resource_owner": "alice",
             "ownership_basis": "CausalGuard authorization_differential context"},
        ],
        "workflow_observations": [
            {"workflow_key": "order-approval", "transition_key": "submit",
             "endpoint": "/api/orders/123/submit", "method": "POST",
             "from_state": "pending", "to_state": "review", "signals": {},
             "evidence_refs": ["wf-1"], "destructive": False,
             "authorization_boundary": "same_identity"},
            {"workflow_key": "order-approval", "transition_key": "approve",
             "endpoint": "/api/orders/123/approve", "method": "POST",
             "from_state": "review", "to_state": "approved",
             "evidence_refs": ["wf-2"], "destructive": False,
             "authorization_boundary": "role_scoped"},
            # the planted SKIP: pending → approved directly, bypassing review
            {"workflow_key": "order-approval", "transition_key": "fasttrack",
             "endpoint": "/api/orders/123/fasttrack", "method": "POST",
             "from_state": "pending", "to_state": "approved",
             "evidence_refs": ["wf-3"], "destructive": False,
             "authorization_boundary": "unknown"},
        ],
        "skg_evidence": [
            {"evidence_kind": "authz_marker", "endpoint": "/api/orders/123",
             "role": "owner", "operation": "read",
             "evidence_refs": ["ev-marker-1"], "declared": False},
            {"evidence_kind": "ownership_change",
             "endpoint": "/api/orders/789/transfer", "resource": "orders:789",
             "attribute": "owner", "operation": "write", "actor": "root",
             "evidence_refs": ["ev-own-1"]},
            {"evidence_kind": "resource_access",
             "endpoint": "/api/admin/invoices/900", "resource": "invoices:900",
             "operation": "read", "evidence_refs": ["ev-acc-1"]},
            {"evidence_kind": "authz_marker", "endpoint": "/api/v1/orders",
             "role": "owner", "operation": "read",
             "evidence_refs": ["ev-marker-2"], "declared": False},
        ],
    }


# The declared ground truth of the fixture above — the numbers the
# builder and queries MUST reproduce exactly.
SKG_GROUND_TRUTH: dict[str, Any] = {
    "kinds": {  # entity kinds present in the model (Users == identity)
        "identity", "role", "resource", "endpoint", "session",
        "workflow", "parameter", "trust_boundary", "state",
        # the base spine still contributes these
        "organization", "tenant", "application",
    },
    "role_labels": {"role:owner", "role:viewer", "role:admin"},
    "session_labels": {"session:alice", "session:bob"},
    "resource_labels": {
        "resource:orders:123", "resource:orders:789", "resource:invoices:900",
    },
    "state_labels": {
        "state:order-approval:pending", "state:order-approval:review",
        "state:order-approval:approved",
    },
    "workflow_labels": {"workflow:order-approval"},
    "parameter_count": 2,
    "trust_boundary_labels": {"trust_boundary:https://shop.example:443"},
    "ownership_changer_paths": {"/api/orders/789/transfer"},
    "reads_without_authz_paths": {"/api/admin/invoices/900"},
    "skip_candidates": [
        {"workflow_key": "order-approval", "from_state": "pending",
         "to_state": "approved", "skipped_states": ["review"]},
    ],
    "ui_api_diffs": [
        {"ui_path": "/orders", "api_path": "/api/v1/orders",
         "ui_authz": False, "api_authz": True},
    ],
    # every path ending at resource orders:123, as (kind, label) chains
    "paths_to_orders_123": {
        (("identity", "identity:alice"), ("resource", "resource:orders:123")),
        (("identity", "identity:bob"), ("resource", "resource:orders:123")),
        (("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("role", "role:owner"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("identity", "identity:owner"), ("role", "role:owner"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("session", "session:alice"), ("identity", "identity:alice"),
         ("resource", "resource:orders:123")),
        (("session", "session:bob"), ("identity", "identity:bob"),
         ("resource", "resource:orders:123")),
        # the base spine paths (application/tenant/organization hosts the
        # endpoint that accesses the resource) — real, evidence-backed
        (("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("tenant", "tenant:umdr46-skg-lab"),
         ("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("organization", "organization:umdr46-skg-lab"),
         ("tenant", "tenant:umdr46-skg-lab"),
         ("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        # profile identities authenticate into the tenant → the spine
        (("identity", "identity:owner"), ("tenant", "tenant:umdr46-skg-lab"),
         ("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("identity", "identity:viewer"), ("tenant", "tenant:umdr46-skg-lab"),
         ("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
        (("identity", "identity:admin"), ("tenant", "tenant:umdr46-skg-lab"),
         ("application", "application:shop.example"),
         ("endpoint", "endpoint:https://shop.example:443/api/orders/123"),
         ("resource", "resource:orders:123")),
    },
}

_ORDER_ENDPOINT_LABEL = "endpoint:https://shop.example:443/api/orders/123"
_ORDER_RESOURCE_LABEL = "resource:orders:123"


def _labels_of_kind(model: Any, kind: str) -> set[str]:
    return {
        str(entity.label)
        for entity in model.entities.values()
        if str(entity.kind) == kind
    }


def _resource_id(model: Any, label: str) -> str:
    for entity_id, entity in model.entities.items():
        if str(entity.kind) == "resource" and str(entity.label) == label:
            return entity_id
    raise AssertionError(f"resource {label} not in model")


class TestSkgEntityFabric:
    """The 9 security entity classes with provenance on every piece."""

    def test_nine_entity_classes_present(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        kinds = {str(e.kind) for e in model.entities.values()}
        missing = SKG_GROUND_TRUTH["kinds"] - kinds
        assert not missing, f"missing entity kinds: {missing}"

    def test_role_session_resource_state_labels(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        assert _labels_of_kind(model, "role") == SKG_GROUND_TRUTH["role_labels"]
        assert _labels_of_kind(model, "session") == SKG_GROUND_TRUTH["session_labels"]
        assert _labels_of_kind(model, "resource") == SKG_GROUND_TRUTH["resource_labels"]
        assert _labels_of_kind(model, "state") == SKG_GROUND_TRUTH["state_labels"]
        assert _labels_of_kind(model, "workflow") == SKG_GROUND_TRUTH["workflow_labels"]
        assert _labels_of_kind(model, "trust_boundary") == SKG_GROUND_TRUTH["trust_boundary_labels"]

    def test_parameter_derivation_from_path_variance(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        params = [e for e in model.entities.values() if str(e.kind) == "parameter"]
        assert len(params) == SKG_GROUND_TRUTH["parameter_count"]
        # /api/orders/123 + /api/orders/456 → one parameter, values recorded
        orders_param = [
            p for p in params
            if sorted(str(v) for v in p.metadata["values_observed"]) == ["123", "456"]
        ]
        assert orders_param, "the /api/orders/{id} variance must yield a parameter"
        assert "orders" in str(orders_param[0].metadata.get("pattern") or "")

    def test_every_skg_entity_and_relation_carries_evidence(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        skg_kinds = {"role", "session", "resource", "state", "parameter",
                     "trust_boundary", "workflow"}
        for entity in model.entities.values():
            if str(entity.kind) in skg_kinds:
                assert entity.ref_list(), f"entity {entity.id} has no evidence"
                assert entity.provenance is not None
        skg_relation_kinds = {
            "assumes_role", "permits", "reads", "modifies", "accesses",
            "transitions", "crosses", "bound_to", "has_parameter", "exposes",
        }
        for relation in model.relations:
            if str(relation.kind) in skg_relation_kinds:
                assert relation.ref_list() or (
                    relation.source_id in model.entities
                    and model.entities[relation.source_id].ref_list()
                ), f"relation {relation.id} carries no evidence anywhere"

    def test_state_transitions_carry_the_before_after_semantics(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        transitions = [r for r in model.relations if str(r.kind) == "transitions"]
        assert len(transitions) == 3
        pairs = {
            (model.entities[r.source_id].label, model.entities[r.target_id].label)
            for r in transitions
        }
        assert pairs == {
            ("state:order-approval:pending", "state:order-approval:review"),
            ("state:order-approval:review", "state:order-approval:approved"),
            ("state:order-approval:pending", "state:order-approval:approved"),
        }
        fasttrack = [
            r for r in transitions
            if r.metadata.get("transition_key") == "fasttrack"
        ]
        assert fasttrack and fasttrack[0].ref_list() == ["wf-3"]

    def test_sessions_never_leak_secret_values(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        dump = model.model_dump(mode="json")
        serialized = repr(dump)
        assert "REDACTED-COOKIE-A" not in serialized
        assert "REDACTED-COOKIE-B" not in serialized

    def test_builder_is_deterministic(self) -> None:
        one = build_security_knowledge_graph(_lab_state())
        two = build_security_knowledge_graph(_lab_state())
        strip = lambda m: (  # noqa: E731
            sorted(m.entities),
            sorted((str(r.kind), r.source_id, r.target_id) for r in m.relations),
            m.revision,
        )
        assert strip(one) == strip(two)


class TestSkgQueries:
    """The five discriminating questions — pure, deterministic, exact."""

    def test_get_all_paths_to_orders_123(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        resource_id = _resource_id(model, _ORDER_RESOURCE_LABEL)
        result = get_all_paths_to(model, resource_id)
        paths = result["paths"]
        got = {
            (tuple(zip(p["node_kinds"], p["node_labels"], strict=True)))
            for p in paths
        }
        expected = {
            tuple((kind, label) for kind, label in chain)
            for chain in SKG_GROUND_TRUTH["paths_to_orders_123"]
        }
        assert got == expected, (
            f"path mismatch:\n  missing={expected - got}\n  extra={got - expected}"
        )
        # every path carries union evidence and a weakest provenance
        for path in paths:
            assert path["evidence_refs"], "paths must carry evidence"
            assert path["provenance_weakest"] in {
                "declared", "observed", "inferred", "unknown", "contradicted"}

    def test_get_all_paths_to_unknown_resource_is_empty(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        result = get_all_paths_to(model, "appmodel-resource:does-not-exist")
        assert result["paths"] == []
        assert result["resource_id"] == "appmodel-resource:does-not-exist"

    def test_ownership_changers(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        changers = ownership_changers(model)
        got = {entry["endpoint_path"] for entry in changers}
        assert got == SKG_GROUND_TRUTH["ownership_changer_paths"]
        entry = changers[0]
        assert entry["attribute"] == "owner"
        assert entry["resource_label"] == "resource:orders:789"
        assert entry["actor"] == "root"
        assert entry["evidence_refs"]

    def test_ownership_changers_empty_without_evidence(self) -> None:
        state = _lab_state()
        state["skg_evidence"] = []
        model = build_security_knowledge_graph(state)
        assert ownership_changers(model) == []

    def test_reads_without_authz_marker(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        flagged = reads_without_authz_marker(model)
        got = {entry["path"] for entry in flagged}
        assert got == SKG_GROUND_TRUTH["reads_without_authz_paths"]
        entry = flagged[0]
        assert entry["resource_labels"] == ["resource:invoices:900"]
        assert entry["evidence_refs"]

    def test_reads_without_authz_marker_respects_markers(self) -> None:
        # the marker on /api/orders/123 must keep it OFF the list even
        # though it ACCESSES a resource
        model = build_security_knowledge_graph(_lab_state())
        flagged_paths = {e["path"] for e in reads_without_authz_marker(model)}
        assert "/api/orders/123" not in flagged_paths

    def test_workflow_skip_candidates(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        skips = workflow_skip_candidates(model, "order-approval")
        assert [
            {"workflow_key": s["workflow_key"], "from_state": s["from_state"],
             "to_state": s["to_state"], "skipped_states": s["skipped_states"]}
            for s in skips
        ] == SKG_GROUND_TRUTH["skip_candidates"]
        assert skips[0]["evidence_refs"]

    def test_workflow_skip_candidates_none_when_linear(self) -> None:
        state = _lab_state()
        state["workflow_observations"] = [
            w for w in state["workflow_observations"]
            if w["transition_key"] != "fasttrack"
        ]
        model = build_security_knowledge_graph(state)
        assert workflow_skip_candidates(model, "order-approval") == []

    def test_ui_vs_api_permission_diff(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        diffs = ui_vs_api_permission_diff(model)
        assert [
            {"ui_path": d["ui_path"], "api_path": d["api_path"],
             "ui_authz": d["ui_authz"], "api_authz": d["api_authz"]}
            for d in diffs
        ] == SKG_GROUND_TRUTH["ui_api_diffs"]
        assert diffs[0]["evidence_refs"]

    def test_queries_are_pure_and_repeatable(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        resource_id = _resource_id(model, _ORDER_RESOURCE_LABEL)
        before = (
            len(model.relations),
            sorted(model.entities),
            model.revision,
        )
        one = get_all_paths_to(model, resource_id)
        two = get_all_paths_to(model, resource_id)
        assert one == two
        # purity: querying did not mutate the model
        after = (len(model.relations), sorted(model.entities), model.revision)
        assert before == after

    def test_summarize_skg_counts(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        summary = summarize_skg(model)
        assert summary["resource_count"] == 3
        assert summary["role_count"] == 3
        assert summary["session_count"] == 2
        assert summary["state_count"] == 3
        assert summary["workflow_count"] == 1
        assert summary["parameter_count"] == 2
        assert summary["trust_boundary_count"] == 1
        assert summary["ownership_changer_count"] == 1
        assert summary["reads_without_authz_count"] == 1
        assert summary["workflow_skip_candidate_count"] == 1
        assert summary["ui_vs_api_diff_count"] == 1


class TestSkgWiring:
    """The production appmodel node builds and exposes the SKG."""

    def test_appmodel_node_emits_skg(self) -> None:
        from webpent.graph.appmodel_nodes import appmodel_node

        update = appmodel_node(_lab_state())
        assert isinstance(update, dict)
        channel = update["appmodel"]
        kinds = {str(e.get("kind")) for e in channel["entities"].values()}
        assert "resource" in kinds and "role" in kinds and "state" in kinds
        summary = update["appmodel_summary"]
        assert summary["built"] is True
        skg = summary["skg"]
        assert skg["resource_count"] == 3
        assert skg["reads_without_authz_count"] == 1
        # the node output must be LangGraph-safe (JSON-serializable)
        import json

        json.dumps(channel)
        json.dumps(summary)

    def test_skg_research_hints_advisory_with_revision(self) -> None:
        model = build_security_knowledge_graph(_lab_state())
        hints = build_skg_research_hints(model)
        assert hints, "the SKG must produce research hints"
        for hint in hints.values():
            assert hint["advisory_only"] is True
            assert hint["source"] == "appmodel"
            assert isinstance(hint["model_revision"], int)
            assert hint["evidence_refs"]
        kinds = {h["kind"] for h in hints.values()}
        assert any("reads_without_authz" in k for k in kinds)
        assert any("workflow_skip" in k for k in kinds)

    def test_hints_merge_into_node_output(self) -> None:
        from webpent.graph.appmodel_nodes import appmodel_node

        update = appmodel_node(_lab_state())
        hint_kinds = {
            str(h.get("kind")) for h in update["appmodel_research_hints"].values()
        }
        assert any("skg" in k for k in hint_kinds)


class TestV1Projection:
    """RC-9: knowledge v1 retires to a read-only AppModel projection."""

    def test_knowledge_builder_prefers_appmodel_projection(self) -> None:
        from webpent.graph.appmodel_nodes import appmodel_node
        from webpent.knowledge.builder import KnowledgeBuilder
        from webpent.knowledge.target_knowledge import KnowledgeKind

        channel = appmodel_node(_lab_state())["appmodel"]
        state = {
            "engagement_id": "umdr46-skg-lab",
            "appmodel": channel,
            # legacy channels present too — the SSOT must win, not compete
            "mental_model": {"nodes": {}, "edges": []},
        }
        model = KnowledgeBuilder.from_state(state).build()
        nodes = list(model.nodes.values())
        assert any(
            n.kind == KnowledgeKind.OBJECT and "orders:123" in n.canonical_key
            for n in nodes
        ), "resources must project into v1 objects"
        assert any(
            n.kind == KnowledgeKind.WORKFLOW and "order-approval" in n.canonical_key
            for n in nodes
        )
        assert model.workflows, "workflow states must project into v1"
        wf = next(iter(model.workflows.values()))
        assert sorted(wf.states) == ["approved", "pending", "review"]
        assert model.authorization_profiles, "roles must project into v1 profiles"

    def test_knowledge_builder_legacy_fallback_without_appmodel(self) -> None:
        from webpent.knowledge.builder import KnowledgeBuilder

        state = {
            "engagement_id": "legacy",
            "mental_model": {
                "nodes": {
                    "n1": {"kind": "object", "identity_key": "k1",
                           "in_scope": True, "evidence_refs": ["e1"]},
                },
                "edges": [],
            },
        }
        model = KnowledgeBuilder.from_state(state).build()
        assert list(model.nodes), "legacy path must keep working unchanged"
