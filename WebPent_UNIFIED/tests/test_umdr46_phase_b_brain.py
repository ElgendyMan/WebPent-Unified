"""UM-DR-46 Phase B — the Researcher Brain (deterministic components).

The mission's Phase B: behavioral understanding, business-logic
inference, state-transition semantics, invariant discovery and
contradiction detection — ALL deterministic pure functions over the
Security Knowledge Graph (no LLM), each evidence-carrying, each wired
into the production graph through the researcher-brain node that feeds
the canonical hypothesis engine.

The lab fixture extends the Phase A SKG fixture with one extra planted
fact (an unmarked ownership change) and declares its ground truth up
front — the A4 Alice/Bob discipline.
"""

from __future__ import annotations

from typing import Any

from webpent.researcher.brain import (
    classify_endpoint_behavior,
    detect_contradictions,
    discover_invariants,
    infer_business_rules,
    transition_semantics,
)

BASE = "https://shop.example"


def _brain_state() -> dict[str, Any]:
    """Phase B lab fixture — Phase A fixture + an UNMARKED ownership
    change on /api/admin/invoices/900 (actor bob)."""
    return {
        "engagement_id": "umdr46-brain-lab",
        "target_url": BASE,
        "base_url": BASE,
        "crawled_data": {
            "openapi_routes": [
                {"method": "GET", "path": "/api/orders/123",
                 "security": [{"sessionAuth": []}]},
                {"method": "GET", "path": "/api/orders/456",
                 "security": [{"sessionAuth": []}]},
                {"method": "POST", "path": "/api/orders/789/transfer",
                 "security": [{"sessionAuth": []}]},
                {"method": "GET", "path": "/api/v1/orders"},
                {"method": "GET", "path": "/orders"},
                {"method": "GET", "path": "/api/admin/invoices/900"},
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
        "session_cookies": {"alice": "REDACTED-A", "bob": "REDACTED-B"},
        "object_identity_observations": [
            {"endpoint": "/api/orders/123", "resource_type": "orders",
             "object_id": "123", "tenant": "t1", "observation_ref": "ob-1"},
        ],
        "authorization_observations": [
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
            # the PLANTED contradiction: an ownership change on an
            # endpoint with NO authorization evidence at all
            {"evidence_kind": "ownership_change",
             "endpoint": "/api/admin/invoices/900", "resource": "invoices:900",
             "attribute": "owner", "operation": "write", "actor": "bob",
             "evidence_refs": ["ev-own-2"]},
        ],
    }


def _model_of(state: dict[str, Any]) -> Any:
    from webpent.appmodel.skg import build_security_knowledge_graph

    return build_security_knowledge_graph(state)


def _profile_by_path(profiles: dict[str, dict[str, Any]], path: str) -> dict[str, Any]:
    for entry in profiles.values():
        if entry["path"] == path:
            return entry
    raise AssertionError(f"no behavioral profile for {path}")


class TestBehavioralUnderstanding:
    """فهم السلوك — evidence-backed per-endpoint behavioral profiles."""

    def test_profiles_are_evidence_backed(self) -> None:
        model = _model_of(_brain_state())
        profiles = classify_endpoint_behavior(model)
        assert profiles, "endpoints with evidence must get profiles"
        for entry in profiles.values():
            assert entry["evidence_refs"], "no profile without evidence"
            assert entry["advisory_only"] is True

    def test_order_123_profile(self) -> None:
        model = _model_of(_brain_state())
        p = _profile_by_path(classify_endpoint_behavior(model), "/api/orders/123")
        assert p["reads"] is True
        assert p["writes"] is False
        assert p["authz_marked"] is True
        assert p["state_trigger"] is False
        assert "identity:bob" in p["accessed_by"]

    def test_state_trigger_endpoints(self) -> None:
        model = _model_of(_brain_state())
        profiles = classify_endpoint_behavior(model)
        for path in ("/api/orders/123/submit", "/api/orders/123/approve",
                     "/api/orders/123/fasttrack"):
            assert _profile_by_path(profiles, path)["state_trigger"] is True, path
        assert _profile_by_path(profiles, "/api/orders/123/approve")[
            "authz_marked"] is False

    def test_transfer_profile_writes(self) -> None:
        model = _model_of(_brain_state())
        p = _profile_by_path(
            classify_endpoint_behavior(model), "/api/orders/789/transfer")
        assert p["writes"] is True
        assert p["authz_marked"] is True
        assert "identity:root" in p["accessed_by"]

    def test_invoices_900_reads_and_writes_unmarked(self) -> None:
        model = _model_of(_brain_state())
        p = _profile_by_path(
            classify_endpoint_behavior(model), "/api/admin/invoices/900")
        assert p["reads"] is True and p["writes"] is True
        assert p["authz_marked"] is False
        assert "identity:bob" in p["accessed_by"]

    def test_no_profile_without_evidence(self) -> None:
        model = _model_of(_brain_state())
        profiles = classify_endpoint_behavior(model)
        # /orders carries NO evidence relations at all → no profile
        assert "/orders" not in {p["path"] for p in profiles.values()}


class TestBusinessLogicInference:
    """استنتاج منطق الأعمال — sequence/role_gate/ownership/parameter rules."""

    def test_rule_kinds_and_evidence(self) -> None:
        model = _model_of(_brain_state())
        rules = infer_business_rules(model)
        kinds = {r["kind"] for r in rules}
        assert {"sequence", "role_gate", "ownership", "parameter"} <= kinds
        for rule in rules:
            assert rule["evidence_refs"], f"rule {rule['rule_id']} has no evidence"
            assert rule["required_validation"] == "causal-guard differential"
            assert rule["statement"]

    def test_sequence_rule_names_the_chain(self) -> None:
        model = _model_of(_brain_state())
        rules = infer_business_rules(model)
        seq = [r for r in rules if r["kind"] == "sequence"]
        assert seq and any("pending" in r["statement"] and "review" in r["statement"]
                           and "approved" in r["statement"] for r in seq)

    def test_role_gate_rules(self) -> None:
        model = _model_of(_brain_state())
        gates = [r for r in infer_business_rules(model) if r["kind"] == "role_gate"]
        assert len(gates) == 2  # owner→/api/orders/123, owner→/api/v1/orders
        assert all("owner" in r["statement"] for r in gates)

    def test_ownership_rule(self) -> None:
        model = _model_of(_brain_state())
        own = [r for r in infer_business_rules(model) if r["kind"] == "ownership"]
        assert own and any("alice" in r["statement"] and "orders:123" in r["statement"]
                           for r in own)


class TestStateTransitionSemantics:
    """نمذجة انتقالات الحالات — per-edge trigger/precondition semantics."""

    def test_three_transitions_with_triggers(self) -> None:
        model = _model_of(_brain_state())
        semantics = transition_semantics(model)
        assert len(semantics) == 3
        by_key = {(s["from_state"], s["to_state"]): s for s in semantics}
        submit = by_key[("pending", "review")]
        assert submit["trigger_endpoint"] == "/api/orders/123/submit"
        assert submit["method"] == "POST"
        assert submit["destructive"] is False
        assert submit["workflow_key"] == "order-approval"
        assert by_key[("pending", "approved")]["trigger_endpoint"] == (
            "/api/orders/123/fasttrack")
        for record in semantics:
            assert record["evidence_refs"]

    def test_empty_without_workflows(self) -> None:
        model = _model_of(_brain_state())
        # a model without any transitions yields nothing
        empty = _model_of({**_brain_state(), "workflow_observations": []})
        assert len(transition_semantics(empty)) == 0
        assert len(transition_semantics(model)) == 3  # purity


class TestInvariantDiscovery:
    """اكتشاف الثوابت — invariant candidates from graph evidence."""

    def test_sequence_invariant_from_skip(self) -> None:
        model = _model_of(_brain_state())
        invariants = discover_invariants(model)
        seq = [i for i in invariants if i["kind"] == "sequence_invariant"]
        assert seq, "the planted skip must yield a sequence invariant"
        assert any("review" in i["statement"] and "bypass" in i["statement"].lower()
                   for i in seq)
        assert all(i["required_validation"] == "causal-guard differential"
                   for i in invariants)

    def test_ownership_invariant(self) -> None:
        model = _model_of(_brain_state())
        invariants = discover_invariants(model)
        own = [i for i in invariants if i["kind"] == "ownership_invariant"]
        assert own and any("alice" in i["statement"] for i in own)
        assert all(i["evidence_refs"] for i in invariants)


class TestContradictionDetection:
    """كشف التناقضات — evidence-vs-evidence conflicts, recorded in the SSOT."""

    def test_three_contradiction_kinds(self) -> None:
        model = _model_of(_brain_state())
        contradictions = detect_contradictions(model)
        kinds = sorted(c["kind"] for c in contradictions)
        assert kinds == [
            "ownership_change_without_marker",
            "surface_marker_mismatch",
            "workflow_protocol_bypass",
        ]
        for c in contradictions:
            assert c["evidence_refs"], "contradiction without evidence"
            assert c["statement"]

    def test_contradictions_marked_in_the_ssot(self) -> None:
        model = _model_of(_brain_state())
        detect_contradictions(model)
        # the involved endpoints flip to CONTRADICTED with evidence kept
        contradicted = [
            e for e in model.entities.values()
            if str(e.provenance) == "contradicted"
        ]
        paths = {str(e.metadata.get("path") or "") for e in contradicted}
        assert "/api/admin/invoices/900" in paths
        assert "/orders" in paths
        assert "/api/orders/123/fasttrack" in paths

    def test_no_contradictions_in_clean_model(self) -> None:
        state = _brain_state()
        # remove the skip + the unmarked ownership change + the ui/api
        # marker pair → no contradictions at all
        state["skg_evidence"] = [
            e for e in state["skg_evidence"] if e.get("evidence_refs") != ["ev-own-2"]
        ]
        state["workflow_observations"] = [
            w for w in state["workflow_observations"]
            if w["transition_key"] != "fasttrack"
        ]
        state["crawled_data"]["openapi_routes"] = [
            r for r in state["crawled_data"]["openapi_routes"]
            if r["path"] not in ("/orders", "/api/v1/orders")
        ]
        model = _model_of(state)
        assert detect_contradictions(model) == []

    def test_purity_of_detection(self) -> None:
        model = _model_of(_brain_state())
        before = sorted(model.entities)
        one = detect_contradictions(model)
        two = detect_contradictions(model)
        assert one == two
        assert sorted(model.entities) == before


class TestResearcherBrainNode:
    """The production node: channels + canonical hypotheses."""

    def test_node_emits_channels_and_hypotheses(self) -> None:
        from webpent.production.researcher_brain import researcher_brain_node

        update = researcher_brain_node(_brain_state())
        assert update["researcher_brain"]["built"] is True
        assert update["researcher_brain"]["advisory_only"] is True
        assert update["researcher_brain"]["behavioral_profile_count"] > 0
        assert update["researcher_brain"]["contradiction_count"] == 3
        assert len(update["researcher_brain_rules"]) >= 6
        assert len(update["researcher_brain_contradictions"]) == 3
        hyps = update["hypotheses"]
        assert len(hyps) == 3, "one hypothesis per contradiction"
        for hyp in hyps:
            for field in ("statement", "vuln_class", "origin",
                          "origin_detail", "expected_behavior",
                          "negative_control"):
                assert str(getattr(hyp, field) or "").strip(), field
            assert getattr(hyp.origin, "value", hyp.origin) == "researcher_brain"

    def test_hypotheses_survive_the_pool_reducer_twice(self) -> None:
        from webpent.production.researcher_brain import researcher_brain_node
        from webpent.state.reducers import merge_hypotheses

        first = merge_hypotheses([], researcher_brain_node(_brain_state())["hypotheses"])
        second = merge_hypotheses(
            first, researcher_brain_node(_brain_state())["hypotheses"])
        assert len(second) == 3, "re-emission must dedupe"

    def test_node_output_is_json_safe(self) -> None:
        import json

        from webpent.production.researcher_brain import researcher_brain_node

        update = researcher_brain_node(_brain_state())
        json.dumps(update["researcher_brain"])
        json.dumps(update["researcher_brain_rules"])
        json.dumps(update["researcher_brain_contradictions"])


class TestBrainDeterminism:
    """Same state in ⇒ same answers out (measurement determinism law)."""

    def test_all_components_deterministic(self) -> None:
        def snapshot(state: dict[str, Any]) -> tuple[Any, ...]:
            model = _model_of(state)
            return (
                repr(classify_endpoint_behavior(model)),
                repr(infer_business_rules(model)),
                repr(transition_semantics(model)),
                repr(discover_invariants(model)),
                repr(detect_contradictions(model)),
            )

        assert snapshot(_brain_state()) == snapshot(_brain_state())
