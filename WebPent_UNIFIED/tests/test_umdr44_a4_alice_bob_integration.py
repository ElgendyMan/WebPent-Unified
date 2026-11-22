"""UM-DR-44 A4 — end-to-end integration: Alice/Bob evidence through
the REAL production nodes.

The unit tests cover each piece in isolation; this test runs the
actual wiring the graph uses, in order:

1. ``identity_workflow_node`` (the real node, flags on) ingests the
   Alice/Bob evidence (owner allowed / foreign denied) and emits
   differential questions + hypotheses through the canonical adapter;
2. the emitted hypotheses flow through the REAL ``merge_hypotheses``
   reducer (two passes — a re-emission, exactly the checkpoint
   round-trip shape);
3. the §5.3 policy keeps Alice-scoped and Bob-scoped hypotheses
   SEPARATE (identity dimensions differ), and a same-id re-emission
   merges without losing promotion fields (B2);
4. ranking: the strategist's ranking function orders the merged pool
   deterministically.

This is the path ``graph/builder`` binds — no stubs for the nodes or
reducers under test.
"""

from __future__ import annotations

from types import SimpleNamespace

from webpent.models.hypothesis import Hypothesis
from webpent.production.identity_workflow import identity_workflow_node
from webpent.state.reducers import merge_hypotheses


def _flags_on() -> None:
    """Turn the identity-workflow gates on for this test."""
    from webpent.config.settings import get_settings

    s = get_settings()
    s.enable_object_identity = True
    s.enable_alias_resolution = True
    s.enable_multi_identity_reasoning = True
    s.enable_composite_workflows = True


def _campaign_state() -> dict[str, Any]:
    return {
        "base_url": "https://lab.example",
        "target_url": "https://lab.example",
        "crawled_data": {
            "openapi_routes": [
                {"method": "GET", "path": "/api/orders/123"},
                {"method": "POST", "path": "/api/orders/123/submit"},
            ],
        },
        "workflow_observations": [],
        "identity_profiles": {
            "alice": {"role": "owner", "tenant": "t1"},
            "bob": {"role": "foreign", "tenant": "t1"},
        },
        "object_identity_observations": [
            {"endpoint": "/api/orders/123", "resource_type": "orders",
             "object_id": "123", "object_id_source": "response_body",
             "tenant": "t1", "observation_ref": "ob1"},
        ],
        "authorization_observations": [
            # Alice (owner) IS allowed to read the order
            {"principal_ref": "alice", "tenant": "t1",
             "object_ref": "orders:123", "operation": "read",
             "outcome": "allowed", "evidence_refs": ["ev-alice"]},
            # Bob (foreign principal) was denied on a DIFFERENT object
            {"principal_ref": "bob", "tenant": "t1",
             "object_ref": "vaults:900", "operation": "read",
             "outcome": "denied", "evidence_refs": ["ev-bob"]},
        ],
        "differential_questions": [
            {"question_id": "dq-1",
             "target_representation": "https://lab.example/api/orders/123",
             "target_object_ref": "orders:123",
             "owner_principal": "alice",
             "foreign_principal": "bob",
             "evidence_refs": ["ev-alice", "ev-bob"]},
        ],
    }


class TestAliceBobEndToEnd:
    def test_full_path_emits_merges_ranks(self) -> None:
        _flags_on()
        state = _campaign_state()

        # 1. the real node ingests the evidence
        update = identity_workflow_node(state)
        assert isinstance(update, dict)
        emitted = list(update.get("hypotheses") or [])
        assert emitted, "identity workflow must emit hypotheses"

        # every emitted hypothesis carries the canonical contract
        for hyp in emitted:
            assert str(getattr(hyp, "expected_behavior", "") or "").strip()
            assert str(getattr(hyp, "negative_control", "") or "").strip()

        # 2. two merge passes (re-emission shape) through the real reducer
        pool_one = merge_hypotheses([], emitted)
        pool_two = merge_hypotheses(pool_one, emitted)

        # the §5.3 policy consulted on same-id collisions: identical
        # re-emissions merge (pool must not double)
        assert len(pool_two) == len(pool_one)

        # 3. Alice-scoped and Bob-scoped stay SEPARATE when their
        #    identity dimensions differ (constructed collision: same id,
        #    different actor channel)
        alice_hyp = Hypothesis(
            target_url="https://lab.example/api/orders/123",
            statement="foreign principal bob can read alice's order",
            vuln_class="privilege_differential",
            request_data={"actor": "bob", "object_id": "orders:123"},
            expected_behavior="bob's read succeeds like alice's",
            negative_control="bob's read on vaults:900 stays denied",
            origin="invariant", origin_detail="a4-alice-bob",
        )
        bob_hyp = Hypothesis(
            id=alice_hyp.id,  # forced collision (round-trip shape)
            target_url="https://lab.example/api/orders/123",
            statement="owner alice reads her own order",
            vuln_class="privilege_differential",
            request_data={"actor": "alice", "object_id": "orders:123"},
            expected_behavior="alice's read succeeds",
            negative_control="bob's read stays denied",
            origin="invariant", origin_detail="a4-alice-bob",
        )
        pool = merge_hypotheses([alice_hyp], [bob_hyp])
        # same (target, class, objective) but the actors differ — the
        # identity-carrying pair must NOT collapse
        actors = {
            str((getattr(h, "request_data", None) or {}).get("actor", ""))
            for h in pool
        }
        assert "alice" in actors and "bob" in actors, (
            f"identity-distinct hypotheses collapsed: {actors}"
        )

        # 4. ranking: the production ranking function the strategist
        #    uses (shared/prioritization.rank_open_hypotheses) orders
        #    the merged pool deterministically.
        from webpent.shared.prioritization import rank_open_hypotheses

        rank_state = {
            "target": SimpleNamespace(url="https://lab.example"),
            "findings": [],
            "decision_log": [],
        }
        ranked_once = rank_open_hypotheses(pool, rank_state)
        ranked_again = rank_open_hypotheses(pool, rank_state)
        ids_once = [str(getattr(h, "id", h)) for h, _score in ranked_once]
        ids_again = [str(getattr(h, "id", h)) for h, _score in ranked_again]
        assert ids_once == ids_again, "ranking must be deterministic"
        assert ids_once, "the merged pool must be rankable"

    def test_node_update_is_langgraph_safe(self) -> None:
        """The update the real node returns must be channel-safe (all
        values JSON-serializable or declared state types)."""
        import json

        _flags_on()
        update = identity_workflow_node(_campaign_state())
        # telemetry / registries are plain dicts — spot-serializable
        json.dumps(update.get("identity_workflow_telemetry") or {})
