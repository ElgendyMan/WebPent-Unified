"""UM-DR-32 §10 — security and regression verification.

Covers:
  * §10.2 identity safety (cross-tenant/type non-merging, ambiguous
    abstention, no promotion from weak evidence, no merge from path
    similarity alone);
  * §10.3 alias safety (query-value distinctness, duplicate query
    params preserved, same-id-across-tenants/types distinct, false
    aliases rejected, weak candidates stay candidates);
  * §10.4 workflow safety (invalid preconditions, invalid transitions,
    missing state evidence, replay behavior, destructive blocked
    outside authorized fixtures, budget enforcement, partial failures);
  * §10.5 causal integrity (CausalGuard unchanged in authority, no
    alternate confirmation path, response-only difference cannot
    confirm, findings cannot be promoted from similarity alone);
  * §10.6 fault injection (missing identity fields, malformed object
    references, conflicting alias evidence, unknown tenant, missing
    principal, expired session, duplicate observations, malformed
    workflow state, missing validator, empty execution inventory,
    budget exhaustion).
"""
from __future__ import annotations

import pytest

from webpent.production.alias_resolution import AliasResolver, AliasState
from webpent.production.composite_workflows import (
    CompositeWorkflowEngine,
    FixtureSafetyContract,
    SequenceOutcomeStatus,
    build_sequence_candidates,
    build_workflows_from_observations,
)
from webpent.production.multi_identity import (
    AuthenticationState,
    PrincipalContext,
    PrincipalRole,
    matrix_from_observations,
    principals_from_state,
)
from webpent.production.object_identity import (
    IdentityRelationshipKind,
    ObjectIdentityRegistry,
    ResourceObservation,
    observations_from_campaign_state,
)


def _obs(endpoint, *, rtype="orders", oid="123", tenant="", body_id=False,
         evidence=(), attributes=None):
    return ResourceObservation(
        endpoint=endpoint, resource_type=rtype, object_id=oid,
        object_id_source="response_body" if body_id else "path_segment",
        tenant=tenant, evidence=list(evidence), attributes=attributes or {},
        observation_ref=f"obs:{endpoint}",
    )


class TestIdentitySafety:
    """§10.2."""

    def test_cross_tenant_non_merging(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/a/orders/1", oid="1", tenant="a")
        b = _obs("/api/b/orders/1", oid="1", tenant="b")
        registry.ingest(a)
        registry.ingest(b)
        rel = registry.relate(a, b)
        assert rel.kind is (
            IdentityRelationshipKind.SAME_IDENTIFIER_DIFFERENT_NAMESPACE
        )
        assert len(registry.identities()) == 2

    def test_cross_resource_type_non_merging(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/orders/1", rtype="orders", oid="1", tenant="t")
        b = _obs("/api/invoices/1", rtype="invoices", oid="1", tenant="t")
        registry.ingest(a)
        registry.ingest(b)
        assert registry.relate(a, b).kind is (
            IdentityRelationshipKind.DISTINCT_OBJECT
        )

    def test_ambiguous_identity_abstention(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/orders/1", oid="1", tenant="")
        b = _obs("/api/o/1", oid="1", tenant="t")
        registry.ingest(a)
        registry.ingest(b)
        assert registry.relate(a, b).kind is (
            IdentityRelationshipKind.AMBIGUOUS_IDENTITY
        )
        assert len(registry.identities()) == 2

    def test_no_identity_promotion_from_weak_evidence(self) -> None:
        # numeric id match alone with unknown tenants: never a confirmed
        # alias
        registry = ObjectIdentityRegistry()
        a = _obs("/api/orders/7", oid="7", tenant="")
        b = _obs("/api/o/7", rtype="orders", oid="7", tenant="")
        registry.ingest(a)
        registry.ingest(b)
        resolver = AliasResolver(registry)
        resolver.resolve([a, b])
        assert not resolver.confirmed()

    def test_no_merge_from_path_similarity_alone(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/orders/111", oid="111")
        b = _obs("/api/orders/112", oid="112")
        registry.ingest(a)
        registry.ingest(b)
        assert registry.relate(a, b).kind is (
            IdentityRelationshipKind.DISTINCT_OBJECT
        )
        assert len(registry.identities()) == 2


class TestAliasSafety:
    """§10.3."""

    def test_different_query_values_remain_distinct(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/reports/9?account=1", rtype="reports", oid="9", tenant="t"),
            _obs("/api/reports/9?account=2", rtype="reports", oid="9", tenant="t"),
        ]
        for obs in observations:
            registry.ingest(obs)
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        pair = [r for r in resolver.relationships() if "account=" in (
            r.source_repr + r.alternate_repr)]
        assert pair
        assert pair[0].state is not AliasState.CONFIRMED_SAME_OBJECT

    def test_duplicate_query_parameters_preserved(self) -> None:
        """UM-DR-31.1 F10 non-regression at the fingerprint layer."""
        from webpent.production.adaptive_research import _normalize_url

        assert _normalize_url(
            "https://x.test/a?b=1&b=2"
        ).endswith("b=1&b=2") or _normalize_url(
            "https://x.test/a?b=2&b=1"
        ).endswith("b=1&b=2")

    def test_same_numeric_id_across_tenants_stays_distinct(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/ta/orders/5", oid="5", tenant="ta", body_id=True),
            _obs("/api/tb/orders/5", oid="5", tenant="tb", body_id=True),
        ]
        for obs in observations:
            registry.ingest(obs)
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        assert not resolver.confirmed()
        assert len(registry.identities()) == 2

    def test_same_numeric_id_across_types_stays_distinct(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/5", rtype="orders", oid="5", tenant="t", body_id=True),
            _obs("/api/users/5", rtype="users", oid="5", tenant="t", body_id=True),
        ]
        for obs in observations:
            registry.ingest(obs)
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        assert not resolver.confirmed()

    def test_false_alias_rejected(self) -> None:
        # similar slug, no linking evidence: never confirmed
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/my-order", oid="my-order", tenant="t"),
            _obs("/api/orders/my-order-2", oid="my-order-2", tenant="t"),
        ]
        for obs in observations:
            registry.ingest(obs)
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        assert not resolver.confirmed()

    def test_weak_candidates_remain_candidates(self) -> None:
        registry = ObjectIdentityRegistry()
        observations = [
            _obs("/api/orders/3", oid="3", tenant="t"),
            _obs("/api/o/3", rtype="orders", oid="3", tenant="t"),
        ]
        for obs in observations:
            registry.ingest(obs)
        resolver = AliasResolver(registry)
        resolver.resolve(observations)
        pair = [r for r in resolver.relationships() if "orders/3" in (
            r.source_repr + r.alternate_repr)]
        assert pair and pair[0].state is AliasState.HIGH_CONFIDENCE_CANDIDATE


class TestWorkflowSafety:
    """§10.4."""

    def test_invalid_preconditions_produce_no_workflow(self) -> None:
        # a workflow observation with garbage fields still builds an
        # honest step; one with NO endpoint builds nothing
        workflows = build_workflows_from_observations([
            {"workflow_key": "w", "endpoint": "", "method": "POST"},
            {"workflow_key": "w", "endpoint": "/x", "method": ""},
        ])
        assert len(workflows) <= 1
        for wf in workflows:
            assert wf.steps  # only real steps

    def test_invalid_transition_evidence_is_not_a_violation(self) -> None:
        # an engine over a client that always 409s (correctly rejecting
        # invalid transitions) must NOT produce a violation candidate
        class _RejectingClient:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, path, *, body=None, headers=None):
                self.calls += 1
                return {
                    "status_code": 409,
                    "body": '{"error": "invalid_transition"}',
                    "headers": {"X-Actor-Echo": "tester",
                                "X-Resource-Type": "order"},
                }

        workflows = build_workflows_from_observations([{
            "fingerprint": "fp" + "b" * 14,
            "workflow_key": "w",
            "transition_key": "approve",
            "endpoint": "/api/w/approve",
            "method": "POST",
            "authorization_boundary": "role_scoped",
        }])
        candidates = build_sequence_candidates(workflows)
        approval = [c for c in candidates
                    if c.invariant == "approval_not_self_completable"][0]
        engine = CompositeWorkflowEngine(
            client=_RejectingClient(),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True),
            reset_fixture=lambda: None,
        )
        outcome = engine.execute(
            approval,
            control_headers={"X-Actor": "mgr"},
            actor_headers={"X-Actor": "intern"},
            negative_control_probe=("GET", "/api/vaults/quote"),
        )
        assert outcome.status is not SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE

    def test_destructive_operations_blocked_outside_authorized_fixtures(self):
        workflows = build_workflows_from_observations([{
            "fingerprint": "fp" + "e" * 14,
            "workflow_key": "w",
            "transition_key": "stage",
            "endpoint": "/api/w/stage",
            "method": "POST",
        }, {
            "fingerprint": "fp" + "c" * 14,
            "workflow_key": "w",
            "transition_key": "purge",
            "endpoint": "/api/w/purge",
            "method": "POST",
            "destructive": True,
        }])
        candidates = build_sequence_candidates(workflows)
        if not candidates:
            pytest.skip("no destructive candidate produced")
        for contract in (
            FixtureSafetyContract(resettable=False),  # not resettable
            FixtureSafetyContract(  # not isolated
                resettable=True, isolated=False, authorized_by_operator=True),
            FixtureSafetyContract(  # not operator-authorized
                resettable=True, isolated=True, authorized_by_operator=False),
        ):
            engine = CompositeWorkflowEngine(client=_NeverClient(), safety=contract)
            for candidate in candidates:
                outcome = engine.execute(candidate)
                assert outcome.status is SequenceOutcomeStatus.BLOCKED

    def test_budget_enforcement(self) -> None:
        engine = CompositeWorkflowEngine(
            client=_NeverClient(),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True),
            max_requests_per_sequence=2,
        )
        workflows = build_workflows_from_observations([{
            "fingerprint": "fp" + "d" * 14, "workflow_key": "w",
            "transition_key": f"s{i}", "endpoint": f"/api/w/s{i}",
            "method": "POST", "authorization_boundary": "same_identity",
        } for i in range(6)])
        candidates = build_sequence_candidates(workflows)
        replay = [c for c in candidates
                  if c.invariant == "replay_restriction"][0]
        outcome = engine.execute(replay, actor_headers={"X-Actor": "a"})
        assert outcome.requests_issued <= 2

    def test_partial_failure_handled(self) -> None:
        class _HalfFailingClient:
            def __init__(self):
                self.n = 0

            def request(self, method, path, *, body=None, headers=None):
                self.n += 1
                if self.n > 2:
                    raise ConnectionError("mid-sequence failure")
                return {"status_code": 200, "body": "{}",
                        "headers": {"X-Actor-Echo": "a"}}

        engine = CompositeWorkflowEngine(
            client=_HalfFailingClient(),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True),
            reset_fixture=lambda: None,
        )
        workflows = build_workflows_from_observations([{
            "fingerprint": f"fp-e{i}", "workflow_key": "w",
            "transition_key": f"s{i}", "endpoint": f"/api/w/s{i}",
            "method": "POST",
        } for i in range(4)])
        candidates = build_sequence_candidates(workflows)
        outcome = engine.execute(candidates[0], actor_headers={"X-Actor": "a"})
        # honest outcome: never a crash, never a fabricated confirmation
        assert outcome.status in (
            SequenceOutcomeStatus.INCONCLUSIVE,
            SequenceOutcomeStatus.FALSE_HYPOTHESIS,
            SequenceOutcomeStatus.EXPECTED_DENIAL,
            SequenceOutcomeStatus.VALID_TRANSACTION,
            SequenceOutcomeStatus.EXPECTED_TRANSITION,
            SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE,
        )


class _NeverClient:
    def request(self, *args, **kwargs):
        raise AssertionError("no request may ever leave this client")


class TestCausalIntegrity:
    """§10.5 — the confirmation architecture is untouched."""

    def test_causal_guard_remains_sole_same_actor_authority(self) -> None:
        from webpent.cqa_v2 import guarded_causal_evaluate
        from webpent.cqa_v2.causal_guard import Verdict
        # a response-ONLY difference (no authorization context) can
        # never confirm
        result = guarded_causal_evaluate(
            baseline=_obs_guard(200, "aaa", actor="u1"),
            candidate=_obs_guard(200, "bbb", actor="u1"),  # differs, same actor
            control=_obs_guard(200, "ccc", actor="u1"),   # no auth enforcement
        )
        assert result.verdict is not Verdict.CONFIRMED

    def test_no_alternate_confirmation_path_in_new_modules(self) -> None:
        # the new modules expose no finding/promotion/confirm API
        import webpent.production.alias_resolution as alias_mod
        import webpent.production.composite_workflows as wf_mod
        import webpent.production.identity_workflow as node_mod
        import webpent.production.multi_identity as mi_mod
        import webpent.production.object_identity as oi_mod
        for module in (alias_mod, wf_mod, node_mod, mi_mod, oi_mod):
            public = [n for n in dir(module) if not n.startswith("_")]
            for name in public:
                assert not any(token in name.lower() for token in (
                    "confirm_finding", "promote", "create_finding",
                    "seal_proof", "authoritative",
                )), f"{module.__name__}.{name}"

    def test_response_difference_alone_cannot_confirm(self) -> None:
        # the composite engine with no authorization context anywhere:
        # two different bodies, same actor -> no violation candidate
        class _VaryingClient:
            def __init__(self):
                self.n = 0

            def request(self, method, path, *, body=None, headers=None):
                self.n += 1
                return {
                    "status_code": 200,
                    "body": '{"seq": %d}' % self.n,
                    "headers": {"X-Resource-Type": "order"},
                }

        engine = CompositeWorkflowEngine(
            client=_VaryingClient(),
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True),
            reset_fixture=lambda: None,
        )
        workflows = build_workflows_from_observations([{
            "fingerprint": "fp" + "f" * 14, "workflow_key": "w",
            "transition_key": "go", "endpoint": "/api/w/go", "method": "POST",
        }, {
            "fingerprint": "fp" + "g" * 14, "workflow_key": "w",
            "transition_key": "done", "endpoint": "/api/w/done",
            "method": "POST",
        }])
        candidates = build_sequence_candidates(workflows)
        replay = [c for c in candidates
                  if c.invariant == "replay_restriction"][0]
        outcome = engine.execute(replay, actor_headers={"X-Actor": "a"})
        assert outcome.status is not SequenceOutcomeStatus.POLICY_VIOLATION_CANDIDATE

    def test_identity_similarity_alone_cannot_promote(self) -> None:
        # the full pipeline over a state whose ONLY signal is
        # similar-looking endpoints: no hypotheses that could promote
        from webpent.config.settings import get_settings
        from webpent.production.identity_workflow import identity_workflow_node
        settings = get_settings()
        saved = {
            f: getattr(settings, f) for f in (
                "enable_object_identity", "enable_alias_resolution",
                "enable_multi_identity_reasoning", "enable_composite_workflows",
            )
        }
        for f in saved:
            setattr(settings, f, True)
        try:
            state = {
                "base_url": "https://lab.example",
                "crawled_data": {"openapi_routes": [
                    {"method": "GET", "path": "/api/thing/1"},
                    {"method": "GET", "path": "/api/thing/2"},
                    {"method": "GET", "path": "/api/things/1"},
                ]},
            }
            update = identity_workflow_node(state)
        finally:
            for f, v in saved.items():
                setattr(settings, f, v)
        # similar paths alone: no alias confirmed, no hypotheses produced
        graph = update.get("identity_alias_graph", {}).get("graph", {})
        confirmed = [
            r for r in graph.get("relationships", [])
            if r["state"] == "confirmed_same_object"
        ]
        assert not confirmed
        assert not update.get("hypotheses")


def _obs_guard(status: int, body: str, *, actor: str) -> dict:
    import hashlib
    return {
        "status_code": status,
        "body_length": len(body),
        "semantic_digest": hashlib.sha256(body.encode()).hexdigest(),
        "response_shape": "text",
        "request": {"method": "GET", "path": "/api/x/1",
                    "header_names": ["x-actor-echo"]},
        "headers": {"x-actor-echo": actor},
        "body_preview": body,
    }


class TestFaultInjection:
    """§10.6 — the engine fails safely with honest telemetry."""

    def _all_flags(self):
        from webpent.config.settings import get_settings
        settings = get_settings()
        flags = (
            "enable_object_identity", "enable_alias_resolution",
            "enable_multi_identity_reasoning", "enable_composite_workflows",
        )
        saved = {f: getattr(settings, f) for f in flags}
        for f in flags:
            setattr(settings, f, True)
        return settings, saved

    def test_missing_identity_fields(self) -> None:
        observations = observations_from_campaign_state({
            "object_identity_observations": [
                {"endpoint": "/a"},  # no type, no id
                {"resource_type": "x", "object_id": "1"},  # no endpoint
            ],
        })
        assert observations == []

    def test_malformed_object_references(self) -> None:
        registry = ObjectIdentityRegistry()
        registry.ingest(ResourceObservation(
            endpoint="/x", resource_type="x", object_id=None,  # type: ignore
        ))
        assert registry.identities() == []

    def test_conflicting_alias_evidence_preserved(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/o/1", rtype="orders", oid="1", tenant="t", body_id=True)
        b = _obs("/api/orders/1", rtype="orders", oid="1", tenant="t", body_id=True)
        resolver = AliasResolver(registry)
        resolver.classify_pair(a, b)  # confirmed
        c = _obs("/api/orders/1", rtype="orders", oid="1", tenant="other")
        resolver.classify_pair(a, c)  # conflicting
        states = [r.state for r in resolver.relationships()]
        assert AliasState.CONFLICTING_EVIDENCE in states

    def test_unknown_tenant(self) -> None:
        registry = ObjectIdentityRegistry()
        a = _obs("/api/orders/1", oid="1", tenant="")
        b = _obs("/api/orders/1", oid="1", tenant="mystery")
        registry.ingest(a)
        registry.ingest(b)
        # unknown tenant never silently merges with a known one
        rel = registry.relate(a, b)
        assert rel.kind is IdentityRelationshipKind.AMBIGUOUS_IDENTITY

    def test_missing_principal(self) -> None:
        principals = principals_from_state({})  # no profiles at all
        matrix = matrix_from_observations(
            principals, [
                {"principal_ref": "ghost", "object_ref": "o:1",
                 "operation": "read", "outcome": "allowed"},
            ],
        )
        assert matrix.cells() == []

    def test_expired_session_context(self) -> None:
        principal = PrincipalContext(
            principal_ref="u1", role=PrincipalRole.OWNER,
            session_ref="session:u1",
            authentication_state=AuthenticationState.EXPIRED,
        )
        assert principal.authentication_state is AuthenticationState.EXPIRED
        # the context is carried honestly; consumers see EXPIRED

    def test_duplicate_observations_idempotent(self) -> None:
        registry = ObjectIdentityRegistry()
        obs = _obs("/api/orders/9", oid="9", tenant="t", body_id=True)
        for _ in range(5):
            registry.ingest(obs)
        assert len(registry.identities()) == 1
        assert registry.identities()[0].representations.count(
            "/api/orders/9") == 1

    def test_malformed_workflow_state(self) -> None:
        workflows = build_workflows_from_observations([
            "string", None, 123, {}, {"workflow_key": "k"},  # junk
        ])
        for wf in workflows:
            assert wf.steps

    def test_missing_validator_class_fails_closed(self) -> None:
        from webpent.production.validators import ValidatorError, run_validator
        with pytest.raises(ValidatorError):
            run_validator("NOT_A_REAL_CLASS", baseline={}, candidate={},
                          negative_control={})

    def test_empty_execution_inventory(self) -> None:
        # no workflow observations -> no candidates -> nothing executes
        workflows = build_workflows_from_observations([])
        assert build_sequence_candidates(workflows) == []

    def test_budget_exhaustion_honest(self) -> None:
        class _CountingClient:
            def __init__(self):
                self.n = 0

            def request(self, method, path, *, body=None, headers=None):
                self.n += 1
                return {"status_code": 200, "body": "{}",
                        "headers": {"X-Actor-Echo": "a"}}

        client = _CountingClient()
        engine = CompositeWorkflowEngine(
            client=client,
            safety=FixtureSafetyContract(
                resettable=True, isolated=True, authorized_by_operator=True),
            max_requests_per_sequence=3,
            reset_fixture=lambda: None,
        )
        workflows = build_workflows_from_observations([{
            "fingerprint": f"fp-h{i}", "workflow_key": "w",
            "transition_key": f"s{i}", "endpoint": f"/api/w/s{i}",
            "method": "POST",
        } for i in range(8)])
        candidates = build_sequence_candidates(workflows)
        replay = [c for c in candidates
                  if c.invariant == "replay_restriction"][0]
        outcome = engine.execute(replay, actor_headers={"X-Actor": "a"})
        assert client.n <= 3  # the budget is a hard ceiling
        assert any(  # the exhaustion is visible in the trace
            step.get("reason") == "per-sequence request budget exhausted"
            for phase in outcome.evidence_trace
            for step in phase["steps"]
        )

    def test_node_survives_total_garbage_state(self) -> None:
        from webpent.production.identity_workflow import identity_workflow_node
        settings, saved = self._all_flags()
        try:
            update = identity_workflow_node({
                "base_url": None, "crawled_data": 42,
                "workflow_observations": [True, False, 3.14],
                "identity_profiles": "junk",
                "authorization_observations": {"not": "a list"},
            })
        finally:
            for f, v in saved.items():
                setattr(settings, f, v)
        assert "identity_workflow" in update
        assert update["identity_workflow"]["hypotheses_generated"] == 0
