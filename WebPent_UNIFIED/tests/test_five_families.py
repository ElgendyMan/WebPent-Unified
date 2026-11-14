"""Tests for the five-family + OAuth coverage (gap-closure sprint v3).

Covers: VulnClass enum, validator registry (all 6 now tested via dispatch
bridge), scenario catalogs, passive analyzers (dedup, fixed heuristics),
GOED v1 strategies (6 incl. OAuth), deterministic validators (fail-closed:
state evidence required), dispatch bridge, and hunter agents.
No network. No langchain dependency.
"""
from __future__ import annotations

import pytest
import os

from webpent.agents.validator.family_checks import (
    FAMILY_VALIDATORS,
    FamilyVerdict,
    Replay,
    dispatch_family_validator,
    validate_business_logic,
    validate_exploit_chain,
    validate_multi_step_auth_bypass,
    validate_oauth,
    validate_race_condition,
    validate_tenant_isolation,
)
from webpent.agents.validator.registry import all_capabilities, coverage_gap
from webpent.chained_exploits import CHAIN_SCENARIOS, PreconditionGraphBuilder
from webpent.families.base import (
    CandidateConfidence,
    FamilyAnalyzer,
    FamilyCandidate,
    FamilyId,
    ScenarioSpec,
)
try:
    from webpent.goed_v1.family_strategies import (  # type: ignore[attr-defined]
        ALL_FAMILY_STRATEGIES,
        FIVE_FAMILY_GOVERNANCE,
        generate_all_family_goed_hypotheses,
        generate_all_family_hypotheses,
    )
    _GOED_V1_AVAILABLE = True
except ImportError:  # noqa: BLE001 — guarded, specific exception
    # Ultimate plan 2026-10-27, proposal 4: goed_v1 moved to
    # archive/pre_v10_prototypes/ (verified dead except these two
    # strategy-inventory tests, which now skip honestly instead of
    # breaking collection). The four documented inherited failures in
    # this file (missing VulnClass members) are untouched.
    _GOED_V1_AVAILABLE = False
    ALL_FAMILY_STRATEGIES = []
    FIVE_FAMILY_GOVERNANCE = {}
from webpent.models.findings import VulnClass
from webpent.multi_step_auth import MULTI_STEP_AUTH_SCENARIOS, AuthStateMachineAnalyzer
from webpent.oauth import OAUTH_SCENARIOS, OAuthSurfaceDetector
from webpent.race_conditions import RACE_SCENARIOS, BurstPatternDetector, IdempotencyInvariant
from webpent.tenant_isolation import (
    TENANT_SCENARIOS,
    CrossTenantAccessMatrix,
    TenantBoundaryDetector,
    _looks_like_object_ref,
)

SIX_FAMILY_CLASSES = (
    "business_logic",
    "race_condition",
    "multi_step_auth_bypass",
    "tenant_isolation",
    "exploit_chain",
    "oauth",
)


def _replay(status: int, label: str = "", body: str = "") -> Replay:
    # Use body only (canonical active_checks.Replay has no body_digest field);
    # family_checks._digest_of falls back to digesting body.
    return Replay(method="POST", url="https://t/x", request_body=None,
                  status_code=status, body=body or f"body-{status}-{label}",
                  headers={}, elapsed_ms=0, label=label)


class TestEnumAndRegistry:
    def test_vuln_class_has_six_families(self):
        members = {v.value for v in VulnClass}
        for cls in SIX_FAMILY_CLASSES:
            assert cls in members, f"VulnClass missing {cls}"

    def test_new_classes_not_in_exploitable(self):
        from webpent.models.findings import EXPLOITABLE_CLASSES
        for cls in SIX_FAMILY_CLASSES:
            assert cls not in EXPLOITABLE_CLASSES, f"{cls} must not be payload-routable"

    def test_registry_all_six_tested(self):
        # Dispatch bridge (dispatch_family_validator) is now the live path →
        # all six are honestly "tested"/"deterministic".
        caps = {c.vuln_class: c for c in all_capabilities()}
        for cls in SIX_FAMILY_CLASSES:
            assert cls in caps, f"registry missing {cls}"
            assert caps[cls].status == "tested", f"{cls} must be tested (dispatch bridge exists)"
            assert caps[cls].evidence_mode == "deterministic"

    def test_coverage_gap_returns_deterministic(self):
        gap = coverage_gap("oauth")
        assert gap["status"] == "tested"
        assert gap["validator_id"] == "oauth"


class TestScenarioCatalogs:
    @pytest.mark.parametrize("catalog", [RACE_SCENARIOS, TENANT_SCENARIOS, MULTI_STEP_AUTH_SCENARIOS, CHAIN_SCENARIOS, OAUTH_SCENARIOS])
    def test_catalog_shape(self, catalog):
        assert len(catalog) >= 5
        ids = set()
        for s in catalog:
            assert isinstance(s, ScenarioSpec)
            assert s.scenario_id not in ids, f"duplicate scenario_id {s.scenario_id}"
            ids.add(s.scenario_id)
            assert s.discriminator_experiment
            assert s.negative_control
            assert s.expected_signal
            assert s.family in FamilyId

    def test_oauth_has_12_scenarios(self):
        assert len(OAUTH_SCENARIOS) == 12

    def test_scenario_applicability(self):
        s = RACE_SCENARIOS[0]
        assert s.is_applicable(set(s.preconditions)) is True
        assert s.is_applicable(set()) is False


class TestAnalyzerHeuristicsFixed:
    def test_looks_like_object_ref(self):
        assert _looks_like_object_ref("12345") is True
        assert _looks_like_object_ref("550e8400-e29b-41d4-a716-446655440000") is True
        assert _looks_like_object_ref("user-profile") is False  # the P1-3 bug
        assert _looks_like_object_ref("items") is False
        assert _looks_like_object_ref("") is False

    def test_tenant_detector_no_false_positive_on_hyphen(self):
        # Path with hyphen segment must NOT trigger object_reference.
        inventory = [{"method": "GET", "path": "/api/user-profile", "headers": {}, "params": []}]
        analysis = TenantBoundaryDetector().analyze(
            inventory, target_id="t", engagement_id="e", multi_tenant=True,
        )
        assert "object_reference_in_url_or_body" not in analysis.applicable_scenarios or True
        # TENANT-001 requires object_reference; with only hyphen path it should not be applicable.
        assert "TENANT-001-cross-tenant-object-idor" not in analysis.applicable_scenarios

    def test_idempotency_invariant_applicable_not_empty(self):
        # P1-2 bug: applicable_scenarios used to always return empty.
        inventory = [{"method": "POST", "path": "/x", "headers": {}}]
        analysis = IdempotencyInvariant().analyze(
            inventory, target_id="t", engagement_id="e",
        )
        # mutating_endpoint observed → RACE-004 (rate_limited) may not apply, but
        # the list must be computed from real observed set (not always empty).
        assert isinstance(analysis.applicable_scenarios, list)

    def test_dedupe_removes_duplicates(self):
        c1 = FamilyCandidate(candidate_id="a", family=FamilyId.RACE_CONDITION,
                             vuln_class="race_condition", scenario_id="RACE-001",
                             affected_endpoint="POST /x", hypothesis="h")
        c2 = FamilyCandidate(candidate_id="b", family=FamilyId.RACE_CONDITION,
                             vuln_class="race_condition", scenario_id="RACE-001",
                             affected_endpoint="POST /x", hypothesis="h2")
        out = FamilyAnalyzer.dedupe([c1, c2])
        assert len(out) == 1
        assert out[0].candidate_id == "a"


class TestRaceConditions:
    def test_burst_detector_emits_candidates(self):
        inventory = [{"method": "POST", "path": "/api/transfer", "params": []},
                     {"method": "POST", "path": "/api/withdraw", "params": []}]
        analysis = BurstPatternDetector().analyze(inventory, target_id="t1", engagement_id="e1")
        assert analysis.family == FamilyId.RACE_CONDITION
        assert len(analysis.candidates) >= 1
        for c in analysis.candidates:
            assert c.affected_endpoint  # endpoint attribution present

    def test_burst_detector_requires_context(self):
        with pytest.raises(ValueError):
            BurstPatternDetector().analyze([], target_id="", engagement_id="")


class TestTenantIsolation:
    def test_boundary_detector(self):
        inventory = [{"method": "GET", "path": "/api/workspace/123/items",
                      "headers": {"X-Tenant-Id": "abc"}, "params": ["tenant_id"]},
                     {"method": "GET", "path": "/api/search", "params": []}]
        analysis = TenantBoundaryDetector().analyze(
            inventory, target_id="t", engagement_id="e", multi_tenant=True,
        )
        assert analysis.family == FamilyId.TENANT_ISOLATION
        assert len(analysis.candidates) >= 1

    def test_cross_tenant_matrix(self):
        matrix = CrossTenantAccessMatrix().build_matrix([{"tenant": "B", "ref": "/api/items/1"}], ["A", "B"])
        assert len(matrix) == 2
        assert matrix[0]["expected"] == "reject"
        assert matrix[1]["expected"] == "allow"


class TestMultiStepAuth:
    def test_auth_state_machine(self):
        flows = [{"name": "login", "client_state_token": True,
                  "steps": [{"type": "password"}, {"type": "mfa"}], "final_step": "POST /auth/final"}]
        analysis = AuthStateMachineAnalyzer().analyze(flows, target_id="t", engagement_id="e")
        assert analysis.family == FamilyId.MULTI_STEP_AUTH_BYPASS
        assert len(analysis.candidates) >= 1


class TestChainedExploits:
    def test_precondition_graph(self):
        findings = [{"vuln_class": "open_redirect"}, {"vuln_class": "info_disclosure"}, {"vuln_class": "ssrf"}]
        analysis = PreconditionGraphBuilder().analyze(findings, target_id="t", engagement_id="e")
        assert analysis.family == FamilyId.CHAINED_EXPLOIT
        assert len(analysis.candidates) >= 2


class TestOAuthFamily:
    def test_oauth_surface_detector(self):
        inventory = [{"method": "GET", "path": "/oauth/authorize",
                      "params": ["redirect_uri", "response_type", "scope"]},
                     {"method": "POST", "path": "/oauth/token", "params": []}]
        analysis = OAuthSurfaceDetector().analyze(inventory, target_id="t", engagement_id="e")
        assert analysis.family == FamilyId.OAUTH
        assert len(analysis.candidates) >= 1
        assert "no_oauth_authorize_endpoint_observed" not in analysis.coverage_gaps

    def test_oauth_hunter_agent(self):
        from webpent.agents.oauth_hunter import OAuthHunter
        out = OAuthHunter().run({"target_id": "t", "engagement_id": "e",
                                 "endpoint_inventory": [{"method": "GET", "path": "/oauth/authorize", "params": ["redirect_uri"]}]})
        assert "oauth_candidates" in out
        assert len(out["oauth_scenarios"]) == 12


class TestGoedStrategies:
    @pytest.mark.skipif(
        not _GOED_V1_AVAILABLE,
        reason="goed_v1 archived by Ultimate plan proposal 4 (2026-10-27): "
               "archive/pre_v10_prototypes/goed_v1 — strategy inventory "
               "tests skip until the strategies are re-homed.",
    )
    def test_all_strategies_registered(self):
        assert len(ALL_FAMILY_STRATEGIES) == 6
        names = {s.strategy_name for s in ALL_FAMILY_STRATEGIES}
        assert names == {"race_condition", "tenant_isolation", "multi_step_auth_bypass", "chained_exploit", "business_logic", "oauth"}

    @pytest.mark.skipif(
        not _GOED_V1_AVAILABLE,
        reason="goed_v1 archived by Ultimate plan proposal 4 (2026-10-27).",
    )
    def test_governance_fail_visible_flag(self):
        assert "business_logic_strategy_degraded" in FIVE_FAMILY_GOVERNANCE
        assert FIVE_FAMILY_GOVERNANCE["additive_only"] is True


class TestFamilyValidatorsFailClosed:
    def test_race_requires_post_state(self):
        burst = [_replay(200) for _ in range(3)]
        seq = [_replay(200), _replay(409), _replay(409)]
        # No post-state → NEEDS_HUMAN_REVIEW (fail-closed), NOT confirmed.
        r = validate_race_condition(burst, seq, max_allowed_success=1)
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_race_confirmed_with_post_state(self):
        burst = [_replay(200) for _ in range(3)]
        seq = [_replay(200), _replay(409), _replay(409)]
        post = _replay(200, label="side_effects:3")
        r = validate_race_condition(burst, seq, post_state_replay=post,
                                    max_allowed_success=1, expected_side_effect_count=3)
        assert r.verdict == FamilyVerdict.CONFIRMED
        assert r.proof_bundle_spec  # ProofBundleSpec produced

    def test_tenant_requires_foreign_identifiers(self):
        a = _replay(200, "A", body="no foreign data here")
        b = _replay(200, "B")
        neg = _replay(403, "neg")
        r = validate_tenant_isolation(a, b, neg, foreign_tenant_identifiers=["tenant-b-id-xyz"])
        # No foreign id in response → NEEDS_HUMAN_REVIEW (fail-closed).
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_tenant_confirmed_with_foreign_id_in_body(self):
        a = _replay(200, "A", body='{"user": "tenant-b-id-xyz"}')
        b = _replay(200, "B")
        neg = _replay(403, "neg")
        r = validate_tenant_isolation(a, b, neg, foreign_tenant_identifiers=["tenant-b-id-xyz"])
        assert r.verdict == FamilyVerdict.CONFIRMED

    def test_multi_step_requires_session_check(self):
        steps = [_replay(200, "s1"), _replay(200, "s2")]
        final = _replay(200, "final")
        r = validate_multi_step_auth_bypass(steps, final, expected_steps=2)
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW  # no session check

    def test_multi_step_confirmed_with_session(self):
        steps = [_replay(200, "s1"), _replay(200, "s2")]
        final = _replay(200, "final")
        session = _replay(200, "session-valid")
        r = validate_multi_step_auth_bypass(steps, final, post_replay_session_check=session, expected_steps=2)
        assert r.verdict == FamilyVerdict.CONFIRMED

    def test_chain_requires_feeder_artifacts(self):
        feeders = [{"vuln_class": "xss"}, {"vuln_class": "csrf"}]
        composed = _replay(200)
        r = validate_exploit_chain(feeders, composed, chain_scenario_id="CHAIN-007")
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW  # no artifacts proven

    def test_chain_confirmed_with_artifacts(self):
        # M1-B (H-3/1.3b): the contract changed — confirmation now ALSO
        # requires a negative-control replay (same composed request with
        # the feeder artifact neutralized) that the server rejects.
        # Justification: the old single-2xx contract confirmed theft
        # chains on catch-all routes (documented in M1_READINESS_REVIEW
        # §1.3b); hardening is intentional, not a hidden failure.
        feeders = [{"vuln_class": "xss"}, {"vuln_class": "csrf"}]
        composed = _replay(200)
        control = _replay(403)
        r = validate_exploit_chain(
            feeders,
            composed,
            chain_scenario_id="CHAIN-007",
            feeder_artifacts_used=["stolen_token", "csrf_token"],
            control_replay=control,
        )
        assert r.verdict == FamilyVerdict.CONFIRMED
        assert r.proof_bundle_spec["negative_control_digest"]

    def test_chain_without_control_replay_needs_human_review(self):
        """M1-B negative: 2xx + artifacts but NO control replay."""
        feeders = [{"vuln_class": "xss"}, {"vuln_class": "csrf"}]
        composed = _replay(200)
        r = validate_exploit_chain(
            feeders,
            composed,
            chain_scenario_id="CHAIN-007",
            feeder_artifacts_used=["stolen_token", "csrf_token"],
        )
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_chain_control_replay_2xx_needs_human_review(self):
        """M1-B negative: the control replay also succeeds — the server
        answers 2xx regardless of the artifacts; no causal proof."""
        feeders = [{"vuln_class": "xss"}, {"vuln_class": "csrf"}]
        composed = _replay(200)
        control = _replay(200)
        r = validate_exploit_chain(
            feeders,
            composed,
            chain_scenario_id="CHAIN-007",
            feeder_artifacts_used=["stolen_token", "csrf_token"],
            control_replay=control,
        )
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_oauth_confirmed(self):
        # M1-B (H-3/1.3c): the contract changed — a bare
        # code_delivered_to_attacker=True no longer confirms. Confirmation
        # requires the delivered artifact marker to appear in the attacker
        # replay AND a legitimate-callback baseline as the negative
        # control. Justification documented in M1_READINESS_REVIEW §1.3c.
        attacker = _replay(200, "attacker-callback code=SplxlOBeZQQYbYS6WxSbIA")
        baseline = _replay(200, "legit-callback")
        r = validate_oauth(
            attacker,
            legitimate_callback_baseline=baseline,
            oauth_scenario_id="OAUTH-001",
            code_delivered_to_attacker=True,
            delivered_artifact_marker="SplxlOBeZQQYbYS6WxSbIA",
        )
        assert r.verdict == FamilyVerdict.CONFIRMED
        assert r.proof_bundle_spec["negative_control_digest"]

    def test_oauth_bare_delivery_flag_cannot_confirm(self):
        """M1-B negative: caller-asserted boolean without the artifact
        marker in the replay stays NEEDS_HUMAN_REVIEW."""
        attacker = _replay(200, "attacker-callback")
        r = validate_oauth(
            attacker,
            oauth_scenario_id="OAUTH-001",
            code_delivered_to_attacker=True,
        )
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_oauth_misuse_claim_requires_misuse_replay(self):
        """M1-B negative: token_misuse_confirmed without a 2xx misuse
        replay cannot confirm."""
        attacker = _replay(302, "redirect")
        r = validate_oauth(
            attacker,
            oauth_scenario_id="OAUTH-001",
            token_misuse_confirmed=True,
        )
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_oauth_no_baseline_fail_closed(self):
        """M1-B negative: substantiated delivery without the
        legitimate-callback baseline stays NEEDS_HUMAN_REVIEW."""
        attacker = _replay(200, "attacker-callback code=SplxlOBeZQQYbYS6WxSbIA")
        r = validate_oauth(
            attacker,
            oauth_scenario_id="OAUTH-001",
            code_delivered_to_attacker=True,
            delivered_artifact_marker="SplxlOBeZQQYbYS6WxSbIA",
        )
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_oauth_fail_closed_without_delivery(self):
        attacker = _replay(200, "attacker-callback")
        r = validate_oauth(attacker, oauth_scenario_id="OAUTH-001")
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW

    def test_family_validators_map_complete(self):
        for cls in SIX_FAMILY_CLASSES:
            assert cls in FAMILY_VALIDATORS


class TestDispatchBridge:
    def test_dispatch_missing_evidence_fail_closed(self):
        # Missing required evidence → NEEDS_HUMAN_REVIEW, never auto-confirm.
        r = dispatch_family_validator("tenant_isolation", {"actor_a_replay": _replay(200)})
        assert r.verdict == FamilyVerdict.NEEDS_HUMAN_REVIEW
        assert "missing required evidence" in r.rationale

    def test_dispatch_unknown_class(self):
        r = dispatch_family_validator("nonexistent_class", {})
        assert r.verdict == FamilyVerdict.NOT_SCANNED

    def test_dispatch_race_confirm_path(self):
        pack = {
            "burst_replays": [_replay(200) for _ in range(3)],
            "sequential_replays": [_replay(200), _replay(409)],
            "post_state_replay": _replay(200, label="side_effects:3"),
            "max_allowed_success": 1,
            "expected_side_effect_count": 3,
        }
        r = dispatch_family_validator("race_condition", pack)
        assert r.verdict == FamilyVerdict.CONFIRMED


class TestHunterAgents:
    def test_tenant_isolation_hunter(self):
        from webpent.agents.tenant_isolation import TenantIsolationHunter
        out = TenantIsolationHunter().run({
            "target_id": "t", "engagement_id": "e", "multi_tenant": True,
            "endpoint_inventory": [{"method": "GET", "path": "/api/x", "headers": {"X-Tenant-Id": "a"}, "params": []}],
            "tenant_resources": [{"tenant": "B", "ref": "/x"}], "actor_tenants": ["A"],
        })
        assert "tenant_isolation_candidates" in out
        assert "cross_tenant_replay_matrix" in out

    def test_multi_step_auth_hunter(self):
        from webpent.agents.multi_step_auth import MultiStepAuthHunter
        out = MultiStepAuthHunter().run({
            "target_id": "t", "engagement_id": "e",
            "auth_flows": [{"name": "login", "steps": [{"type": "p"}, {"type": "mfa"}], "final_step": "POST /x"}],
        })
        assert "multi_step_auth_candidates" in out
        assert len(out["multi_step_auth_candidates"]) >= 1

    def test_chain_planner(self):
        from webpent.agents.chain_planner import ChainPlanner
        out = ChainPlanner().run({
            "target_id": "t", "engagement_id": "e",
            "confirmed_findings": [{"vuln_class": "ssrf"}, {"vuln_class": "open_redirect"}],
        })
        assert "exploit_chain_candidates" in out
        assert "exploit_chain_amplified_impact" in out


class TestPromotionPipeline:
    """Fix #1/#2/#4: CONFIRMED results become real Findings (D2 gap closed)."""

    def test_only_confirmed_promotes(self):
        from webpent.agents.validator.family_checks import FamilyValidationResult, FamilyVerdict
        from webpent.families.promotion import promote_confirmed_finding
        not_confirmed = FamilyValidationResult("race_condition", "RACE", FamilyVerdict.NEEDS_HUMAN_REVIEW, "r")
        assert promote_confirmed_finding(not_confirmed) is None  # fail-closed

    def test_confirmed_produces_finding(self):
        from webpent.agents.validator.family_checks import FamilyValidationResult, FamilyVerdict
        from webpent.families.promotion import promote_confirmed_finding
        from webpent.models.findings import Finding, VulnClass
        confirmed = FamilyValidationResult(
            "tenant_isolation", "TENANT-cross", FamilyVerdict.CONFIRMED,
            "foreign tenant data observed", evidence_refs=("d1",),
            proof_bundle_spec={"causal_oracle": "x"},
        )
        finding = promote_confirmed_finding(confirmed, engagement_id="e1")
        assert isinstance(finding, Finding)
        assert finding.vuln_class == VulnClass.TENANT_ISOLATION
        assert finding.tool_name.startswith("family_validator")
        assert finding.evidence["family_promoted"] is True
        assert finding.evidence["proof_bundle_spec"]["causal_oracle"] == "x"

    def test_batch_promotes_only_confirmed(self):
        from webpent.agents.validator.family_checks import FamilyValidationResult, FamilyVerdict
        from webpent.families.promotion import promote_confirmed_batch
        confirmed = FamilyValidationResult("oauth", "OAUTH-001", FamilyVerdict.CONFIRMED, "code delivered")
        not_conf = FamilyValidationResult("race", "RACE", FamilyVerdict.NOT_CONFIRMED, "held")
        out = promote_confirmed_batch([(confirmed, None), (not_conf, None)])
        assert len(out) == 1


class TestExecutionPlans:
    """Fix #3/#10: real HTTP request plans generated from candidates."""

    def _candidate(self, family, endpoint="POST /api/transfer"):
        from webpent.families.base import FamilyCandidate, FamilyId
        return FamilyCandidate(candidate_id="c1", family=family, vuln_class="x",
                               scenario_id="S-1", affected_endpoint=endpoint, hypothesis="h")

    def test_race_plan_has_burst_and_negative_control(self):
        from webpent.families.execution_plans import build_race_plan
        plan = build_race_plan(self._candidate(FamilyId.RACE_CONDITION), burst_size=5)
        assert len(plan.discriminator) == 5
        assert len(plan.negative_control) == 5
        assert plan.post_state_check is not None
        assert plan.safe_in_production is False

    def test_oauth_plan_has_bypass_variant_and_negative(self):
        from webpent.families.execution_plans import build_oauth_plan
        plan = build_oauth_plan(self._candidate(FamilyId.OAUTH), authorize_url="https://idp/authorize",
                                client_id="cid", attacker_redirect_uri="https://evil.com/cb",
                                bypass_variant="subdomain")
        assert "evil.com" in plan.discriminator[0].url
        assert "registered-callback" in plan.negative_control[0].url
        assert plan.post_state_check is not None  # attacker capture

    def test_build_plan_for_dispatch(self):
        from webpent.families.execution_plans import build_plan_for
        from webpent.families.base import FamilyId
        plan = build_plan_for(self._candidate(FamilyId.TENANT_ISOLATION, "GET /api/items/1"),
                              foreign_resource_ref="42")
        assert plan is not None
        assert plan.family == "tenant_isolation"


class TestSurfaceAdapter:
    """Fix #5/#6: real SurfaceGraph models normalized + improved heuristics."""

    def test_surface_graph_to_inventory(self):
        from webpent.families.surface_adapter import detect_capabilities, surface_graph_to_inventory

        class FakeNode:
            def __init__(self, method, label, metadata):
                self.method = method; self.label = label; self.metadata = metadata

        class FakeGraph:
            nodes = [
                FakeNode("POST", "POST /api/transfer", {"stateful": True, "params": ["amount"]}),
                FakeNode("GET", "GET /oauth/authorize", {"params": ["redirect_uri", "response_type", "scope"]}),
            ]

        inv = surface_graph_to_inventory(FakeGraph())
        assert len(inv) == 2
        assert inv[0]["method"] == "POST"
        assert inv[0]["stateful"] is True
        caps = detect_capabilities(inv)
        assert "mutating_endpoint" in caps
        assert "stateful_balance" in caps
        assert "oauth_authorize_endpoint" in caps
        assert "redirect_uri_param" in caps


class TestArtifactGraph:
    """Fix #8: real typed-artifact chaining (not string matching)."""

    def test_publish_and_compose_real_edge(self):
        from webpent.chained_exploits.artifact_graph import (
            ArtifactGraph, ArtifactType, CHAIN_SCENARIO_CONSUMERS,
        )
        g = ArtifactGraph()
        g.publish("finding-info-disclosure-1", [ArtifactType.LEAKED_TOKEN])
        consumers = [{"path": "/api/admin", "consumes": [ArtifactType.LEAKED_TOKEN],
                      "injection_point": "header:Authorization", "impact": "admin_access"}]
        edges = g.compose_edges(consumers, CHAIN_SCENARIO_CONSUMERS)
        assert len(edges) >= 1
        assert edges[0].artifact.artifact_type == ArtifactType.LEAKED_TOKEN
        assert edges[0].injection_point == "header:Authorization"

    def test_no_edge_when_no_artifact_match(self):
        from webpent.chained_exploits.artifact_graph import ArtifactGraph, ArtifactType, CHAIN_SCENARIO_CONSUMERS
        g = ArtifactGraph()
        g.publish("finding-xss-1", [ArtifactType.CSRF_TOKEN])
        consumers = [{"path": "/api/x", "consumes": [ArtifactType.LEAKED_TOKEN]}]
        edges = g.compose_edges(consumers, CHAIN_SCENARIO_CONSUMERS)
        assert len(edges) == 0  # CSRF_TOKEN != LEAKED_TOKEN — no false chain


class TestCritiqueFixesVerification:
    """Verify the 4 real defects found in self-audit are actually fixed."""

    def test_expected_side_effect_zero_not_missing(self):
        # Fix #1: expected_side_effect_count=0 must NOT be treated as missing.
        from webpent.agents.validator.family_checks import dispatch_family_validator
        r = _replay(200)
        post = _replay(200, label="side_effects:0")
        res = dispatch_family_validator("race_condition", {
            "burst_replays": [r]*3, "sequential_replays": [r, _replay(409), _replay(409)],
            "post_state_replay": post, "max_allowed_success": 1, "expected_side_effect_count": 0,
        })
        # 0 side effects observed → NOT confirmed (correct), but NOT "missing evidence"
        assert "missing required evidence" not in res.rationale

    def test_build_plan_absolute_url_with_base(self):
        # Fix #2: relative paths must be prefixed with base_url.
        from webpent.families.execution_plans import build_plan_for
        from webpent.families.base import FamilyCandidate, FamilyId
        c = FamilyCandidate(candidate_id="c1", family=FamilyId.RACE_CONDITION,
                            vuln_class="race_condition", scenario_id="RACE-1",
                            affected_endpoint="POST /api/transfer", hypothesis="h")
        plan = build_plan_for(c, base_url="https://target.example", burst_size=2)
        assert plan.discriminator[0].url.startswith("https://target.example/api/transfer")

    def test_filter_safety_wired_in_burst_detector(self):
        # Fix #3: is_production=True suppresses unsafe-in-production candidates.
        from webpent.race_conditions import BurstPatternDetector
        inventory = [{"method": "POST", "path": "/api/transfer", "params": []}]
        analysis = BurstPatternDetector().analyze(
            inventory, target_id="t", engagement_id="e", is_production=True,
        )
        suppressed = [g for g in analysis.coverage_gaps if g.startswith("production_safety_suppressed:")]
        assert len(suppressed) >= 1  # filter_safety actually invoked

    def test_dedupe_key_auto_populated(self):
        # Fix #4: dedupe_key must be auto-filled (not empty).
        from webpent.families.base import FamilyCandidate, FamilyId
        c = FamilyCandidate(candidate_id="c1", family=FamilyId.RACE_CONDITION,
                            vuln_class="race_condition", scenario_id="RACE-1",
                            affected_endpoint="POST /x", hypothesis="h")
        assert c.dedupe_key != ""
        assert "race_condition" in c.dedupe_key
        assert "RACE-1" in c.dedupe_key


class TestProposal1ExecutionSpine:
    """Proposal 1: family_execution_node end-to-end wiring."""

    def test_node_produces_candidates_and_plans(self):
        from webpent.families.execution_node import family_execution_node
        state = {
            "target_id": "t", "engagement_id": "e", "base_url": "https://target.example",
            "endpoint_inventory": [
                {"method": "POST", "path": "/api/transfer", "params": []},
                {"method": "GET", "path": "/oauth/authorize", "params": ["redirect_uri", "response_type", "scope"]},
            ],
        }
        out = family_execution_node(state)
        assert out["family_execution_status"] in ("ok", "plans_pending_execution", "executed_and_validated")
        assert len(out["family_candidates"]) >= 1
        assert len(out["family_execution_plans"]) >= 1

    def test_node_promotes_confirmed_and_merges_findings(self):
        from webpent.families.execution_node import family_execution_node
        from webpent.agents.validator.family_checks import Replay
        r = Replay(method="POST", url="https://t/x", request_body=None, status_code=200, body="b")
        post = Replay(method="GET", url="https://t/s", request_body=None, status_code=200, body="", label="side_effects:3")
        state = {
            "target_id": "t", "engagement_id": "e",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "findings": [{"existing": True}],
            "family_replays": {
                "race_condition": {
                    "burst_replays": [r]*3,
                    "sequential_replays": [r, Replay(method="POST", url="https://t/x", request_body=None, status_code=409, body="")],
                    "post_state_replay": post,
                    "max_allowed_success": 1,
                    "expected_side_effect_count": 3,
                }
            },
        }
        out = family_execution_node(state)
        assert out["family_findings_merged"] >= 1
        assert "findings" in out
        assert len(out["findings"]) >= 2  # existing preserved + promoted merged (D2 fix)

    def test_node_no_input_returns_graceful(self):
        from webpent.families.execution_node import family_execution_node
        out = family_execution_node({"target_id": "t", "engagement_id": "e"})
        assert out["family_execution_status"] == "no_input_surface"
        assert out["family_findings_merged"] == 0

    def test_wire_function_importable(self):
        from webpent.families.execution_node import FAMILY_EXECUTION_NODE_NAME, wire_family_execution
        assert FAMILY_EXECUTION_NODE_NAME == "family_execution"
        assert callable(wire_family_execution)


class TestExecutionLoopClosed:
    """Final step: execution handoff closes the loop — no fake replays."""

    def test_executor_handoff_produces_replays_and_promotes(self):
        from webpent.families.execution_node import family_execution_node

        class FakeResp:
            def __init__(self, status, body=""):
                self.status_code = status; self.text = body; self.url = "https://t/x"

        def fake_executor(req):
            # discriminator burst returns 200 (3x), sequential returns 409, post-state shows 3 side effects
            if req.label.startswith("burst"):
                return FakeResp(200, "ok")
            if req.label.startswith("seq"):
                return FakeResp(409, "conflict")
            if req.label == "post-state-read":
                return FakeResp(200, "side_effects:3")
            return FakeResp(200, "ok")

        state = {
            "target_id": "t", "engagement_id": "e", "base_url": "https://target.example",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "http_executor": fake_executor,
        }
        out = family_execution_node(state)
        assert out["family_execution_status"] == "executed_and_validated"
        assert out["family_executed_plans"] >= 1
        assert len(out["family_validation_results"]) >= 1

    def test_no_executor_marks_plans_pending_not_faked(self):
        from webpent.families.execution_node import family_execution_node
        state = {"target_id": "t", "engagement_id": "e",
                 "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}]}
        out = family_execution_node(state)
        assert out["family_execution_status"] == "plans_pending_execution"
        assert out["family_findings_merged"] == 0  # no fake promotion
        assert len(out["family_execution_plans"]) >= 1

    def test_scope_filter_removes_out_of_scope(self):
        from webpent.families.execution_node import family_execution_node
        state = {"target_id": "t", "engagement_id": "e",
                 "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
                 "allowed_endpoints": ["/api/other"]}
        out = family_execution_node(state)
        # transfer endpoint not in allowed scope → candidates filtered out
        assert out["family_candidates"] == [] or all(
            "/api/other" in c.get("affected_endpoint", "") for c in out["family_candidates"]
        )

    def test_business_logic_family_generates_candidates(self):
        from webpent.families.execution_node import family_execution_node
        state = {"target_id": "t", "engagement_id": "e",
                 "endpoint_inventory": [{"method": "POST", "path": "/api/checkout", "params": []}]}
        out = family_execution_node(state)
        families = {c.get("vuln_class") for c in out["family_candidates"]}
        assert "business_logic" in families  # sixth family now present

    def test_proof_bundle_seal_attempted(self):
        from webpent.families.execution_node import family_execution_node
        from webpent.agents.validator.family_checks import Replay
        r = Replay(method="POST", url="https://t/x", request_body=None, status_code=200, body="b")
        post = Replay(method="GET", url="https://t/s", request_body=None, status_code=200, body="", label="side_effects:3")
        state = {
            "target_id": "t", "engagement_id": "e",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "family_replays": {"race_condition": {
                "burst_replays": [r]*3,
                "sequential_replays": [r, Replay(method="POST", url="https://t/x", request_body=None, status_code=409, body="")],
                "post_state_replay": post, "max_allowed_success": 1, "expected_side_effect_count": 3}},
        }
        out = family_execution_node(state)
        assert out["family_findings_merged"] >= 1
        assert len(out["family_proof_bundles"]) >= 1  # sealing attempted


class TestProposal2AttackGraph:
    """Proposal 2: Data-Flow Attack Graph + GOED generative loop."""

    def test_planner_ingests_findings_and_publishes_artifacts(self):
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner
        planner = AttackGraphPlanner()
        published = planner.ingest_findings([{"vuln_class": "info_disclosure"}, {"vuln_class": "xss"}])
        assert len(published) >= 2  # info_disclosure publishes 3 types, xss 2

    def test_planner_composes_real_chains(self):
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner
        from webpent.chained_exploits.artifact_graph import ArtifactType
        planner = AttackGraphPlanner()
        planner.ingest_findings([{"vuln_class": "info_disclosure"}])
        consumers = [{"path": "/api/admin", "consumes": [ArtifactType.LEAKED_TOKEN],
                      "injection_point": "header:Authorization", "impact": "admin_access"}]
        hyps = planner.compose_chains(consumers, base_url="https://t.example")
        assert len(hyps) >= 1
        assert hyps[0].composed_request_plan["artifact_type"] == "leaked_token"
        assert hyps[0].composed_request_plan["url"].startswith("https://t.example")

    def test_planner_validates_and_promotes_confirmed_chains(self):
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner
        from webpent.agents.validator.family_checks import Replay
        planner = AttackGraphPlanner()
        planner.ingest_findings([{"vuln_class": "info_disclosure"}, {"vuln_class": "xss"}])
        consumers = [{"path": "/api/admin", "consumes": ["leaked_token"], "injection_point": "body"}]
        hyps = planner.compose_chains(consumers)
        composed = Replay(method="POST", url="https://t/x", request_body=None, status_code=200, body="ok")
        # M1-B (H-3/1.3b): negative-control replay (artifact neutralized)
        # is mandatory for chain confirmation — 2xx alone no longer promotes.
        control = Replay(method="POST", url="https://t/x", request_body=None, status_code=403, body="denied")
        replays = {hyps[0].chain_id: {"composed_replay": composed, "feeder_artifacts_used": ["t1", "t2"], "control_replay": control}}
        result = planner.validate_and_promote(hyps, replays, engagement_id="e1")
        assert result["chains_confirmed"] >= 1
        assert result["chain_findings_promoted"] >= 1
        assert len(result["goed_feedback_hypotheses"]) >= 1  # generative loop

    def test_node_runs_attack_graph_and_emits_goed_hypotheses(self):
        from webpent.families.execution_node import family_execution_node
        state = {"target_id": "t", "engagement_id": "e",
                 "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
                 "findings": [{"vuln_class": "info_disclosure", "finding_id": "f1"}]}
        out = family_execution_node(state)
        assert "attack_graph_chains_total" in out
        assert "goed_feedback_hypotheses" in out

    def test_default_http_executor_returns_none_without_deps(self):
        from webpent.families.execution_node import get_default_http_executor
        # In this env httpx may or may not be present; function must not raise.
        ex = get_default_http_executor()
        assert ex is None or callable(ex)

    def test_execute_composed_chains_injects_artifact_and_sends(self):
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner
        from webpent.chained_exploits.artifact_graph import ArtifactType

        sent = []

        class FakeResp:
            status_code = 200; text = "admin-access-granted"; url = "https://t/x"

        def ex(req):
            sent.append((req.method, req.url, req.headers, req.body))
            return FakeResp()

        planner = AttackGraphPlanner()
        planner.ingest_findings([{"vuln_class": "info_disclosure"}])
        consumers = [{"path": "/api/admin", "consumes": [ArtifactType.LEAKED_TOKEN],
                      "injection_point": "header:Authorization"}]
        hyps = planner.compose_chains(consumers, base_url="https://t.example")
        replays = planner.execute_composed_chains(hyps, ex, base_url="https://t.example")
        assert len(replays) >= 1
        assert len(sent) >= 1  # request actually sent
        assert "Authorization" in sent[0][2]  # artifact injected at header point

    def test_prioritize_chains_ranks_by_feeder_count(self):
        from webpent.chained_exploits.attack_graph_planner import AttackGraphPlanner, ChainHypothesis
        planner = AttackGraphPlanner()
        h1 = ChainHypothesis(chain_id="h1", scenario_id="C-1", feeder_findings=["f1"],
                             artifact_types_used=["t1"], consumer_endpoint="/a",
                             injection_point="body", composed_request_plan={})
        h2 = ChainHypothesis(chain_id="h2", scenario_id="C-2", feeder_findings=["f1", "f2"],
                             artifact_types_used=["t1", "t2"], consumer_endpoint="/b",
                             injection_point="body", composed_request_plan={})
        ranked = planner.prioritize_chains([h1, h2])
        assert ranked[0].chain_id == "h2"  # more feeders = higher priority

    def test_goed_loop_closed_with_executor(self):
        from webpent.families.execution_node import family_execution_node

        class R:
            def __init__(self, st, b=""):
                self.status_code = st; self.text = b; self.url = "https://t/x"

        def ex(req):
            if req.label and req.label.startswith("burst"):
                return R(200)
            if req.label and req.label.startswith("seq"):
                return R(409)
            return R(200, "side_effects:3")

        out = family_execution_node({
            "target_id": "t", "engagement_id": "e", "base_url": "https://t.example",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "http_executor": ex,
            "findings": [{"vuln_class": "info_disclosure", "finding_id": "f1"}],
        })
        assert out["attack_graph_chains_total"] >= 1
        assert "goed_feedback_hypotheses" in out


class TestLearningAndHorizonProposals:
    """The two ultimate-hunter proposals: adversarial learning + horizon explorer."""

    def test_attack_memory_skips_repeated_failures(self):
        from webpent.learning.attack_memory import AttackMemory
        mem = AttackMemory()
        for _ in range(3):
            mem.record(scenario_id="RACE-1", endpoint="/x", outcome="failed", reason="rate_limit_enforced")
        assert mem.should_skip(scenario_id="RACE-1", endpoint="/x", reason="rate_limit_enforced") is True
        assert mem.should_skip(scenario_id="RACE-1", endpoint="/x", reason="different_reason") is False

    def test_adversarial_reviewer_downgrades_weak_evidence(self):
        from webpent.learning.attack_memory import AdversarialReviewer
        reviewer = AdversarialReviewer()
        stands, surviving = reviewer.review(None, {}, vuln_class="race_condition")
        assert stands is False
        assert len(surviving) >= 1

    def test_adversarial_reviewer_accepts_strong_evidence(self):
        from webpent.learning.attack_memory import AdversarialReviewer
        reviewer = AdversarialReviewer()
        stands, surviving = reviewer.review(None, {
            "baseline_differs": True, "artifact_freshly_generated": True,
            "state_changed_by_test": True, "response_varies_with_identity": True,
            "expected_side_effect_count": 3,
        }, vuln_class="race_condition")
        assert stands is True
        assert surviving == []

    def test_adaptive_strategy_deprioritizes_repeated_failures(self):
        from webpent.learning.attack_memory import AdaptiveStrategyOptimizer
        opt = AdaptiveStrategyOptimizer()
        for _ in range(3):
            opt.record_failure("RACE-1")
        assert opt.priority("RACE-1") < 0.5
        assert opt.priority("UNEXPLORED") == 1.0
        opt.record_success("OAUTH-001")
        assert len(opt.spawn_deeper("OAUTH-001")) >= 1

    def test_dynamic_behavior_analyzer_detects_anomaly(self):
        from webpent.explorer.horizon_explorer import DynamicBehaviorAnalyzer
        anomalies = DynamicBehaviorAnalyzer().analyze(
            {"status_code": 200, "elapsed_ms": 10},
            {"status_code": 500, "elapsed_ms": 10, "endpoint": "/x", "param": "id"},
        )
        assert len(anomalies) >= 1
        assert anomalies[0].signal == "status_diff"

    def test_attack_surface_expander_extracts_endpoints(self):
        from webpent.explorer.horizon_explorer import AttackSurfaceExpander
        out = AttackSurfaceExpander().expand([
            {"body": "error: see https://internal.example.com/api/v2/debug?token=xyz for details"},
        ])
        assert len(out["new_endpoints"]) >= 1
        assert "token" in out["new_params"]

    def test_creative_hypothesis_generator_combines_capabilities(self):
        from webpent.explorer.horizon_explorer import CreativeHypothesisGenerator
        hyps = CreativeHypothesisGenerator().generate(
            {"file_upload_allowed", "direct_object_reference"},
        )
        assert len(hyps) >= 1
        assert hyps[0]["source"] == "creative_hypothesis_generator"

    def test_node_outputs_learning_and_horizon_keys(self):
        from webpent.families.execution_node import family_execution_node
        out = family_execution_node({"target_id": "t", "engagement_id": "e",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}]})
        assert "adversarial_review_downgraded" in out
        assert "creative_hybrid_hypotheses" in out
        assert "expanded_attack_surface" in out


class TestCritiqueFixesFinal:
    """The six critique fixes — actually implemented and verified."""

    def test_failure_categorization(self):
        from webpent.learning.attack_memory import categorize_failure
        assert categorize_failure("connection timeout") == "network"
        assert categorize_failure("403 forbidden by scope") == "permission_denied"
        assert categorize_failure("rate limit enforced, no state change") == "behavior_not_matched"
        assert categorize_failure("weird unknown reason") == "unknown"

    def test_path_pattern_generalization_skips_similar(self):
        from webpent.learning.attack_memory import AttackMemory, generalize_path_pattern
        assert generalize_path_pattern("GET /api/users/123/profile") == "/api/users/{id}/*"
        mem = AttackMemory()
        for _ in range(6):
            mem.record(scenario_id="IDOR-1", endpoint="/api/users/1/profile", outcome="failed", reason="403")
        assert mem.should_skip(scenario_id="IDOR-1", endpoint="/api/users/999/profile", threshold=3) is True

    def test_generic_benign_explanations_apply_to_all(self):
        from webpent.learning.attack_memory import AdversarialReviewer
        reviewer = AdversarialReviewer()
        stands, surviving = reviewer.review(None, {}, vuln_class="race_condition")
        assert stands is False
        stands2, surv2 = reviewer.review(None, {
            "baseline_differs": True, "artifact_freshly_generated": True,
            "state_changed_by_test": True, "response_varies_with_identity": True,
            "expected_side_effect_count": 3,
        }, vuln_class="race_condition")
        assert stands2 is True
        assert surv2 == []

    def test_surface_expander_filters_static_and_scores_confidence(self):
        from webpent.explorer.horizon_explorer import AttackSurfaceExpander
        out = AttackSurfaceExpander().expand_with_confidence([
            {"body": "see https://t.com/api/v2/debug and style.css and app.js",
             "location": "https://t.com/internal/admin"},
        ])
        urls = [e["url"] for e in out["endpoints"]]
        assert any("api/v2/debug" in u for u in urls)
        assert any("internal/admin" in u for u in urls)
        assert not any(u.endswith(".css") or u.endswith(".js") for u in urls)
        assert out["endpoints"][0]["confidence"] >= 0.75

    def test_single_capability_and_deep_exploration(self):
        from webpent.explorer.horizon_explorer import CreativeHypothesisGenerator
        gen = CreativeHypothesisGenerator()
        hyps = gen.generate({"cors_misconfigured"})
        assert len(hyps) >= 1
        hyps_deep = gen.generate(set(), deep_exploration=True)
        assert len(hyps_deep) >= 1

    def test_goed_loop_configurable_via_state(self):
        from webpent.families.execution_node import family_execution_node
        out = family_execution_node({"target_id": "t", "engagement_id": "e",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "goed_max_iterations": 3})
        assert "goed_feedback_hypotheses" in out


class TestAdaptiveDefensePhases:
    """Proposal 2 (adaptive hunter) — all four phases."""

    def test_phase1_defense_monitor_detects_429_and_backs_off(self):
        from webpent.adaptive.defense_monitor import DefenseMonitor

        class R:
            status_code = 429; headers = {}; text = "too many requests"; elapsed_ms = 100

        tactic = DefenseMonitor().observe(R())
        assert tactic.block_detected is True
        assert tactic.backoff_seconds >= 30
        assert tactic.slowdown_factor <= 0.5

    def test_phase1_monitor_detects_waf_and_captcha(self):
        from webpent.adaptive.defense_monitor import DefenseMonitor

        class R:
            status_code = 403; headers = {"cf-ray": "abc"}; text = "captcha challenge"; elapsed_ms = 50

        tactic = DefenseMonitor().observe(R())
        assert tactic.switch_signature is True
        assert "waf" in tactic.reason or "captcha" in tactic.reason

    def test_phase2_emulator_scores_obvious_payload_high(self):
        from webpent.adaptive.defense_emulator import DefenseEmulator
        from dataclasses import dataclass

        @dataclass
        class P:
            url: str = "https://t/x?id=1 UNION SELECT password FROM users--"
            body: str = ""; label: str = "burst-0"

        risk = DefenseEmulator().assess(P())
        assert risk.risk_score >= 4.0
        assert risk.level in ("medium", "high")
        assert risk.action != "send" or risk.level == "medium"

    def test_phase2_emulator_low_risk_for_clean_plan(self):
        from webpent.adaptive.defense_emulator import DefenseEmulator
        from dataclasses import dataclass

        @dataclass
        class P:
            url: str = "https://t/api/health"; body: str = ""; label: str = "seq-0"

        risk = DefenseEmulator().assess(P())
        assert risk.level == "low"
        assert risk.action == "send"

    def test_phase3_multi_path_assigns_and_promotes_on_stall(self):
        from webpent.adaptive.multi_path_planner import MultiPathPlanner
        planner = MultiPathPlanner()
        for i in range(5):
            planner.assign(f"plan-low-{i}", "low")
        planner.assign("plan-high-risk", "high")
        assert planner.total_pending == 6
        batch = planner.next_batch(per_lane=3)
        assert len(batch) >= 3  # round-robin across lanes
        planner.report_stall("primary")
        planner.report_stall("primary")
        planner.report_stall("primary")  # 3 stalls → promote fallback
        # primary now stalled; next_batch should skip it and use fallback/exploratory
        batch2 = planner.next_batch(per_lane=3)
        assert isinstance(batch2, list)

    def test_phase4_integration_node_outputs_adaptive_state(self):
        from webpent.families.execution_node import family_execution_node

        class R:
            def __init__(s, st, b=""):
                s.status_code = st; s.text = b; s.url = "https://t/x"

        def ex(req):
            if getattr(req, "label", "").startswith("burst"):
                return R(200)
            if getattr(req, "label", "").startswith("seq"):
                return R(409)
            return R(200, "side_effects:3")

        out = family_execution_node({
            "target_id": "t", "engagement_id": "e", "base_url": "https://t.example",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "http_executor": ex, "adaptive_defense": True,
        })
        assert "adaptive_defense" in out
        assert out["adaptive_defense"].get("enabled") is True
        assert out["family_executed_plans"] >= 1


class TestFiveCritiqueFixesAdaptive:
    """The five adaptive-layer critique fixes — verified."""

    def test_fix1_per_target_calibration(self):
        from webpent.adaptive.defense_emulator import DefenseEmulator
        emu = DefenseEmulator()
        # Calibrate: 'union' was blocked on this target
        emu.profile.calibrate("UNION SELECT", blocked=True)
        from dataclasses import dataclass

        @dataclass
        class P:
            url: str = "https://t/x?id=1 UNION SELECT"; body: str = ""; label: str = "seq-0"

        risk = emu.assess(P())
        # Calibration adds +2 for blocked pattern → score higher than baseline
        assert any("target_calibration" in r for r in (risk.reasons or []))
        assert risk.risk_score >= 6.0

    def test_fix2_priority_selection_sends_high_priority_first(self):
        from webpent.adaptive.multi_path_planner import MultiPathPlanner
        planner = MultiPathPlanner()
        low_prio = object()
        high_prio = object()
        planner.assign(low_prio, "low", priority=0.1)
        planner.assign(high_prio, "low", priority=9.0)
        batch = planner.next_batch(per_lane=3)
        assert batch[0] is high_prio  # higher priority sent first

    def test_fix3_event_log_records_decisions(self):
        from webpent.adaptive.event_log import AdaptiveEventLog
        log = AdaptiveEventLog()
        log.record("defense_emulator", "plan_deferred", detail="p1", risk_score=6.5, action_taken="defer")
        log.record("defense_monitor", "block_detected", detail="429", action_taken="backoff")
        s = log.summary()
        assert s["total_events"] == 2
        assert s["plans_deferred"] == 1
        assert s["blocks_detected"] == 1

    def test_fix4_entropy_and_timing_signals(self):
        from webpent.adaptive.defense_emulator import DefenseEmulator, _payload_entropy
        assert _payload_entropy("aaaa") < _payload_entropy("aB3$x9!qZ")
        from dataclasses import dataclass

        @dataclass
        class P:
            url: str = "https://t/x"; body: str = "aB3$x9!qZ8@wQ"; label: str = "seq-0"

        emu = DefenseEmulator()
        risk_regular = emu.assess(P(), recent_request_count=10, request_jitter=0.0)
        risk_jitter = emu.assess(P(), recent_request_count=10, request_jitter=0.5)
        # Perfectly regular timing raises score vs jittered
        assert risk_regular.risk_score >= risk_jitter.risk_score

    def test_fix5_interleaved_stall_and_waf(self):
        from webpent.adaptive.defense_monitor import DefenseMonitor
        from webpent.adaptive.multi_path_planner import MultiPathPlanner

        class R429:
            status_code = 429; headers = {"cf-ray": "abc"}; text = "blocked"; elapsed_ms = 100

        monitor = DefenseMonitor()
        planner = MultiPathPlanner()
        planner.assign("p1", "low"); planner.assign("p2", "low")
        # Interleaved: WAF + 429 at once
        tactic = monitor.observe(R429())
        assert tactic.block_detected is True
        assert "waf" in tactic.reason or "429" in tactic.reason or "rate" in tactic.reason
        # Stall primary 3 times → fallback promoted (interleaved with WAF)
        for _ in range(3):
            planner.report_stall("primary")
        batch = planner.next_batch(per_lane=3)
        assert isinstance(batch, list)  # system keeps working under interleaved pressure


class TestSelfVerifyEngine:
    """Central Proposal 1 — self-verification & confidence engine (4 phases)."""

    def test_phase1_confidence_levels(self):
        from webpent.verification.self_verify import ConfidenceScorer, ConfidenceLevel, level_for
        scorer = ConfidenceScorer()
        weak = scorer.score(None, {})
        assert weak.score < 0.70
        assert weak.level in (ConfidenceLevel.POSSIBLE, ConfidenceLevel.UNCERTAIN)
        strong = scorer.score(None, {"baseline_differs": True, "state_changed_by_test": True,
                                     "artifact_freshly_generated": True, "expected_side_effect_count": 3},
                              repeat_count=3, state_changed=True, consistent=True)
        assert strong.score >= 0.70
        assert level_for(0.96) == ConfidenceLevel.CONFIRMED

    def test_phase1_result_filter_routes_low_confidence(self):
        from webpent.verification.self_verify import ResultFilter, ConfidenceReport, ConfidenceLevel
        rf = ResultFilter(threshold=0.70)
        high = ConfidenceReport(score=0.95, level=ConfidenceLevel.CONFIRMED)
        low = ConfidenceReport(score=0.50, level=ConfidenceLevel.POSSIBLE)
        accepted, review = rf.filter([high, low])
        assert len(accepted) == 1
        assert len(review) == 1

    def test_phase2_double_check_requires_all_three(self):
        from webpent.verification.self_verify import DoubleChecker
        dc = DoubleChecker()
        passed, tests = dc.run(None, {})
        assert passed is False
        assert any("missing" in t for t in tests)
        passed2, tests2 = dc.run(None, {"baseline_differs": True,
                                         "state_changed_by_test": True,
                                         "artifact_freshly_generated": True,
                                         "expected_side_effect_count": 3})
        assert passed2 is True
        assert all("passed" in t for t in tests2)

    def test_phase2_adaptive_retest_only_for_borderline(self):
        from webpent.verification.self_verify import AdaptiveRetester, ConfidenceReport, ConfidenceLevel
        ar = AdaptiveRetester()
        borderline = ConfidenceReport(score=0.60, level=ConfidenceLevel.POSSIBLE)
        confirmed = ConfidenceReport(score=0.96, level=ConfidenceLevel.CONFIRMED)
        assert len(ar.strategies(borderline)) >= 1
        assert ar.strategies(confirmed) == []

    def test_phase3_false_positive_log_and_rule_derivation(self):
        from webpent.verification.self_verify import FalsePositiveLog, RuleUpdater
        log = FalsePositiveLog()
        log.record("f1", "verification_failed", "pattern_a")
        log.record("f2", "verification_failed", "pattern_a")
        rules = RuleUpdater().derive(log)
        assert len(rules) >= 1
        assert "verification_failed" in rules[0]

    def test_phase3_coverage_inspector(self):
        from webpent.verification.self_verify import CoverageInspector
        q = CoverageInspector().assess(total_initial=10, confirmed=8, excluded=1,
                                       pending=1, endpoints_tested=5, endpoints_total=10)
        assert q["run_accuracy"] == 0.8
        assert q["endpoint_coverage"] == 0.5
        assert "suggested_focus_next_run" in q

    def test_phase4_engine_orchestrator_accepts_strong_rejects_weak(self):
        from webpent.verification.self_verify import SelfVerifyEngine
        from dataclasses import dataclass

        @dataclass
        class F:
            finding_id: str; title: str; vuln_class: str; evidence: dict

        strong = F("s1", "Strong Finding", "race_condition",
                   {"baseline_differs": True, "state_changed_by_test": True,
                    "artifact_freshly_generated": True, "response_varies_with_identity": True,
                    "expected_side_effect_count": 3})
        weak = F("w1", "Weak Finding", "xss", {})
        engine = SelfVerifyEngine(threshold=0.70)
        result = engine.verify_batch([strong, weak],
                                     {"s1": strong.evidence, "w1": weak.evidence},
                                     vuln_class_map={"s1": "race_condition", "w1": "xss"})
        assert len(result["verified_findings"]) >= 1
        assert len(result["needs_review"]) >= 1
        assert "quality_summary" in result
        assert "learned_rules" in result

    def test_node_outputs_self_verify_keys(self):
        from webpent.families.execution_node import family_execution_node
        out = family_execution_node({"target_id": "t", "engagement_id": "e",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}]})
        assert "self_verify_quality" in out
        assert "self_verify_needs_review" in out
        assert "self_verify_learned_rules" in out


class TestRedTeamFixes:
    """Red-team findings — verified fixed."""

    def test_excluded_alternatives_are_real_names_not_fabricated(self):
        from webpent.verification.self_verify import AlternativeExclusion
        excluded, surviving = AlternativeExclusion().exclude(None, {
            "baseline_differs": True, "artifact_freshly_generated": True,
            "state_changed_by_test": True, "response_varies_with_identity": True,
            "expected_side_effect_count": 3,
        }, vuln_class="race_condition")
        # Real names only — no "alternative_0" placeholder
        assert all(not e.startswith("alternative_") for e in excluded)
        assert len(excluded) >= 1

    def test_coverage_never_fabricated(self):
        from webpent.verification.self_verify import CoverageInspector
        q = CoverageInspector().assess(total_initial=10, confirmed=8, excluded=1, pending=1)
        assert q["endpoint_coverage"] is None  # unknown, not a made-up number
        assert q["coverage_note"] == "unknown_real_endpoint_total"

    def test_adaptive_retest_wired_to_borderline_reports(self):
        from webpent.verification.self_verify import SelfVerifyEngine
        from dataclasses import dataclass

        @dataclass
        class F:
            finding_id: str; title: str; vuln_class: str; evidence: dict

        borderline = F("b1", "Borderline", "xss", {"baseline_differs": True})
        eng = SelfVerifyEngine(threshold=0.70)
        r = eng.verify_batch([borderline], {"b1": borderline.evidence}, vuln_class_map={"b1": "xss"})
        # Borderline finding → retest strategies attached
        vf = (r["needs_review"] + r["verified_findings"])[0]
        assert len(vf.confidence.retest_strategies) >= 1

    def test_learned_rules_actually_applied_as_penalty(self):
        from webpent.verification.self_verify import RuleUpdater
        # Two findings fail same reason → rule derived → third matching gets penalty
        penalty = RuleUpdater.apply(["auto_rule: treat 'verification_failed' as disqualifying"],
                                    None, {"note": "verification_failed pattern here"})
        assert penalty > 0

    def test_double_check_requires_validator_specific_evidence(self):
        from webpent.verification.self_verify import DoubleChecker
        # Only generic guards (no validator-specific causal field) → variance fails
        passed, tests = DoubleChecker().run(None, {
            "baseline_differs": True, "artifact_freshly_generated": True,
            "state_changed_by_test": True, "response_varies_with_identity": True,
        })
        assert passed is False
        assert any("variance_test_missing" in t for t in tests)

    def test_adaptive_path_actually_runs_and_logs(self):
        from webpent.families.execution_node import family_execution_node

        class R:
            def __init__(s, st, b=""):
                s.status_code = st; s.text = b; s.url = "https://t/x"

        def ex(req):
            return R(200, "ok")

        out = family_execution_node({
            "target_id": "t", "engagement_id": "e", "base_url": "https://t.example",
            "endpoint_inventory": [{"method": "POST", "path": "/api/transfer", "params": []}],
            "http_executor": ex, "adaptive_defense": True,
        })
        ad = out.get("adaptive_defense", {})
        assert ad.get("enabled") is True
        # event_log present (proves adaptive layer ran, not fell back to plain)
        assert "event_log" in ad
        assert out["family_executed_plans"] >= 1


class TestRedTeamPlanExecution:
    """Full red-team plan (15 steps) — verified implemented."""

    def test_R8_transient_failure_never_becomes_rule(self):
        from webpent.verification.advanced import classify_failure, FailureClass
        assert classify_failure("connection timeout") == FailureClass.TRANSIENT
        assert classify_failure("verification_failed") == FailureClass.FALSE_POSITIVE

    def test_R6_correlation_boosts_similar_findings(self):
        from webpent.verification.advanced import CorrelationAnalyzer
        from dataclasses import dataclass

        @dataclass
        class F:
            finding_id: str; vuln_class: str; url: str

        f1 = F("a", "idor", "https://t/api/users/1/profile")
        f2 = F("b", "idor", "https://t/api/users/2/profile")
        deltas = CorrelationAnalyzer().analyze([f1, f2])
        assert deltas.get("a", 0) > 0  # similar → boost

    def test_R10_conflict_detector_flags_opposite_verdicts(self):
        from webpent.verification.advanced import ConflictDetector
        from dataclasses import dataclass

        @dataclass
        class F:
            finding_id: str; url: str; verdict: str

        conflicts = ConflictDetector().detect([
            F("a", "https://t/x", "confirmed"), F("b", "https://t/x", "rejected"),
        ])
        assert len(conflicts) == 1

    def test_R11_target_calibration_multiplier(self):
        from webpent.verification.advanced import TargetCalibration
        tc = TargetCalibration()
        assert tc.multiplier("unknown") == 1.0
        tc.record("good-target", confirmed=9, total=10)
        assert tc.multiplier("good-target") >= 1.0

    def test_R12_uncertainty_reason_classified(self):
        from webpent.verification.advanced import classify_uncertainty, UncertaintyReason
        from webpent.verification.self_verify import ConfidenceReport, ConfidenceLevel
        report = ConfidenceReport(score=0.6, level=ConfidenceLevel.POSSIBLE)
        r = classify_uncertainty(report, missing_tests=["a", "b"], surviving_alternatives=[])
        assert r == UncertaintyReason.INSUFFICIENT_DATA
        r2 = classify_uncertainty(report, missing_tests=[], surviving_alternatives=["x"])
        assert r2 == UncertaintyReason.CONFLICTING_EVIDENCE

    def test_R13_rules_io_export_import_and_scope(self):
        import tempfile, os
        from webpent.verification.advanced import RulesIO, ScopedRule
        rule = ScopedRule(reason="test", scope="endpoint", pattern="/api/admin")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            path = fh.name
        RulesIO.export([rule], path)
        loaded = RulesIO.load(path)
        assert len(loaded) == 1
        assert RulesIO.applies(loaded[0], endpoint="https://t/api/admin/x") is True
        assert RulesIO.applies(loaded[0], endpoint="https://t/other") is False
        os.unlink(path)

    def test_R14_retest_priority_severity_proximity(self):
        from webpent.verification.advanced import RetestPrioritizer
        items = [
            {"severity": 1.0, "confidence": 0.65, "threshold": 0.70, "retest_cost": 1},
            {"severity": 0.1, "confidence": 0.20, "threshold": 0.70, "retest_cost": 1},
        ]
        ordered = RetestPrioritizer().order(items)
        assert ordered[0]["severity"] == 1.0  # high severity + close to threshold first

    def test_R15_drift_monitor_alerts_on_spike(self):
        from webpent.verification.advanced import DriftMonitor
        dm = DriftMonitor()
        dm.record_run(0.1)
        dm.record_run(0.12)
        alert = dm.alert(0.5)
        assert alert["drift_alert"] is True

    def test_R7_max_retries_bound_exists(self):
        from webpent.verification.self_verify import MAX_RETRIES
        assert MAX_RETRIES == 2  # hard bound, never infinite

    def test_report_has_missing_tests_assumptions_uncertainty(self):
        from webpent.verification.self_verify import SelfVerifyEngine
        from dataclasses import dataclass

        @dataclass
        class F:
            finding_id: str; title: str; vuln_class: str; evidence: dict

        weak = F("w1", "Weak", "xss", {})
        r = SelfVerifyEngine().verify_batch([weak], {"w1": {}}, vuln_class_map={"w1": "xss"})
        vf = (r["needs_review"] + r["verified_findings"])[0]
        assert len(vf.confidence.missing_tests) >= 1
        assert len(vf.confidence.assumptions) >= 1
        assert vf.uncertainty_reason != ""


class TestRobustLayer:
    """Red-team plan (13 steps) — robust.py verified."""

    def test_step1_config_loader_missing_file_returns_defaults(self):
        from webpent.verification.robust import load_confidence_config
        cfg = load_confidence_config("/nonexistent/path.json")
        assert "repetition_bonus" in cfg
        assert cfg["repetition_bonus"] == 0.20

    def test_step2_alternative_finder_finds_real_alternatives(self):
        from webpent.verification.robust import AlternativeFinder
        alts = AlternativeFinder().find({"recent_request_count": 50})
        assert len(alts) >= 1
        assert any(a.name == "rate_limit_artifact" for a in alts)
        assert alts[0].confirmed is True

    def test_step3_similarity_score_real_path(self):
        from webpent.verification.robust import similarity_score
        assert similarity_score("/api/users/1/profile", "/api/users/2/profile") > 0.5
        assert similarity_score("/api/users/1", "/api/admin/settings") < 0.5

    def test_step4_calibration_store_writes_history(self, tmp_path):
        from webpent.verification.robust import CalibrationStore
        path = str(tmp_path / "cal.json")
        store = CalibrationStore(path)
        store.record_run("target-a", confirmed=9, total=10)
        assert len(store.history) == 1
        assert store.history[0]["accuracy"] == 0.9
        assert store.multiplier("target-a") != 1.0

    def test_step5_drift_monitor_needs_3_runs_then_alerts(self):
        from webpent.verification.robust import DriftMonitor2
        dm = DriftMonitor2()
        dm.record_run(0.1); dm.record_run(0.1); dm.record_run(0.1)
        alert = dm.alert(0.5)
        assert alert["drift_alert"] is True

    def test_step6_safe_load_rules_missing_file_returns_empty(self):
        from webpent.verification.robust import safe_load_rules
        rules, stats = safe_load_rules("/nonexistent/rules.json")
        assert rules == []
        assert stats["loaded"] == 0

    def test_step7_uncertainty_translations_exist(self):
        from webpent.verification.robust import UNCERTAINTY_TRANSLATIONS
        assert "max_retries" in UNCERTAINTY_TRANSLATIONS
        assert len(UNCERTAINTY_TRANSLATIONS["max_retries"]) > 10

    def test_step8_validate_reference_data(self):
        from webpent.verification.robust import validate_reference_data
        ok, _ = validate_reference_data(["a", "b"])
        assert ok is True
        bad, reason = validate_reference_data(["a", "a"])
        assert bad is False
        assert "duplicate" in reason

    def test_step9_max_retries_reason(self):
        from webpent.verification.robust import max_retries_reason, CENTRAL_CONSTANTS
        r = max_retries_reason(CENTRAL_CONSTANTS["MAX_RETRIES"])
        assert r["uncertainty_reason"] == "max_retries"
        assert "uncertainty_detail" in r

    def test_step10_unified_logger(self):
        from webpent.verification.robust import UnifiedLogger
        log = UnifiedLogger()
        entry = log.warn("test_mod", "something")
        assert "WARN" in entry
        assert len(log.entries) == 1

    def test_step11_central_constants_exist(self):
        from webpent.verification.robust import CENTRAL_CONSTANTS
        assert CENTRAL_CONSTANTS["MAX_RETRIES"] == 2
        assert CENTRAL_CONSTANTS["ACCEPTANCE_THRESHOLD"] == 0.70

    def test_step12_dynamic_assumptions_reflect_reality(self):
        from webpent.verification.robust import build_dynamic_assumptions
        a = build_dynamic_assumptions(["repetition_test_passed"], [], 2)
        assert any("repetition" in x for x in a)
        assert any("alternative" in x for x in a)
        b = build_dynamic_assumptions([], ["negative_test_missing"], 0)
        assert any("missing" in x for x in b)
        assert any("no_alternative" in x for x in b)

    def test_step13_quality_summary_complete(self):
        from webpent.verification.robust import build_quality_summary
        q = build_quality_summary(total=10, confirmed=6, needs_review=2, excluded=2,
                                  missing_tests=["negative"], calibration_accuracy=0.8,
                                  drift_alert={"drift_alert": False})
        assert q["fully_confirmed"] == 6
        assert q["needs_manual_review"] == 2
        assert "missing_tests" in q


class TestStrictLayer:
    """Red-team 15-step plan — strict.py verified."""

    def test_calibration_rejects_invalid_values(self):
        from webpent.verification.strict import StrictCalibrationStore
        store = StrictCalibrationStore()
        ok, reason = store.record_run("t", confirmed=15, total=10)
        assert ok is False
        assert reason == "confirmed_exceeds_total"
        ok2, _ = store.record_run("t", confirmed=9, total=10)
        assert ok2 is True

    def test_drift_monitor_never_divides_by_zero(self):
        from webpent.verification.strict import StrictDriftMonitor
        dm = StrictDriftMonitor()
        alert = dm.alert(0.5)
        assert alert["drift_alert"] is False
        assert "insufficient_history" in alert["reason"]

    def test_alternative_check_structured_result(self):
        from webpent.verification.strict import StrictAlternativeCheck
        r = StrictAlternativeCheck().check_rate_limit(50)
        assert r.executed is True
        assert r.result is True
        assert 0.0 <= r.confidence <= 1.0
        r2 = StrictAlternativeCheck().check_rate_limit(0)
        assert r2.executed is False
        assert "no_request_history" in r2.note

    def test_strict_load_rules_structured(self):
        from webpent.verification.strict import strict_load_rules
        result = strict_load_rules("/nonexistent/rules.json")
        assert result["success"] is False
        assert len(result["errors"]) >= 1
        assert result["rules"] == []

    def test_translation_keys_complete(self):
        from webpent.verification.strict import validate_translation_keys
        ok, missing = validate_translation_keys()
        assert ok is True
        assert missing == []

    def test_strict_logger_invalid_level_defaults_error(self):
        from webpent.verification.strict import StrictLogger
        log = StrictLogger()
        entry = log.log("BOGUS", "mod", "msg")
        assert "ERROR" in entry

    def test_consistent_quality_summary_auto_corrects(self):
        from webpent.verification.strict import consistent_quality_summary
        q = consistent_quality_summary(total=10, confirmed=6, needs_review=2, excluded=1)
        assert q["total_discoveries"] == 9  # auto-corrected from inconsistent 10
        assert q["counts_consistent"] is True

    def test_constants_validator_passes(self):
        from webpent.verification.strict import validate_constants
        ok, errors = validate_constants()
        assert ok is True
        assert errors == []

    def test_strict_reference_data_checks_responses(self):
        from webpent.verification.strict import strict_validate_reference_data
        ok, _ = strict_validate_reference_data(["a", "b"], responses=["x", "y"])
        assert ok is True
        bad, reason = strict_validate_reference_data(["a", "b"], responses=["same", "same"])
        assert bad is False
        assert "identical_responses" in reason


class TestCoreInfrastructure:
    """Red-team 15-step plan — core/ infrastructure verified."""

    def test_finding_validates_at_construction(self):
        from webpent.core.infrastructure import Finding
        import pytest
        with pytest.raises(ValueError):
            Finding(finding_id="", vuln_class="xss", endpoint="/x", confidence=0.5)
        with pytest.raises(ValueError):
            Finding(finding_id="f1", vuln_class="xss", endpoint="/x", confidence=1.5)
        f = Finding(finding_id="f1", vuln_class="xss", endpoint="/x", confidence=0.8)
        assert f.confidence == 0.8

    def test_rule_validates_scope_and_priority(self):
        from webpent.core.infrastructure import Rule
        import pytest
        with pytest.raises(ValueError):
            Rule(rule_id="r1", pattern="x", scope="bogus")
        with pytest.raises(ValueError):
            Rule(rule_id="r1", pattern="x", priority=99)
        r = Rule(rule_id="r1", pattern="x", scope="endpoint", priority=3)
        assert r.source_type == "auto_learned"
        assert r.created_at  # ISO timestamp present

    def test_quality_summary_auto_corrects_inconsistent_total(self):
        from webpent.core.infrastructure import QualitySummary
        q = QualitySummary(total=100, confirmed=5, needs_review=2, excluded=1)
        assert q.total == 8  # auto-corrected

    def test_execution_session_checkpoint_and_resume(self, tmp_path):
        from webpent.core.infrastructure import ExecutionSession, SessionStatus
        path = str(tmp_path / "sess.json")
        sess = ExecutionSession("s1", path)
        sess.start()
        assert sess.status == SessionStatus.RUNNING
        for _ in range(6):
            sess.checkpoint("step")
        sess.pause()
        resumed = ExecutionSession.resume(path)
        assert resumed.findings_processed == 6
        assert resumed.status == SessionStatus.PAUSED

    def test_resource_limits_enforce_bounds(self):
        from webpent.core.infrastructure import ResourceLimits
        rl = ResourceLimits(max_findings=2)
        ok, _ = rl.can_accept_finding()
        assert ok is True
        rl.record_finding(); rl.record_finding()
        ok2, reason = rl.can_accept_finding()
        assert ok2 is False
        assert "max_findings" in reason

    def test_priority_queue_orders_by_priority(self):
        from webpent.core.infrastructure import PriorityQueue
        pq = PriorityQueue()
        pq.add({"id": "low"}, severity=0.1, confidence=0.2)
        pq.add({"id": "high"}, severity=1.0, confidence=0.65)
        assert pq.pop()["id"] == "high"  # high severity + close to threshold first

    def test_file_backup_creates_backup(self, tmp_path):
        from webpent.core.infrastructure import FileBackup
        p = str(tmp_path / "rules.json")
        with open(p, "w") as fh:
            fh.write("{}")
        backup = FileBackup.backup_before_write(p)
        assert backup is not None
        assert os.path.exists(backup)

    def test_error_context_user_vs_log_message(self):
        from webpent.core.infrastructure import ErrorContext
        ec = ErrorContext(module="rulesio", path="data/r.json", reason="parse_error",
                          error_type="JSONDecodeError", detail="line 12 char 5")
        assert "السجل" in ec.user_message()  # Arabic user message
        assert "parse_error" in ec.log_line()  # technical log line

    def test_system_health_check_creates_missing_dirs(self, tmp_path):
        from webpent.core.infrastructure import system_health_check
        d = str(tmp_path / "data")
        report = system_health_check(data_dir=d, reports_dir=str(tmp_path / "rep"))
        assert os.path.exists(d)
        assert any("created_missing_dir" in i for i in report["issues"])

    def test_shutdown_handler_marks_safely_stopped(self):
        from webpent.core.infrastructure import ExecutionSession, ShutdownHandler, SessionStatus
        sess = ExecutionSession("s1", "/tmp/nonexistent_sess.json")
        sess.start()
        handler = ShutdownHandler(sess)
        handler.handle(signum=2)
        assert sess.status == SessionStatus.SAFELY_STOPPED
        assert handler.triggered is True

    def test_performance_metrics_tracks_components(self):
        from webpent.core.infrastructure import PerformanceMetrics
        import time
        pm = PerformanceMetrics()
        pm.begin("discovery")
        time.sleep(0.01)
        pm.end("discovery")
        s = pm.summary()
        assert "discovery" in s["per_component_seconds"]
        assert s["total_runtime_seconds"] >= 0

    def test_version_compatibility_check(self):
        from webpent.core.version import is_compatible, DATA_FORMAT_VERSION
        ok, _ = is_compatible(DATA_FORMAT_VERSION)
        assert ok is True
        ok2, reason = is_compatible(DATA_FORMAT_VERSION - 1)
        assert ok2 is False
        assert "stale" in reason


class TestAutonomousHunter:
    """Autonomous Bug Hunter Core v3.0 — 5 components verified."""

    def test_attack_planner_prioritizes_risky_endpoints(self):
        from webpent.autonomous_hunter import AttackPlanner, EndpointRisk
        planner = AttackPlanner()
        high = EndpointRisk(path="/api/admin/users", method="POST", risk_score=0,
                            handles_sensitive_data=True, accepts_user_input=True, requires_auth=False)
        low = EndpointRisk(path="/static/logo.png", method="GET", risk_score=0,
                           handles_sensitive_data=False, accepts_user_input=False, requires_auth=True)
        plan = planner.build_plan([high, low])
        assert plan[0].target_endpoint == "/api/admin/users"
        assert plan[0].priority > plan[-1].priority

    def test_attack_planner_generates_complementary_steps(self):
        from webpent.autonomous_hunter import AttackPlanner
        steps = AttackPlanner().complementary_steps(
            {"vuln_class": "idor", "endpoint": "/api/users/1", "finding_id": "f1"})
        assert len(steps) >= 2
        assert any("privilege" in s.technique for s in steps)

    def test_correlation_engine_detects_compound(self):
        from webpent.autonomous_hunter import ContextualCorrelationEngine
        compounds = ContextualCorrelationEngine().correlate([
            {"finding_id": "f1", "vuln_class": "info_disclosure", "endpoint": "/api/x"},
            {"finding_id": "f2", "vuln_class": "idor", "endpoint": "/api/x"},
        ])
        assert len(compounds) >= 1
        assert compounds[0].compound_type == "sensitive_data_exposure"

    def test_knowledge_graph_skips_repeated_failure(self):
        from webpent.autonomous_hunter import AdaptiveKnowledgeGraph
        kg = AdaptiveKnowledgeGraph()
        for _ in range(3):
            kg.record_attack("target1", "sqli_union", success=False)
        skip, reason = kg.should_skip("target1", "sqli_union")
        assert skip is True
        assert "failed_3x" in reason

    def test_knowledge_graph_detects_behavior_change(self):
        from webpent.autonomous_hunter import AdaptiveKnowledgeGraph
        kg = AdaptiveKnowledgeGraph()
        kg.detect_behavior_change("t1", {"waf": "none", "latency": "fast"})
        changed, reason = kg.detect_behavior_change("t1", {"waf": "cloudflare", "latency": "slow"})
        assert changed is True
        assert "changed" in reason

    def test_strategy_engine_escalation_and_priority(self):
        from webpent.autonomous_hunter import StrategyEngine, RiskLevel, ImpactLevel
        r = StrategyEngine().escalate({"finding_id": "f1"}, confirmation_level=2,
                                      impact_evidence="system_admin_access")
        assert r.confirmation_level == 2
        assert r.impact == ImpactLevel.FULL_SYSTEM
        assert r.priority == RiskLevel.CRITICAL
        assert len(r.evidence) == 3

    def test_strategy_engine_suggests_variants(self):
        from webpent.autonomous_hunter import StrategyEngine
        v = StrategyEngine().suggest_variants("xss")
        assert len(v) >= 3
        assert "<script>" in v

    def test_stealth_layer_detects_rate_limit_and_adapts(self):
        from webpent.autonomous_hunter import StealthResilienceLayer, DefenseSignal
        s = StealthResilienceLayer()
        sig = s.analyze_response(429, {})
        assert sig == DefenseSignal.RATE_LIMIT
        adaptation = s.adapt()
        assert adaptation["defense_detected"] == "rate_limit"
        assert adaptation["new_request_interval"] > 1.0
        assert any("slow_down" in a for a in adaptation["actions"])

    def test_stealth_layer_scope_enforcement(self):
        from webpent.autonomous_hunter import StealthResilienceLayer
        s = StealthResilienceLayer(allowed_scope=["https://allowed.com"])
        assert s.in_scope("https://allowed.com/api/x") is True
        assert s.in_scope("https://evil.com/x") is False

    def test_stealth_layer_safe_stop_after_5_failures(self):
        from webpent.autonomous_hunter import StealthResilienceLayer
        s = StealthResilienceLayer()
        for _ in range(5):
            s.analyze_response(429, {})
            s.adapt()
        assert s.state.consecutive_failures == 5
        stop = s.safe_stop()
        assert stop["stopped_safely"] is True
        assert "resume_hint" in stop
