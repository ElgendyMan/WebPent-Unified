"""TEAM-1 DEEP RECON & SCHEMA-TO-HYPOTHESIS V1 — tests."""
from __future__ import annotations

import pytest

from webpent.live_hunter.deep_recon import (
    DeepReconEngine,
    EvidenceTier,
    InferredRelationship,
    ParameterLocation,
    PrincipalCategory,
    ReconParameter,
    ReconPrincipal,
    RelationshipStrength,
)
from webpent.live_hunter.research_loop import ResearchControlLoop


def _engine():
    return DeepReconEngine(engagement_id="e1")


# ---------- Phase 1: Recon contract ----------
class TestReconContract:
    def test_principal_requires_evidence(self):
        p = ReconPrincipal(principal_id="p1", category=PrincipalCategory.ANONYMOUS,
                           normalized_identifier="anon", source_evidence_refs=("obs1",),
                           confidence=0.9, observation_provenance="401_challenge")
        assert p.evidence_tier == EvidenceTier.OBSERVED
        assert p.confidence > 0

    def test_principal_role_not_assumed_from_string(self):
        # String "admin" alone does NOT make it administrator — requires evidence
        p = ReconPrincipal(principal_id="p1", category=PrincipalCategory.AUTHENTICATED_USER,
                           normalized_identifier="user_with_admin_string", source_evidence_refs=("obs1",),
                           confidence=0.5, observation_provenance="username_string_only")
        assert p.category == PrincipalCategory.AUTHENTICATED_USER  # NOT auto-promoted to ADMINISTRATOR

    def test_parameter_not_security_sensitive_from_name(self):
        p = ReconParameter(parameter_id="param1", name="id", location=ParameterLocation.PATH,
                           structural_type="int", security_sensitive=False)
        assert p.security_sensitive is False  # name "id" alone does NOT make it sensitive


# ---------- Phase 2: Surface discovery ----------
class TestSurfaceDiscovery:
    def test_route_observation_creates_entities(self):
        eng = _engine()
        aid = eng.ingest_route_observation(path="/api/users/123", method="GET", status_code=200,
                                           parameters={"id": "123"})
        assert aid in eng.actions
        assert len(eng.actions) == 1
        assert "users" in eng.resources  # structural resource inference
        assert len(eng.parameters) >= 1

    def test_401_creates_anonymous_principal(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/secret", method="GET", status_code=401)
        assert "anonymous" in eng.principals
        assert eng.principals["anonymous"].category == PrincipalCategory.ANONYMOUS

    def test_path_shape_normalized(self):
        eng = _engine()
        aid = eng.ingest_route_observation(path="/api/orders/999/items/abc123def", method="GET", status_code=200)
        action = eng.actions[aid]
        assert "{id}" in action.endpoint_identity  # numeric segments normalized
        assert "999" not in action.endpoint_identity  # no raw IDs


# ---------- Phase 3: Schema ingestion (STRUCTURAL, NOT proof) ----------
class TestSchemaIngestion:
    def test_openapi_schema_marked_schema_derived(self):
        eng = _engine()
        schema = {"openapi": "3.0", "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id"}]}}}}
        count = eng.ingest_openapi_schema(schema)
        assert count >= 1
        action = list(eng.actions.values())[0]
        assert action.evidence_tier == EvidenceTier.SCHEMA_DERIVED  # NOT proof

    def test_schema_does_not_imply_vulnerability(self):
        eng = _engine()
        schema = {"paths": {"/users/{id}": {"get": {}}}}
        eng.ingest_openapi_schema(schema)
        hyps = eng.generate_hypothesis_candidates()
        # Hypothesis says "authorization/trust boundary question" — NOT "IDOR confirmed"
        for h in hyps:
            assert "confirmed_vulnerability" in h
            assert h["confirmed_vulnerability"] is False
            assert "IDOR" not in h["statement"].upper() or "question" in h["statement"].lower()

    def test_graphql_schema_ingestion(self):
        eng = _engine()
        schema = {"__schema": {"types": [{"kind": "QUERY", "name": "Query", "fields": [{"name": "getUser"}]}]}}
        count = eng.ingest_graphql_schema(schema)
        assert count >= 1
        action = list(eng.actions.values())[0]
        assert action.evidence_tier == EvidenceTier.SCHEMA_DERIVED


# ---------- Phase 4: Relationship inference ----------
class TestRelationshipInference:
    def test_inferred_requires_reason_confidence(self):
        with pytest.raises(ValueError, match="inference_reason"):
            InferredRelationship(relation_id="r1", relation_type="test", source_id="a", target_id="b",
                                 strength=RelationshipStrength.INFERRED)
        with pytest.raises(ValueError, match="confidence"):
            InferredRelationship(relation_id="r1", relation_type="test", source_id="a", target_id="b",
                                 strength=RelationshipStrength.INFERRED, inference_reason="x",
                                 supporting_observations=("o1",), confidence=0.0)

    def test_inferred_relationship_created(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/users/123", method="GET", status_code=200, parameters={"id": "123"})
        rels = eng.infer_relationships()
        assert len(rels) >= 1
        for r in rels:
            assert r.strength == RelationshipStrength.INFERRED
            assert r.confidence > 0
            assert r.uncertainty > 0

    def test_unknown_relationship_creates_unresolved_question(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/x", method="GET", status_code=200)
        # Add an UNKNOWN relationship
        eng.relationships.append(InferredRelationship(
            relation_id="r_unknown", relation_type="unknown_rel", source_id="a", target_id="b",
            strength=RelationshipStrength.UNKNOWN))
        g = eng.project_to_world_model()
        # UNKNOWN → unresolved question, NOT a fact
        assert any("Unknown relationship" in q["text"] for q in g._questions.values())


# ---------- Phase 5: Trust boundaries (questions, NOT confirmed vulns) ----------
class TestTrustBoundaries:
    def test_trust_boundary_becomes_question_not_vuln(self):
        eng = _engine()
        eng._register_principal("anon", PrincipalCategory.ANONYMOUS, "anon", ("o1",), 0.9, "401")
        eng._register_principal("user", PrincipalCategory.AUTHENTICATED_USER, "user", ("o2",), 0.8, "login")
        boundaries = eng.extract_trust_boundaries()
        assert len(boundaries) >= 1
        for b in boundaries:
            q = b.to_unresolved_question()
            assert q["resolution_status"] == "open"
            assert "NOT confirmed" in q["text"] or "question" in q["text"].lower()

    def test_no_confirmed_authorization_vulnerability(self):
        eng = _engine()
        eng._register_principal("anon", PrincipalCategory.ANONYMOUS, "anon", ("o1",), 0.9, "401")
        eng._register_principal("admin", PrincipalCategory.ADMINISTRATOR, "admin", ("o2",), 0.8, "role_header")
        boundaries = eng.extract_trust_boundaries()
        # Trust boundaries are QUESTIONS — never "confirmed IDOR" or "confirmed auth bypass"
        for b in boundaries:
            assert "confirmed" not in b.boundary_type.lower()


# ---------- Integration: Deep Recon → World Model → ResearchControlLoop ----------
class TestIntegration:
    def test_deep_recon_feeds_world_model(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/users/123", method="GET", status_code=200, parameters={"id": "123"})
        eng.ingest_route_observation(path="/api/orders/456", method="POST", status_code=201)
        eng.infer_relationships()
        g = eng.project_to_world_model()
        assert g.entity_count >= 3  # principals + resources + actions
        assert g.relation_count >= 1

    def test_deep_recon_not_second_planner(self):
        eng = _engine()
        # DeepReconEngine has NO step()/select()/schedule() method — it's a producer only
        assert not hasattr(eng, "step")
        assert not hasattr(eng, "select_candidate")
        assert not hasattr(eng, "schedule")
        # ResearchControlLoop remains the ONE planner
        loop = ResearchControlLoop(engagement_id="e1", graph=eng.graph)
        assert hasattr(loop, "step")

    def test_hypotheses_feed_research_loop(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/users/123", method="GET", status_code=200)
        hyps = eng.generate_hypothesis_candidates()
        assert len(hyps) >= 1
        loop = ResearchControlLoop(engagement_id="e1", graph=eng.graph)
        for h in hyps:
            loop.graph.register_hypothesis(h["hypothesis_id"], h["statement"], branch_id=h["branch_id"])
            loop.register_candidate(f"c_{h['hypothesis_id']}", (h["hypothesis_id"],), f"sig_{h['hypothesis_id']}")
        decision = loop.step()
        assert decision["selected_candidate"] is not None
        assert loop.decision_count == 1

    def test_no_secret_leakage(self):
        eng = _engine()
        eng.ingest_route_observation(path="/api/login", method="POST", status_code=200,
                                     response_headers={"Set-Cookie": "session=secret123"})
        g = eng.project_to_world_model()
        assert g.verify_no_secret_leakage() is True
        serialized = g.serialize()
        assert "secret123" not in serialized


# ---------- Authority preservation ----------
class TestAuthorityUnchanged:
    # RUNTIME-INTEGRATION FIX (RIT-2): previous version hard-coded an
    # absolute path ("/home/user/webpent/webpent-goed/...") that only exists
    # on the original author's machine, so these authority hash gates
    # FileNotFoundError'd everywhere else. Paths are now resolved relative to
    # the repository root; the enforced SHA-256 contract is UNCHANGED.
    @staticmethod
    def _repo_file(rel: str) -> str:
        import hashlib
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        data = (root / rel).read_bytes()
        return hashlib.sha256(data).hexdigest()

    # The frozen manifest is authoritative for these trust-spine files. This
    # test must agree with that manifest rather than with a stale ZIP-local
    # hash from an earlier remediation attempt.
    def test_proof_bundle_unchanged(self):
        h = self._repo_file("src/webpent/models/proof_bundle.py")
        assert h == "2f429b3c4c3ef205f471d53163ccee89a773bcd8fe7154f02b6e2eca0f513110"

    def test_replay_verifier_unchanged(self):
        h = self._repo_file("src/webpent/validators/replay_validator.py")
        assert h == "5b11f7c8e12b34842fe4e62cbb067c563b2034bf640caf7caea3f01864cbb085"

    def test_tool_boundary_unchanged(self):
        # DR-006 (TC-2): re-pinned to the adjudicated hash — the resurrection's
        # +17-line delta was reviewed and adopted as an additive, default-off
        # S-3 authority extension (allowed_hosts=() + fail-closed is_allowed();
        # authorize() semantics untouched).  Adjudication: DRIFT_REGISTER.md
        # DR-006.  Further drift still fails.
        h = self._repo_file("src/webpent/llm_researcher/tool_boundary.py")
        assert h == "01dafce37a6eea81b1c6a6dee46f2836f8e8850ef7fb6d4a2d8f21a86a11e616"

    def test_bounded_limits(self):
        eng = _engine()
        assert eng.MAX_ACTIONS == 2000
        assert eng.MAX_RESOURCES == 500
        assert eng.MAX_PARAMETERS == 5000
        assert eng.MAX_PRINCIPALS == 50
        assert eng.MAX_TRUST_BOUNDARIES == 100
