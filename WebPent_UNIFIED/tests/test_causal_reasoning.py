# tests/test_causal_reasoning.py
"""Tests for Proposal #1 — Causal Reasoning Engine (additive layer).

Covers contracts, ArchitectureInferrer, ContextualMemory, RootCauseAnalyzer,
and the full CausalReasoningEngine lifecycle.  All tests are deterministic
and offline; no network, no LLM, no execution authority.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from webpent.causal_reasoning import (
    ArchitectureInferrer,
    ContextFingerprint,
    ContextualMemory,
    CausalReasoningEngine,
    RootCauseAnalyzer,
    WeaknessCategory,
    glob_matches,
    route_to_glob,
    stable_id,
)


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------

class TestContracts:
    def test_route_to_glob_numeric_id(self):
        assert route_to_glob("/api/users/123/profile") == "/api/users/*/profile"

    def test_route_to_glob_uuid(self):
        assert route_to_glob("/api/v2/orders/550e8400-e29b-41d4-a716-446655440000") == "/api/v2/orders/*"

    def test_route_to_glob_strips_query(self):
        assert route_to_glob("/items?foo=bar&id=1") == "/items"

    def test_glob_matches_single_segment_wildcard(self):
        assert glob_matches("/api/users/*/profile", "/api/users/42/profile")
        assert not glob_matches("/api/users/*/profile", "/api/users/42/extra/profile")
        assert not glob_matches("/api/users/*", "/api/users/42/profile")

    def test_stable_id_deterministic(self):
        a = stable_id("hyp", "f1", "idor")
        b = stable_id("hyp", "f1", "idor")
        assert a == b
        assert stable_id("hyp", "f1", "xss") != a

    def test_fingerprint_similarity_identical(self):
        fp = ContextFingerprint(
            fingerprint_id="fp1", engagement_id="e1",
            frameworks=("django", "drf"), auth_scheme="jwt",
            auth_policy_pattern="middleware", validation_pattern="shared_layer",
            orm_in_use="django_orm", api_style="rest",
        )
        assert fp.similarity(fp) == pytest.approx(1.0, abs=0.01)

    def test_fingerprint_similarity_different(self):
        fp1 = ContextFingerprint(
            fingerprint_id="fp1", engagement_id="e1",
            frameworks=("django",), auth_scheme="jwt",
            auth_policy_pattern="middleware",
        )
        fp2 = ContextFingerprint(
            fingerprint_id="fp2", engagement_id="e2",
            frameworks=("express",), auth_scheme="session",
            auth_policy_pattern="inline",
        )
        assert fp1.similarity(fp2) < 0.5

    def test_fingerprint_strips_secrets_in_metadata(self):
        fp = ContextFingerprint(
            fingerprint_id="fp1", engagement_id="e1",
            metadata={"authorization": "Bearer xyz", "safe_key": "ok"},
        )
        assert "authorization" not in fp.metadata
        assert fp.metadata.get("safe_key") == "ok"

    def test_fingerprint_digest_excludes_volatile_fields(self):
        fp1 = ContextFingerprint(fingerprint_id="a", engagement_id="e1", frameworks=("django",))
        fp2 = ContextFingerprint(fingerprint_id="b", engagement_id="e2", frameworks=("django",))
        assert fp1.digest() == fp2.digest()


# ---------------------------------------------------------------------------
# ArchitectureInferrer
# ---------------------------------------------------------------------------

def _idor_finding(fid: str, route: str) -> dict:
    return {
        "id": fid, "vuln_class": "idor", "route": route,
        "target_param": "user_id", "severity": "high",
        "title": "IDOR detected", "description": "x", "tool_name": "test",
        "url": f"https://target{route}",
    }


class TestArchitectureInferrer:
    def test_idor_propagates_to_sibling_endpoints(self):
        inferrer = ArchitectureInferrer()
        knowledge = {
            "e1": {"kind": "endpoint", "canonical_key": "/api/users/1", "metadata": {"object_resolver": "UserResolver"}},
            "e2": {"kind": "endpoint", "canonical_key": "/api/orders/5", "metadata": {"object_resolver": "UserResolver"}},
            "e3": {"kind": "endpoint", "canonical_key": "/api/health", "metadata": {"object_resolver": "None"}},
        }
        result = inferrer.ingest_finding(_idor_finding("f1", "/api/users/1"), knowledge_entities=knowledge)
        assert len(result.hypotheses) >= 1
        hyp = result.hypotheses[0]
        assert hyp.weakness_category == WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE
        # e2 shares the resolver -> should appear as at-risk
        keys = {r.canonical_key for r in result.at_risk_regions}
        assert any("/api/orders" in k for k in keys), keys

    def test_unknown_vuln_class_emits_low_confidence_no_propagation(self):
        inferrer = ArchitectureInferrer()
        result = inferrer.ingest_finding({**_idor_finding("f1", "/x"), "vuln_class": "totally_new"})
        assert len(result.hypotheses) == 1
        assert result.hypotheses[0].confidence < 0.2
        assert result.at_risk_regions == ()

    def test_covered_regions_downweighted(self):
        inferrer = ArchitectureInferrer()
        knowledge = {
            "e1": {"kind": "endpoint", "canonical_key": "/api/users/1", "metadata": {"object_resolver": "R"}},
            "e2": {"kind": "endpoint", "canonical_key": "/api/orders/5", "metadata": {"object_resolver": "R"}},
        }
        # e2 already has a confirmed finding -> should be marked covered
        existing = [_idor_finding("f0", "/api/orders/5")]
        result = inferrer.ingest_finding(
            _idor_finding("f1", "/api/users/1"),
            knowledge_entities=knowledge, existing_findings=existing,
        )
        covered = [r for r in result.at_risk_regions if r.already_covered]
        uncovered = [r for r in result.at_risk_regions if not r.already_covered]
        assert covered, "expected at least one covered region"
        # top region should be uncovered (coverage-gap bonus)
        top = result.top_regions(1)[0]
        assert not top.already_covered
        assert top.priority_score > max((r.priority_score for r in covered), default=0)

    def test_top_regions_sorted_and_capped(self):
        inferrer = ArchitectureInferrer()
        result = inferrer.ingest_finding(_idor_finding("f1", "/api/users/1"))
        top = result.top_regions(3)
        assert len(top) <= 3
        scores = [r.priority_score for r in top]
        assert scores == sorted(scores, reverse=True)

    def test_no_knowledge_still_emits_self_region(self):
        inferrer = ArchitectureInferrer()
        result = inferrer.ingest_finding(_idor_finding("f1", "/api/users/123"))
        assert result.at_risk_regions, "self-region should always be present"
        assert any(r.canonical_key == "/api/users/*" for r in result.at_risk_regions)


# ---------------------------------------------------------------------------
# ContextualMemory
# ---------------------------------------------------------------------------

class TestContextualMemory:
    def test_empty_store_returns_no_lessons(self):
        with tempfile.TemporaryDirectory() as d:
            mem = ContextualMemory(memory_dir=Path(d))
            fp = ContextFingerprint(fingerprint_id="fp", engagement_id="e", frameworks=("django",))
            assert mem.begin_engagement(fp) == []

    def test_persist_and_transfer_direct(self):
        with tempfile.TemporaryDirectory() as d:
            mem = ContextualMemory(memory_dir=Path(d))
            fp_old = ContextFingerprint(
                fingerprint_id="old", engagement_id="old_e",
                frameworks=("django", "drf"), auth_scheme="jwt",
                auth_policy_pattern="middleware", validation_pattern="shared_layer",
                orm_in_use="django_orm", api_style="rest",
            )
            mem.record_engagement_outcome(
                fp_old,
                finding_families=("IDOR",),
                confirmed_weaknesses=[WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE.value],
                routes_by_weakness={
                    WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE.value: ["/api/users/*/profile", "/api/orders/*"],
                },
                total_findings=3,
            )
            fp_new = ContextFingerprint(
                fingerprint_id="new", engagement_id="new_e",
                frameworks=("django", "drf"), auth_scheme="jwt",
                auth_policy_pattern="middleware", validation_pattern="shared_layer",
                orm_in_use="django_orm", api_style="rest",
            )
            lessons = mem.begin_engagement(fp_new)
            assert lessons, "expected transferred lessons for identical stack"
            assert lessons[0].transfer_strength.value == "direct"
            assert WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE in [l.weakness_category for l in lessons]
            assert any("/api/users/*/profile" in l.typical_route_globs for l in lessons)

    def test_no_transfer_below_threshold(self):
        with tempfile.TemporaryDirectory() as d:
            mem = ContextualMemory(memory_dir=Path(d))
            fp_old = ContextFingerprint(fingerprint_id="old", engagement_id="old_e", frameworks=("express",), auth_scheme="session")
            mem.record_engagement_outcome(
                fp_old, confirmed_weaknesses=[WeaknessCategory.XSS.value if hasattr(WeaknessCategory, "XSS") else WeaknessCategory.INCONSISTENT_INPUT_SANITISATION.value],
                routes_by_weakness={WeaknessCategory.INCONSISTENT_INPUT_SANITISATION.value: ["/x"]},
            )
            fp_new = ContextFingerprint(fingerprint_id="new", engagement_id="new_e", frameworks=("rails",), auth_scheme="jwt")
            assert mem.begin_engagement(fp_new) == []

    def test_pattern_distillation_accumulates(self):
        with tempfile.TemporaryDirectory() as d:
            mem = ContextualMemory(memory_dir=Path(d))
            for i in range(3):
                fp = ContextFingerprint(fingerprint_id=f"fp{i}", engagement_id=f"e{i}", frameworks=("django",))
                mem.record_engagement_outcome(
                    fp, confirmed_weaknesses=[WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS.value],
                    routes_by_weakness={WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS.value: ["/api/write/*"]},
                )
            summary = mem.pattern_summary()
            assert summary["engagement_count"] == 3
            patterns = summary["patterns"]
            mass = [p for p in patterns if p["weakness_category"] == WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS.value]
            assert mass and mass[0]["observation_count"] >= 3

    def test_records_file_is_valid_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            mem = ContextualMemory(memory_dir=Path(d))
            fp = ContextFingerprint(fingerprint_id="fp", engagement_id="e", frameworks=("django",))
            mem.record_engagement_outcome(fp, confirmed_weaknesses=[WeaknessCategory.AUTH_CHECK_AFTER_MUTATION.value])
            lines = (Path(d) / "engagement_records.jsonl").read_text().splitlines()
            assert len(lines) == 1
            json.loads(lines[0])  # must parse


# ---------------------------------------------------------------------------
# RootCauseAnalyzer
# ---------------------------------------------------------------------------

class TestRootCauseAnalyzer:
    def test_clusters_findings_by_shared_root_cause(self):
        analyzer = RootCauseAnalyzer()
        findings = [
            _idor_finding("f1", "/api/users/1"),
            _idor_finding("f2", "/api/orders/7"),
            {**_idor_finding("f3", "/api/login"), "vuln_class": "auth_bypass"},
        ]
        clusters = analyzer.analyze(findings)
        assert clusters
        # IDOR findings should share one cluster; auth_bypass another (or unknown)
        idor_cluster = [c for c in clusters if "f1" in c.member_finding_ids]
        assert idor_cluster
        assert "f2" in idor_cluster[0].member_finding_ids
        # every cluster has a remediation hint
        assert all(c.remediation_hint for c in clusters if c.weakness_category != WeaknessCategory.UNKNOWN)

    def test_empty_findings_returns_empty(self):
        assert RootCauseAnalyzer().analyze([]) == ()

    def test_single_finding_root_cause(self):
        analyzer = RootCauseAnalyzer()
        f = _idor_finding("f1", "/api/users/1")
        cluster = analyzer.root_cause_for_finding(f)
        assert cluster is not None
        assert "f1" in cluster.member_finding_ids
        assert cluster.weakness_category == WeaknessCategory.DIRECT_OBJECT_REFERENCE_WITHOUT_SCOPE


# ---------------------------------------------------------------------------
# Full engine lifecycle
# ---------------------------------------------------------------------------

class TestEngineLifecycle:
    def test_start_ingest_end_full_cycle(self):
        with tempfile.TemporaryDirectory() as d:
            # Seed memory with an analogous past engagement.
            mem = ContextualMemory(memory_dir=Path(d))
            fp_old = ContextFingerprint(
                fingerprint_id="old", engagement_id="old_e",
                frameworks=("django", "drf"), auth_scheme="jwt",
                auth_policy_pattern="middleware", validation_pattern="shared_layer",
                orm_in_use="django_orm", api_style="rest",
            )
            mem.record_engagement_outcome(
                fp_old, confirmed_weaknesses=[WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS.value],
                routes_by_weakness={WeaknessCategory.MASS_ASSIGNMENT_UNBOUND_FIELDS.value: ["/api/users/*"]},
            )

            fp_new = ContextFingerprint(
                fingerprint_id="new", engagement_id="new_e",
                frameworks=("django", "drf"), auth_scheme="jwt",
                auth_policy_pattern="middleware", validation_pattern="shared_layer",
                orm_in_use="django_orm", api_style="rest",
            )
            engine = CausalReasoningEngine(fingerprint=fp_new, memory_dir=Path(d))

            transferred = engine.start()
            assert transferred, "knowledge should transfer from the seeded past engagement"

            knowledge = {
                "e1": {"kind": "endpoint", "canonical_key": "/api/users/1", "metadata": {"object_resolver": "R"}},
                "e2": {"kind": "endpoint", "canonical_key": "/api/orders/9", "metadata": {"object_resolver": "R"}},
            }
            result = engine.ingest_finding(_idor_finding("f1", "/api/users/1"), knowledge_entities=knowledge)
            assert result.hypotheses
            assert result.top_regions(5)

            end = engine.end_engagement(finding_families=("IDOR",))
            assert end["inference_count"] == 1
            assert end["root_cause_clusters"]
            assert end["persisted_record"] is not None
            # memory now has 2 engagements
            assert engine.pattern_summary()["engagement_count"] == 2

    def test_engine_without_fingerprint_still_works(self):
        with tempfile.TemporaryDirectory() as d:
            engine = CausalReasoningEngine(memory_dir=Path(d))
            assert engine.start() == []  # no fingerprint -> no transfer
            result = engine.ingest_finding(_idor_finding("f1", "/x"))
            assert result.hypotheses
            end = engine.end_engagement(persist=False)
            assert end["persisted_record"] is None
