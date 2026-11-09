# tests/team1_acceptance/test_b_legacy_containment.py
"""TEAM-1 ACCEPTANCE B — Legacy containment.

Legacy paths may remain for compatibility but MUST NOT provide an alternate
authority model. Legacy code cannot: execute arbitrary HTTP directly, bypass
scope, assert confirmed findings, manufacture evidence, bypass replay.
"""
from __future__ import annotations


def make_authorized_profile(authorized_targets=("lab.example.com", "target.example.com"), engagement_id="eng_team1_test"):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    return AuthorizedLabProfile(
        authorized_targets=authorized_targets,
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )

def make_scope_law(engagement_id="eng_team1_test", authorized_targets=("lab.example.com", "target.example.com")):
    from webpent.live_hunter.tool_scope import ScopeLaw
    profile = make_authorized_profile(authorized_targets=authorized_targets, engagement_id=engagement_id)
    return ScopeLaw(profile=profile, engagement_id=engagement_id)


import pytest

from webpent.shared.legacy_containment import (
    LEGACY_REGISTRY,
    ContainedHTTPClient,
    LegacyContainmentError,
    legacy_advisory_finding_only,
    legacy_proof_construction_denied,
    populate_legacy_registry,
)


def make_authorized_profile(authorized_targets=("lab.example.com", "target.example.com"), engagement_id="eng_team1_test"):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    return AuthorizedLabProfile(
        authorized_targets=authorized_targets,
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )

def make_scope_law(engagement_id="eng_team1_test", authorized_targets=("lab.example.com", "target.example.com")):
    from webpent.live_hunter.tool_scope import ScopeLaw
    profile = make_authorized_profile(authorized_targets=authorized_targets, engagement_id=engagement_id)
    return ScopeLaw(profile=profile, engagement_id=engagement_id)



def _make_scope():
    return make_scope_law(engagement_id="eng_legacy_test")


def test_contained_http_requires_bound_scope():
    """Legacy HTTP without bound ScopeLaw is structurally denied."""
    client = ContainedHTTPClient(legacy_path_name="legacy_agent_x")
    with pytest.raises(LegacyContainmentError, match="without bound ScopeLaw"):
        client.get("https://target.example.com/api")


def test_contained_http_denies_out_of_scope():
    """Legacy HTTP to out-of-scope target is denied by ScopeLaw."""
    scope = _make_scope()
    client = ContainedHTTPClient(scope_law=scope, legacy_path_name="legacy_agent_y")
    with pytest.raises(LegacyContainmentError, match="DENIED by ScopeLaw"):
        client.get("https://evil.example.com/ssrf")
    # Call log must record the denial.
    assert len(client.call_log) == 1
    assert client.call_log[0]["authorized"] is False


def test_contained_http_authorizes_in_scope():
    """Legacy HTTP to in-scope target passes authorization (execution delegated)."""
    scope = _make_scope()
    client = ContainedHTTPClient(scope_law=scope, legacy_path_name="legacy_agent_z")
    # Authorization passes; execution would delegate to shared/http.
    # We test authorization only (no network). The _authorize method must not raise.
    client._authorize("GET", "https://target.example.com/api")
    assert client.call_log[-1]["authorized"] is True


def test_legacy_advisory_finding_cannot_confirm():
    """Legacy finding-generation paths produce ADVISORY findings only (cannot confirm)."""
    @legacy_advisory_finding_only(legacy_path="legacy_hypothesis_agent")
    def legacy_finding_generator():
        return {"title": "Possible IDOR", "severity": "high", "confirmed": True}

    result = legacy_finding_generator()
    assert result["advisory_only"] is True
    assert result["confirmed"] is False  # structurally overridden
    assert result["requires_modern_evidence_path"] is True
    assert result["legacy_path"] == "legacy_hypothesis_agent"


def test_legacy_proof_construction_denied():
    """Legacy paths CANNOT construct promotion-grade ProofBundles."""
    @legacy_proof_construction_denied(legacy_path="legacy_validator_agent")
    def legacy_build_proof():
        return {"bundle": "fake"}

    with pytest.raises(LegacyContainmentError, match="attempted to construct a ProofBundle"):
        legacy_build_proof()


def test_legacy_registry_populated_and_contained():
    """All production-reachable legacy paths are registered and contained."""
    summary = populate_legacy_registry()
    assert summary["total_legacy_modules"] > 0
    assert summary["all_production_contained"] is True, (
        f"Uncontained production paths: {summary['uncontained_production_paths']}"
    )
    # Registry must have records with classification and contained flag.
    records = LEGACY_REGISTRY.records()
    assert len(records) > 0
    for r in records:
        assert r.classification in {"ACTIVE_PRODUCTION", "COMPATIBILITY_ONLY", "TEST_ONLY", "ORPHANED"}
        if r.classification in {"ACTIVE_PRODUCTION", "COMPATIBILITY_ONLY"}:
            assert r.contained is True, f"{r.module_path} not contained"


def test_no_second_scope_law():
    """Part 15: There must be ONE ScopeLaw. ContainedHTTPClient delegates to it."""
    scope = _make_scope()
    client = ContainedHTTPClient(scope_law=scope, legacy_path_name="legacy_x")
    # The contained client uses THE SAME ScopeLaw instance (one authority).
    assert client._scope_law is scope
    # Decisions are recorded in THE SAME ScopeLaw.decisions log.
    client._authorize("GET", "https://target.example.com/api")
    assert len(scope.decisions) >= 1
