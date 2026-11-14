from __future__ import annotations

import hashlib

from webpent.agents.access_control import agent as access_agent
from webpent.models.targets import Target
from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    assess_access_control,
    build_relational_evidence,
    normalise_identity_profiles,
    sanitise_probe_result,
)


def test_identity_profiles_normalise_legacy_session_without_claiming_two_users():
    profiles = normalise_identity_profiles({}, fallback_cookies={"session": "secret"})
    assert len(profiles) == 1
    assert profiles[0].name == "session-1"
    assert profiles[0].cookies == {"session": "secret"}
    assert "secret" not in repr(profiles[0].public_metadata)


def test_assessment_requires_explicit_owner_for_tool_confirmation():
    rows = [
        sanitise_probe_result(
            profile=IdentityProfile(name="alice", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        sanitise_probe_result(
            profile=IdentityProfile(name="bob", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
    ]
    result = assess_access_control(rows)
    assert result["status"] == "needs_review"
    assert result["confidence_level"] == "Needs Human Review"


def test_assessment_confirms_owner_and_foreign_success():
    rows = [
        sanitise_probe_result(
            profile=IdentityProfile(name="alice", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        sanitise_probe_result(
            profile=IdentityProfile(name="bob", role="user"),
            url="http://lab.local/orders/1001",
            status_code=200,
            content_length=42,
        ),
        # GOED added a negative-control requirement: owner+foreign both
        # succeeding is only "confirmed" (not "needs_review") alongside
        # proof that access control is enforced elsewhere for some other
        # non-owner identity — otherwise it could just mean the endpoint
        # is wide open to everyone, not a scoping bug. See
        # webpent.shared.bac_identity_tester.assess_access_control.
        sanitise_probe_result(
            profile=IdentityProfile(name="eve", role="user"),
            url="http://lab.local/orders/9999",
            status_code=403,
            content_length=0,
        ),
    ]
    result = assess_access_control(rows, owner_identity="alice")
    assert result["status"] == "confirmed"
    # UM-DR-35: the differential gate returns a CANDIDATE result — the
    # intermediate assessment never carries a confirmation label anymore;
    # confirmation belongs to the CausalGuard authority chain alone.
    assert result["confidence_level"] == "Identity-Differential-Verified"
    assert result["candidate_result"] is True
    assert result["differential_gate"] == "bac.identity_differential_gate"
    edges = build_relational_evidence(rows, owner_identity="alice", object_id="1001")
    assert edges and edges[0]["differential"] is False
    assert "session" not in str(edges)


def test_access_control_node_emits_confirmed_finding_only_with_owner_metadata(monkeypatch):
    target = Target(url="http://lab.local")

    def probe(url, cookies=None, timeout=10.0, headers=None, **_kwargs):
        # A rich, target-backed probe result (dict), not the legacy bare
        # (status_code, content_length) tuple — the legacy tuple path is
        # intentionally review-only and can never satisfy strict proof
        # (see webpent.shared.bac_identity_tester.sanitise_probe_result).
        session = (cookies or {}).get("session")
        if session in {"alice-secret", "bob-secret"}:
            status_code, content_length, body = 200, 123, b"owner-or-foreign-body"
        else:
            status_code, content_length, body = 403, 0, b""
        return {
            "status_code": status_code,
            "content_length": content_length,
            "target_backed": True,
            "request_digest": "sha256:" + hashlib.sha256(f"{url}|{session}".encode()).hexdigest(),
            "response_digest": "sha256:" + hashlib.sha256(body).hexdigest(),
        }

    monkeypatch.setattr(access_agent, "_probe_url", probe)
    state = {
        "target": target,
        "findings": [],
        "engagement_id": "test-fixture-engagement",
        "crawled_data": {
            "endpoints": [
                {
                    "url": "http://lab.local/orders/1001",
                    "owner_identity": "alice",
                    "object_id": "1001",
                }
            ]
        },
        "identity_profiles": {
            "alice": {"role": "user", "cookies": {"session": "alice-secret"}},
            "bob": {"role": "user", "cookies": {"session": "bob-secret"}},
        },
    }
    result = access_agent.access_control_node(state)
    assert len(result["findings"]) == 1
    finding = result["findings"][0]
    # UM-DR-35 corrective closure regression lock: the owner-vs-foreign
    # differential (owner as baseline, foreign as candidate — different
    # actors) is NOT guard-admissible evidence for the same-actor causal
    # contract, and the recorded observations carry no resource-owner
    # evidence. Even though the strict replay verifier ran, the mandatory
    # CausalGuard adjudication cannot confirm, so the finding MUST stay at
    # Needs Human Review — never auto-confirmed without the authority.
    assert finding.confidence_level == "Needs Human Review"
    guard_block = (finding.evidence or {}).get("promotion_guard") or {}
    assert guard_block.get("status") == "blocked"
    assert str(guard_block.get("reason", "")).startswith("causal_guard_")
    assert finding.vuln_class == "idor"
    assert finding.evidence["owner_identity"] == "alice"
    assert "alice-secret" not in str(finding.evidence)
    assert "bob-secret" not in str(finding.evidence)
    assert result["relational_evidence"]


def test_access_control_node_records_coverage_gap_with_one_identity(monkeypatch):
    target = Target(url="http://lab.local")
    monkeypatch.setattr(access_agent, "_probe_url", lambda *args, **kwargs: (200, 80))
    result = access_agent.access_control_node(
        {
            "target": target,
            "findings": [],
            "crawled_data": {"urls": ["http://lab.local/orders/1001"]},
            "identity_profiles": {"alice": {"cookies": {"session": "secret"}}},
        }
    )
    assert result["findings"] == []
    assert result["bac_coverage_gaps"]
    assert result["bac_coverage_gaps"][0]["status"] == "coverage_gap"
    assert "secret" not in str(result)
