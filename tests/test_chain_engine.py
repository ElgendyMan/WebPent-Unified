from __future__ import annotations

import os

from webpent.agents.chain_engine import (
    CHAIN_PATTERNS,
    ChainEngine,
    ChainExecutionResult,
    discover_chains,
)
from webpent.models.proof_bundle import build_proof_bundle
from webpent.production.product_layer import render_campaign_dashboard

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "chain-test-key-2026-with-strong-entropy-123456")


def _finding(fid, family, *, target="http://target.test", engagement="eng-1", capabilities=(), severity="5.0"):
    bundle = build_proof_bundle(
        engagement_id=engagement,
        finding_id=fid,
        hypothesis_id=f"hyp-{fid}",
        target_fingerprint="target-fingerprint",
        scope_context={"target_url": target},
        identity_context={"principal_alias": "owner"},
        evidence=({"status": 200}, {"status": 200}, {"status": 404}),
        evidence_refs=(f"evidence-{fid}-baseline", f"evidence-{fid}-candidate", f"evidence-{fid}-control"),
        negative_control={"status": 404},
        baseline={"status": 200},
        request_evidence=({"method": "GET", "path": f"/api/{fid}"},),
        response_evidence=({"status": 200},),
        causal_oracle={"causal_signal": True, "negative_control_complete": True},
        validator_id="validator.chain-test",
        validator_version="chain-test.v1",
        replay_metadata={"replayable": True},
        cleanup_status="not_applicable",
    ).seal()
    return {
        "id": fid,
        "status": "PROMOTED",
        "family": family,
        "target_url": target,
        "engagement_id": engagement,
        "route": f"/api/{fid}",
        "severity": severity,
        "capabilities": list(capabilities),
        "proof_bundle_ref": bundle.bundle_id,
        "proof_bundle": bundle.model_dump(mode="json"),
        "replay_verified": True,
        "promotion": {"decision": "PROMOTED", "gates_passed": ["g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8"]},
    }


def test_chain_discovery_matches_info_disclosure_to_idor_same_engagement():
    findings = [
        _finding("disclosure", "INFO_DISCLOSURE", capabilities=("user_ids",), severity="3.1"),
        _finding("idor", "IDOR", capabilities=("user_ids", "other_user_data"), severity="6.5"),
    ]
    candidates = discover_chains(findings, mind_map_notes=("info disclosure user IDs can feed IDOR",))
    candidate = next(item for item in candidates if item.pattern == "info_disclosure_to_idor")
    assert candidate.prerequisites_met is True
    assert candidate.step_1_finding["finding_id"] == "disclosure"
    assert candidate.step_2_finding["finding_id"] == "idor"
    assert candidate.target_url == "http://target.test"


def test_chain_discovery_rejects_cross_target_and_incompatible_findings():
    findings = [
        _finding("disclosure", "INFO_DISCLOSURE", capabilities=("user_ids",)),
        _finding("idor-other-target", "IDOR", target="http://other.test", capabilities=("user_ids",)),
        _finding("xss", "XSS", capabilities=("script_execution",)),
    ]
    candidates = discover_chains(findings)
    assert not any(item.pattern == "info_disclosure_to_idor" for item in candidates)
    assert not any(item.pattern == "idor_to_privilege_escalation" for item in candidates)


def test_chain_discovery_rejects_promoted_ref_without_verified_sealed_bundle():
    forged = _finding("forged", "SSRF", capabilities=("internal_access",))
    forged["proof_bundle"] = {"sealed": True, "seal_digest": "sha256:" + "0" * 64}
    forged["replay_verified"] = True
    assert discover_chains([forged]) == ()


def test_chain_execution_records_audit_and_requires_governed_result():
    events = []
    engine = ChainEngine(audit_event=lambda name, details: events.append((name, dict(details))))
    candidate = engine.discover([
        _finding("ssrf", "SSRF", capabilities=("internal_access",), severity="8.0"),
    ])[0]

    run = engine.execute(
        [candidate],
        lambda item: ChainExecutionResult(
            chain_id=item.chain_id,
            status="chain_confirmed",
            confirmed=True,
            reason="M4/AVI/PromotionPipeline passed",
            evidence={"authority": "M4/AVI/PromotionPipeline", "response_digest": "redacted"},
            proof_bundle_ref="chain-proof",
            replay_verified=True,
            gates_passed=("g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8"),
        ),
    )
    assert run.to_dict()["chains_confirmed"] == 1
    assert run.reports[0].combined_severity == "CRITICAL"
    assert run.reports[0].combined_cvss == 9.0
    assert [event[0] for event in events] == ["chain.discovered", "chain.executed", "chain.confirmed"]
    assert "redacted" in str(run.reports[0].to_dict())


def test_chain_without_executor_is_blocked_and_not_reportable():
    engine = ChainEngine()
    candidate = engine.discover([_finding("ssrf", "SSRF", capabilities=("internal_access",))])[0]
    run = engine.execute([candidate], executor=None)
    assert run.executions[0].status == "chain_blocked"
    assert run.reports == ()
    assert run.to_dict()["combined_severity_upgrades"] == 0


def test_chain_patterns_are_bounded_and_reportable_only_after_replay_and_gates():
    assert len(CHAIN_PATTERNS) == 5
    engine = ChainEngine(max_chains=99)
    findings = [_finding(f"ssrf-{i}", "SSRF", capabilities=("internal_access",)) for i in range(9)]
    candidates = engine.discover(findings)
    assert len(candidates) == 5
    rejected = engine.execute(
        candidates[:1],
        lambda item: {"status": "chain_confirmed", "confirmed": True, "replay_verified": False},
    )
    assert rejected.reports == ()


def test_dashboard_renders_chain_metrics_without_authority_side_effects():
    html = render_campaign_dashboard(
        "campaign-1",
        [],
        chain_metrics={"chains_discovered": 2, "chains_confirmed": 1, "combined_severity_upgrades": 1},
    )
    assert "Chaining Engine" in html
    assert "Chains discovered" in html
    assert "combined severity upgrades" in html


def test_chain_source_identifier_changes_only_candidate_request():
    from webpent.agents.hunter_runner import _apply_chain_source_identifier

    candidate = {
        "metadata": {"owner_value": "5"},
        "requests": {
            "baseline": {"path": "/identity/api/v2/user/5", "principal_alias": "owner"},
            "candidate": {"path": "/identity/api/v2/user/5", "principal_alias": "foreign"},
            "negative_control": {"path": "/identity/api/v2/user/99999", "principal_alias": "foreign"},
        },
    }
    updated, applied = _apply_chain_source_identifier(candidate, "8")
    assert applied is True
    assert updated["requests"]["candidate"]["path"] == "/identity/api/v2/user/8"
    assert updated["requests"]["baseline"]["path"] == "/identity/api/v2/user/5"
    assert updated["requests"]["negative_control"]["path"] == "/identity/api/v2/user/99999"


def test_chain_source_identifier_rejects_path_injection():
    from webpent.agents.hunter_runner import _apply_chain_source_identifier

    candidate = {"metadata": {"owner_value": "5"}, "requests": {"candidate": {"path": "/user/5"}}}
    updated, applied = _apply_chain_source_identifier(candidate, "8/../../admin")
    assert applied is False
    assert updated is candidate


def test_chain_source_identifier_requires_existing_replacement_point():
    from webpent.agents.hunter_runner import _apply_chain_source_identifier

    candidate = {"metadata": {"owner_value": "5"}, "requests": {"candidate": {"path": "/user/current"}}}
    updated, applied = _apply_chain_source_identifier(candidate, "8")
    assert applied is False
    assert updated is candidate
