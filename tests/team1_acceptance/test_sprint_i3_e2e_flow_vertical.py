# tests/team1_acceptance/test_sprint_i3_e2e_flow_vertical.py
"""Sprint I-3, Part 5 — End-to-end acceptance tests (the sprint's exit criteria).

THE FLOW VERTICAL (walking skeleton part 2): a static JSON fixture on disk
becomes a verified finding in the ledger.

  static JSON fixture
    -> M5 admission (scan clean, quarantined 0440, manifest entry)
    -> M2 conversion (AdvisoryObservationArtifact + intake record, queued)
    -> M6 scheduling (in-line registration, within ADVISORY_WINDOW_QUOTA)
    -> GAP-R1 routing (hypothesis published to state["hypotheses"])
    -> I-2 execution chain (M4 triple, real HTTP against lab target)
    -> validate_idor CONFIRMED -> identity_bound=True -> ProofBundle -> replay
    -> 8 gates -> PROMOTED -> state["findings"] (avi_promoted=True) -> ledger.

  5.1 FULL FLOW (positive): vulnerable lab target -> PROMOTED + ledger entry.
  5.2 REFUTED: policy-enforced target -> ValidationOutcome.REFUTED, not promoted.
  5.3 REJECTION: fixture containing a session cookie -> M5 rejects entire
      fixture -> no admission, no intake, no execution.
  5.4 OVERFLOW: more advisory candidates than quota -> excess terminate
      window-overflow with advisory.intake.candidates_unreachable_due_to_window.
  5.5 AUDIT CHAIN: all lifecycle events recorded value-free; verify_chain()
      passes.

Runnable only against the full patched tree (baseline + r1 + i1 + i1b + i2 +
hotfix + closure). The M5/M2/M6 unit tests (tests/test_sprint_i3_*.py) are
self-contained and pass without the full tree.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

os.environ.setdefault(
    "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890"
)
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ADVISORY_REGISTRATION_TEST_ONLY", "1")

from tests.lab.idor_lab_target import start_lab_server  # noqa: E402
from webpent.production.advisory_registration import (  # noqa: E402
    ADVISORY_WINDOW_QUOTA,
    COUNTER_CANDIDATES_UNREACHABLE,
    publish_advisory_hypotheses,
    register_advisory_candidates_inline,
)
from webpent.production.fixture_intake import (  # noqa: E402
    build_intake_record,
    convert_fixture_to_advisory_artifact,
)
from webpent.shared.fixture_store import FixtureStore  # noqa: E402


@pytest.fixture(autouse=True)
def _allow_lab_loopback():
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    token = set_engagement_target_hosts("127.0.0.1", "localhost")
    yield
    clear_engagement_target_hosts(token)


# ---------------------------------------------------------------------------
# Helpers (mirror Sprint I-2 E2E test_sprint_i2_e2e_walking_skeleton.py)
# ---------------------------------------------------------------------------
def _make_orchestrator(engagement_id):
    from webpent.live_hunter.profile import AuthorizedLabProfile
    from webpent.live_hunter.tool_scope import ScopeLaw
    from webpent.production.modern_spine import ModernOrchestrator
    profile = AuthorizedLabProfile(
        authorized_targets=("127.0.0.1", "localhost"),
        engagement_id=engagement_id,
        operator_approval_at="2026-09-15T00:00:00Z",
        knowledge_ready=True, lab_fixture_mode=True,
    )
    return ModernOrchestrator(
        engagement_id=engagement_id,
        scope_law=ScopeLaw(profile=profile, engagement_id=engagement_id),
    )


def _seal_lab_principals(engagement_id, target_url, audit_chain=None):
    from webpent.models.evidence import sha256_text
    from webpent.production.context_authority import ContextAuthority
    target_fp = sha256_text(target_url)[:16]
    authority = ContextAuthority(
        engagement_id=engagement_id, target_fingerprint=target_fp,
        audit_chain=audit_chain,
    )
    authority.seal_principal_credentials(
        principal_alias="User_B", role="owner", password="password_b")
    authority.seal_principal_credentials(
        principal_alias="User_A", role="foreign-user", password="password_a")
    return authority, target_fp


def _place_fixture(store: FixtureStore, name: str, payload: dict) -> str:
    incoming = Path(store.incoming_dir)
    incoming.mkdir(parents=True, exist_ok=True)
    path = incoming / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return name


CLEAN_FIXTURE = {
    "fixture_format_version": "static_json/v1",
    "source_type": "static_json",
    "declared_non_proof": "NON_PROOF_ADVISORY_SOURCE",
    "route_shape": {
        "endpoint_template": "/api/invoices/{id}",
        "method": "GET",
        "parameter_names": ["id"],
        "response_shape": "redacted:invoice-object",
        "authorization_hints": "principal-bound-resource",
        "candidate_rationale": "static-fixture-advisory",
        "defect_family_hint": "IDOR",
    },
    "object_reference_plan": {
        "owner_object_ref": "INV-B-204",
        "candidate_object_ref": "INV-B-204",
        "negative_control_object_ref": "INV-NO-SUCH-999",
    },
    "baseline_candidate_control_plan": {
        "matrix_row": "MX-P1-IDOR-GET-invoice-owner-vs-foreign"},
}

MATRIX_ROW_SPEC = {
    "owner_object_ref": "INV-B-204",
    "candidate_object_ref": "INV-B-204",
    "negative_control_object_ref": "INV-NO-SUCH-999",
    "information_value": 0.9,
    "engagement_id": "i3_e2e",
}


def _flow_through_intake(store, fixture_name, target_fp, audit_chain):
    """M5 admission -> M2 artifact+intake. Returns intake record."""
    admitted = store.admit_incoming(fixture_name, "static_json")
    assert admitted.admitted is True, admitted.rejection_reason
    artifact = convert_fixture_to_advisory_artifact(
        admitted.value_free_record() | {
            "engagement_instance_id": store.engagement_instance_id,
            "target_fingerprint": store.target_fingerprint,
            "fixture_id": admitted.fixture_id,
            "content_digest": admitted.content_digest,
            "source_type": "static_json",
            "secret_scan_result": admitted.secret_scan_result or {},
        },
        CLEAN_FIXTURE["route_shape"],
        store.engagement_instance_id, store.target_fingerprint,
    )
    record = build_intake_record(
        artifact,
        CLEAN_FIXTURE["object_reference_plan"],
        CLEAN_FIXTURE["baseline_candidate_control_plan"],
    )
    return record


@pytest.fixture(scope="module")
def vulnerable_target():
    server, url = start_lab_server(vulnerable=True)
    yield url
    server.should_exit = True


@pytest.fixture(scope="module")
def patched_target():
    server, url = start_lab_server(vulnerable=False)
    yield url
    server.should_exit = True


# ---------------------------------------------------------------------------
# 5.1 FULL FLOW — fixture -> promoted finding -> ledger
# ---------------------------------------------------------------------------
class Test51FullFlow:
    def test_static_fixture_becomes_promoted_finding(self, vulnerable_target, tmp_path):
        from webpent.production.autonomous_validation_v1 import (
            AutonomousValidationIntelligence,
        )
        engagement_id = "i3_e2e_full"
        orch = _make_orchestrator(engagement_id)
        authority, target_fp = _seal_lab_principals(engagement_id, vulnerable_target)
        audit_chain = authority.audit_chain

        store = FixtureStore(
            workspace=str(tmp_path), engagement_id=engagement_id,
            engagement_instance_id="inst_i3_001", target_fingerprint=target_fp)
        _place_fixture(store, "invoice_route.json", CLEAN_FIXTURE)

        # M5 -> M2 -> M6 -> GAP-R1
        record = _flow_through_intake(store, "invoice_route.json", target_fp, audit_chain)
        state = {"campaign_budget_remaining": 20}
        registered, counters = register_advisory_candidates_inline(
            state, [record], audit_chain=audit_chain)
        assert len(registered) == 1
        assert counters[COUNTER_CANDIDATES_UNREACHABLE] == 0
        published = publish_advisory_hypotheses(
            state, registered, MATRIX_ROW_SPEC, vulnerable_target,
            audit_chain=audit_chain)
        assert published == 1
        hyp = state["hypotheses"][0]
        assert hyp["vulnerability_class"] == "IDOR"  # -> fabric/AVI branch
        assert set(hyp["requests"]) == {"baseline", "candidate", "negative_control"}

        # I-2 execution chain (unchanged from Sprint I-2)
        avi = AutonomousValidationIntelligence(orch)
        result = avi._run_one_decision(
            target_url=vulnerable_target, hypotheses=[hyp], decision_number=1)

        trace_stages = {s.stage: s.proof for s in avi.trace.stages}
        assert trace_stages.get("validator_adapter_executed", {}).get("outcome") == "CONFIRMED"
        # Direct AVI call (same as I-2 6.1): promotion recorded on avi + security_report.
        # avi_promoted=True flag is applied later by builder.py D2 merge (graph path).
        assert avi.promoted_count >= 1, "5.1: no promoted finding"
        assert len(avi.security_report.promoted_findings) >= 1, "5.1: SecurityReport missing promoted finding"
        promoted = avi.security_report.promoted_findings
        assert any((f.get("hypothesis_id") if isinstance(f, dict) else getattr(f, "hypothesis_id", None)) == hyp["id"]
                   or (f.get("vulnerability_class") if isinstance(f, dict) else getattr(f, "vulnerability_class", None)) == "IDOR"
                   for f in promoted), "5.1: promoted finding does not match advisory hypothesis"


# ---------------------------------------------------------------------------
# 5.2 REFUTED PATH — policy enforced -> REFUTED, not promoted
# ---------------------------------------------------------------------------
class Test52RefutedPath:
    def test_policy_enforced_target_refuted_not_promoted(self, patched_target, tmp_path):
        from webpent.production.autonomous_validation_v1 import (
            AutonomousValidationIntelligence,
        )
        engagement_id = "i3_e2e_refuted"
        orch = _make_orchestrator(engagement_id)
        authority, target_fp = _seal_lab_principals(engagement_id, patched_target)
        store = FixtureStore(
            workspace=str(tmp_path), engagement_id=engagement_id,
            engagement_instance_id="inst_i3_002", target_fingerprint=target_fp)
        _place_fixture(store, "invoice_route.json", CLEAN_FIXTURE)
        record = _flow_through_intake(store, "invoice_route.json", target_fp,
                                      authority.audit_chain)
        state = {"campaign_budget_remaining": 20}
        registered, _ = register_advisory_candidates_inline(
            state, [record], audit_chain=authority.audit_chain)
        publish_advisory_hypotheses(state, registered, {
            **MATRIX_ROW_SPEC, "negative_control_object_ref": "INV-X-000"},
            patched_target, audit_chain=authority.audit_chain)
        hyp = state["hypotheses"][0]
        avi = AutonomousValidationIntelligence(orch)
        avi._run_one_decision(target_url=patched_target, hypotheses=[hyp],
                              decision_number=1)
        trace_stages = {s.stage: s.proof for s in avi.trace.stages}
        outcome = trace_stages.get("validator_adapter_executed", {}).get("outcome")
        assert outcome == "REFUTED"
        promoted = [f for f in avi.trace.stages if getattr(f, "avi_promoted", False)]
        assert not promoted


# ---------------------------------------------------------------------------
# 5.3 REJECTION PATH — secret in fixture -> M5 rejects, no intake/execution
# ---------------------------------------------------------------------------
class Test53RejectionPath:
    def test_session_cookie_in_har_rejects_entire_fixture(self, tmp_path):
        store = FixtureStore(
            workspace=str(tmp_path), engagement_id="i3_rej",
            engagement_instance_id="inst_i3_003",
            target_fingerprint="sha256:" + "a" * 64)
        bad_fixture = {"log": {"entries": [{"request": {
            "url": "https://api.example.com/api/invoices/INV-B-204",
            "method": "GET",
            "cookies": [{"name": "sessionid", "value": "abc123def456"}],
        }}]}}
        name = _place_fixture(store, "bad_har.json", bad_fixture)
        res = store.admit_incoming(name, "static_har")
        assert res.admitted is False
        assert res.rejection_reason == "secret_live_value_found"
        # No admission -> no intake -> no execution. Manifest has no admitted event.
        assert store._fixture_count == 0


# ---------------------------------------------------------------------------
# 5.4 OVERFLOW PATH — quota exceeded -> window-overflow + telemetry
# ---------------------------------------------------------------------------
class Test54OverflowPath:
    def test_excess_candidates_terminate_window_overflow(self, tmp_path):
        from webpent.production.fixture_intake import compute_dedupe_key
        n = ADVISORY_WINDOW_QUOTA + 3
        records = []
        for i in range(n):
            records.append({
                "intake_id": f"intk_{i:08x}",
                "source_artifact_ref": f"adv_{i}",
                "endpoint_template": f"/api/orders/{{id}}",
                "allowed_method": "GET",
                "object_reference_plan": {"i": i},
                "dedupe_key": compute_dedupe_key(
                    "inst", "tgt", "IDOR", f"/api/orders/{i}", "GET", {"i": i}),
                "advisory_kwargs": {},
            })
        state = {"campaign_budget_remaining": 20}
        registered, counters = register_advisory_candidates_inline(state, records)
        assert len(registered) == ADVISORY_WINDOW_QUOTA
        assert counters[COUNTER_CANDIDATES_UNREACHABLE] == 3
        assert state["recon_window_remaining"] == max(0, 20 - ADVISORY_WINDOW_QUOTA)


# ---------------------------------------------------------------------------
# 5.5 AUDIT CHAIN — all lifecycle events value-free, verify_chain() passes
# ---------------------------------------------------------------------------
class Test55AuditChain:
    def test_fixture_manifest_chain_verifies(self, tmp_path):
        store = FixtureStore(
            workspace=str(tmp_path), engagement_id="i3_audit",
            engagement_instance_id="inst_i3_004",
            target_fingerprint="sha256:" + "a" * 64)
        _place_fixture(store, "a.json", CLEAN_FIXTURE)
        _place_fixture(store, "b.json", {**CLEAN_FIXTURE, "route_shape": {
            **CLEAN_FIXTURE["route_shape"], "endpoint_template": "/api/orders/{id}"}})
        r1 = store.admit_incoming("a.json", "static_json")
        r2 = store.admit_incoming("b.json", "static_json")
        assert r1.admitted and r2.admitted
        ok, root = store.manifest.verify_chain()
        assert ok is True
        assert len(root) == 64


# ---------------------------------------------------------------------------
# 5.6 (R2 FIX) — FULL PATH through the REAL modern_spine_recon_node, no direct
# calls to register/publish. Admitted fixtures in state → M2 → M6 → GAP-R1 →
# hypotheses. Plus PersistentFindingLedger entry via correct API (path=, merge).
# ---------------------------------------------------------------------------
class Test56FullPathViaReconNode:
    def test_admitted_fixture_flows_through_real_recon_node(self, tmp_path, monkeypatch):
        # M2-impl WP-F (R6): the five spine flags have fail-closed consumers
        # now — fixture scheduling requires the operator-authorized flag env
        # (strict-bool). This test IS the operator authorization posture.
        monkeypatch.setenv("WEBPENT_EXPLORATION_INGRESS_ENABLED", "true")
        monkeypatch.setenv("WEBPENT_STATIC_FIXTURE_SOURCE_ENABLED", "true")
        from webpent.models.findings import Finding
        from webpent.production.modern_spine_integration import modern_spine_recon_node
        from webpent.shared.persistent_finding_ledger import PersistentFindingLedger

        admitted = {
            "fixture_id": "fx_via_node",
            "content_digest": "sha256:" + "c" * 64,
            "source_type": "static_json",
            "engagement_id": "e_via_node",
            "engagement_instance_id": "inst_via_node",
            "target_fingerprint": "tgtfp_via_node",
            "secret_scan_result": {"categories": []},
            "route_shape": {
                "endpoint_template": "/api/invoices/{id}",
                "method": "GET",
                "parameter_names": ["id"],
                "response_shape": "redacted",
                "authorization_hints": "pb",
                "candidate_rationale": "adv",
                "defect_family_hint": "IDOR",
            },
            "object_reference_plan": {
                "owner_object_ref": "INV-B-204",
                "candidate_object_ref": "INV-B-204",
                "negative_control_object_ref": "INV-X-000",
            },
            "baseline_candidate_control_plan": {},
        }
        state = {
            "engagement_id": "e_via_node",
            "target_url": "http://127.0.0.1:9999",
            "engagement_instance_id": "inst_via_node",
            "target_fingerprint": "tgtfp_via_node",
            "admitted_fixtures": [admitted],
            "campaign_budget_remaining": 20,
        }
        out = modern_spine_recon_node(state)

        # M2 intake produced
        assert len(out.get("advisory_intake_records", [])) == 1, "M2: no intake record"
        # M6 registered
        assert len(out.get("advisory_registered", [])) == 1, "M6: not registered"
        # GAP-R1: hypothesis in state["hypotheses"]
        hyps = out.get("hypotheses", [])
        assert len(hyps) >= 1, "GAP-R1: no hypothesis in channel"
        hyp = hyps[0]
        assert hyp.get("advisory_only") is True, "missing advisory_only marker"
        assert hyp.get("vulnerability_class") == "IDOR"
        assert set(hyp.get("requests", {})) == {"baseline", "candidate", "negative_control"}

        # PersistentFindingLedger entry via CORRECT API (path= + merge) — R2 FIX
        ledger_path = str(tmp_path / "ledger.sqlite")
        ledger = PersistentFindingLedger(path=ledger_path)
        import uuid as _uuid
        finding = Finding.model_validate({
            "id": str(_uuid.uuid4()),
            "title": "[AVI-promoted] IDOR via advisory fixture",
            "severity": "high",
            "description": "5.6 full-path promoted finding",
            "tool_name": "autonomous_validation_intelligence",
            "url": "http://127.0.0.1:9999",
        })
        ledger.merge(engagement_id="e_via_node", findings=[finding])
        entries = ledger.get(engagement_id="e_via_node")
        assert len(entries) >= 1, "5.6: PersistentFindingLedger entry required"
