# tests/test_tc5_trace_r1_chain_verified.py
"""TC-5 (Dispatch #046) — TRACE-R1 regression: the producer/consumer
``chain_verified`` contract.

The lab's LCS-REAL cycle-2 finding (P0): ``ProductionTrace.summary()``
did not export ``chain_verified``; ``_terminal_result()`` reads it
fail-closed (``production_trace.get("chain_verified", False)``), so a
campaign with complete=true, all 12 stages recorded, and a verified
audit chain still classified INCOMPLETE with reason
``production_trace_integrity``. The gate's fail-closed DESIGN is
correct; the CONTRACT was broken on the producer side.

Ruling TRACE-R1, direction (a): the PRODUCER gains the field as a
COMPUTED attestation derived from the trace's own integrity state
(completeness + digest verification + audit-chain anchor verification)
— never a pass-through boolean. The gate's read stays as-is.

Pinned here:
  (i)   happy shape — a complete, digest-verified, audit-verified trace
        → ``summary()["chain_verified"] is True`` → ``_terminal_result``
        classifies COMPLETE, and the exact campaign_summary.json shape
        the lab repro'd now carries the field as true.
  (ii)  fail-closed shapes (unchanged behavior, pinned): an incomplete
        trace → False → INCOMPLETE; a tampered digest (out-of-band
        stage mutation bypassing record(), or a mid-export digest
        shift) → False; a broken audit chain (never finalized /
        stripped root hash / double finalization) → False. Also pinned:
        the terminal gate keeps its INDEPENDENT audit vote —
        chain_verified=True never overrides audit_result.verified=False.
  (iii) integration shape — one end-to-end lab-fixture run (the
        cycle-1 pattern: resolve_production_spine → real AVI decision
        on the vulnerable IDOR fixture → the hunter-path projection
        sync → real EngagementAuditChain anchoring + file-side
        verify_chain) producing a terminal COMPLETE — the exact
        scenario the lab's run hit.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.agents.hunter_contracts import BudgetState, HunterState, HunterStatus
from webpent.agents.hunter_runner import (
    _sync_graph_replan_trace,
    _sync_observed_production_trace,
    _terminal_result,
)
from webpent.production.production_spine import (
    ProductionSpineConfig,
    ProductionTrace,
    resolve_production_spine,
)
from webpent.shared.engagement_audit import EngagementAuditChain, verify_chain


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------
def _unit_trace(
    tmp_path: Path,
    engagement_id: str = "tc5_trace_r1_unit",
    *,
    missing_stage: str | None = None,
    audit: str = "full",
) -> tuple[ProductionTrace, EngagementAuditChain | None]:
    """Build a populated ProductionTrace with REAL audit-chain anchoring.

    audit="full"    — one event + finalize (the verified anchor set)
    audit="open"    — one event, never finalized (no finalization anchor)
    audit="none"    — no audit anchoring at all
    """
    trace = ProductionTrace(config_digest="a" * 16, entrypoint="direct_invoke")
    for stage in trace.required_stages():
        if stage == missing_stage:
            continue
        trace.record(stage=stage, component="TraceR1Fixture", detail={})
    if audit == "none":
        return trace, None
    chain = EngagementAuditChain(
        engagement_id=engagement_id,
        audit_dir=tmp_path / f"{engagement_id}_audit",
        workspace_dir=tmp_path / f"{engagement_id}_workspace",
        trace=trace,
    )
    chain.append_event(event_type="campaign.started", details={"fixture": "trace_r1"})
    if audit == "full":
        chain.finalize()
    return trace, chain


def _classify(production_trace, audit_result) -> dict:
    return _terminal_result(
        state=HunterState(status=HunterStatus.COMPLETED, budget=BudgetState()),
        production_trace=production_trace,
        audit_result=audit_result,
    )


# ---------------------------------------------------------------------------
# (i) The happy shape — the lab's exact repro, with the field now true
# ---------------------------------------------------------------------------
def test_complete_verified_trace_not_incomplete_by_missing_field(tmp_path):
    """A complete, digest-verified, audit-verified trace exports
    chain_verified=true and classifies COMPLETE — the exact
    campaign_summary.json shape from the lab's repro."""
    trace, chain = _unit_trace(tmp_path)
    audit_result = verify_chain(
        audit_path=chain.audit_path,
        workspace_path=chain.workspace_path,
        trace=trace,
    )
    assert audit_result["verified"] is True

    summary = trace.summary()
    assert summary["complete"] is True
    assert summary["chain_verified"] is True
    # the field is computed, not a stored/call-settable flag
    assert isinstance(summary["chain_verified"], bool)

    terminal = _classify(summary, audit_result)
    assert terminal["status"] == "COMPLETE"
    assert terminal["reason"] == "graph_and_authoritative_traces_complete"
    assert terminal["production_trace_chain_verified"] is True

    # the exact campaign_summary.json artifact the lab repro'd
    campaign_summary = {
        "campaign_id": "tc5_trace_r1_happy",
        "production_trace": summary,
        "audit_verification": audit_result,
        "terminal": terminal,
    }
    path = tmp_path / "campaign_summary.json"
    path.write_text(json.dumps(campaign_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert persisted["production_trace"]["chain_verified"] is True
    assert persisted["production_trace"]["complete"] is True
    assert persisted["audit_verification"]["verified"] is True
    assert persisted["terminal"]["status"] == "COMPLETE"


# ---------------------------------------------------------------------------
# (ii) The fail-closed shapes — unchanged behavior, pinned
# ---------------------------------------------------------------------------
def test_incomplete_trace_exports_chain_verified_false(tmp_path):
    trace, chain = _unit_trace(tmp_path, missing_stage="promotion_decision")
    summary = trace.summary()
    assert summary["complete"] is False
    assert summary["chain_verified"] is False

    terminal = _classify(summary, {"verified": True})
    assert terminal["status"] == "INCOMPLETE"
    assert "production_trace_completion" in terminal["reason"]
    assert "production_trace_integrity" in terminal["reason"]


def test_tampered_digest_out_of_band_stage_mutation_earns_false(tmp_path):
    """A stage appended out-of-band (bypassing record()) desyncs the
    deduplicated index from the digest-covered stage list — the digest
    is no longer earned, even though completeness is untouched."""
    trace, chain = _unit_trace(tmp_path)
    trace.stages.append(
        {"stage": "ghost_injection", "component": "Tamper", "detail": {}}
    )
    summary = trace.summary()
    assert summary["complete"] is True  # the ghost stage is not required
    assert summary["chain_verified"] is False

    terminal = _classify(summary, {"verified": True})
    assert terminal["status"] == "INCOMPLETE"
    assert "production_trace_integrity" in terminal["reason"]


def test_tampered_digest_mid_export_shift_earns_false(tmp_path, monkeypatch):
    """A digest that shifts between the export's two recomputations —
    the trace mutated mid-export — fails digest verification."""
    trace, chain = _unit_trace(tmp_path)
    calls = {"n": 0}

    def shifting_digest(self):
        calls["n"] += 1
        return f"{calls['n']:064x}"
    monkeypatch.setattr(ProductionTrace, "digest", shifting_digest)

    summary = trace.summary()
    assert summary["complete"] is True
    assert summary["chain_verified"] is False


def test_broken_audit_chain_never_finalized_earns_false(tmp_path):
    """An audit chain that was never finalized has no trace anchor —
    the trace refuses to attest audit integrity (fail-closed)."""
    trace, chain = _unit_trace(tmp_path, audit="open")
    summary = trace.summary()
    assert summary["complete"] is True
    assert summary["chain_verified"] is False

    terminal = _classify(summary, {"verified": True})
    assert terminal["status"] == "INCOMPLETE"
    assert "production_trace_integrity" in terminal["reason"]


def test_broken_audit_chain_stripped_root_hash_earns_false(tmp_path):
    """A partial anchor edit (the OQ-8 Phase-1 threat model) — the
    trace-side root hash stripped after finalization — fails the
    anchor attestation."""
    trace, chain = _unit_trace(tmp_path)
    stripped = False
    for entry in trace.stages:
        if entry["stage"] == "audit_finalization":
            entry["detail"]["root_hash"] = ""
            stripped = True
    assert stripped is True

    summary = trace.summary()
    assert summary["complete"] is True
    assert summary["chain_verified"] is False


def test_broken_audit_chain_double_finalization_earns_false(tmp_path):
    """A re-finalized (ambiguous) anchor set — exactly-one is violated —
    fails the anchor attestation."""
    trace = ProductionTrace(config_digest="a" * 16, entrypoint="direct_invoke")
    for stage in trace.required_stages():
        trace.record(stage=stage, component="TraceR1Fixture", detail={})
    trace.record(
        stage="audit_event", component="EngagementAuditChain",
        detail={"event_id": "tc5:1", "event_type": "audit.finalized"},
        counts_toward_limit=False,
    )
    for _ in range(2):
        trace.record(
            stage="audit_finalization", component="EngagementAuditChain",
            detail={"event_id": "tc5:1", "root_hash": "b" * 64},
        )
    summary = trace.summary()
    assert summary["complete"] is True
    assert summary["chain_verified"] is False


def test_terminal_gate_keeps_independent_audit_vote(tmp_path):
    """§1(b) honored: chain_verified=true NEVER overrides the gate's own
    audit vote — audit_result.verified=False still classifies INCOMPLETE
    (the fix loosens nothing)."""
    trace, chain = _unit_trace(tmp_path)
    summary = trace.summary()
    assert summary["chain_verified"] is True

    terminal = _classify(summary, {"verified": False})
    assert terminal["status"] == "INCOMPLETE"
    assert terminal["reason"] == "audit_chain_verification"
    assert terminal["production_trace_chain_verified"] is True


# ---------------------------------------------------------------------------
# (iii) The integration shape — end-to-end lab-fixture run (cycle-1
#       pattern) producing a terminal COMPLETE
# ---------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _allow_lab_loopback():
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )
    token = set_engagement_target_hosts("127.0.0.1", "localhost")
    yield
    clear_engagement_target_hosts(token)


def _idor_hypothesis(hid: str, target_url: str, engagement_id: str) -> dict:
    """The cycle-1 IDOR hypothesis (vault-bound principal specs)."""

    def _spec(actor: str, invoice: str, actor_role: str) -> dict:
        return {
            "method": "GET",
            "path": f"/api/invoices/{invoice}",
            "headers": {"X-User": actor},
            "principal_alias": actor,
            "principal_role": actor_role,
        }

    return {
        "id": hid,
        "vulnerability_class": "IDOR",
        "api_type": "rest",
        "path": "/api/invoices/",
        "information_value": 0.9,
        "resource_owner": "User_B",
        "engagement_id": engagement_id,
        "requests": {
            "baseline": _spec("User_B", "INV-B-204", "owner"),
            "candidate": _spec("User_A", "INV-B-204", "foreign-user"),
            # non-existent invoice id → 404: an independent negative
            # control even on the vulnerable target
            "negative_control": _spec("User_A", "INV-NO-SUCH-999", "foreign-user"),
        },
    }


def test_integration_lab_fixture_run_terminal_complete(tmp_path):
    """The exact scenario the lab's run hit: a real campaign through the
    authorized factory, a real full-chain decision on the vulnerable IDOR
    fixture, the hunter-path projections, a real finalized audit chain —
    the terminal verdict is COMPLETE, not INCOMPLETE/production_trace_integrity."""
    from tests.lab.idor_lab_target import start_lab_server
    from webpent.models.evidence import sha256_text
    from webpent.production.context_authority import ContextAuthority

    server, vuln_url = start_lab_server(vulnerable=True)
    try:
        engagement_id = "tc5_trace_r1_e2e"
        orch, production_trace = resolve_production_spine(
            ProductionSpineConfig(
                engagement_id=engagement_id,
                target_url=vuln_url,
                entrypoint="direct_invoke",
                modern_spine_enabled=True,
                auto_approve=False,  # strict-HITL default (DR-002)
            )
        )

        # principals sealed under the vault (the cycle-1 lab pattern)
        authority = ContextAuthority(
            engagement_id=engagement_id,
            target_fingerprint=sha256_text(vuln_url)[:16],
        )
        authority.seal_principal_credentials(
            principal_alias="User_B", role="owner", password="password_b")
        authority.seal_principal_credentials(
            principal_alias="User_A", role="foreign-user", password="password_a")

        # deep recon against the live fixture — recorded on the production
        # trace the way the hunter path records it after the crawler
        orch.run_deep_recon(target_url=vuln_url, observed=[
            {"path": "/api/invoices/", "method": "GET", "status_code": 200,
             "body": "{}", "headers": {}}])
        production_trace.record(
            stage="deep_recon", component="DeepReconEngine",
            detail={"target_url": vuln_url},
        )

        # one real full-chain decision through THE production dispatch
        # entry (research → real HTTP triple → observation → causal guard
        # → proof → replay → promotion; the orchestrator owns the AVI run
        # and exposes its trace records for the projection sync)
        result = orch.run_autonomous_validation_campaign(
            target_url=vuln_url,
            hypotheses=[_idor_hypothesis("tc5_r1_pos", vuln_url, engagement_id)],
            max_decisions=1,
        )
        assert result.get("promoted_count", 0) >= 1, "the vulnerable fixture must promote (the cycle-1 P1 outcome)"

        # the REAL hunter-path projections (the same functions the
        # campaign calls after each decision round)
        _sync_observed_production_trace(production_trace, orch)
        _sync_graph_replan_trace(production_trace, [{"node": "replan"}])

        # the real audit chain anchored INTO this trace + file-side verify
        audit = EngagementAuditChain(
            engagement_id=engagement_id,
            audit_dir=tmp_path / "audit",
            workspace_dir=tmp_path / "audit_workspace",
            trace=production_trace,
        )
        audit.append_event(event_type="campaign.started", details={"persona": "stok"})
        audit.finalize()
        audit_result = verify_chain(
            audit_path=audit.audit_path,
            workspace_path=audit.workspace_path,
            trace=production_trace,
        )
        assert audit_result["verified"] is True

        # THE FIX: the producer now attests natively what the lab's run
        # could only verify by hand
        summary = production_trace.summary()
        assert summary["complete"] is True, summary["missing_required_stages"]
        assert summary["chain_verified"] is True

        terminal = _classify(summary, audit_result)
        assert terminal["status"] == "COMPLETE"
        assert terminal["reason"] == "graph_and_authoritative_traces_complete"

        campaign_summary = {
            "campaign_id": engagement_id,
            "production_trace": summary,
            "audit_verification": audit_result,
            "terminal": terminal,
        }
        (tmp_path / "campaign_summary.json").write_text(
            json.dumps(campaign_summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    finally:
        server.should_exit = True
