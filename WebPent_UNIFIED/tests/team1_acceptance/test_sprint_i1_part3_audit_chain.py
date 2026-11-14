# tests/team1_acceptance/test_sprint_i1_part3_audit_chain.py
"""Sprint I-1, item 3.2 — tests for shared/engagement_audit.py (M4 v2.1
OQ-8, ratified)."""
from __future__ import annotations

import json
import sys

import pytest

from webpent.production.production_spine import ProductionTrace
from webpent.shared.engagement_audit import (
    AuditChainVerificationFailed,
    EngagementAuditChain,
    verify_chain,
)


@pytest.fixture()
def dirs(tmp_path):
    return tmp_path / "audit", tmp_path / "workspace"


class TestAppendAndVerify:
    def test_append_n_events_then_verify_passes(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e1", audit_dir=audit_dir, workspace_dir=workspace_dir)
        for i in range(5):
            chain.append_event(event_type="context.resolution_denied", details={"i": i})
        chain.finalize()
        result = verify_chain(audit_path=chain.audit_path, workspace_path=chain.workspace_path)
        assert result["verified"] is True
        assert result["event_count"] == 6  # 5 + finalization

    def test_file_mode_is_0600(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e2", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="vault.key_ambiguous", details={})
        mode = chain.audit_path.stat().st_mode & 0o777
        # POSIX: the audit file must be owner-only (0o600). Windows/NTFS does
        # not model the POSIX group/other bits (chmod only toggles the
        # read-only attribute); profile-scoped ACLs provide the equivalent
        # current-user-only property there, so the bit assertion is POSIX-only.
        if sys.platform == "win32":
            assert chain.audit_path.exists()
        else:
            assert mode == 0o600

    def test_payload_schema_matches_m4_spec(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e3", audit_dir=audit_dir, workspace_dir=workspace_dir)
        event = chain.append_event(
            event_type="principal.role_mismatch", principal_alias="alice",
            target_fingerprint="abc123", error_class="PRINCIPAL_ROLE_MISMATCH",
            details={"note": "test"},
        )
        for key in (
            "event_id", "event_type", "seq", "prev_hash", "timestamp",
            "principal_alias", "engagement_id", "target_fingerprint",
            "error_class", "details",
        ):
            assert key in event, f"missing M4-required field: {key}"

    def test_cannot_append_after_finalization(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e4", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="context.resolution_denied", details={})
        chain.finalize()
        with pytest.raises(AuditChainVerificationFailed):
            chain.append_event(event_type="context.resolution_denied", details={})

    def test_cannot_finalize_twice(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e5", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="context.resolution_denied", details={})
        chain.finalize()
        with pytest.raises(AuditChainVerificationFailed):
            chain.finalize()


class TestTamperDetection:
    def test_tampered_event_detected(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e6", audit_dir=audit_dir, workspace_dir=workspace_dir)
        for i in range(5):
            chain.append_event(event_type="context.resolution_denied", details={"i": i})
        chain.finalize()

        lines = chain.audit_path.read_text().splitlines()
        tampered = json.loads(lines[2])
        tampered["details"] = {"i": 999}
        lines[2] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        chain.audit_path.write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditChainVerificationFailed, match="tampered event"):
            verify_chain(audit_path=chain.audit_path, workspace_path=chain.workspace_path)

    def test_truncate_and_rebuild_detected_via_workspace_anchor(self, dirs, tmp_path):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e7", audit_dir=audit_dir, workspace_dir=workspace_dir)
        for i in range(5):
            chain.append_event(event_type="vault.key_ambiguous", details={"i": i})
        chain.finalize()
        workspace_snapshot = chain.workspace_path.read_text()

        # Attacker truncates and rebuilds a shorter fake chain in place.
        chain.audit_path.unlink()
        fake = EngagementAuditChain(
            engagement_id="e7", audit_dir=audit_dir, workspace_dir=tmp_path / "fake_workspace",
        )
        fake.append_event(event_type="vault.key_ambiguous", details={"i": 0})
        fake.finalize()

        # The ORIGINAL workspace anchor is untouched — must catch the mismatch.
        chain.workspace_path.write_text(workspace_snapshot)
        with pytest.raises(AuditChainVerificationFailed, match="workspace-record anchor mismatch"):
            verify_chain(audit_path=chain.audit_path, workspace_path=chain.workspace_path)

    def test_broken_hash_chain_link_detected(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e8", audit_dir=audit_dir, workspace_dir=workspace_dir)
        for i in range(3):
            chain.append_event(event_type="context.resolution_denied", details={"i": i})
        chain.finalize()

        lines = chain.audit_path.read_text().splitlines()
        second = json.loads(lines[1])
        second["prev_hash"] = "f" * 64  # break the link without fixing the hash
        lines[1] = json.dumps(second, sort_keys=True, separators=(",", ":"))
        chain.audit_path.write_text("\n".join(lines) + "\n")

        with pytest.raises(AuditChainVerificationFailed):
            verify_chain(audit_path=chain.audit_path, workspace_path=chain.workspace_path)

    def test_missing_finalization_event_detected(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e9", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="context.resolution_denied", details={})
        # No finalize() call.
        with pytest.raises(AuditChainVerificationFailed, match="no finalization event"):
            verify_chain(audit_path=chain.audit_path, workspace_path=chain.workspace_path)

    def test_no_external_anchor_supplied_refuses_to_verify(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e10", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="context.resolution_denied", details={})
        chain.finalize()
        with pytest.raises(AuditChainVerificationFailed, match="no external anchor"):
            verify_chain(audit_path=chain.audit_path)


class TestTraceAnchor:
    def test_trace_anchor_verify_passes(self, dirs):
        audit_dir, workspace_dir = dirs
        trace = ProductionTrace(config_digest="deadbeef", entrypoint="cli")
        chain = EngagementAuditChain(
            engagement_id="e11", audit_dir=audit_dir, workspace_dir=workspace_dir, trace=trace,
        )
        chain.append_event(event_type="context.resolution_denied", details={})
        chain.finalize()
        result = verify_chain(audit_path=chain.audit_path, trace=trace)
        assert result["verified"] is True

    def test_per_event_trace_summary_has_only_event_id_and_type(self, dirs):
        """Per OQ-8/§3.3.4: 'the trace recorder receives only a one-line
        summary event_id + event_type per event' — details must never
        reach the trace. Two audit_event stages are expected here: one
        for the real appended event, one for the finalization event
        itself (finalize() routes through append_event() too) — the
        finalization event ADDITIONALLY gets the separate
        audit_finalization stage tested below, on top of its own normal
        audit_event summary."""
        audit_dir, workspace_dir = dirs
        trace = ProductionTrace(config_digest="deadbeef", entrypoint="cli")
        chain = EngagementAuditChain(
            engagement_id="e12", audit_dir=audit_dir, workspace_dir=workspace_dir, trace=trace,
        )
        chain.append_event(
            event_type="context.resolution_denied",
            details={"secret_looking_field": "should-never-reach-trace"},
        )
        chain.finalize()
        audit_stages = [s for s in trace.stages if s["stage"] == "audit_event"]
        assert len(audit_stages) == 2
        for stage in audit_stages:
            assert set(stage["detail"].keys()) == {"event_id", "event_type"}

    def test_finalization_stage_is_explicit_exception_with_root_hash(self, dirs):
        audit_dir, workspace_dir = dirs
        trace = ProductionTrace(config_digest="deadbeef", entrypoint="cli")
        chain = EngagementAuditChain(
            engagement_id="e13", audit_dir=audit_dir, workspace_dir=workspace_dir, trace=trace,
        )
        chain.append_event(event_type="context.resolution_denied", details={})
        finalization_event = chain.finalize()
        final_stages = [s for s in trace.stages if s["stage"] == "audit_finalization"]
        assert len(final_stages) == 1
        assert final_stages[0]["detail"]["root_hash"] == finalization_event["hash"]

    def test_trace_anchor_mismatch_detected(self, dirs):
        audit_dir, workspace_dir = dirs
        trace = ProductionTrace(config_digest="deadbeef", entrypoint="cli")
        chain = EngagementAuditChain(
            engagement_id="e14", audit_dir=audit_dir, workspace_dir=workspace_dir, trace=trace,
        )
        chain.append_event(event_type="context.resolution_denied", details={})
        chain.finalize()
        # Corrupt the trace's own recorded root hash.
        for stage in trace.stages:
            if stage["stage"] == "audit_finalization":
                stage["detail"]["root_hash"] = "0" * 64
        with pytest.raises(AuditChainVerificationFailed, match="trace anchor mismatch"):
            verify_chain(audit_path=chain.audit_path, trace=trace)


class TestPauseResumeContinuity:
    def test_resumed_chain_continues_seq_and_hash(self, dirs):
        audit_dir, workspace_dir = dirs
        chain = EngagementAuditChain(engagement_id="e15", audit_dir=audit_dir, workspace_dir=workspace_dir)
        chain.append_event(event_type="context.stale_restore_blocked", details={"n": 1})
        del chain

        resumed = EngagementAuditChain(engagement_id="e15", audit_dir=audit_dir, workspace_dir=workspace_dir)
        assert resumed._seq == 1
        resumed.append_event(event_type="context.resolution_denied", details={"n": 2})
        resumed.finalize()

        result = verify_chain(audit_path=resumed.audit_path, workspace_path=resumed.workspace_path)
        assert result["event_count"] == 3
