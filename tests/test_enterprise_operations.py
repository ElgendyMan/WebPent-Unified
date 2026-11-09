# tests/test_enterprise_operations.py
"""Track 12 item 9 — enterprise operations: RBAC (frozen least-
privilege), SSO mapping seam, workspace isolation, multi-analyst review
queue, retention policies, audit export."""

from __future__ import annotations

import json
import time

from webpent.production.enterprise_operations import (
    AuditExporter,
    Permission,
    RbacPolicy,
    RetentionPolicy,
    ReviewQueue,
    ReviewState,
    Role,
    SsoIdentity,
    WorkspaceRegistry,
)


class TestRbac:
    def test_frozen_matrix_least_privilege(self):
        assert RbacPolicy.authorize(Role.VIEWER, Permission.VIEW_FINDINGS) is True
        assert RbacPolicy.authorize(Role.VIEWER, Permission.TRIAGE_FINDINGS) is False
        assert RbacPolicy.authorize(Role.ANALYST, Permission.TRIAGE_FINDINGS) is True
        assert RbacPolicy.authorize(Role.ANALYST, Permission.NOMINATE_REPORT) is False
        assert RbacPolicy.authorize(Role.LEAD, Permission.NOMINATE_REPORT) is True
        assert RbacPolicy.authorize(Role.ADMIN, Permission.MANAGE_USERS) is True
        # Analyst can run campaigns but never manage users.
        assert RbacPolicy.authorize(Role.ANALYST, Permission.MANAGE_USERS) is False

    def test_fail_closed_on_unknown_values(self):
        assert RbacPolicy.authorize("ghost-role", Permission.VIEW_FINDINGS) is False
        assert RbacPolicy.authorize(Role.ADMIN, "ghost-permission") is False
        assert RbacPolicy.authorize(None, None) is False

    def test_sso_mapping_explicit_and_fail_closed(self):
        sso = SsoIdentity({"bugcrowd-lead": Role.LEAD, "h1-researchers": Role.ANALYST})
        policy = RbacPolicy(sso)
        assert policy.authorize_identity("u1", ["h1-researchers"], Permission.RUN_CAMPAIGN) is True
        # Unmapped identity falls back to VIEWER — never privileged.
        assert policy.authorize_identity("u2", ["unknown-org"], Permission.RUN_CAMPAIGN) is False
        assert policy.authorize_identity("u2", [], Permission.VIEW_FINDINGS) is True
        # No group can ever silently become ADMIN without an explicit rule.
        assert policy.authorize_identity("u3", ["admins-ish"], Permission.MANAGE_USERS) is False


class TestWorkspaceIsolation:
    def test_membership_required_fail_closed(self):
        ws = WorkspaceRegistry()
        ws.grant("analyst-1", "client-A")
        assert ws.assert_same_workspace("analyst-1", "client-A") is True
        assert ws.assert_same_workspace("analyst-1", "client-B") is False
        assert ws.assert_same_workspace("stranger", "client-A") is False


class TestReviewQueue:
    def make(self, required=1):
        ws = WorkspaceRegistry()
        ws.grant("a1", "client-A")
        ws.grant("a2", "client-A")
        return ws, ReviewQueue(ws, required_approvals=required)

    def test_enqueue_claim_decide_flow(self):
        ws, queue = self.make()
        queue.enqueue("i1", "client-A", "finding-1", severity="high", actor="a1")
        assert queue.claim("i1", "a1").state is ReviewState.CLAIMED
        item = queue.submit_decision("i1", "a1", approve=True)
        assert item.state is ReviewState.APPROVED
        assert queue.nominatable("i1") is True

    def test_cross_workspace_operations_refused(self):
        ws, queue = self.make()
        queue.enqueue("i1", "client-A", "f-1", actor="a1")
        outsider = WorkspaceRegistry()  # stranger with no grants
        assert ws.assert_same_workspace("outsider", "client-A") is False
        # Outsider enqueue is refused entirely.
        assert queue.enqueue("i9", "client-B", "f-9", actor="outsider") is None
        # Outsider claim/decision refused.
        assert queue.claim("i1", "outsider") is None
        assert queue.submit_decision("i1", "outsider", approve=True) is None
        assert outsider is not None  # isolation is registry-level

    def test_two_analyst_rule(self):
        ws, queue = self.make(required=2)
        queue.enqueue("i1", "client-A", "f-1", actor="a1")
        queue.claim("i1", "a1")
        queue.submit_decision("i1", "a1", approve=True)
        # One approval is not enough with required_approvals=2.
        assert queue.nominatable("i1") is False
        queue.claim("i1", "a2") if queue.claim("i1", "a2") else None
        queue.submit_decision("i1", "a2", approve=True)
        assert queue.nominatable("i1") is True

    def test_no_double_voting(self):
        ws, queue = self.make(required=2)
        queue.enqueue("i1", "client-A", "f-1", actor="a1")
        queue.claim("i1", "a1")
        queue.submit_decision("i1", "a1", approve=True)
        # Same analyst votes again — ignored (no second approval).
        same = queue.submit_decision("i1", "a1", approve=True)
        assert len(same.approvals) == 1
        assert queue.nominatable("i1") is False

    def test_rejection_rejects_item(self):
        ws, queue = self.make(required=2)
        queue.enqueue("i1", "client-A", "f-1", actor="a1")
        queue.claim("i1", "a1")
        queue.submit_decision("i1", "a1", approve=False)
        assert queue.nominatable("i1") is False
        assert queue.pending("client-A") == []

    def test_pending_ordering_deterministic(self):
        ws, queue = self.make()
        for item in ("i3", "i1", "i2"):
            queue.enqueue(item, "client-A", f"f-{item}", actor="a1")
        assert [i.item_id for i in queue.pending("client-A")] == ["i1", "i2", "i3"]


class TestRetention:
    def test_dry_run_default_reports_only(self):
        policy = RetentionPolicy({"findings": 30})
        now = time.time()
        records = [
            {"finding_ref": "old", "created_at": now - 40 * 86400},
            {"finding_ref": "new", "created_at": now - 5 * 86400},
        ]
        result = policy.apply_retention(records, data_class="findings", now=now)
        assert result["would_purge"] == 1
        assert result["purged"] == 0
        assert len(records) == 2  # nothing deleted

    def test_enact_when_dry_run_false(self):
        policy = RetentionPolicy()
        now = time.time()
        records = [
            {"finding_ref": "ancient", "created_at": now - 400 * 86400},
            {"finding_ref": "recent", "created_at": now},
        ]
        result = policy.apply_retention(records, data_class="findings", now=now, dry_run=False)
        assert result["purged"] == 1
        assert [r["finding_ref"] for r in records] == ["recent"]

    def test_unknown_class_fails_closed(self):
        policy = RetentionPolicy()
        result = policy.apply_retention([{"created_at": 1}], data_class="tweets")
        assert result["expired"] == [] and "unknown data class" in result["error"]


class TestAuditExport:
    def test_export_single_client_isolation(self, tmp_path):
        ws = WorkspaceRegistry()
        ws.grant("auditor", "client-A")
        exporter = AuditExporter(ws)
        exporter.record("triage", actor="a1", client_id="client-A", finding_ref="f1")
        exporter.record("triage", actor="a2", client_id="client-B", finding_ref="f2")
        ok, count = exporter.export_for(
            "client-A", tmp_path / "export" / "audit.jsonl", actor="auditor"
        )
        assert ok is True and count == 1
        lines = (tmp_path / "export" / "audit.jsonl").read_text().splitlines()
        rows = [json.loads(line) for line in lines]
        assert rows[0]["client_id"] == "client-A"

    def test_export_refused_without_membership(self, tmp_path):
        ws = WorkspaceRegistry()
        exporter = AuditExporter(ws)
        ok, count = exporter.export_for(
            "client-A", tmp_path / "x.jsonl", actor="intruder"
        )
        assert ok is False and count == 0
        assert not (tmp_path / "x.jsonl").exists()

    def test_unwritable_target_reports_not_raises(self, tmp_path):
        ws = WorkspaceRegistry()
        ws.grant("auditor", "client-A")
        exporter = AuditExporter(ws)
        blocker = tmp_path / "blocker"
        blocker.write_text("file")
        ok, count = exporter.export_for("client-A", blocker / "x" / "y.jsonl", actor="auditor")
        assert ok is False


class TestIntrospection:
    def test_membership_view(self):
        ws = WorkspaceRegistry()
        ws.grant("a1", "client-A")
        ws.grant("a1", "client-B")
        assert set(ws.memberships("a1")) == {"client-A", "client-B"}
        assert ws.memberships("ghost") == frozenset()
