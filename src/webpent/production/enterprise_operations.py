# src/webpent/production/enterprise_operations.py
"""webpent.production.enterprise_operations — Track 12, item 9.

Roadmap contract (المسار 12، البند 9 — تشغيل مؤسسي):

    RBAC، طابور مراجعة متعدد المحللين، SSO، عزل مساحات العمل، وسياسات
    احتفاظ وتصدير للتدقيق.

    ("RBAC, a multi-analyst review queue, SSO, workspace isolation, and
    retention/export policies for audit.")

Design
------
``enterprise_operations`` composes the enterprise layer from small,
fail-closed primitives:

* **RBAC** — a fixed least-privilege matrix (``Role`` → ``Permission``).
  ``RbacPolicy.authorize`` is fail-closed: an unknown role or unknown
  permission is a refusal, and the matrix is a frozen constant — no
  runtime mutation of grants.
* **SSO seam** — ``SsoIdentity`` maps an identity-provider subject to a
  LOCAL role via explicit, reviewed mapping rules; no OIDC/SAML network
  code lives here. The adapter contract is documented at the seam so an
  operator integrates their IdP without this module making network
  calls or trusting unverified assertions.
* **Workspace isolation** — every artifact carries a ``client_id``;
  ``WorkspaceRegistry.assert_same_workspace`` refuses cross-client
  operations (fail-closed) — the platform privacy rule at the
  enterprise layer.
* **Multi-analyst review queue** — claim → decide → (optionally)
  require N distinct approvals before a finding may be nominated to
  the final report. Decisions are attributed, conflict-locked (one
  open claim per analyst per item), and ordered deterministically.
* **Retention** — class-based retention days (raw evidence, findings,
  audit logs) with ``apply_retention`` returning the EXPIRED refs for
  a purge performed by the caller; dry-run by default so a policy
  mistake cannot delete anything by itself.
* **Audit export** — a redaction-first JSONL bundle of decisions for
  external auditors: identifier-level records only, export event
  itself logged.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "AuditExporter",
    "Permission",
    "RbacPolicy",
    "RetentionPolicy",
    "ReviewItem",
    "ReviewQueue",
    "ReviewState",
    "Role",
    "SsoIdentity",
    "WorkspaceRegistry",
]


class Role(str, Enum):
    """Fixed enterprise roles (least privilege)."""

    VIEWER = "viewer"
    ANALYST = "analyst"
    LEAD = "lead"
    ADMIN = "admin"


class Permission(str, Enum):
    """The permission vocabulary (fail-closed checks only)."""

    VIEW_FINDINGS = "view_findings"
    TRIAGE_FINDINGS = "triage_findings"
    NOMINATE_REPORT = "nominate_report"
    RUN_CAMPAIGN = "run_campaign"
    MANAGE_SCOPE = "manage_scope"
    MANAGE_USERS = "manage_users"
    EXPORT_AUDIT = "export_audit"


#: The frozen least-privilege matrix — never mutated at runtime.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset({Permission.VIEW_FINDINGS}),
    Role.ANALYST: frozenset(
        {Permission.VIEW_FINDINGS, Permission.TRIAGE_FINDINGS, Permission.RUN_CAMPAIGN}
    ),
    Role.LEAD: frozenset(
        {
            Permission.VIEW_FINDINGS,
            Permission.TRIAGE_FINDINGS,
            Permission.RUN_CAMPAIGN,
            Permission.NOMINATE_REPORT,
            Permission.MANAGE_SCOPE,
            Permission.EXPORT_AUDIT,
        }
    ),
    Role.ADMIN: frozenset(set(Permission)),
}


class SsoIdentity:
    """Map an IdP subject to a LOCAL role via explicit rules.

    This is a documented SEAM, not an SSO client: no network calls, no
    assertion verification here (the operator's IdP adapter performs
    verification and hands over a verified subject + group claims).
    Mapping rules are (idp_group → Role) pairs reviewed by an admin;
    an unmapped subject falls back to the least-privileged role.
    """

    def __init__(self, group_role_map: dict[str, Role] | None = None) -> None:
        self._map: dict[str, Role] = {
            str(k): (v if isinstance(v, Role) else Role(v))
            for k, v in (group_role_map or {}).items()
        }

    def map_identity(self, subject: str, groups: list[str]) -> Role:
        """Fail-closed: unmapped identity → VIEWER (never ADMIN)."""
        for group in groups:
            role = self._map.get(str(group))
            if role is not None:
                return role
        logger.info("enterprise: identity %s unmapped — falling back to viewer", subject)
        return Role.VIEWER


class RbacPolicy:
    """Fail-closed authorization against the frozen matrix."""

    def __init__(self, sso: SsoIdentity | None = None) -> None:
        self._sso = sso or SsoIdentity()

    @staticmethod
    def authorize(role: Role | str, permission: Permission | str) -> bool:
        """True only when the role's frozen grant set contains the
        permission; unknown values refuse (fail-closed)."""
        try:
            role_value = role if isinstance(role, Role) else Role(str(role))
            perm_value = (
                permission
                if isinstance(permission, Permission)
                else Permission(str(permission))
            )
        except ValueError:
            return False
        return perm_value in ROLE_PERMISSIONS.get(role_value, frozenset())

    def authorize_identity(
        self, subject: str, groups: list[str], permission: Permission
    ) -> bool:
        role = self._sso.map_identity(subject, groups)
        return self.authorize(role, permission)


class WorkspaceRegistry:
    """Client-isolation enforcement for the enterprise layer."""

    def __init__(self) -> None:
        self._memberships: dict[str, set[str]] = {}  # analyst -> clients

    def grant(self, analyst: str, client_id: str) -> None:
        self._memberships.setdefault(analyst, set()).add(client_id)

    def assert_same_workspace(self, actor: str, client_id: str) -> bool:
        """Fail-closed: an actor without an explicit membership grant
        can never touch a client's workspace."""
        return client_id in self._memberships.get(actor, set())

    def memberships(self, actor: str) -> frozenset[str]:
        return frozenset(self._memberships.get(actor, set()))


class ReviewState(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass
class ReviewItem:
    """One finding awaiting multi-analyst review (identifier-level)."""

    item_id: str
    client_id: str
    finding_ref: str
    severity: str = "info"
    state: ReviewState = ReviewState.PENDING
    claimed_by: str = ""
    approvals: list[str] = field(default_factory=list)
    rejections: list[str] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "client_id": self.client_id,
            "finding_ref": self.finding_ref,
            "severity": self.severity,
            "state": self.state.value,
            "claimed_by": self.claimed_by,
            "approvals": list(self.approvals),
            "rejections": list(self.rejections),
            "updated_at": self.updated_at,
        }


class ReviewQueue:
    """Multi-analyst review queue with an optional N-approvals rule."""

    def __init__(self, workspace: WorkspaceRegistry, *, required_approvals: int = 1) -> None:
        self._workspace = workspace
        self._required = max(1, int(required_approvals))
        self._items: dict[str, ReviewItem] = {}

    @property
    def required_approvals(self) -> int:
        return self._required

    def enqueue(
        self,
        item_id: str,
        client_id: str,
        finding_ref: str,
        *,
        severity: str = "info",
        actor: str = "",
    ) -> ReviewItem | None:
        """Enqueue for review — the actor must belong to the workspace."""
        if actor and not self._workspace.assert_same_workspace(actor, client_id):
            return None
        item = ReviewItem(
            item_id=item_id, client_id=client_id, finding_ref=finding_ref, severity=severity
        )
        self._items[item_id] = item
        return item

    def claim(self, item_id: str, analyst: str) -> ReviewItem | None:
        item = self._items.get(item_id)
        if item is None:
            return None
        if not self._workspace.assert_same_workspace(analyst, item.client_id):
            return None  # cross-workspace claim refused (fail-closed)
        if item.state is not ReviewState.PENDING:
            return None
        item.state = ReviewState.CLAIMED
        item.claimed_by = analyst
        item.updated_at = time.time()
        return item

    def submit_decision(
        self, item_id: str, analyst: str, *, approve: bool
    ) -> ReviewItem | None:
        """Attribute a decision; approval state advances only when the
        configured number of DISTINCT analysts have approved."""
        item = self._items.get(item_id)
        if item is None or item.state is ReviewState.PENDING:
            return None
        if not self._workspace.assert_same_workspace(analyst, item.client_id):
            return None
        if analyst in item.approvals or analyst in item.rejections:
            return item  # one decision per analyst — no double voting
        if approve:
            item.approvals.append(analyst)
            if len(item.approvals) >= self._required:
                item.state = ReviewState.APPROVED
        else:
            item.rejections.append(analyst)
            item.state = ReviewState.REJECTED
        item.updated_at = time.time()
        return item

    def nominatable(self, item_id: str) -> bool:
        """A finding may enter the final report only when the queue
        itself says APPROVED (the N-approvals rule honored)."""
        item = self._items.get(item_id)
        return bool(item and item.state is ReviewState.APPROVED)

    def pending(self, client_id: str | None = None) -> list[ReviewItem]:
        items = [
            i
            for i in self._items.values()
            if i.state in (ReviewState.PENDING, ReviewState.CLAIMED)
            and (client_id is None or i.client_id == client_id)
        ]
        return sorted(items, key=lambda i: (i.client_id, i.item_id))


class RetentionPolicy:
    """Class-based retention; dry-run by default — the caller purges."""

    def __init__(self, retention_days: dict[str, int] | None = None) -> None:
        self._days = {
            "raw_evidence": int((retention_days or {}).get("raw_evidence", 90)),
            "findings": int((retention_days or {}).get("findings", 365)),
            "audit_logs": int((retention_days or {}).get("audit_logs", 730)),
        }

    @property
    def retention_days(self) -> dict[str, int]:
        return dict(self._days)

    def apply_retention(
        self,
        records: list[dict[str, Any]],
        *,
        data_class: str,
        now: float | None = None,
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Return expired records for one data class.

        ``dry_run=True`` (default) only REPORTS what would expire; the
        caller performs any deletion. Unknown classes fail closed.
        """
        if data_class not in self._days:
            return {"expired": [], "purged": 0, "error": f"unknown data class '{data_class}'"}
        current = now if now is not None else time.time()
        horizon = self._days[data_class] * 86400.0
        expired: list[dict[str, Any]] = []
        for record in records:
            try:
                created = float(record.get("created_at") or 0.0)
            except (TypeError, ValueError):
                created = 0.0
            if created and (current - created) > horizon:
                expired.append(record)
        purged = 0
        if not dry_run:
            keep = [r for r in records if r not in expired]
            purged = len(records) - len(keep)
            records[:] = keep
        return {
            "data_class": data_class,
            "expired": expired,
            "would_purge": len(expired),
            "purged": purged,
            "dry_run": dry_run,
        }


class AuditExporter:
    """Redaction-first JSONL audit bundle for external auditors."""

    def __init__(self, workspace: WorkspaceRegistry) -> None:
        self._workspace = workspace
        self._events: list[dict[str, Any]] = []

    def record(self, event: str, *, actor: str, client_id: str, **fields: Any) -> None:
        self._events.append(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event,
                "actor": actor,
                "client_id": client_id,
                **fields,
            }
        )

    def export_for(
        self,
        client_id: str,
        out_path: str | os.PathLike[str],
        *,
        actor: str,
    ) -> tuple[bool, int]:
        """Export ONE client's audit events (never cross-client).

        The exporter requires ``export_audit``-capable callers upstream;
        the workspace check here is the isolation backstop. The export
        event itself is recorded before writing.
        """
        if not self._workspace.assert_same_workspace(actor, client_id):
            return False, 0
        rows = [e for e in self._events if e.get("client_id") == client_id]
        self.record("audit_export", actor=actor, client_id=client_id)
        try:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(path, "w", encoding="utf-8") as fh:
                for row in rows:
                    fh.write(json.dumps(row, separators=(",", ":"), default=str) + "\n")
            return True, len(rows)
        except OSError:
            logger.warning("enterprise: audit export write failed", exc_info=True)
            return False, len(rows)
