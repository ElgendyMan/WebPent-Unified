"""Fail-closed Target Package v2 engagement admission and one-time consumption."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from webpent.shared.package_scope import ScopeCompiler
from webpent.shared.target_package_context import (
    TargetPackageContext,
    admit_target_package,
)


class EngagementAdmissionError(ValueError):
    """Raised when a package cannot create an executable engagement."""


@dataclass(frozen=True)
class EngagementBinding:
    engagement_id: str
    package_id: str
    package_sha256: str
    scope_digest: str
    policy_digest: str
    lease_id: str
    consumed_at: str
    context: TargetPackageContext

    def as_dict(self) -> dict[str, Any]:
        return {
            "engagement_id": self.engagement_id,
            "package_id": self.package_id,
            "package_sha256": self.package_sha256,
            "scope_digest": self.scope_digest,
            "policy_digest": self.policy_digest,
            "lease_id": self.lease_id,
            "consumed_at": self.consumed_at,
            "target_package_status": "consumed",
        }


class EngagementFactory:
    """Create exactly one executable engagement from one signed package.

    The package itself is never persisted. The durable record contains only the
    binding identity, hashes, and lease state needed to prevent replay/conflict.
    """

    def __init__(
        self,
        lease_path: str | Path,
        *,
        signature_verifier: Callable[[Mapping[str, Any]], Any] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.lease_path = Path(lease_path)
        self.signature_verifier = signature_verifier
        self.clock = clock or (lambda: datetime.now(UTC))
        self.lease_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.lease_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS target_package_consumptions (
                    package_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL UNIQUE,
                    package_sha256 TEXT NOT NULL,
                    scope_digest TEXT NOT NULL,
                    policy_digest TEXT NOT NULL,
                    lease_id TEXT NOT NULL UNIQUE,
                    consumed_at TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status = 'consumed')
                )
                """
            )

    @staticmethod
    def _confirmation_value(confirmation: Mapping[str, Any], *keys: str) -> str:
        for key in keys:
            value = confirmation.get(key)
            if value not in (None, ""):
                return str(value).strip()
        return ""

    def _admit_and_validate(
        self,
        package: Mapping[str, Any],
        confirmation: Mapping[str, Any],
    ) -> tuple[TargetPackageContext, str]:
        """Perform all non-mutating checks shared by create and restore."""
        if not isinstance(confirmation, Mapping):
            raise EngagementAdmissionError("confirmation_required")
        if confirmation.get("user_confirmed") is not True:
            raise EngagementAdmissionError("explicit_user_confirmation_required")
        context = admit_target_package(package, now=self.clock(), require_signature=True)
        if self.signature_verifier is None:
            raise EngagementAdmissionError("detached_signature_verifier_required")
        try:
            self.signature_verifier(package)
        except Exception as exc:
            raise EngagementAdmissionError("detached_signature_invalid") from exc

        confirmed_package_id = self._confirmation_value(
            confirmation, "package_id", "target_package_id"
        )
        confirmed_digest = self._confirmation_value(
            confirmation,
            "package_sha256",
            "target_package_sha256",
            "content_sha256",
        )
        engagement_id = self._confirmation_value(confirmation, "engagement_id")
        if not engagement_id:
            raise EngagementAdmissionError("engagement_id_required")
        if confirmed_package_id != context.package_id:
            raise EngagementAdmissionError("confirmation_package_id_mismatch")
        if confirmed_digest != context.package_sha256:
            raise EngagementAdmissionError("confirmation_package_digest_mismatch")
        target_url = self._confirmation_value(confirmation, "target_url", "target_origin")
        if not target_url:
            raise EngagementAdmissionError("confirmed_target_required")
        scope_decision = ScopeCompiler.from_package_context(context).decide(target_url)
        if not scope_decision.allowed:
            raise EngagementAdmissionError(
                f"confirmed_target_{scope_decision.status.value}"
            )
        return context, engagement_id

    def create_from_package(
        self,
        package: Mapping[str, Any],
        confirmation: Mapping[str, Any],
    ) -> EngagementBinding:
        """Validate and consume a package once, returning its redacted binding."""
        context, engagement_id = self._admit_and_validate(package, confirmation)
        consumed_at = self.clock().astimezone(UTC).isoformat().replace("+00:00", "Z")
        lease_id = "lease-" + uuid.uuid4().hex
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT package_id, engagement_id "
                    "FROM target_package_consumptions WHERE package_id = ?",
                    (context.package_id,),
                ).fetchone()
                if existing is not None:
                    raise EngagementAdmissionError("package_already_consumed")
                existing_engagement = connection.execute(
                    "SELECT package_id FROM target_package_consumptions WHERE engagement_id = ?",
                    (engagement_id,),
                ).fetchone()
                if existing_engagement is not None:
                    raise EngagementAdmissionError("engagement_already_bound")
                connection.execute(
                    """
                    INSERT INTO target_package_consumptions
                    (package_id, engagement_id, package_sha256, scope_digest,
                     policy_digest, lease_id, consumed_at, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'consumed')
                    """,
                    (
                        context.package_id,
                        engagement_id,
                        context.package_sha256,
                        context.scope_digest,
                        context.policy_digest,
                        lease_id,
                        consumed_at,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise EngagementAdmissionError("package_or_engagement_consumption_conflict") from exc

        return EngagementBinding(
            engagement_id=engagement_id,
            package_id=context.package_id,
            package_sha256=context.package_sha256,
            scope_digest=context.scope_digest,
            policy_digest=context.policy_digest,
            lease_id=lease_id,
            consumed_at=consumed_at,
            context=context,
        )

    def restore_existing_binding(
        self,
        package: Mapping[str, Any],
        confirmation: Mapping[str, Any],
    ) -> EngagementBinding:
        """Reconstitute an exact prior lease without consuming it again."""
        context, engagement_id = self._admit_and_validate(package, confirmation)
        existing = self.get_binding(context.package_id)
        if existing is None:
            raise EngagementAdmissionError("package_binding_missing")
        expected = {
            "engagement_id": engagement_id,
            "package_id": context.package_id,
            "package_sha256": context.package_sha256,
            "scope_digest": context.scope_digest,
            "policy_digest": context.policy_digest,
        }
        if any(str(existing.get(key) or "") != value for key, value in expected.items()):
            raise EngagementAdmissionError("package_binding_continuity_mismatch")
        return EngagementBinding(
            engagement_id=engagement_id,
            package_id=context.package_id,
            package_sha256=context.package_sha256,
            scope_digest=context.scope_digest,
            policy_digest=context.policy_digest,
            lease_id=str(existing["lease_id"]),
            consumed_at=str(existing["consumed_at"]),
            context=context,
        )

    def get_binding(self, package_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT package_id, engagement_id, package_sha256, scope_digest, "
                "policy_digest, lease_id, consumed_at, status "
                "FROM target_package_consumptions WHERE package_id = ?",
                (str(package_id),),
            ).fetchone()
        return dict(row) if row is not None else None

    def restore_binding_projection(
        self,
        binding_projection: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Verify a redacted checkpoint binding against the durable lease.

        Resume must not require the raw package or consume a second lease. The
        checkpoint still cannot authorize a new engagement: every identity and
        digest is compared with the SQLite record created during admission.
        """
        if not isinstance(binding_projection, Mapping):
            raise EngagementAdmissionError("package_binding_required")
        required = (
            "package_id",
            "engagement_id",
            "package_sha256",
            "scope_digest",
            "policy_digest",
            "lease_id",
        )
        projected_status = binding_projection.get("target_package_status")
        if projected_status is not None and str(projected_status) != "consumed":
            raise EngagementAdmissionError("package_binding_status_mismatch")
        values = {key: str(binding_projection.get(key) or "") for key in required}
        if any(not value for value in values.values()):
            raise EngagementAdmissionError("package_binding_incomplete")
        existing = self.get_binding(values["package_id"])
        if existing is None:
            raise EngagementAdmissionError("package_binding_missing")
        if any(str(existing.get(key) or "") != value for key, value in values.items()):
            raise EngagementAdmissionError("package_binding_continuity_mismatch")
        if str(existing.get("status") or "") != "consumed":
            raise EngagementAdmissionError("package_binding_not_consumed")
        return existing


__all__ = ["EngagementAdmissionError", "EngagementBinding", "EngagementFactory"]
