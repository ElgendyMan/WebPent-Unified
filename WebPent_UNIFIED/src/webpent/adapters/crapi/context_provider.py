"""Offline crAPI adapter for generic context and fixture contracts.

This module intentionally stops at deterministic descriptors. It does not
create accounts, tokens, credentials, application objects, or live requests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from webpent.adapters.mock_target.context_provider import (
    MockContextProvider,
    MockFixtureProvider,
    MockSessionProvider,
)
from webpent.models.evidence import canonical_json
from webpent.shared.target_context import (
    ContextStatus,
    FixtureHandle,
    FixtureRequest,
    IdentityRequest,
    RestoreResult,
    SessionHandle,
    SnapshotHandle,
    TargetScope,
)

CRAPI_TARGET_SPEC_ID = "crapi-target-spec"
CRAPI_OFFLINE_CAPABILITIES = frozenset(
    {"read_only_navigation", "context_snapshot", "context_restore", "context_disposal"}
)


@dataclass(frozen=True)
class CrAPIDisposableOwnershipFixture:
    """Deterministic offline model for crAPI object ownership.

    The model represents only opaque synthetic identifiers. It can produce an
    expected owner-allowed/requester-denied observation and a deliberately
    labelled hypothetical unauthorized candidate for oracle tests. Neither
    path performs an application request or changes external state.
    """

    owner_id: str
    requester_id: str
    object_id: str
    state_hash: str

    def evaluate_access(
        self,
        session: SessionHandle,
        *,
        simulate_unauthorized_access: bool = False,
    ) -> dict[str, Any]:
        """Return redacted access/invariant signals for one synthetic session."""
        subject = session.identity.subject_ref
        is_owner = subject == self.owner_id
        is_requester = subject == self.requester_id
        expected_allowed = is_owner
        actual_allowed = is_owner or (is_requester and simulate_unauthorized_access)
        return {
            "invariant_holds": actual_allowed == expected_allowed,
            "invariant_violated": actual_allowed != expected_allowed,
            "resource_state": "owner_resource" if is_owner else "foreign_resource",
            "access_allowed": actual_allowed,
            "access_denied": not actual_allowed,
            "subject_role": "owner" if is_owner else "requester" if is_requester else "unknown",
            "object_id": self.object_id,
            "state_hash": self.state_hash,
        }


class CrAPIContextProvider(MockContextProvider):
    """Offline target context provider; live auth remains explicitly unsupported."""

    def capabilities(self) -> set[str]:
        return set(CRAPI_OFFLINE_CAPABILITIES)


class CrAPISyntheticSessionProvider(MockSessionProvider):
    """Synthetic requester/owner metadata only; no JWT/API key is produced."""

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle:
        session = super().create_synthetic_context(request)
        return SessionHandle(
            session_ref="crapi-offline-session-" + request.identity_ref,
            identity=session.identity,
            in_memory_only=True,
            ready=session.ready,
            reason=session.reason,
        )


class CrAPIObjectFixtureProvider(MockFixtureProvider):
    """Disposable ownership fixture provider with deterministic reset/restore."""

    def __init__(
        self,
        *,
        ready: bool = True,
        restore_fails: bool = False,
        cleanup_fails: bool = False,
    ) -> None:
        super().__init__(
            ready=ready,
            restore_fails=restore_fails,
            cleanup_fails=cleanup_fails,
        )
        self._ownership: dict[str, CrAPIDisposableOwnershipFixture] = {}
        self._snapshots: dict[str, CrAPIDisposableOwnershipFixture] = {}

    def provision(self, fixture_request: FixtureRequest) -> FixtureHandle:
        handle = super().provision(fixture_request)
        owner_id = str(fixture_request.metadata.get("owner_id", "crapi-synthetic-owner"))
        requester_id = str(
            fixture_request.metadata.get("requester_id", "crapi-synthetic-requester")
        )
        object_id = str(fixture_request.metadata.get("object_id", "crapi-synthetic-object"))
        state_hash = _ownership_hash(
            fixture_request.fixture_ref,
            owner_id,
            requester_id,
            object_id,
        )
        fixture = CrAPIDisposableOwnershipFixture(
            owner_id=owner_id,
            requester_id=requester_id,
            object_id=object_id,
            state_hash=state_hash,
        )
        self._ownership[handle.fixture_ref] = fixture
        return FixtureHandle(
            fixture_ref=handle.fixture_ref,
            state_hash=state_hash,
            role=handle.role,
            disposable=True,
            ready=handle.ready,
            reason=handle.reason,
        )

    def get_ownership_model(
        self,
        handle: FixtureHandle,
    ) -> CrAPIDisposableOwnershipFixture | None:
        """Return the in-memory ownership model for a disposable fixture."""
        return self._ownership.get(handle.fixture_ref)

    def snapshot(self, fixture: FixtureHandle) -> SnapshotHandle:
        model = self._ownership.get(fixture.fixture_ref)
        if model is None:
            raise ValueError("crapi_fixture_not_provisioned")
        self._snapshots[fixture.fixture_ref] = model
        return SnapshotHandle(
            "crapi-offline-snapshot-" + fixture.fixture_ref,
            fixture.fixture_ref,
            model.state_hash,
        )

    def restore(self, snapshot: SnapshotHandle) -> RestoreResult:
        if self.restore_fails:
            return RestoreResult(ContextStatus.RESTORE_FAILED, "crapi_fixture_restore_failed")
        model = self._snapshots.get(snapshot.scope_key)
        if model is None or model.state_hash != snapshot.state_hash:
            return RestoreResult(ContextStatus.RESTORE_FAILED, "crapi_snapshot_state_mismatch")
        self._ownership[snapshot.scope_key] = model
        return RestoreResult(ContextStatus.READY, "crapi_fixture_restored", model.state_hash)

    def reset(self, fixture: FixtureHandle) -> bool:
        """Restore a prior snapshot and verify the deterministic state hash."""
        snapshot = self._snapshots.get(fixture.fixture_ref)
        if snapshot is None:
            return False
        snapshot_handle = SnapshotHandle(
            "crapi-offline-snapshot-" + fixture.fixture_ref,
            fixture.fixture_ref,
            snapshot.state_hash,
        )
        result = self.restore(snapshot_handle)
        return result.status == ContextStatus.READY and result.state_hash == fixture.state_hash


def _ownership_hash(fixture_ref: str, owner_id: str, requester_id: str, object_id: str) -> str:
    payload = {
        "fixture_ref": fixture_ref,
        "owner_id": owner_id,
        "requester_id": requester_id,
        "object_id": object_id,
    }
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def crapi_scope(
    campaign_id: str = "crapi-context-campaign",
    run_id: str = "crapi-context-run",
) -> TargetScope:
    return TargetScope(
        CRAPI_TARGET_SPEC_ID,
        campaign_id,
        run_id,
        "http://127.0.0.1:8888",
        "crapi-scope",
    )


__all__ = [
    "CRAPI_OFFLINE_CAPABILITIES",
    "CRAPI_TARGET_SPEC_ID",
    "CrAPIContextProvider",
    "CrAPISyntheticSessionProvider",
    "CrAPIObjectFixtureProvider",
    "CrAPIDisposableOwnershipFixture",
    "crapi_scope",
]
