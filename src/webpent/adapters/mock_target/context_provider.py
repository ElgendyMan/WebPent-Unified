"""Deterministic target-context providers used only by local regression tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from webpent.models.evidence import canonical_json
from webpent.shared.target_context import (
    CapabilityLease,
    ContextHandle,
    ContextRequest,
    ContextStatus,
    DisposalResult,
    FixtureDescriptor,
    FixtureHandle,
    FixtureProvider,
    FixtureRequest,
    IdentityRequest,
    ReadinessResult,
    RestoreResult,
    SessionHandle,
    SessionProvider,
    SnapshotHandle,
    TargetScope,
)


@dataclass
class MockContextProvider:
    """In-memory provider with explicit failure switches for contract tests."""

    ready: bool = True
    snapshot_restore_fails: bool = False
    cleanup_fails: bool = False

    def capabilities(self) -> set[str]:
        return {"read_only_navigation", "context_snapshot", "context_restore", "context_disposal"}

    def prepare(self, request: ContextRequest) -> ContextHandle:
        status = ContextStatus.READY if self.ready else ContextStatus.LAB_NOT_READY
        reason = "ready" if self.ready else "mock_context_not_ready"
        lease = CapabilityLease(
            lease_ref="provider-placeholder",
            scope_key=request.scope.key,
            capabilities=frozenset(request.requested_capabilities),
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        )
        return ContextHandle("mock-context", request.scope, lease, status, reason)

    def readiness(self, handle: ContextHandle) -> ReadinessResult:
        if not self.ready:
            return ReadinessResult(ContextStatus.LAB_NOT_READY, ("mock_context_not_ready",))
        return ReadinessResult(ContextStatus.READY, ("mock_context_ready",), ("mock:readiness",))

    def snapshot(self, handle: ContextHandle) -> SnapshotHandle:
        state_hash = hashlib.sha256(handle.scope.key.encode()).hexdigest()
        return SnapshotHandle("mock-context-snapshot", handle.scope.key, state_hash)

    def restore(self, snapshot: SnapshotHandle) -> RestoreResult:
        if self.snapshot_restore_fails:
            return RestoreResult(ContextStatus.RESTORE_FAILED, "mock_restore_failed")
        return RestoreResult(ContextStatus.READY, "mock_restored", snapshot.state_hash)

    def dispose(self, handle: ContextHandle) -> DisposalResult:
        if self.cleanup_fails:
            return DisposalResult(ContextStatus.DISPOSAL_FAILED, "mock_cleanup_failed")
        return DisposalResult(ContextStatus.READY, "mock_disposed")


class MockSessionProvider(SessionProvider):
    def __init__(self, *, ready: bool = True) -> None:
        self.ready = ready
        self.revoked: list[str] = []

    def capabilities(self) -> set[str]:
        return {"synthetic_session"}

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle:
        from webpent.shared.target_context import IdentityContext

        identity = IdentityContext(
            request.identity_ref,
            request.subject_ref,
            owner_group=request.owner_group,
            metadata=request.metadata,
        )
        return SessionHandle(
            "mock-session-" + request.identity_ref,
            identity,
            ready=self.ready,
            reason="mock_session_not_ready" if not self.ready else "mock_session_ready",
        )

    def readiness(self, session: SessionHandle) -> ReadinessResult:
        if not self.ready:
            return ReadinessResult(ContextStatus.SESSION_UNAVAILABLE, ("mock_session_not_ready",))
        return ReadinessResult(ContextStatus.READY, ("mock_session_ready",))

    def revoke(self, session: SessionHandle) -> None:
        self.revoked.append(session.session_ref)


class MockFixtureProvider(FixtureProvider):
    def __init__(
        self,
        *,
        ready: bool = True,
        restore_fails: bool = False,
        cleanup_fails: bool = False,
    ):
        self.ready = ready
        self.restore_fails = restore_fails
        self.cleanup_fails = cleanup_fails
        self.disposed: list[str] = []

    def capabilities(self) -> set[str]:
        return {"disposable_fixture", "fixture_snapshot", "fixture_restore"}

    def describe(self, fixture_request: FixtureRequest) -> FixtureDescriptor:
        return FixtureDescriptor(
            fixture_request.fixture_ref,
            disposable=True,
            supports_snapshot=True,
            supports_restore=not self.restore_fails,
            state_hash=self._state_hash(fixture_request),
            metadata={"role": fixture_request.role.value},
        )

    def provision(self, fixture_request: FixtureRequest) -> FixtureHandle:
        return FixtureHandle(
            fixture_request.fixture_ref,
            self._state_hash(fixture_request),
            fixture_request.role,
            ready=self.ready,
            reason="mock_fixture_not_ready" if not self.ready else "mock_fixture_ready",
        )

    def snapshot(self, fixture: FixtureHandle) -> SnapshotHandle:
        return SnapshotHandle(
            "mock-fixture-snapshot-" + fixture.fixture_ref,
            fixture.state_hash,
            fixture.state_hash,
        )

    def restore(self, snapshot: SnapshotHandle) -> RestoreResult:
        if self.restore_fails:
            return RestoreResult(ContextStatus.RESTORE_FAILED, "mock_fixture_restore_failed")
        return RestoreResult(ContextStatus.READY, "mock_fixture_restored", snapshot.state_hash)

    def dispose(self, fixture: FixtureHandle) -> DisposalResult:
        self.disposed.append(fixture.fixture_ref)
        if self.cleanup_fails:
            return DisposalResult(ContextStatus.DISPOSAL_FAILED, "mock_fixture_cleanup_failed")
        return DisposalResult(ContextStatus.READY, "mock_fixture_disposed")

    @staticmethod
    def _state_hash(request: FixtureRequest) -> str:
        payload = {"fixture": request.fixture_ref, "role": request.role.value}
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def mock_scope(origin: str = "http://127.0.0.1:4200") -> TargetScope:
    return TargetScope("mock-target-spec", "mock-campaign", "mock-run", origin, "mock-scope")


__all__ = [
    "MockContextProvider",
    "MockFixtureProvider",
    "MockSessionProvider",
    "mock_scope",
]
