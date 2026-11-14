"""Generic target-context, session, fixture, and capability contracts.

This module is deliberately target-neutral. It owns typed metadata, policy, and
lifecycle sequencing; target adapters own transport and application semantics.
No credential, cookie, token, raw header, or response body is accepted here.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Protocol
from urllib.parse import urlsplit

from webpent.models.evidence import canonical_json

TARGET_CONTEXT_CONTRACT_VERSION = "target-context.v1"


class ContextStatus(str, Enum):
    READY = "ready"
    LAB_NOT_READY = "lab_not_ready"
    PRECONDITION_BLOCKED = "precondition_blocked"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    SESSION_UNAVAILABLE = "session_unavailable"
    FIXTURE_UNAVAILABLE = "fixture_unavailable"
    ORACLE_INCONCLUSIVE = "oracle_inconclusive"
    CONFIRMED = "confirmed"
    EXPIRED = "expired"
    RESTORE_FAILED = "restore_failed"
    DISPOSAL_FAILED = "disposal_failed"


class ContextRole(str, Enum):
    CANDIDATE = "candidate"
    NEGATIVE_CONTROL = "negative_control"
    BASELINE = "baseline"


_FORBIDDEN_CAPABILITIES = frozenset(
    {
        "credentials",
        "credential_use",
        "token_generation",
        "external_network",
        "external_callback",
        "auth_bypass",
        "state_mutation",
        "destructive_action",
    }
)


def _clean(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _scope_key(scope: TargetScope) -> str:
    return hashlib.sha256(canonical_json(scope.as_dict()).encode()).hexdigest()


@dataclass(frozen=True)
class TargetScope:
    """Authorization identity for one target, campaign, and run."""

    target_spec_id: str
    campaign_id: str
    run_id: str
    target_origin: str
    scope_digest: str = ""

    def __post_init__(self) -> None:
        for name in ("target_spec_id", "campaign_id", "run_id", "target_origin"):
            if not _clean(getattr(self, name)):
                raise ValueError(f"target_scope_{name}_required")
        parsed = urlsplit(self.target_origin)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("target_scope_origin_invalid")
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError("target_scope_origin_must_not_contain_path")

    @property
    def key(self) -> str:
        return _scope_key(self)

    def as_dict(self) -> dict[str, str]:
        return {
            "target_spec_id": _clean(self.target_spec_id),
            "campaign_id": _clean(self.campaign_id),
            "run_id": _clean(self.run_id),
            "target_origin": _clean(self.target_origin),
            "scope_digest": _clean(self.scope_digest, 240),
            "contract_version": TARGET_CONTEXT_CONTRACT_VERSION,
        }


@dataclass(frozen=True)
class IdentityContext:
    """Non-secret metadata for a disposable synthetic identity."""

    identity_ref: str
    subject_ref: str
    is_synthetic: bool = True
    owner_group: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _clean(self.identity_ref) or not _clean(self.subject_ref):
            raise ValueError("identity_context_reference_required")
        if not self.is_synthetic:
            raise ValueError("identity_context_real_identity_forbidden")
        forbidden = {"password", "secret", "token", "cookie", "authorization", "credential"}
        if any(str(key).lower() in forbidden for key in self.metadata):
            raise ValueError("identity_context_secret_metadata_forbidden")
        if len(self.metadata) > 12:
            raise ValueError("identity_context_metadata_limit_exceeded")

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity_ref": _clean(self.identity_ref),
            "subject_ref": _clean(self.subject_ref),
            "is_synthetic": True,
            "owner_group": _clean(self.owner_group),
            "metadata": {str(k)[:80]: _clean(v, 200) for k, v in self.metadata.items()},
        }


@dataclass(frozen=True)
class SessionHandle:
    """Opaque in-memory session handle; it never contains session material."""

    session_ref: str
    identity: IdentityContext
    in_memory_only: bool = True
    ready: bool = True
    reason: str = "ready"

    def __post_init__(self) -> None:
        if not _clean(self.session_ref):
            raise ValueError("session_handle_reference_required")
        if not self.in_memory_only:
            raise ValueError("session_handle_persistent_material_forbidden")

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_ref": _clean(self.session_ref),
            "identity": self.identity.as_dict(),
            "in_memory_only": True,
            "ready": self.ready,
            "reason": _clean(self.reason, 240),
        }


@dataclass(frozen=True)
class IdentityRequest:
    scope: TargetScope
    identity_ref: str
    subject_ref: str
    owner_group: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class FixtureRequest:
    scope: TargetScope
    fixture_ref: str
    role: ContextRole
    disposable: bool = True
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not _clean(self.fixture_ref):
            raise ValueError("fixture_request_reference_required")
        if not self.disposable:
            raise ValueError("persistent_fixture_forbidden")


@dataclass(frozen=True)
class FixtureDescriptor:
    fixture_ref: str
    disposable: bool
    supports_snapshot: bool
    supports_restore: bool
    state_hash: str = ""
    metadata: Mapping[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_ref": _clean(self.fixture_ref),
            "disposable": self.disposable,
            "supports_snapshot": self.supports_snapshot,
            "supports_restore": self.supports_restore,
            "state_hash": _clean(self.state_hash, 240),
            "metadata": {str(k)[:80]: _clean(v, 200) for k, v in self.metadata.items()},
        }


@dataclass(frozen=True)
class FixtureHandle:
    fixture_ref: str
    state_hash: str
    role: ContextRole
    disposable: bool = True
    ready: bool = True
    reason: str = "ready"

    def __post_init__(self) -> None:
        if not _clean(self.fixture_ref) or not _clean(self.state_hash):
            raise ValueError("fixture_handle_identity_required")
        if not self.disposable:
            raise ValueError("persistent_fixture_forbidden")

    def as_dict(self) -> dict[str, Any]:
        return {
            "fixture_ref": _clean(self.fixture_ref),
            "state_hash": _clean(self.state_hash, 240),
            "role": self.role.value,
            "disposable": True,
            "ready": self.ready,
            "reason": _clean(self.reason, 240),
        }


@dataclass(frozen=True)
class ContextRequest:
    scope: TargetScope
    role: ContextRole
    requested_capabilities: frozenset[str] = frozenset()
    identity_request: IdentityRequest | None = None
    fixture_request: FixtureRequest | None = None
    requires_session: bool = False
    requires_fixture: bool = False
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.requires_session and self.identity_request is None:
            raise ValueError("context_request_identity_required")
        if self.requires_fixture and self.fixture_request is None:
            raise ValueError("context_request_fixture_required")
        if self.role not in set(ContextRole):
            raise ValueError("context_request_role_invalid")


@dataclass(frozen=True)
class ReadinessResult:
    status: ContextStatus
    reasons: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()
    state_hash: str = ""

    @property
    def ready(self) -> bool:
        return self.status == ContextStatus.READY

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "reasons": list(self.reasons),
            "evidence_refs": list(self.evidence_refs),
            "state_hash": _clean(self.state_hash, 240),
        }


@dataclass
class CapabilityLease:
    lease_ref: str
    scope_key: str
    capabilities: frozenset[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False

    @property
    def active(self) -> bool:
        return not self.revoked and datetime.now(UTC) < self.expires_at

    def permits(self, capability: str, scope_key: str) -> bool:
        return self.active and self.scope_key == scope_key and capability in self.capabilities

    def as_dict(self) -> dict[str, Any]:
        return {
            "lease_ref": _clean(self.lease_ref),
            "scope_key": _clean(self.scope_key, 240),
            "capabilities": sorted(self.capabilities),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "revoked": self.revoked,
            "active": self.active,
        }


@dataclass(frozen=True)
class ContextHandle:
    handle_ref: str
    scope: TargetScope
    lease: CapabilityLease
    status: ContextStatus = ContextStatus.READY
    reason: str = "ready"

    @property
    def ready(self) -> bool:
        return self.status == ContextStatus.READY and self.lease.active

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle_ref": _clean(self.handle_ref),
            "scope": self.scope.as_dict(),
            "lease": self.lease.as_dict(),
            "status": self.status.value,
            "reason": _clean(self.reason, 240),
        }


@dataclass(frozen=True)
class ExecutionContext:
    handle: ContextHandle
    role: ContextRole
    identity: IdentityContext | None = None
    session: SessionHandle | None = None
    fixture: FixtureHandle | None = None
    readiness: ReadinessResult = field(
        default_factory=lambda: ReadinessResult(ContextStatus.READY)
    )

    @property
    def scope(self) -> TargetScope:
        return self.handle.scope

    def as_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle.as_dict(),
            "role": self.role.value,
            "identity": self.identity.as_dict() if self.identity else None,
            "session": self.session.as_dict() if self.session else None,
            "fixture": self.fixture.as_dict() if self.fixture else None,
            "readiness": self.readiness.as_dict(),
        }


@dataclass(frozen=True)
class SnapshotHandle:
    snapshot_ref: str
    scope_key: str
    state_hash: str
    disposable: bool = True

    def __post_init__(self) -> None:
        if (
            not _clean(self.snapshot_ref)
            or not _clean(self.scope_key)
            or not _clean(self.state_hash)
        ):
            raise ValueError("snapshot_handle_identity_required")
        if not self.disposable:
            raise ValueError("persistent_snapshot_forbidden")


@dataclass(frozen=True)
class StateSnapshot:
    snapshot_ref: str
    scope_key: str
    context_snapshot: SnapshotHandle
    fixture_snapshot: SnapshotHandle | None
    state_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "snapshot_ref": _clean(self.snapshot_ref),
            "scope_key": _clean(self.scope_key, 240),
            "context_snapshot_ref": _clean(self.context_snapshot.snapshot_ref),
            "fixture_snapshot_ref": (
                _clean(self.fixture_snapshot.snapshot_ref) if self.fixture_snapshot else None
            ),
            "state_hash": _clean(self.state_hash, 240),
        }


@dataclass(frozen=True)
class RestoreResult:
    status: ContextStatus
    reason: str = "restored"
    state_hash: str = ""


@dataclass(frozen=True)
class DisposalResult:
    status: ContextStatus
    reason: str = "disposed"


class ContextProvider(Protocol):
    def capabilities(self) -> set[str]: ...

    def prepare(self, request: ContextRequest) -> ContextHandle: ...

    def readiness(self, handle: ContextHandle) -> ReadinessResult: ...

    def snapshot(self, handle: ContextHandle) -> SnapshotHandle: ...

    def restore(self, snapshot: SnapshotHandle) -> RestoreResult: ...

    def dispose(self, handle: ContextHandle) -> DisposalResult: ...


class SessionProvider(Protocol):
    def capabilities(self) -> set[str]: ...

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle: ...

    def readiness(self, session: SessionHandle) -> ReadinessResult: ...

    def revoke(self, session: SessionHandle) -> None: ...


class FixtureProvider(Protocol):
    def capabilities(self) -> set[str]: ...

    def describe(self, fixture_request: FixtureRequest) -> FixtureDescriptor: ...

    def provision(self, fixture_request: FixtureRequest) -> FixtureHandle: ...

    def snapshot(self, fixture: FixtureHandle) -> SnapshotHandle: ...

    def restore(self, snapshot: SnapshotHandle) -> RestoreResult: ...

    def dispose(self, fixture: FixtureHandle) -> DisposalResult: ...


class CapabilityPolicy:
    """Fail-closed capability lease issuer with no default permissions."""

    def __init__(
        self, *, allowed_capabilities: Sequence[str] = (), lease_seconds: int = 300
    ) -> None:
        self.allowed_capabilities = frozenset(_clean(item, 80) for item in allowed_capabilities)
        self.lease_seconds = max(1, min(3600, int(lease_seconds)))
        self._leases: dict[str, CapabilityLease] = {}
        self._lock = threading.Lock()

    def issue(self, scope: TargetScope, requested: Sequence[str]) -> CapabilityLease | None:
        capabilities = frozenset(_clean(item, 80) for item in requested if _clean(item, 80))
        if not capabilities or not capabilities.issubset(self.allowed_capabilities):
            return None
        if capabilities.intersection(_FORBIDDEN_CAPABILITIES):
            return None
        now = datetime.now(UTC)
        lease = CapabilityLease(
            lease_ref="lease-" + uuid.uuid4().hex,
            scope_key=scope.key,
            capabilities=capabilities,
            issued_at=now,
            expires_at=now + timedelta(seconds=self.lease_seconds),
        )
        with self._lock:
            self._leases[lease.lease_ref] = lease
        return lease

    def revoke(self, lease: CapabilityLease) -> None:
        with self._lock:
            current = self._leases.get(lease.lease_ref)
            if current is not None:
                current.revoked = True
            lease.revoked = True


class ContextCoordinator:
    """Orchestrates generic context/session/fixture lifecycle and cleanup."""

    def __init__(
        self,
        provider: ContextProvider,
        *,
        policy: CapabilityPolicy,
        session_provider: SessionProvider | None = None,
        fixture_provider: FixtureProvider | None = None,
    ) -> None:
        self.provider = provider
        self.policy = policy
        self.session_provider = session_provider
        self.fixture_provider = fixture_provider

    def acquire(
        self, request: ContextRequest
    ) -> tuple[ContextStatus, str, ExecutionContext | None]:
        lease = self.policy.issue(request.scope, tuple(request.requested_capabilities))
        if lease is None:
            return ContextStatus.CAPABILITY_UNAVAILABLE, "capability_lease_denied", None
        if not request.requested_capabilities.issubset(self.provider.capabilities()):
            self.policy.revoke(lease)
            return ContextStatus.CAPABILITY_UNAVAILABLE, "context_capability_unavailable", None
        prepared_handle = self.provider.prepare(request)
        handle = replace(prepared_handle, lease=lease)
        if not handle.ready:
            self.policy.revoke(lease)
            return handle.status, handle.reason, None
        readiness = self.provider.readiness(handle)
        if not readiness.ready:
            self.policy.revoke(lease)
            return readiness.status, ",".join(readiness.reasons) or "context_not_ready", None

        identity = request.identity_request
        identity_context = None
        session = None
        if request.requires_session:
            if self.session_provider is None:
                self.policy.revoke(lease)
                return ContextStatus.SESSION_UNAVAILABLE, "session_provider_unavailable", None
            if "synthetic_session" not in self.session_provider.capabilities():
                self.policy.revoke(lease)
                return (
                    ContextStatus.SESSION_UNAVAILABLE,
                    "synthetic_session_capability_unavailable",
                    None,
                )
            session = self.session_provider.create_synthetic_context(identity)  # type: ignore[arg-type]
            if not session.ready:
                self.policy.revoke(lease)
                return ContextStatus.SESSION_UNAVAILABLE, session.reason, None
            session_ready = self.session_provider.readiness(session)
            if not session_ready.ready:
                self.policy.revoke(lease)
                return ContextStatus.SESSION_UNAVAILABLE, ",".join(session_ready.reasons), None
            identity_context = session.identity

        fixture = None
        if request.requires_fixture:
            if self.fixture_provider is None:
                if session is not None and self.session_provider is not None:
                    self.session_provider.revoke(session)
                self.policy.revoke(lease)
                return ContextStatus.FIXTURE_UNAVAILABLE, "fixture_provider_unavailable", None
            if "disposable_fixture" not in self.fixture_provider.capabilities():
                if session is not None and self.session_provider is not None:
                    self.session_provider.revoke(session)
                self.policy.revoke(lease)
                return (
                    ContextStatus.FIXTURE_UNAVAILABLE,
                    "disposable_fixture_capability_unavailable",
                    None,
                )
            fixture = self.fixture_provider.provision(request.fixture_request)  # type: ignore[arg-type]
            if not fixture.ready:
                if session is not None and self.session_provider is not None:
                    self.session_provider.revoke(session)
                self.policy.revoke(lease)
                return ContextStatus.FIXTURE_UNAVAILABLE, fixture.reason, None

        context = ExecutionContext(
            handle=handle,
            role=request.role,
            identity=identity_context,
            session=session,
            fixture=fixture,
            readiness=readiness,
        )
        return ContextStatus.READY, "ready", context

    def snapshot(self, context: ExecutionContext) -> StateSnapshot:
        context_snapshot = self.provider.snapshot(context.handle)
        fixture_snapshot = None
        if context.fixture is not None and self.fixture_provider is not None:
            fixture_snapshot = self.fixture_provider.snapshot(context.fixture)
        state_hash = hashlib.sha256(
            canonical_json(
                {
                    "context": context_snapshot.state_hash,
                    "fixture": fixture_snapshot.state_hash if fixture_snapshot else "",
                }
            ).encode()
        ).hexdigest()
        return StateSnapshot(
            snapshot_ref="snapshot-" + uuid.uuid4().hex,
            scope_key=context.scope.key,
            context_snapshot=context_snapshot,
            fixture_snapshot=fixture_snapshot,
            state_hash=state_hash,
        )

    def restore(self, context: ExecutionContext, snapshot: StateSnapshot) -> RestoreResult:
        if snapshot.scope_key != context.scope.key or not context.handle.lease.active:
            return RestoreResult(ContextStatus.EXPIRED, "snapshot_scope_or_lease_invalid")
        if snapshot.fixture_snapshot is not None and self.fixture_provider is not None:
            fixture_result = self.fixture_provider.restore(snapshot.fixture_snapshot)
            if fixture_result.status != ContextStatus.READY:
                return RestoreResult(ContextStatus.RESTORE_FAILED, fixture_result.reason)
        return self.provider.restore(snapshot.context_snapshot)

    def dispose(self, context: ExecutionContext) -> DisposalResult:
        failures: list[str] = []
        if context.fixture is not None and self.fixture_provider is not None:
            result = self.fixture_provider.dispose(context.fixture)
            if result.status != ContextStatus.READY:
                failures.append(result.reason)
        if context.session is not None and self.session_provider is not None:
            try:
                self.session_provider.revoke(context.session)
            except Exception:
                failures.append("session_revoke_failed")
        result = self.provider.dispose(context.handle)
        if result.status != ContextStatus.READY:
            failures.append(result.reason)
        self.policy.revoke(context.handle.lease)
        if failures:
            return DisposalResult(ContextStatus.DISPOSAL_FAILED, ",".join(failures)[:240])
        return DisposalResult(ContextStatus.READY, "disposed")


__all__ = [
    "CapabilityLease",
    "CapabilityPolicy",
    "ContextCoordinator",
    "ContextHandle",
    "ContextProvider",
    "ContextRequest",
    "ContextRole",
    "ContextStatus",
    "DisposalResult",
    "ExecutionContext",
    "FixtureDescriptor",
    "FixtureHandle",
    "FixtureProvider",
    "FixtureRequest",
    "IdentityContext",
    "IdentityRequest",
    "ReadinessResult",
    "SessionHandle",
    "SessionProvider",
    "SnapshotHandle",
    "StateSnapshot",
    "TargetScope",
    "TARGET_CONTEXT_CONTRACT_VERSION",
]
