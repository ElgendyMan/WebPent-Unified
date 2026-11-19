"""Offline disposable fixture/session harness for the approved Option B lab.

The harness models synthetic ownership and session *descriptors* only.  It never
creates application accounts, logs in, generates tokens, stores cookies, injects
state into a target, or performs network I/O.  A target-live precondition must be
attested separately by a target-local adapter before a GET is permitted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from webpent.adapters.local_causal_lab.fixtures import (
    DisposableCanary,
    DisposableFixture,
    SyntheticIdentity,
)


@dataclass(frozen=True)
class OpaqueSessionDescriptor:
    """A non-authenticating offline descriptor, never a cookie or token."""

    session_id: str
    identity_id: str
    purpose: str
    credential_material_present: bool = False
    token_material_present: bool = False
    cookie_material_present: bool = False
    injected_into_target: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.session_id.startswith("session_"):
            errors.append("session_id_must_be_opaque")
        if not self.identity_id.startswith("test_"):
            errors.append("session_identity_must_be_opaque_test_id")
        if self.purpose != "offline_fixture_descriptor":
            errors.append("session_purpose_must_be_offline_descriptor")
        if (
            self.credential_material_present
            or self.token_material_present
            or self.cookie_material_present
        ):
            errors.append("session_auth_material_forbidden")
        if self.injected_into_target:
            errors.append("target_session_injection_not_permitted_by_harness")
        return tuple(errors)


@dataclass(frozen=True)
class OwnershipCanary:
    """Typed ownership relation with no raw object value or personal data."""

    object_id: str
    owner_identity_id: str
    requester_identity_id: str
    owner_canary_id: str
    negative_control_canary_id: str

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.object_id.startswith("object_"):
            errors.append("object_id_must_be_opaque")
        if not self.owner_identity_id.startswith("test_"):
            errors.append("owner_identity_must_be_opaque_test_id")
        if not self.requester_identity_id.startswith("test_"):
            errors.append("requester_identity_must_be_opaque_test_id")
        if not self.owner_canary_id.startswith("canary_"):
            errors.append("owner_canary_id_must_be_opaque")
        if not self.negative_control_canary_id.startswith("canary_"):
            errors.append("negative_control_canary_id_must_be_opaque")
        if self.owner_identity_id == self.requester_identity_id:
            errors.append("owner_and_requester_must_be_distinct")
        if self.owner_canary_id == self.negative_control_canary_id:
            errors.append("ownership_canaries_must_be_distinct")
        return tuple(errors)


@dataclass(frozen=True)
class HarnessSnapshot:
    """Redacted snapshot of fixture and descriptor metadata only."""

    snapshot_id: str
    target_id: str
    fixture_snapshot_id: str
    fixture_state_hash: str
    owner_session_id: str
    requester_session_id: str
    ownership_object_id: str
    ownership_relation_hash: str

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.snapshot_id.startswith("harness_snapshot_"):
            errors.append("harness_snapshot_id_must_be_opaque")
        if not self.target_id:
            errors.append("harness_target_required")
        if not self.fixture_snapshot_id.startswith("snapshot_"):
            errors.append("fixture_snapshot_id_invalid")
        if len(self.fixture_state_hash) != 64:
            errors.append("fixture_state_hash_must_be_sha256")
        if not self.owner_session_id.startswith("session_"):
            errors.append("owner_session_id_invalid")
        if not self.requester_session_id.startswith("session_"):
            errors.append("requester_session_id_invalid")
        if not self.ownership_object_id.startswith("object_"):
            errors.append("ownership_object_id_invalid")
        if len(self.ownership_relation_hash) != 64:
            errors.append("ownership_relation_hash_must_be_sha256")
        return tuple(errors)


@dataclass(frozen=True)
class DisposableSessionHarness:
    """An offline-only synthetic requester/owner harness."""

    target_id: str
    fixture: DisposableFixture
    ownership: OwnershipCanary
    owner_session: OpaqueSessionDescriptor
    requester_session: OpaqueSessionDescriptor
    target_fixture_injected: bool = False
    network_attempted: bool = False

    def validate(self) -> tuple[str, ...]:
        errors = list(self.fixture.validate())
        errors.extend(self.ownership.validate())
        errors.extend(self.owner_session.validate())
        errors.extend(self.requester_session.validate())
        if self.fixture.target_id != self.target_id:
            errors.append("fixture_target_mismatch")
        if self.owner_session.identity_id != self.ownership.owner_identity_id:
            errors.append("owner_session_identity_mismatch")
        if self.requester_session.identity_id != self.ownership.requester_identity_id:
            errors.append("requester_session_identity_mismatch")
        if self.target_fixture_injected:
            errors.append("target_fixture_injection_requires_separate_authorization")
        if self.network_attempted:
            errors.append("harness_must_not_attempt_network")
        return tuple(errors)

    def ownership_relation_hash(self) -> str:
        payload = {
            "object_id": self.ownership.object_id,
            "owner_identity_id": self.ownership.owner_identity_id,
            "requester_identity_id": self.ownership.requester_identity_id,
            "owner_canary_id": self.ownership.owner_canary_id,
            "negative_control_canary_id": self.ownership.negative_control_canary_id,
        }
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def snapshot(self) -> HarnessSnapshot:
        errors = self.validate()
        if errors:
            raise ValueError("harness_snapshot_blocked:" + ",".join(errors))
        fixture_snapshot = self.fixture.snapshot()
        snapshot_id = "harness_snapshot_" + sha256(
            f"{self.target_id}:{fixture_snapshot.snapshot_id}:{self.ownership_relation_hash()}".encode()
        ).hexdigest()[:24]
        snapshot = HarnessSnapshot(
            snapshot_id=snapshot_id,
            target_id=self.target_id,
            fixture_snapshot_id=fixture_snapshot.snapshot_id,
            fixture_state_hash=fixture_snapshot.state_hash,
            owner_session_id=self.owner_session.session_id,
            requester_session_id=self.requester_session.session_id,
            ownership_object_id=self.ownership.object_id,
            ownership_relation_hash=self.ownership_relation_hash(),
        )
        if snapshot.validate():
            raise ValueError("harness_snapshot_invalid")
        return snapshot

    def restore_from_snapshot(self, snapshot: HarnessSnapshot) -> DisposableSessionHarness:
        errors = snapshot.validate()
        if errors:
            raise ValueError("harness_restore_blocked:" + ",".join(errors))
        fixture_snapshot = self.fixture.snapshot()
        if fixture_snapshot.snapshot_id != snapshot.fixture_snapshot_id:
            raise ValueError("harness_restore_fixture_snapshot_mismatch")
        restored = build_offline_harness(self.target_id)
        restored_snapshot = restored.snapshot()
        if restored_snapshot != snapshot:
            raise ValueError("harness_restore_snapshot_mismatch")
        return restored

    def readiness(
        self,
        *,
        runtime_digest_verified: bool,
        network_scope_verified: bool,
    ) -> dict[str, Any]:
        validation_errors = list(self.validate())
        try:
            snapshot = self.snapshot()
            restored = self.restore_from_snapshot(snapshot)
            reset_verified = (
                restored.fixture.state_hash() == self.fixture.state_hash()
                and restored.ownership_relation_hash() == self.ownership_relation_hash()
            )
            snapshot_status = "verified" if reset_verified else "blocked"
        except ValueError as exc:
            snapshot = None
            reset_verified = False
            snapshot_status = "blocked"
            validation_errors.append(str(exc))
        identity_model_ready = not any(
            error.endswith("auth_material_forbidden")
            or error.endswith("session_injection_not_permitted_by_harness")
            for error in validation_errors
        ) and not validation_errors
        fixture_ready = snapshot_status == "verified"
        preconditions_ready = all(
            (
                fixture_ready,
                identity_model_ready,
                reset_verified,
                runtime_digest_verified,
                network_scope_verified,
            )
        )
        return {
            "preconditions_ready": preconditions_ready,
            "fixture_ready": fixture_ready,
            "identity_model_ready": identity_model_ready,
            "reset_verified": reset_verified,
            "runtime_digest_verified": runtime_digest_verified,
            "network_scope_verified": network_scope_verified,
            "status": "ready" if preconditions_ready else "blocked",
            "snapshot_status": snapshot_status,
            "snapshot_id": snapshot.snapshot_id if snapshot else None,
            "fixture_state_hash": snapshot.fixture_state_hash if snapshot else None,
            "network_attempted": self.network_attempted,
            "target_fixture_injected": self.target_fixture_injected,
            "errors": tuple(dict.fromkeys(validation_errors)),
        }


def build_offline_harness(target_id: str) -> DisposableSessionHarness:
    """Create deterministic opaque owner/requester descriptors for regression only."""
    fixture = DisposableFixture(
        fixture_id=f"fixture_session_harness_{target_id}",
        target_id=target_id,
        identities=(
            SyntheticIdentity("test_owner_a", "owner"),
            SyntheticIdentity("test_requester_b", "requester"),
        ),
        canaries=(
            DisposableCanary("canary_owner_object", "owner-only semantic marker"),
            DisposableCanary("canary_negative_control", "independent negative-control marker"),
        ),
    )
    ownership = OwnershipCanary(
        object_id="object_disposable_001",
        owner_identity_id="test_owner_a",
        requester_identity_id="test_requester_b",
        owner_canary_id="canary_owner_object",
        negative_control_canary_id="canary_negative_control",
    )
    harness = DisposableSessionHarness(
        target_id=target_id,
        fixture=fixture,
        ownership=ownership,
        owner_session=OpaqueSessionDescriptor(
            session_id="session_offline_owner_a",
            identity_id="test_owner_a",
            purpose="offline_fixture_descriptor",
        ),
        requester_session=OpaqueSessionDescriptor(
            session_id="session_offline_requester_b",
            identity_id="test_requester_b",
            purpose="offline_fixture_descriptor",
        ),
    )
    if harness.validate():
        raise ValueError("offline_harness_invalid:" + ",".join(harness.validate()))
    return harness


def harness_snapshot_restore_check(target_id: str) -> dict[str, Any]:
    harness = build_offline_harness(target_id)
    readiness = harness.readiness(
        runtime_digest_verified=True,
        network_scope_verified=True,
    )
    return readiness


__all__ = [
    "DisposableSessionHarness",
    "HarnessSnapshot",
    "OpaqueSessionDescriptor",
    "OwnershipCanary",
    "build_offline_harness",
    "harness_snapshot_restore_check",
]
