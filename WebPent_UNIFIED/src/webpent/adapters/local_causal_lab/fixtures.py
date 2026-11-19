"""Non-networking disposable fixture model for the Option B readiness gate.

This is test infrastructure only.  It never creates an application account,
performs login, calls a reset endpoint, or stores a raw canary/body.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any


@dataclass(frozen=True)
class SyntheticIdentity:
    identity_id: str
    role: str
    credential_material_present: bool = False
    session_material_present: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.identity_id.startswith("test_"):
            errors.append("identity_must_be_opaque_test_id")
        if self.credential_material_present or self.session_material_present:
            errors.append("credential_or_session_material_forbidden")
        return tuple(errors)


@dataclass(frozen=True)
class DisposableCanary:
    canary_id: str
    semantic_label: str
    raw_value_persisted: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.canary_id.startswith("canary_"):
            errors.append("canary_id_must_be_opaque")
        if not self.semantic_label:
            errors.append("canary_semantic_label_required")
        if self.raw_value_persisted:
            errors.append("raw_canary_persistence_forbidden")
        return tuple(errors)


@dataclass(frozen=True)
class FixtureSnapshot:
    """Redacted offline snapshot; it contains typed metadata, never raw values."""

    snapshot_id: str
    fixture_id: str
    target_id: str
    state_hash: str
    identity_roles: tuple[tuple[str, str], ...]
    canary_labels: tuple[tuple[str, str], ...]

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.snapshot_id.startswith("snapshot_"):
            errors.append("snapshot_id_must_be_opaque")
        if not self.fixture_id.startswith("fixture_"):
            errors.append("snapshot_fixture_id_invalid")
        if not self.target_id:
            errors.append("snapshot_target_required")
        if len(self.state_hash) != 64:
            errors.append("snapshot_state_hash_must_be_sha256")
        if not self.identity_roles or not self.canary_labels:
            errors.append("snapshot_typed_state_required")
        for identity_id, role in self.identity_roles:
            if not identity_id.startswith("test_") or not role:
                errors.append("snapshot_identity_metadata_invalid")
        for canary_id, label in self.canary_labels:
            if not canary_id.startswith("canary_") or not label:
                errors.append("snapshot_canary_metadata_invalid")
        return tuple(errors)


@dataclass(frozen=True)
class DisposableFixture:
    fixture_id: str
    target_id: str
    identities: tuple[SyntheticIdentity, ...]
    canaries: tuple[DisposableCanary, ...]
    application_mutation_performed: bool = False
    application_reset_endpoint_called: bool = False
    raw_values_persisted: bool = False

    def validate(self) -> tuple[str, ...]:
        errors: list[str] = []
        if not self.fixture_id.startswith("fixture_"):
            errors.append("fixture_id_must_be_disposable")
        if not self.target_id:
            errors.append("fixture_target_required")
        if not self.identities or not self.canaries:
            errors.append("fixture_identity_and_canary_required")
        for item in (*self.identities, *self.canaries):
            errors.extend(item.validate())
        if self.application_mutation_performed:
            errors.append("application_mutation_must_remain_false")
        if self.application_reset_endpoint_called:
            errors.append("application_reset_endpoint_must_remain_false")
        if self.raw_values_persisted:
            errors.append("raw_values_persistence_must_remain_false")
        return tuple(errors)

    def state_hash(self) -> str:
        """Hash typed fixture metadata, never raw canary or credential material."""
        payload = {
            "fixture_id": self.fixture_id,
            "target_id": self.target_id,
            "identities": [(item.identity_id, item.role) for item in self.identities],
            "canaries": [(item.canary_id, item.semantic_label) for item in self.canaries],
            "application_mutation_performed": self.application_mutation_performed,
            "application_reset_endpoint_called": self.application_reset_endpoint_called,
            "raw_values_persisted": self.raw_values_persisted,
        }
        return sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def snapshot(self) -> FixtureSnapshot:
        """Create an offline redacted snapshot without serializing raw fixture data."""
        errors = self.validate()
        if errors:
            raise ValueError("fixture_snapshot_blocked:" + ",".join(errors))
        identity_roles = tuple((item.identity_id, item.role) for item in self.identities)
        canary_labels = tuple((item.canary_id, item.semantic_label) for item in self.canaries)
        state_hash = self.state_hash()
        snapshot_id = "snapshot_" + sha256(
            f"{self.fixture_id}:{state_hash}".encode()
        ).hexdigest()[:24]
        return FixtureSnapshot(
            snapshot_id=snapshot_id,
            fixture_id=self.fixture_id,
            target_id=self.target_id,
            state_hash=state_hash,
            identity_roles=identity_roles,
            canary_labels=canary_labels,
        )

    @classmethod
    def restore_from_snapshot(cls, snapshot: FixtureSnapshot) -> DisposableFixture:
        """Restore a fresh in-memory fixture from typed snapshot metadata only."""
        errors = snapshot.validate()
        if errors:
            raise ValueError("fixture_restore_blocked:" + ",".join(errors))
        fixture = cls(
            fixture_id=snapshot.fixture_id,
            target_id=snapshot.target_id,
            identities=tuple(
                SyntheticIdentity(identity_id, role)
                for identity_id, role in snapshot.identity_roles
            ),
            canaries=tuple(
                DisposableCanary(canary_id, label)
                for canary_id, label in snapshot.canary_labels
            ),
        )
        if fixture.validate() or fixture.state_hash() != snapshot.state_hash:
            raise ValueError("fixture_restore_hash_mismatch")
        return fixture

    def snapshot_restore_check(self) -> dict[str, Any]:
        """Verify offline restore equality and prove no application reset occurred."""
        snapshot = self.snapshot()
        restored = self.restore_from_snapshot(snapshot)
        restored_hash = restored.state_hash()
        return {
            "status": "verified" if restored_hash == snapshot.state_hash else "blocked",
            "snapshot_id": snapshot.snapshot_id,
            "before_state_hash": snapshot.state_hash,
            "restored_state_hash": restored_hash,
            "state_hash_equal": restored_hash == snapshot.state_hash,
            "network_attempted": False,
            "application_reset_endpoint_called": False,
            "application_mutation_performed": False,
            "raw_values_persisted": False,
        }

    def reset_check(self, before_hash: str) -> dict[str, object]:
        after_hash = self.state_hash()
        validation_errors = self.validate()
        return {
            "status": "verified"
            if before_hash == after_hash and not validation_errors
            else "blocked",
            "before_state_hash": before_hash,
            "after_state_hash": after_hash,
            "state_hash_equal": before_hash == after_hash,
            "validation_errors": validation_errors,
            "application_reset_endpoint_called": self.application_reset_endpoint_called,
            "application_mutation_performed": self.application_mutation_performed,
            "raw_values_persisted": self.raw_values_persisted,
        }


def build_regression_fixture(target_id: str) -> DisposableFixture:
    """Build a local typed fixture for contract regression, not target evidence."""
    fixture = DisposableFixture(
        fixture_id=f"fixture_option_b_{target_id}",
        target_id=target_id,
        identities=(
            SyntheticIdentity("test_subject_a", "owner"),
            SyntheticIdentity("test_subject_b", "requester"),
        ),
        canaries=(
            DisposableCanary("canary_owner_object", "owner-specific semantic marker"),
            DisposableCanary("canary_negative_control", "negative-control semantic marker"),
        ),
    )
    if fixture.validate():
        raise ValueError("regression_fixture_invalid")
    return fixture
