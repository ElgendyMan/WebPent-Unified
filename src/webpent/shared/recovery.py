"""Fail-closed checkpoint, idempotency, and stop-state primitives.

The module is storage-agnostic and intentionally does not start workers,
threads, polling, or network services.  A deployment may persist these records
through an existing store, but every resume decision remains identity-bound.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive


class StopState(str, Enum):
    ACTIVE = "active"
    STOP_REQUESTED = "stop_requested"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class CheckpointRecord:
    checkpoint_id: str
    run_id: str
    engagement_id: str
    target_package_digest: str
    scope_digest: str
    policy_digest: str
    last_completed_action: str
    completed_action_signatures: tuple[str, ...] = ()
    stop_state: StopState = StopState.ACTIVE
    sequence: int = 0
    checkpoint_digest: str = ""

    def unsigned(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id[:160],
            "run_id": self.run_id[:160],
            "engagement_id": self.engagement_id[:160],
            "target_package_digest": self.target_package_digest[:240],
            "scope_digest": self.scope_digest[:240],
            "policy_digest": self.policy_digest[:240],
            "last_completed_action": self.last_completed_action[:160],
            "completed_action_signatures": list(self.completed_action_signatures[:256]),
            "stop_state": self.stop_state.value,
            "sequence": max(0, int(self.sequence)),
        }

    def seal(self) -> CheckpointRecord:
        digest = hashlib.sha256(canonical_json(self.unsigned()).encode()).hexdigest()
        return replace(self, checkpoint_digest=digest)

    def verify(self) -> bool:
        return (
            bool(self.checkpoint_digest) and self.checkpoint_digest == self.seal().checkpoint_digest
        )

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {**self.unsigned(), "checkpoint_digest": self.checkpoint_digest}
        )
        return clean if isinstance(clean, dict) else {"checkpoint_digest": self.checkpoint_digest}


@dataclass(frozen=True)
class ResumeDecision:
    allowed: bool
    reasons: tuple[str, ...]


class CheckpointLedger:
    """Bounded in-memory ledger suitable for an existing durable backend."""

    def __init__(self, *, max_records: int = 512) -> None:
        self.max_records = max(1, min(5000, int(max_records)))
        self._records: list[CheckpointRecord] = []

    def append(self, record: CheckpointRecord) -> CheckpointRecord:
        sealed = record.seal()
        self._records.append(sealed)
        if len(self._records) > self.max_records:
            del self._records[: len(self._records) - self.max_records]
        return sealed

    def latest(self, *, engagement_id: str, run_id: str = "") -> CheckpointRecord | None:
        for record in reversed(self._records):
            if record.engagement_id != engagement_id:
                continue
            if run_id and record.run_id != run_id:
                continue
            return record
        return None

    def snapshot(self) -> tuple[dict[str, Any], ...]:
        return tuple(record.as_dict() for record in self._records)

    @staticmethod
    def resume(
        record: CheckpointRecord,
        *,
        engagement_id: str,
        target_package_digest: str,
        scope_digest: str,
        policy_digest: str,
    ) -> ResumeDecision:
        reasons: list[str] = []
        if not record.verify():
            reasons.append("checkpoint:seal_invalid")
        expected = {
            "engagement_id": engagement_id,
            "target_package_digest": target_package_digest,
            "scope_digest": scope_digest,
            "policy_digest": policy_digest,
        }
        actual = {
            "engagement_id": record.engagement_id,
            "target_package_digest": record.target_package_digest,
            "scope_digest": record.scope_digest,
            "policy_digest": record.policy_digest,
        }
        for field_name, value in expected.items():
            if not str(value).strip() or value != actual[field_name]:
                reasons.append(f"checkpoint:{field_name}_mismatch")
        if record.stop_state in {StopState.STOPPED, StopState.COMPLETED, StopState.FAILED}:
            reasons.append(f"checkpoint:terminal_state:{record.stop_state.value}")
        return ResumeDecision(allowed=not reasons, reasons=tuple(reasons))


class IdempotencyLedger:
    """Explicit claim/complete ledger; completed actions cannot be replayed."""

    def __init__(self, *, max_keys: int = 4096) -> None:
        self.max_keys = max(1, min(20000, int(max_keys)))
        self._claimed: set[str] = set()
        self._completed: list[str] = []

    def claim(self, signature: str) -> bool:
        key = str(signature).strip()[:240]
        if not key or key in self._claimed or key in self._completed:
            return False
        self._claimed.add(key)
        return True

    def complete(self, signature: str) -> bool:
        key = str(signature).strip()[:240]
        if key not in self._claimed or key in self._completed:
            return False
        self._completed.append(key)
        self._claimed.discard(key)
        if len(self._completed) > self.max_keys:
            del self._completed[: len(self._completed) - self.max_keys]
        return True

    def completed(self) -> tuple[str, ...]:
        return tuple(self._completed)


class StopStateMachine:
    _allowed: dict[StopState, frozenset[StopState]] = {
        StopState.ACTIVE: frozenset(
            {StopState.STOP_REQUESTED, StopState.COMPLETED, StopState.FAILED}
        ),
        StopState.STOP_REQUESTED: frozenset({StopState.STOPPED}),
        StopState.STOPPED: frozenset(),
        StopState.COMPLETED: frozenset(),
        StopState.FAILED: frozenset(),
    }

    def __init__(self, state: StopState = StopState.ACTIVE) -> None:
        self.state = state

    def transition(self, next_state: StopState) -> bool:
        if next_state not in self._allowed[self.state]:
            return False
        self.state = next_state
        return True

    def request_stop(self) -> bool:
        return self.transition(StopState.STOP_REQUESTED)

    def should_execute(self) -> bool:
        return self.state is StopState.ACTIVE


__all__ = [
    "CheckpointLedger",
    "CheckpointRecord",
    "IdempotencyLedger",
    "ResumeDecision",
    "StopState",
    "StopStateMachine",
]
