"""Bounded worker reliability and observability contracts.

This module is intentionally local and additive.  It records lifecycle metadata
without persisting task payloads or changing task outcomes.  A real broker DLQ
still requires independent deployment qualification; the capability report
therefore remains explicit about that boundary.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class RetryPolicy:
    """Conservative retry policy metadata for operator configuration."""

    max_retries: int = 2
    backoff_seconds: int = 30
    retryable_errors: tuple[str, ...] = (
        "TimeoutError",
        "ConnectionError",
        "SoftTimeLimitExceeded",
    )

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["retryable_errors"] = list(self.retryable_errors)
        return result


@dataclass(frozen=True)
class DeadLetterRecord:
    """Redacted metadata for a task that exhausted its bounded retry policy."""

    task_name: str
    task_id: str
    retries: int
    reason: str
    payload_sha256: str
    recorded_at: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class WorkerObservability:
    """Thread-safe, bounded in-process event projection for worker diagnostics."""

    def __init__(self, *, max_events: int = 512, retry_policy: RetryPolicy | None = None) -> None:
        if max_events < 1:
            raise ValueError("max_events must be positive")
        self.max_events = max_events
        self.retry_policy = retry_policy or RetryPolicy()
        self._events: list[dict[str, Any]] = []
        self._dead_letters: list[DeadLetterRecord] = []
        self._lock = threading.Lock()

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _payload_hash(payload: Any) -> str:
        material = repr(payload).encode("utf-8", errors="replace")
        return hashlib.sha256(material).hexdigest()

    def _append(self, collection: list[Any], value: Any) -> None:
        collection.append(value)
        overflow = len(collection) - self.max_events
        if overflow > 0:
            del collection[:overflow]

    def record(self, event: str, *, task_name: str, task_id: str, **metadata: Any) -> None:
        """Record redacted lifecycle metadata with a bounded retention window."""
        item = {
            "event": event,
            "task_name": task_name,
            "task_id": task_id,
            "recorded_at": self._timestamp(),
            **{
                key: value
                for key, value in metadata.items()
                if key not in {"payload", "args", "kwargs"}
            },
        }
        with self._lock:
            self._append(self._events, item)

    def record_dead_letter(
        self,
        *,
        task_name: str,
        task_id: str,
        retries: int,
        reason: str,
        payload: Any = None,
    ) -> DeadLetterRecord:
        """Record a redacted DLQ projection; never stores task arguments."""
        record = DeadLetterRecord(
            task_name=task_name,
            task_id=task_id,
            retries=max(0, int(retries)),
            reason=str(reason)[:240],
            payload_sha256=self._payload_hash(payload),
            recorded_at=self._timestamp(),
        )
        with self._lock:
            self._append(self._dead_letters, record)
        return record

    def snapshot(self) -> dict[str, Any]:
        """Return JSON-safe diagnostics without secrets or task payloads."""
        with self._lock:
            return {
                "retry_policy": self.retry_policy.as_dict(),
                "events": [dict(item) for item in self._events],
                "dead_letters": [item.as_dict() for item in self._dead_letters],
                "qualified_live_broker": False,
            }


DEFAULT_RETRY_POLICY = RetryPolicy()
WORKER_OBSERVABILITY = WorkerObservability(retry_policy=DEFAULT_RETRY_POLICY)


def celery_reliability_config() -> dict[str, Any]:
    """Return safe Celery settings; live DLQ routing remains deployment-specific."""
    return {
        "task_reject_on_worker_lost": True,
        "task_default_queue": "webpent",
        "task_routes": {"webpent.workers.pentest_worker.*": {"queue": "webpent"}},
        "webpent_retry_policy": DEFAULT_RETRY_POLICY.as_dict(),
        "webpent_dlq_queue": "webpent.dlq",
        "webpent_dlq_qualified": False,
    }


__all__ = [
    "DEFAULT_RETRY_POLICY",
    "DeadLetterRecord",
    "RetryPolicy",
    "WORKER_OBSERVABILITY",
    "WorkerObservability",
    "celery_reliability_config",
]
