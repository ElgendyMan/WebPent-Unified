# src/webpent/production/cross_process_leases.py
"""webpent.production.cross_process_leases — Track 12, item 2 (phase 2).

Roadmap contract (المسار 12، البند 2 — تشغيل متوازٍ):

    تأكيد فعالية صفوف العمال، ثم إضافة محدد تزامن مشترك ومراقبة تمنع
    استنزاف الموارد أو تجويع حملة.

Phase 1 (:mod:`webpent.production.concurrency_governor`) delivered the
process-wide FIFO-fair governor. This module delivers the documented
follow-up: **cross-process leases behind the same interface**, so several
worker processes (CLI + API server + Celery workers) share the SAME
global cap and the SAME per-target cap.

Design
------
``FileLeaseBackend`` is an all-or-nothing slot lender on a local runtime
directory. Every slot is one small file guarded by ``fcntl.flock``:

* Acquiring a slot = open + non-blocking exclusive flock + write a tiny
  metadata record (campaign, target, pid, acquired-at). The fd is held
  open by the process for the lease lifetime.
* Releasing = truncate the metadata and close the fd (the kernel drops
  the flock).
* Crash safety is inherited from the kernel: when a process dies the OS
  releases its flocks immediately, so there is NO stale-lease state to
  clean up — the very next acquirer of that slot file wins the lock and
  rewrites the metadata.
* All-or-nothing: per-target slots are acquired BEFORE global slots
  (fixed ordering prevents cross-campaign deadlock); on any failure
  everything already taken in this call is released again.
* A cap of 0 means "no slot files for that dimension" — unlimited,
  matching the phase-1 contract.

Failure semantics mirror phase 1 exactly: the backend is a RESOURCE
guard, not a scope/security boundary. On internal errors callers fail
OPEN for availability and record what happened; the change never goes
unlogged. (Scope and authorization live in ``webpent.scope`` and always
run first, independently of this module.)

Fairness note: strict cross-process FIFO would need a central arbiter
process. Within each process the governor keeps its strict FIFO queue;
ACROSS processes admission is best-effort with short randomized jitter,
which prevents lock-step thundering herds while bounded waits prevent
starvation in practice.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "FileLeaseBackend",
    "LeaseSnapshot",
]


@dataclass
class LeaseSnapshot:
    """Monitoring projection of the shared lease directory."""

    global_slots_total: int = 0
    global_slots_active: int = 0
    target_slots_total: int = 0
    target_slots_active: int = 0
    active_leases: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.active_leases is None:
            self.active_leases = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "global_slots_total": self.global_slots_total,
            "global_slots_active": self.global_slots_active,
            "target_slots_total": self.target_slots_total,
            "target_slots_active": self.target_slots_active,
            "active_leases": list(self.active_leases),
        }


class FileLeaseBackend:
    """Cross-process lease slots on a local runtime directory (flock)."""

    def __init__(
        self,
        lease_dir: str | os.PathLike[str],
        *,
        max_global: int = 2,
        max_per_target: int = 1,
        poll_interval: float = 0.25,
        max_poll_interval: float = 2.0,
    ) -> None:
        self._dir = Path(lease_dir).expanduser()
        self._max_global = max(0, int(max_global))
        self._max_per_target = max(0, int(max_per_target))
        self._poll_interval = max(0.05, float(poll_interval))
        self._max_poll_interval = max(self._poll_interval, float(max_poll_interval))
        self._held: dict[str, list[tuple[Path, int]]] = {}
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ------------------------------------------------------------------
    # properties
    # ------------------------------------------------------------------
    @property
    def lease_dir(self) -> Path:
        return self._dir

    @property
    def max_global(self) -> int:
        return self._max_global

    @property
    def max_per_target(self) -> int:
        return self._max_per_target

    # ------------------------------------------------------------------
    # slot paths
    # ------------------------------------------------------------------
    @staticmethod
    def _target_hash(target_key: str) -> str:
        return hashlib.sha256(target_key.encode("utf-8", "replace")).hexdigest()[:16]

    def _global_slot_path(self, index: int) -> Path:
        return self._dir / f"g{index}.lock"

    def _target_slot_path(self, target_key: str, index: int) -> Path:
        return self._dir / f"t{self._target_hash(target_key)}-{index}.lock"

    def _target_slot_paths(self, target_key: str) -> list[Path]:
        if self._max_per_target <= 0:
            return []
        return [
            self._target_slot_path(target_key, i) for i in range(self._max_per_target)
        ]

    def _global_slot_paths(self) -> list[Path]:
        if self._max_global <= 0:
            return []
        return [self._global_slot_path(i) for i in range(self._max_global)]

    # ------------------------------------------------------------------
    # low-level flock helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _try_flock(path: Path, meta: dict[str, Any]) -> int | None:
        """Open+flock a slot non-blocking; on success write meta, return fd."""
        try:
            fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return None
        try:
            import fcntl

            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (ImportError, OSError):
            os.close(fd)
            return None
        with suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps(meta, separators=(",", ":")).encode("utf-8"))
        return fd

    @staticmethod
    def _release_fd(fd: int) -> None:
        with suppress(OSError):
            os.ftruncate(fd, 0)
        with suppress(OSError):
            os.close(fd)

    @staticmethod
    def _peek(path: Path) -> dict[str, Any] | None:
        """Read the meta of a BUSY slot without disturbing the lease."""
        try:
            with open(path, "rb") as fh:
                raw = fh.read(1024)
            if not raw:
                return None
            data = json.loads(raw.decode("utf-8", "replace"))
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    # ------------------------------------------------------------------
    # backend contract used by ConcurrencyGovernor
    # ------------------------------------------------------------------
    def try_acquire_slots(self, campaign_id: str, target_key: str) -> bool:
        """All-or-nothing acquisition of ONE per-target slot + ONE global
        slot (a campaign consumes a single slot per dimension, exactly
        like the phase-1 governor counts)."""
        acquired: list[tuple[Path, int]] = []
        try:
            meta = {
                "campaign_id": campaign_id,
                "target_key": target_key,
                "pid": os.getpid(),
                "acquired_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            # Fixed ordering (target first, then global) prevents
            # cross-campaign deadlock.
            target_taken = False
            for path in self._target_slot_paths(target_key):
                fd = self._try_flock(path, meta)
                if fd is not None:
                    acquired.append((path, fd))
                    target_taken = True
                    break
            if self._max_per_target > 0 and not target_taken:
                raise SlotBusyError("per-target")
            global_taken = False
            for path in self._global_slot_paths():
                fd = self._try_flock(path, meta)
                if fd is not None:
                    acquired.append((path, fd))
                    global_taken = True
                    break
            if self._max_global > 0 and not global_taken:
                raise SlotBusyError("global")
        except SlotBusyError:
            for _path, fd in acquired:
                self._release_fd(fd)
            return False
        except OSError:
            # Environment error (unwritable dir, no flock, ...) — release
            # what we took and report failure; the caller decides the
            # fail-open/fail-closed policy and logs loudly.
            for _path, fd in acquired:
                self._release_fd(fd)
            raise
        self._held.setdefault(campaign_id, []).extend(acquired)
        return True

    def release_slots(self, campaign_id: str, target_key: str) -> None:
        """Release every slot this process holds for ``campaign_id``."""
        held = self._held.pop(campaign_id, None)
        if not held:
            return
        for _path, fd in held:
            self._release_fd(fd)

    def holds(self, campaign_id: str) -> bool:
        return bool(self._held.get(campaign_id))

    # ------------------------------------------------------------------
    # blocking acquire with jittered backoff (cross-process fairness)
    # ------------------------------------------------------------------
    def acquire_slots(
        self,
        campaign_id: str,
        target_key: str,
        *,
        timeout: float | None = 60.0,
    ) -> bool:
        """Poll-based bounded blocking acquisition across processes.

        Short randomized jitter avoids thundering-herd lock-step; the
        bounded wait prevents indefinite starvation. ``None`` waits
        forever (callers should usually pass a timeout).
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        interval = self._poll_interval
        while True:
            if self.try_acquire_slots(campaign_id, target_key):
                return True
            if deadline is not None and time.monotonic() >= deadline:
                return False
            jitter = interval * (0.5 + os.urandom(1)[0] / 255.0)
            time.sleep(min(jitter, self._max_poll_interval))
            interval = min(interval * 1.5, self._max_poll_interval)

    # ------------------------------------------------------------------
    # monitoring
    # ------------------------------------------------------------------
    def snapshot(self) -> LeaseSnapshot:
        """Scan the lease directory: free slots lock cleanly, busy slots
        expose their metadata. Totals reflect CAPACITY (max_global and
        max_per_target per distinct target seen), never mutating leases."""
        snap = LeaseSnapshot(active_leases=[])
        snap.global_slots_total = self._max_global
        active_global = 0
        for index in range(self._max_global):
            path = self._global_slot_path(index)
            fd = self._try_flock(path, {"probe": True})
            if fd is not None:
                self._release_fd(fd)
            else:
                active_global += 1
                meta = self._peek(path)
                if meta:
                    snap.active_leases.append({"slot": "global", **meta})
        snap.global_slots_active = active_global
        hashes = sorted(
            {p.name[1:].split("-")[0] for p in self._dir.glob("t*.lock")}
        )
        active_target = 0
        target_meta: dict[str, dict[str, Any]] = {}
        for digest in hashes:
            snap.target_slots_total += self._max_per_target
            for index in range(self._max_per_target):
                path = self._dir / f"t{digest}-{index}.lock"
                fd = self._try_flock(path, {"probe": True})
                if fd is not None:
                    self._release_fd(fd)
                else:
                    active_target += 1
                    meta = self._peek(path)
                    if meta:
                        target_meta.setdefault(digest, meta)
        snap.target_slots_active = active_target
        for meta in target_meta.values():
            snap.active_leases.append({"slot": "target", **meta})
        return snap


class SlotBusyError(Exception):
    """Internal: a required slot file is locked by another process."""


def make_lease_backend_from_settings() -> FileLeaseBackend | None:
    """Build the phase-2 backend when cross-process mode is enabled.

    Enabled only when ``WEBPENT_GOVERNOR_CROSS_PROCESS=true`` AND a lease
    directory is provided (``WEBPENT_GOVERNOR_LEASE_DIR``; a safe default
    under the platform temp dir is used when the value is empty).
    Any construction error is logged and returns ``None`` — the governor
    then keeps working in phase-1 (process-wide) mode, never losing
    availability because of an optional backend.
    """
    import tempfile

    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        if not bool(getattr(settings, "governor_cross_process", False)):
            return None
        lease_dir = str(getattr(settings, "governor_lease_dir", "") or "").strip()
        if not lease_dir:
            lease_dir = os.path.join(
                tempfile.gettempdir(), "webpent_governor_leases"
            )
        return FileLeaseBackend(
            lease_dir,
            max_global=int(getattr(settings, "max_concurrent_campaigns", 2)),
            max_per_target=int(getattr(settings, "max_concurrent_per_target", 1)),
        )
    except Exception:  # noqa: BLE001 — optional backend must never break startup
        logger.warning(
            "cross_process_leases: backend disabled (construction failed)",
            exc_info=True,
        )
        return None
