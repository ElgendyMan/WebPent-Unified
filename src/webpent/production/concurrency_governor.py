# src/webpent/production/concurrency_governor.py
"""webpent.production.concurrency_governor — Track 12, item 2 (phase 1).

Roadmap contract (المسار 12، البند 2 — تشغيل متوازٍ):

    تأكيد فعالية صفوف العمال، ثم إضافة محدد تزامن مشترك ومراقبة تمنع
    استنزاف الموارد أو تجويع حملة.

    ("Confirm the effectiveness of worker queues, then add a SHARED
    concurrency limiter and monitoring that prevent resource exhaustion
    or starving a campaign.")

This is the process-wide phase-1 governor:

* **Shared admission control** — a process-wide singleton arbitrates
  how many campaigns may run at once (global cap) and how many may run
  against the SAME normalized target (per-target cap). Campaigns are
  admitted at start and hold their slot until release/completion.
* **FIFO fairness (no starvation)** — waiters are served strictly in
  arrival order: a long-waiting campaign can never be jumped by newer
  ones, which is exactly the "تجويع حملة" (campaign starvation) the
  roadmap forbids.
* **Monitoring** — live counters (active/waiting per target, totals,
  admitted/rejected/timed-out) and a snapshot for dashboards.
* **Fail-safe defaults** — conservative caps from settings
  (``max_concurrent_campaigns=2``, ``max_concurrent_per_target=1``);
  a limit of 0 disables that specific limit; on any internal error the
  governor fails OPEN for admission (availability over strictness — the
  caps are a resource guard, not a scope/security boundary) but NEVER
  fails to record what happened.

Phase 2 (2026-10-28, v0.19.0): cross-process coordination arrived via
``webpent.production.cross_process_leases.FileLeaseBackend`` — shared
flock-based slot files on a runtime directory, dropped in behind THIS
same interface (constructor seam ``lease_backend``). When the backend
is present, admission requires BOTH the in-process caps AND a free set
of cross-process slots (global + per-target), and release frees both.
Fail-open on backend internal errors keeps the phase-1 availability
contract; every decision is still counted and logged.

Scope note: this governor is a RESOURCE guard. It is not, and must
never become, an authorization mechanism — scope/authorization checks
live in ``webpent.scope`` and the scope_enforcer and always run first.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

__all__ = [
    "AdmissionDenied",
    "AdmissionTicket",
    "ConcurrencyGovernor",
    "get_concurrency_governor",
    "reset_concurrency_governor",
]


class AdmissionDeniedError(RuntimeError):
    """Raised when admission is refused under explicit (blocking) mode."""


#: Backwards-compatible alias (kept for the documented public surface).
AdmissionDenied = AdmissionDeniedError


@dataclass
class AdmissionTicket:
    """Handle returned on admission; holds the slot until released."""

    campaign_id: str
    target_key: str
    admitted_at: float
    released: bool = field(default=False)


@dataclass
class GovernorSnapshot:
    """Monitoring projection (dashboard/doctor friendly)."""

    active_total: int = 0
    waiting_total: int = 0
    active_by_target: dict[str, int] = field(default_factory=dict)
    waiting_by_target: dict[str, int] = field(default_factory=dict)
    admitted_total: int = 0
    rejected_total: int = 0
    expired_total: int = 0
    cross_process: dict[str, Any] | None = field(default=None)

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "active_total": self.active_total,
            "waiting_total": self.waiting_total,
            "active_by_target": dict(self.active_by_target),
            "waiting_by_target": dict(self.waiting_by_target),
            "admitted_total": self.admitted_total,
            "rejected_total": self.rejected_total,
            "expired_total": self.expired_total,
        }
        if self.cross_process is not None:
            payload["cross_process"] = dict(self.cross_process)
        return payload


def _target_key(target_url: str) -> str:
    """Normalize a target URL to scheme+host (port-sensitive, path-free)."""
    try:
        parts = urlsplit(str(target_url or "").strip())
        host = (parts.hostname or "").lower()
        if not host:
            return "unknown"
        port = parts.port
        scheme = (parts.scheme or "https").lower()
        return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
    except ValueError:
        return "unknown"


@dataclass
class _Waiter:
    campaign_id: str
    target_key: str
    event: threading.Event
    granted: bool = False


class ConcurrencyGovernor:
    """FIFO-fair shared concurrency limiter with monitoring counters."""

    def __init__(
        self,
        *,
        max_global: int = 2,
        max_per_target: int = 1,
        lease_backend: Any | None = None,
    ) -> None:
        self._max_global = max(0, int(max_global))
        self._max_per_target = max(0, int(max_per_target))
        # Track 12 item 2 phase 2: optional cross-process lease backend
        # (FileLeaseBackend). None = phase-1 process-wide behavior only.
        self._lease_backend = lease_backend
        self._lock = threading.Lock()
        self._active: dict[str, str] = {}  # campaign_id -> target_key
        self._active_by_target: dict[str, set[str]] = {}
        self._wait_queue: deque[_Waiter] = deque()
        self._wait_by_target: dict[str, int] = {}
        self._admitted_total = 0
        self._rejected_total = 0
        self._expired_total = 0

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    @property
    def max_global(self) -> int:
        return self._max_global

    @property
    def max_per_target(self) -> int:
        return self._max_per_target

    @property
    def lease_backend(self) -> Any | None:
        """The cross-process lease backend (phase 2), when configured."""
        return self._lease_backend

    # ------------------------------------------------------------------
    # admission
    # ------------------------------------------------------------------
    def _would_admit_locked(self, campaign_id: str, target_key: str) -> tuple[bool, str]:
        # Global cap (0 = unlimited).
        if self._max_global > 0 and len(self._active) >= self._max_global:
            return False, f"global concurrency cap reached ({self._max_global})"
        # Per-target cap (0 = unlimited).
        if self._max_per_target > 0:
            same = self._active_by_target.get(target_key, set())
            if campaign_id not in same and len(same) >= self._max_per_target:
                return False, (
                    f"target concurrency cap reached for {target_key} "
                    f"({self._max_per_target})"
                )
        return True, ""

    def _admit_with_backend_locked(
        self, campaign_id: str, target_key: str
    ) -> tuple[AdmissionTicket | None, str]:
        """Combined admission (local caps first, then cross-process
        slots). Caller holds ``self._lock``. The backend uses only
        non-blocking flocks, so calling it under the local lock cannot
        deadlock. Local-cap check errors PROPAGATE so the public
        fail-open contract (``try_acquire``) stays intact; nothing is
        mutated unless the full admission commits."""
        ok, reason = self._would_admit_locked(campaign_id, target_key)
        if not ok:
            return None, reason
        backend = self._lease_backend
        if backend is not None:
            try:
                if not backend.try_acquire_slots(campaign_id, target_key):
                    return None, "cross-process cap reached (shared lease slots)"
            except Exception:  # noqa: BLE001 — resource guard, not a boundary
                logger.warning(
                    "governor: lease backend error for %s — failing open",
                    campaign_id,
                    exc_info=True,
                )
        return self._admit_locked(campaign_id, target_key), ""

    def try_acquire(self, campaign_id: str, target_url: str) -> AdmissionTicket | None:
        """Non-blocking admission attempt. None = not admitted now."""
        target_key = _target_key(target_url)
        try:
            with self._lock:
                ticket, reason = self._admit_with_backend_locked(campaign_id, target_key)
                if ticket is None:
                    self._rejected_total += 1
                    logger.info(
                        "governor: admission denied for %s (%s)", campaign_id, reason
                    )
                    return None
                return ticket
        except Exception:  # noqa: BLE001 — fail open on internal error
            logger.warning("governor: try_acquire error — failing open", exc_info=True)
            return AdmissionTicket(
                campaign_id=campaign_id, target_key=target_key, admitted_at=0.0
            )

    def acquire(
        self, campaign_id: str, target_url: str, *, timeout: float | None = None
    ) -> AdmissionTicket:
        """FIFO-fair blocking admission.

        Waiters are granted strictly in arrival order; a waiter never
        starves behind newer campaigns. ``timeout`` bounds the wait
        (None = wait forever); on timeout the waiter leaves the queue
        and raises :class:`AdmissionDenied`.

        Phase 2: when a cross-process lease backend is attached, the
        fair queue head must ALSO win shared lease slots. Because no
        cross-process event exists, a waiter blocked ONLY by the backend
        re-polls on a short interval (its queue-head position is kept,
        so local FIFO fairness is never lost).
        """
        import time

        target_key = _target_key(target_url)
        waiter = _Waiter(campaign_id=campaign_id, target_key=target_key, event=threading.Event())
        deadline = None if timeout is None else time.monotonic() + timeout
        reason = ""
        backend_poll = 0.25

        while True:
            backend_only_block = False
            with self._lock:
                # 1. Already admitted by _promote_waiters? Take the ticket.
                if campaign_id in self._active:
                    waiter.event.set()
                    ticket = AdmissionTicket(
                        campaign_id=campaign_id,
                        target_key=target_key,
                        admitted_at=time.monotonic(),
                    )
                    break
                ahead = self._waiting_ahead_locked(waiter)
                ok, reason = self._would_admit_locked(campaign_id, target_key)
                queue_head = not self._wait_queue or ahead == 0
                # 2. Local capacity available AND we are the fair queue
                # head (or the queue is empty) → try the cross-process
                # backend, then commit; detach first so the queue never
                # holds an active holder.
                if ok and queue_head:
                    backend = self._lease_backend
                    if backend is not None:
                        try:
                            if not backend.try_acquire_slots(campaign_id, target_key):
                                backend_only_block = True
                        except Exception:  # noqa: BLE001 — fail open
                            logger.warning(
                                "governor: lease backend error for %s — failing open",
                                campaign_id,
                                exc_info=True,
                            )
                    if not backend_only_block:
                        self._detach_waiter_locked(waiter)
                        ticket = self._admit_locked(campaign_id, target_key)
                        waiter.event.set()
                        break
                # 3. Otherwise enqueue (once) and wait for promotion.
                if waiter not in self._wait_queue:
                    self._wait_queue.append(waiter)
                    self._wait_by_target[target_key] = self._wait_by_target.get(target_key, 0) + 1
                    logger.info(
                        "governor: campaign %s waiting (%s) — position %d",
                        campaign_id,
                        reason or "fairness",
                        len(self._wait_queue),
                    )
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                self._remove_waiter(waiter)
                self._expired_total += 1
                raise AdmissionDenied(
                    f"admission timeout for {campaign_id} ({reason or 'cap'})"
                )
            # A waiter blocked only by cross-process slots gets no event
            # from another process's release — poll instead of sleeping
            # until the (possibly unbounded) deadline.
            wait_for = remaining
            if backend_only_block and (remaining is None or remaining > backend_poll):
                wait_for = backend_poll
            waiter.event.wait(timeout=wait_for)
            waiter.event.clear()

        return ticket

    def release(self, ticket: AdmissionTicket) -> None:
        """Release a slot and promote the next fair waiter(s)."""
        try:
            # Cross-process slots are freed FIRST so another worker can
            # take them as soon as this process lets go.
            backend = self._lease_backend
            if backend is not None:
                try:
                    backend.release_slots(ticket.campaign_id, ticket.target_key)
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "governor: lease release error for %s",
                        ticket.campaign_id,
                        exc_info=True,
                    )
            with self._lock:
                if ticket.released:
                    return
                ticket.released = True
                if self._active.pop(ticket.campaign_id, None) is not None:
                    target_set = self._active_by_target.get(ticket.target_key)
                    if target_set is not None:
                        target_set.discard(ticket.campaign_id)
                        if not target_set:
                            self._active_by_target.pop(ticket.target_key, None)
            self._promote_waiters()
        except Exception:  # noqa: BLE001
            logger.warning("governor: release error", exc_info=True)

    # ------------------------------------------------------------------
    # monitoring
    # ------------------------------------------------------------------
    def snapshot(self) -> GovernorSnapshot:
        with self._lock:
            snap = GovernorSnapshot(
                active_total=len(self._active),
                waiting_total=len(self._wait_queue),
                active_by_target={
                    key: len(ids) for key, ids in self._active_by_target.items()
                },
                waiting_by_target=dict(self._wait_by_target),
                admitted_total=self._admitted_total,
                rejected_total=self._rejected_total,
                expired_total=self._expired_total,
            )
        backend = self._lease_backend
        if backend is not None:
            try:
                snap.cross_process = backend.snapshot().as_dict()
            except Exception:  # noqa: BLE001 — monitoring must never raise
                logger.warning("governor: lease snapshot error", exc_info=True)
        return snap

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------
    def _waiting_ahead_locked(self, waiter: _Waiter) -> int:
        try:
            return self._wait_queue.index(waiter)
        except ValueError:
            return len(self._wait_queue)

    def _admit_locked(self, campaign_id: str, target_key: str) -> AdmissionTicket:
        import time

        self._active[campaign_id] = target_key
        self._active_by_target.setdefault(target_key, set()).add(campaign_id)
        self._admitted_total += 1
        logger.info(
            "governor: admitted campaign %s (active=%d, target=%s)",
            campaign_id,
            len(self._active),
            target_key,
        )
        return AdmissionTicket(
            campaign_id=campaign_id, target_key=target_key, admitted_at=time.monotonic()
        )

    def _remove_waiter(self, waiter: _Waiter) -> None:
        with self._lock:
            self._detach_waiter_locked(waiter)

    def _detach_waiter_locked(self, waiter: _Waiter) -> None:
        """Detach a waiter from the queue (caller holds the lock)."""
        try:
            self._wait_queue.remove(waiter)
        except ValueError:
            return
        count = self._wait_by_target.get(waiter.target_key, 0) - 1
        if count <= 0:
            self._wait_by_target.pop(waiter.target_key, None)
        else:
            self._wait_by_target[waiter.target_key] = count

    def _promote_waiters(self) -> None:
        """Grant slots to as many queue-head waiters as capacity allows.

        Phase 2: a promoted waiter must ALSO win the shared cross-process
        lease slots; if those are busy, promotion stops here (the waiter
        keeps its queue-head position and re-polls). Backend errors fail
        open exactly like the admission paths.
        """
        with self._lock:
            promoted: list[_Waiter] = []
            while self._wait_queue:
                head = self._wait_queue[0]
                ok, _reason = self._would_admit_locked(
                    head.campaign_id, head.target_key
                )
                if not ok:
                    break
                backend = self._lease_backend
                if backend is not None:
                    try:
                        if not backend.try_acquire_slots(
                            head.campaign_id, head.target_key
                        ):
                            break  # cross-process slots busy — stop promoting
                    except Exception:  # noqa: BLE001 — fail open
                        logger.warning(
                            "governor: lease backend error on promote — failing open",
                            exc_info=True,
                        )
                self._wait_queue.popleft()
                count = self._wait_by_target.get(head.target_key, 0) - 1
                if count <= 0:
                    self._wait_by_target.pop(head.target_key, None)
                else:
                    self._wait_by_target[head.target_key] = count
                self._admit_locked(head.campaign_id, head.target_key)
                promoted.append(head)
            for waiter in promoted:
                waiter.granted = True
                waiter.event.set()


_singleton: ConcurrencyGovernor | None = None
_singleton_lock = threading.Lock()


def get_concurrency_governor() -> ConcurrencyGovernor:
    """Process-wide governor from current settings (lazy singleton).

    When cross-process mode is enabled in settings, the phase-2 lease
    backend is attached so caps are shared across worker processes."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            from webpent.config.settings import get_settings
            from webpent.production.cross_process_leases import (
                make_lease_backend_from_settings,
            )

            settings = get_settings()
            _singleton = ConcurrencyGovernor(
                max_global=int(getattr(settings, "max_concurrent_campaigns", 2)),
                max_per_target=int(getattr(settings, "max_concurrent_per_target", 1)),
                lease_backend=make_lease_backend_from_settings(),
            )
        return _singleton


def reset_concurrency_governor() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None
