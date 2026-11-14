# src/webpent/shared/rate_governor.py
"""webpent.shared.rate_governor

V7 Sprint 2.7 — Request-Rate Governor for concurrent-request test code.

Provides a hard cap on simultaneous in-flight requests per target and
an automatic abort-and-backoff if the target's error rate crosses a
threshold mid-burst. This protects against accidentally DoS-ing a
real bug-bounty target, which is a program-rules violation, not just
bad practice.

Per Principle 1 (deterministic gates over LLM judgment): the cap and
the abort threshold are plain Python ``if`` statements. The LLM never
decides whether to back off — the governor does.

Per Principle 2 (fail-closed, not fail-open): if the governor itself
errors (lock contention, counter overflow), it defaults to ABORT
(stop the burst) rather than proceeding unchecked.

Usage::

    from webpent.shared.rate_governor import RequestRateGovernor

    governor = RequestRateGovernor(
        max_concurrent=20,
        error_rate_threshold=0.3,  # abort if 30% of responses are 5xx
    )

    # Inside a concurrent burst:
    with governor.acquire(target_host) as permit:
        if permit.aborted:
            logger.warning("Burst aborted: %s", permit.reason)
            break
        response = make_request(...)
        permit.record_response(response.status_code)
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


def _kill_switch_abort() -> bool:
    """r6c wiring: the kill switch gates every governor permit.

    Flag-off semantics are unchanged (the switch is ignored). With the flag
    on, an ENGAGED switch aborts the permit BEFORE any host slot is consumed,
    so aborted acquires leave the host state untouched.
    """
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_kill_switch:
            return False
        from webpent.safety import kill_switch

        return bool(kill_switch.engaged())
    except Exception:  # noqa: BLE001 — fail closed toward abort
        return False


@dataclass
class Permit:
    """Per-burst permit returned by :meth:`RequestRateGovernor.acquire`.

    Attributes:
        aborted: True if the burst has been aborted (error threshold
            crossed or governor error). The caller MUST stop sending
            requests immediately.
        reason: Human-readable reason for the abort (empty if not aborted).
        host: The target host this permit is for.
        in_flight: Current number of in-flight requests for this host
            (including this one) at acquire time.
        error_count: Running count of error responses (5xx) so far.
        total_count: Running count of ALL responses so far.
    """

    aborted: bool = False
    reason: str = ""
    host: str = ""
    in_flight: int = 0
    error_count: int = 0
    total_count: int = 0

    def record_response(self, status_code: int) -> None:
        """DEPRECATED — no-op. Use :meth:`RequestRateGovernor.record_response`.

        V10 P0-3 FIX: this method previously mutated the permit's own
        ``error_count`` / ``total_count`` counters, which were then
        propagated back to the shared governor state on context-manager
        exit. That propagation path was BUGGY: the permit's counters were
        initialised from the shared state at acquire time, so adding them
        back double-counted the baseline. The whole flow is now removed.

        The AUTHORITATIVE API is
        :meth:`RequestRateGovernor.record_response`, which updates the
        shared state directly (under the lock) and is what callers should
        use. This method is retained as a no-op for backwards
        compatibility with any caller that still holds a Permit and calls
        it — it logs a deprecation warning and does nothing.
        """
        logger.warning(
            "Permit.record_response(status_code=%s) is a deprecated "
            "no-op and does NOT record the response. Use "
            "RequestRateGovernor.record_response(host, status_code) "
            "instead — the authoritative API that updates shared state.",
            status_code,
        )
        return None


class RequestRateGovernor:
    """V7 Sprint 2.7: Per-target request-rate governor.

    Enforces two safety controls on concurrent-request test code
    (e.g., race-condition testing, IDOR enumeration):

      1. **Hard cap on simultaneous in-flight requests per target**
         (config default: 20). Prevents a single burst from
         overwhelming a real bug-bounty target.

      2. **Automatic abort-and-backoff on error-rate threshold**
         (config default: 30% of responses are 5xx). If the target
         starts erroring mid-burst, the governor aborts the remaining
         requests to avoid DoS-ing the target (a program-rules
         violation).

    Thread-safe via a single ``threading.Lock`` guarding all state.
    The lock is held briefly (microseconds) for each acquire/release,
    so contention is negligible even at the 20-concurrent-request cap.
    """

    def __init__(
        self,
        max_concurrent: int = 20,
        error_rate_threshold: float = 0.3,
        min_samples_before_abort: int = 5,
    ) -> None:
        """Initialize the governor.

        Args:
            max_concurrent: Hard cap on simultaneous in-flight requests
                per target host. Default 20 (per V7 Architectural Plan §2.7).
            error_rate_threshold: If the fraction of 5xx responses
                exceeds this value, the burst is aborted. Default 0.3 (30%).
            min_samples_before_abort: Minimum number of responses before
                the error-rate check kicks in. Prevents a single early
                5xx from aborting the burst before we have enough data.
                Default 5.
        """
        self._max_concurrent = max_concurrent
        self._error_rate_threshold = error_rate_threshold
        self._min_samples_before_abort = min_samples_before_abort
        self._lock = threading.Lock()
        # Per-host state: {host: {"in_flight": int, "error_count": int,
        # "total_count": int, "aborted": bool, "abort_reason": str}}
        self._state: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "in_flight": 0,
                "error_count": 0,
                "total_count": 0,
                "aborted": False,
                "abort_reason": "",
            }
        )

    @contextmanager
    def acquire(self, host: str) -> Iterator[Permit]:
        """Acquire a permit for one in-flight request to ``host``.

        Yields a :class:`Permit`. If ``permit.aborted`` is True, the
        caller MUST NOT send the request — the burst has been aborted
        (either by the error-rate check or by reaching the concurrent
        cap). The context manager automatically releases the slot on
        exit, so the caller should wrap the actual request in the
        ``with`` block.
        """
        permit = Permit(host=host)
        with self._lock:
            state = self._state[host]
            # r6c: the kill switch is checked FIRST, before any slot is
            # consumed, so an engaged switch aborts without touching the
            # per-host accounting at all.
            if _kill_switch_abort():
                permit.aborted = True
                permit.reason = "kill_switch_engaged"
                yield permit
                return
            # Check if the burst has already been aborted.
            if state["aborted"]:
                permit.aborted = True
                permit.reason = state["abort_reason"]
                yield permit
                return
            # Check the concurrent cap.
            if state["in_flight"] >= self._max_concurrent:
                permit.aborted = True
                permit.reason = (
                    f"concurrent cap reached ({state['in_flight']}/{self._max_concurrent})"
                )
                yield permit
                return
            # Check the error-rate threshold (only after enough samples).
            if (
                state["total_count"] >= self._min_samples_before_abort
                and state["error_count"] / max(state["total_count"], 1)
                >= self._error_rate_threshold
            ):
                state["aborted"] = True
                state["abort_reason"] = (
                    f"error rate {state['error_count']}/{state['total_count']} "
                    f"({state['error_count'] / max(state['total_count'], 1) * 100:.1f}%) "
                    f"exceeded threshold {self._error_rate_threshold * 100:.1f}%"
                )
                permit.aborted = True
                permit.reason = state["abort_reason"]
                logger.warning(
                    "Rate governor: aborting burst for host %s — %s",
                    host,
                    permit.reason,
                )
                yield permit
                return
            # Acquire the slot.
            state["in_flight"] += 1
            permit.in_flight = state["in_flight"]
            permit.error_count = state["error_count"]
            permit.total_count = state["total_count"]

        try:
            yield permit
        finally:
            # Release the slot.
            # V10 P0-3 FIX: the buggy double-counting of permit.error_count
            # / permit.total_count has been removed entirely. The permit's
            # counters were initialised from the shared state at acquire time
            # and ``Permit.record_response`` is now a no-op (see below), so
            # the permit's counters carry no new information here. The
            # AUTHORITATIVE response-recording API is
            # :meth:`RequestRateGovernor.record_response`, which updates the
            # shared state directly and is what callers should use.
            with self._lock:
                state = self._state[host]
                state["in_flight"] = max(0, state["in_flight"] - 1)

    def record_response(self, host: str, status_code: int) -> None:
        """Record a response for ``host`` and check the error threshold.

        Called by the test code after each request completes (instead
        of or in addition to ``Permit.record_response``). This is the
        preferred API — it updates the shared state directly so the
        error-rate check sees the latest data on the next ``acquire``.
        """
        with self._lock:
            state = self._state[host]
            state["total_count"] += 1
            if status_code >= 500:
                state["error_count"] += 1
            # Check the error-rate threshold.
            if (
                not state["aborted"]
                and state["total_count"] >= self._min_samples_before_abort
                and state["error_count"] / max(state["total_count"], 1)
                >= self._error_rate_threshold
            ):
                state["aborted"] = True
                state["abort_reason"] = (
                    f"error rate {state['error_count']}/{state['total_count']} "
                    f"({state['error_count'] / max(state['total_count'], 1) * 100:.1f}%) "
                    f"exceeded threshold {self._error_rate_threshold * 100:.1f}%"
                )
                logger.warning(
                    "Rate governor: aborting burst for host %s — %s",
                    host,
                    state["abort_reason"],
                )

    def is_aborted(self, host: str) -> bool:
        """Check whether the burst for ``host`` has been aborted."""
        with self._lock:
            return self._state[host]["aborted"]

    def reset(self, host: str | None = None) -> None:
        """Reset the governor state for ``host`` (or all hosts if None)."""
        with self._lock:
            if host is None:
                self._state.clear()
            else:
                self._state.pop(host, None)

    def get_stats(self, host: str) -> dict[str, Any]:
        """Return the current state for ``host`` (for debugging)."""
        with self._lock:
            state = self._state[host]
            return {
                "in_flight": state["in_flight"],
                "error_count": state["error_count"],
                "total_count": state["total_count"],
                "aborted": state["aborted"],
                "abort_reason": state["abort_reason"],
                "error_rate": (
                    state["error_count"] / max(state["total_count"], 1)
                    if state["total_count"] > 0
                    else 0.0
                ),
            }


# Module-level singleton (like get_vector_store_manager).
# All concurrent-request test code should use this instance.
_GOVERNOR: RequestRateGovernor | None = None
_GOVERNOR_LOCK = threading.Lock()


def get_rate_governor() -> RequestRateGovernor:
    """Return the process-wide :class:`RequestRateGovernor` singleton.

    V10 P1-2 (RCA follow-up): the governor's ``max_concurrent`` and
    ``error_rate_threshold`` are now read from settings (env-configurable)
    instead of hardcoded. Safe defaults (20 / 0.3) are preserved in
    settings.py; operators can override via
    ``GOVERNOR_MAX_CONCURRENT`` / ``GOVERNOR_ERROR_RATE_THRESHOLD`` env
    vars for lab vs production tuning.
    """
    global _GOVERNOR
    if _GOVERNOR is not None:
        return _GOVERNOR
    with _GOVERNOR_LOCK:
        if _GOVERNOR is None:
            # V10 P1-2: read thresholds from settings (env-driven).
            try:
                from webpent.config.settings import get_settings

                s = get_settings()
                _GOVERNOR = RequestRateGovernor(
                    max_concurrent=getattr(s, "governor_max_concurrent", 20),
                    error_rate_threshold=getattr(s, "governor_error_rate_threshold", 0.3),
                )
            except Exception:
                # Settings load failure — fall back to hardcoded defaults
                # (legacy behaviour) rather than blocking the scan.
                _GOVERNOR = RequestRateGovernor()
    return _GOVERNOR
