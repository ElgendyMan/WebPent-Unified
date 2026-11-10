# src/webpent/shared/global_rate_governor.py
"""webpent.shared.global_rate_governor

Ultimate plan 2026-10-27, proposal 6 — cross-campaign LLM request
governor.

``shared/rate_governor.py`` caps in-flight requests per *target host*
inside one burst. This module sits one level up: it caps the total
LLM-request concurrency and the per-minute request budget across **all
running campaigns combined**, so that N parallel campaigns on different
targets share one institutional provider budget instead of starving
each other (the plan's success criterion: 5 campaigns in parallel with
one shared cost ceiling).

Two backends, chosen at construction:

  * **Redis** (``redis_client`` injected, duck-typed: ``get``/``set``/
    ``incr``). Coordinates across *processes* — required when more
    than one worker process shares the provider budget. The duck-typed
    interface intentionally avoids Lua/transactions: the increment-
    first-then-rollback pattern below is used instead. That pattern is
    race-tolerant in the fail-closed direction (a race can make the
    counters slightly *over*-count, never under-count), which is the
    safe direction for a rate cap. Documented honestly: it is
    best-effort coordination, not a strict semaphore.
  * **In-memory** (``redis_client=None``, the default). A
    ``threading.Lock`` plus dict state that coordinates *threads
    within one process only*. Honest limitation: with multiple worker
    processes, each process enforces its own copy of the caps and the
    aggregate can exceed them. Use Redis for multi-process deployments.

Fail-closed degradation: if a Redis call raises one of the narrow
exception types in ``_REDIS_FAILURE_EXCEPTIONS`` (Redis errors, plus
the TypeError/AttributeError/KeyError/OSError family a misconfigured
or half-mock client produces), the governor falls back to the
in-memory path *for that call* and flags ``backend_degraded`` in
:meth:`GlobalRateGovernor.snapshot`. ``try_acquire`` and ``release``
never block, never sleep, and never raise.

Window rollover: the request budget is a fixed 60-second window; when
``now - window_start >= 60`` the counter resets to 0 for the new
window.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "GlobalRateGovernor",
    "RateWindow",
    "get_global_rate_governor",
    "reset_global_rate_governor",
]

WINDOW_SECONDS = 60.0
"""Fixed request-budget window length (plan proposal 6, Phase 2)."""

MAX_TOKENS_PER_ACQUIRE = 64
"""Cap on the ``tokens`` argument of :meth:`GlobalRateGovernor.try_acquire`
(bounded everywhere — a runaway caller asking for 10**9 tokens would
otherwise permanently wedge the budget)."""

MAX_CAMPAIGN_ID_LENGTH = 128
"""Campaign ids longer than this are rejected (fail-closed False)."""

MAX_TRACKED_CAMPAIGNS = 512
"""Upper bound on the campaign bookkeeping lists (documented cap; the
default concurrency cap of 8 means real usage is far below this)."""

# Narrow tuple of exception types treated as "Redis backend failure".
# This project's governance forbids blanket ``except Exception`` — a
# truly unexpected exception type from a client is allowed to propagate
# so programming errors stay visible. The tuple below covers real
# redis-py failures (RedisError, TimeoutError subclasses, OSError from
# socket transport) and the failure modes of a misconfigured duck-typed
# client (AttributeError for a missing method, KeyError/TypeError/
# ValueError for bad shapes, UnicodeDecodeError for bytes decoding).
_REDIS_FAILURE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    AttributeError,
    KeyError,
    TypeError,
    ValueError,
    OSError,
    TimeoutError,
    UnicodeDecodeError,
)
try:  # pragma: no cover - exercised implicitly; redis-py is optional.
    import redis.exceptions as _redis_exceptions

    _REDIS_FAILURE_EXCEPTIONS = _REDIS_FAILURE_EXCEPTIONS + (
        _redis_exceptions.RedisError,
    )
except ImportError:  # pragma: no cover - environments without redis-py.
    # redis-py is optional: without it the tuple above still covers the
    # failure modes of duck-typed injected clients.
    pass


@dataclass
class RateWindow:
    """One fixed request-budget window.

    Attributes:
        window_start: Epoch timestamp (``time.time()``) at which this
            window opened.
        tokens: Tokens consumed inside this window. A new window starts
            at 0 tokens (rollover resets the counter).
    """

    window_start: float
    tokens: int


class GlobalRateGovernor:
    """Cross-campaign LLM request governor (proposal 6, Phase 2).

    Enforces two shared caps over all campaigns combined:

      1. **Concurrency cap** — the sum of held tokens across all active
         campaigns stays <= ``max_concurrent``. Each campaign acquires
         tokens (default 1) via :meth:`try_acquire` and gives them back
         via :meth:`release`.
      2. **Per-minute request budget** — the sum of tokens consumed in
         the current 60-second window stays <= ``requests_per_minute``.

    Never blocks, never sleeps, never raises on the public API: when a
    cap is exceeded, :meth:`try_acquire` returns ``False`` and the
    caller decides how to back off (the LLM layer already has provider
    fallback and retry logic — this governor only says yes/no).
    """

    _KEY_CONCURRENCY = "webpent:grg:concurrency"
    _KEY_CAMPAIGNS = "webpent:grg:campaigns"
    _KEY_WINDOW_START = "webpent:grg:window_start"
    _KEY_WINDOW_TOKENS = "webpent:grg:window_tokens"
    _KEY_TOKENS_PREFIX = "webpent:grg:tokens:"

    def __init__(
        self,
        *,
        max_concurrent: int = 8,
        requests_per_minute: int = 120,
        redis_client: Any = None,
    ) -> None:
        """Initialize the governor.

        Args:
            max_concurrent: Maximum total held tokens (concurrency
                slots) across ALL campaigns combined. Default 8.
            requests_per_minute: Maximum tokens consumable within any
                60-second window across all campaigns. Default 120.
            redis_client: Optional duck-typed Redis client exposing
                ``get(key) -> str|bytes|None``, ``set(key, value)`` and
                ``incr(key, amount=1) -> int``. When ``None`` the
                governor coordinates threads within this process only
                (multi-PROCESS coordination requires Redis — honest
                limitation, see module docstring).
        """
        self._max_concurrent = max(1, int(max_concurrent))
        self._requests_per_minute = max(1, int(requests_per_minute))
        self._redis_client = redis_client
        # In-memory state: always maintained. It is the sole source of
        # truth in memory mode, and an approximate mirror (this
        # process's view) in Redis mode so degradation does not start
        # from zero.
        self._lock = threading.Lock()
        self._mem_active: dict[str, int] = {}
        self._mem_window = RateWindow(window_start=time.time(), tokens=0)
        # Sticky, honest degradation flag: once ANY Redis call has
        # failed, snapshots report backend_degraded=True until a new
        # governor is built. Never silently claim healthy again.
        self._degraded = False
        # UM-DR-34 §5.3: production fail-closed coordination posture.
        # When ``coordination_required`` is True and the Redis backend is
        # unavailable/degraded, ``try_acquire`` DENIES every request.
        self.coordination_required: bool = False
        self.coordination_degraded: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def try_acquire(self, campaign_id: str, *, tokens: int = 1) -> bool:
        """Try to acquire ``tokens`` concurrency units for a campaign.

        Atomically (under the lock in memory mode; increment-then-
        rollback in Redis mode) checks BOTH caps:

          * total held tokens across campaigns + ``tokens`` must not
            exceed ``max_concurrent``;
          * tokens consumed in the current 60s window + ``tokens`` must
            not exceed ``requests_per_minute``.

        On success the acquisition is recorded (the caller MUST later
        call :meth:`release` with the same ``campaign_id``). On failure
        returns ``False`` — never blocks, never raises, and records
        nothing.

        Bounds: ``tokens`` is clamped to ``1..MAX_TOKENS_PER_ACQUIRE``
        (64); ``campaign_id`` must be a non-empty string of at most 128
        characters (comma-free, because Redis bookkeeping joins ids
        with commas) — invalid ids fail closed with ``False``.

        Args:
            campaign_id: Identifier of the campaign requesting LLM
                budget.
            tokens: How many concurrency units this request needs
                (default 1). Each unit also consumes one unit from the
                per-minute window budget.

        Returns:
            True if the acquisition was granted, False if either cap
            would be exceeded (or the arguments are invalid).
        """
        if not isinstance(campaign_id, str) or not campaign_id:
            return False
        if len(campaign_id) > MAX_CAMPAIGN_ID_LENGTH or "," in campaign_id:
            return False
        try:
            bounded_tokens = min(MAX_TOKENS_PER_ACQUIRE, max(1, int(tokens)))
        except (TypeError, ValueError):
            return False
        # UM-DR-34 §5.3 fail-closed production posture: when global
        # coordination is REQUIRED and the backend is unavailable, no
        # request is admitted — an institution-wide limit must never
        # silently degrade into N uncoordinated process-local limits.
        if self.coordination_required and (self._redis_client is None or self.coordination_degraded):
            return False
        now = time.time()
        if self._redis_client is not None:
            try:
                granted = self._redis_try_acquire(campaign_id, bounded_tokens, now)
            except _REDIS_FAILURE_EXCEPTIONS:
                self._degraded = True
                if self.coordination_required:
                    self.coordination_degraded = True
                    logger.error(
                        "GlobalRateGovernor: Redis backend failed during "
                        "try_acquire while coordination is REQUIRED — "
                        "DENYING (fail-closed) instead of degrading to "
                        "uncoordinated process-local limits.",
                    )
                    return False
                logger.warning(
                    "GlobalRateGovernor: Redis backend failed during "
                    "try_acquire; degrading to in-memory path for this "
                    "call (per-process coordination only).",
                )
                return self._memory_try_acquire(campaign_id, bounded_tokens, now)
            if granted:
                self._mirror_memory_acquire(campaign_id, bounded_tokens)
            return granted
        return self._memory_try_acquire(campaign_id, bounded_tokens, now)

    def release(self, campaign_id: str) -> None:
        """Release all concurrency units held by ``campaign_id``.

        Never raises; releasing an unknown/already-released campaign is
        a no-op. In Redis mode the release is best-effort (a Redis
        failure degrades to the in-memory path for this call).
        """
        if not isinstance(campaign_id, str) or not campaign_id:
            return
        if self._redis_client is not None:
            try:
                self._redis_release(campaign_id)
            except _REDIS_FAILURE_EXCEPTIONS:
                self._degraded = True
                logger.warning(
                    "GlobalRateGovernor: Redis backend failed during "
                    "release; degrading to in-memory path for this call.",
                )
                self._memory_release(campaign_id)
            else:
                self._memory_release(campaign_id)
            return
        self._memory_release(campaign_id)

    def snapshot(self) -> dict[str, Any]:
        """Return an honest point-in-time view of the governor state.

        Shape::

            {
                "active_campaigns": [campaign_id, ...],
                "requests_last_minute": int,   # tokens in current window
                "max_concurrent": int,
                "requests_per_minute": int,
                "backend": "redis" | "memory",
                "backend_degraded": bool,
            }

        ``backend_degraded`` is True once any Redis call has failed
        (sticky — a healthy-looking snapshot after a failure would be
        dishonest). In degraded snapshots the numbers come from the
        in-process mirror, which may under-count other processes.
        """
        now = time.time()
        base = {
            "max_concurrent": self._max_concurrent,
            "requests_per_minute": self._requests_per_minute,
        }
        if self._redis_client is not None:
            try:
                return dict(base, **self._redis_snapshot(now))
            except _REDIS_FAILURE_EXCEPTIONS:
                self._degraded = True
                logger.warning(
                    "GlobalRateGovernor: Redis backend failed during "
                    "snapshot; reporting in-process view.",
                )
        return dict(base, **self._memory_snapshot(now))

    # ------------------------------------------------------------------
    # In-memory backend (also the degradation fallback)
    # ------------------------------------------------------------------

    def _memory_rollover_locked(self, now: float) -> None:
        """Reset the window counter when the 60s window has elapsed.

        Must be called while holding ``self._lock``.
        """
        if now - self._mem_window.window_start >= WINDOW_SECONDS:
            self._mem_window = RateWindow(window_start=now, tokens=0)

    def _memory_try_acquire(self, campaign_id: str, tokens: int, now: float) -> bool:
        """Check-and-commit both caps under the lock (atomic in-process)."""
        with self._lock:
            self._memory_rollover_locked(now)
            if sum(self._mem_active.values()) + tokens > self._max_concurrent:
                return False
            if self._mem_window.tokens + tokens > self._requests_per_minute:
                return False
            self._mem_active[campaign_id] = self._mem_active.get(campaign_id, 0) + tokens
            self._mem_window.tokens += tokens
            return True

    def _memory_release(self, campaign_id: str) -> None:
        """Drop the campaign's held tokens (no-op if unknown)."""
        with self._lock:
            self._mem_active.pop(campaign_id, None)

    def _memory_snapshot(self, now: float) -> dict[str, Any]:
        """In-process view (never mutates state; rollover is computed)."""
        with self._lock:
            window_tokens = self._mem_window.tokens
            if now - self._mem_window.window_start >= WINDOW_SECONDS:
                window_tokens = 0
            return {
                "active_campaigns": sorted(self._mem_active.keys())[:MAX_TRACKED_CAMPAIGNS],
                "requests_last_minute": window_tokens,
                "backend": "memory",
                "backend_degraded": self._degraded,
                # UM-DR-34 §5.3: honest coordination scope — a memory
                # backend coordinates THIS PROCESS ONLY; callers must
                # never describe it as a global multi-process limit.
                "coordination_scope": "process-local",
            }

    def _mirror_memory_acquire(self, campaign_id: str, tokens: int) -> None:
        """Mirror a successful Redis acquisition into the local view.

        Approximate by construction: it records THIS process's
        contributions only, so the mirror under-counts other processes
        (documented honestly — the mirror exists so degradation does
        not restart from a zeroed view, not to replicate Redis).
        """
        with self._lock:
            now = time.time()
            self._memory_rollover_locked(now)
            self._mem_active[campaign_id] = self._mem_active.get(campaign_id, 0) + tokens
            self._mem_window.tokens += tokens

    # ------------------------------------------------------------------
    # Redis backend (duck-typed client: get / set / incr)
    # ------------------------------------------------------------------

    @staticmethod
    def _decode(value: Any) -> str | None:
        """Coerce a Redis ``get`` result (str|bytes|int|None) to str."""
        if value is None:
            return None
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    @classmethod
    def _to_int(cls, value: Any) -> int | None:
        """Parse a Redis value as int; None on missing/garbage values."""
        text = cls._decode(value)
        if text is None:
            return None
        return int(text.strip() or "0")

    @classmethod
    def _to_float(cls, value: Any) -> float | None:
        """Parse a Redis value as float; None on missing/garbage values."""
        text = cls._decode(value)
        if text is None:
            return None
        return float(text.strip())

    def _redis_read_campaigns(self) -> list[str]:
        """Read the tracked-campaign list from Redis (comma-joined)."""
        joined = self._decode(self._redis_client.get(self._KEY_CAMPAIGNS)) or ""
        return [c for c in joined.split(",") if c][:MAX_TRACKED_CAMPAIGNS]

    def _redis_try_acquire(self, campaign_id: str, tokens: int, now: float) -> bool:
        """Increment-first-then-rollback acquisition over Redis.

        Races between processes can only ever over-count (a loser
        rolls its increment back; two winners both see the post-increment
        value), which errs in the fail-closed direction for a rate
        cap. Raises a ``_REDIS_FAILURE_EXCEPTIONS`` member on backend
        failure — the caller degrades to the in-memory path.
        """
        client = self._redis_client
        # 1) Window rollover (best-effort; a concurrent rollover race
        #    resets to a fresh window, which is the safe direction).
        start = self._to_float(client.get(self._KEY_WINDOW_START))
        if start is None or now - start >= WINDOW_SECONDS:
            client.set(self._KEY_WINDOW_START, repr(now))
            client.set(self._KEY_WINDOW_TOKENS, "0")
        # 2) Per-minute budget: increment first, roll back if over.
        new_window_tokens = int(client.incr(self._KEY_WINDOW_TOKENS, tokens))
        if new_window_tokens > self._requests_per_minute:
            client.incr(self._KEY_WINDOW_TOKENS, -tokens)
            return False
        # 3) Concurrency cap: increment first, roll both back if over.
        new_concurrency = int(client.incr(self._KEY_CONCURRENCY, tokens))
        if new_concurrency > self._max_concurrent:
            client.incr(self._KEY_CONCURRENCY, -tokens)
            client.incr(self._KEY_WINDOW_TOKENS, -tokens)
            return False
        # 4) Record the campaign's slot for release()/snapshot().
        client.incr(self._KEY_TOKENS_PREFIX + campaign_id, tokens)
        campaigns = self._redis_read_campaigns()
        if campaign_id not in campaigns:
            campaigns.append(campaign_id)
            client.set(self._KEY_CAMPAIGNS, ",".join(campaigns[:MAX_TRACKED_CAMPAIGNS]))
        return True

    def _redis_release(self, campaign_id: str) -> None:
        """Release the campaign's tokens in Redis (full slot release)."""
        client = self._redis_client
        held = self._to_int(client.get(self._KEY_TOKENS_PREFIX + campaign_id)) or 0
        if held <= 0:
            return
        client.incr(self._KEY_CONCURRENCY, -held)
        client.set(self._KEY_TOKENS_PREFIX + campaign_id, "0")
        campaigns = self._redis_read_campaigns()
        if campaign_id in campaigns:
            remaining = [c for c in campaigns if c != campaign_id]
            client.set(self._KEY_CAMPAIGNS, ",".join(remaining[:MAX_TRACKED_CAMPAIGNS]))

    def _redis_snapshot(self, now: float) -> dict[str, Any]:
        """Read the cross-process view from Redis."""
        client = self._redis_client
        start = self._to_float(client.get(self._KEY_WINDOW_START))
        window_tokens = self._to_int(client.get(self._KEY_WINDOW_TOKENS)) or 0
        if start is None or now - start >= WINDOW_SECONDS:
            window_tokens = 0
        campaigns = self._redis_read_campaigns()
        active = [
            campaign
            for campaign in campaigns
            if (self._to_int(client.get(self._KEY_TOKENS_PREFIX + campaign)) or 0) > 0
        ]
        return {
            "active_campaigns": active[:MAX_TRACKED_CAMPAIGNS],
            "requests_last_minute": window_tokens,
            "backend": "redis",
            "backend_degraded": self._degraded,
            "coordination_scope": "cross-process",
        }


# Module-level singleton (same pattern as shared/rate_governor.py).
_GLOBAL_GOVERNOR: GlobalRateGovernor | None = None
_GLOBAL_GOVERNOR_LOCK = threading.Lock()


def get_global_rate_governor() -> GlobalRateGovernor:
    """Return the process-wide :class:`GlobalRateGovernor` singleton.

    UM-DR-34 §5.3 (multi-process coordination):

    * When ``global_rate_governor_redis_url`` is configured, the
      singleton is built with a Redis client so the ceiling coordinates
      across worker PROCESSES (the institution-wide limit is one limit,
      not N per-process copies).
    * When the URL is empty, the limit is PROCESS-LOCAL (single-process
      dev posture) and ``snapshot()["backend"]`` reports ``"memory"``
      honestly — it is never described as a globally coordinated limit.
    * When ``global_rate_governor_require_coordination`` is True and
      the Redis backend cannot be constructed, the singleton is marked
      coordination-degraded and :meth:`GlobalRateGovernor.try_acquire`
      DENIES every request (fail-closed): a Redis outage must not
      silently turn one institution-wide limit into uncoordinated
      process-local limits.

    Caps default to 16 concurrent / 900 requests-per-minute; operators
    can override via the ``global_rate_governor_max_concurrent`` /
    ``global_rate_governor_requests_per_minute`` settings fields.
    """
    global _GLOBAL_GOVERNOR
    if _GLOBAL_GOVERNOR is not None:
        return _GLOBAL_GOVERNOR
    with _GLOBAL_GOVERNOR_LOCK:
        if _GLOBAL_GOVERNOR is None:
            max_concurrent = 16
            requests_per_minute = 900
            redis_url = ""
            require_coordination = False
            try:
                from webpent.config.settings import get_settings

                settings = get_settings()
                max_concurrent = int(settings.global_rate_governor_max_concurrent)
                requests_per_minute = int(
                    settings.global_rate_governor_requests_per_minute
                )
                # Static attribute access inside try/except AttributeError
                # (deliberately NOT getattr — this module must not add
                # dynamic-resolution records to the G-02 direct-I/O
                # inventory; same contract as the original factory).
                redis_url = str(
                    settings.global_rate_governor_redis_url
                    if hasattr(settings, "global_rate_governor_redis_url")
                    else ""
                )
                require_coordination = bool(
                    settings.global_rate_governor_require_coordination
                    if hasattr(settings, "global_rate_governor_require_coordination")
                    else False
                )
            except (AttributeError, ValueError, TypeError, OSError, ImportError):
                # Field absent from this settings version, or settings
                # failed to load — honest fallback to the documented
                # defaults; the governor must still exist and enforce
                # its caps.
                max_concurrent = 16
                requests_per_minute = 900
            redis_client = None
            if redis_url:
                try:
                    import redis as _redis

                    redis_client = _redis.Redis.from_url(
                        redis_url, socket_connect_timeout=2.0, socket_timeout=2.0
                    )
                except (ImportError, ValueError, TypeError, OSError) as exc:
                    if require_coordination:
                        logger.error(
                            "GlobalRateGovernor: Redis coordination is "
                            "REQUIRED but the client could not be built "
                            "(%s) — every try_acquire will DENY (fail-"
                            "closed). Fix the Redis configuration or "
                            "unset require_coordination for single-"
                            "process development.",
                            type(exc).__name__,
                        )
                        redis_client = None
                    else:
                        logger.warning(
                            "GlobalRateGovernor: Redis URL configured but "
                            "the client could not be built — falling back "
                            "to PROCESS-LOCAL coordination (limits apply "
                            "per process, not institution-wide).",
                            exc_info=True,
                        )
            _GLOBAL_GOVERNOR = GlobalRateGovernor(
                max_concurrent=max_concurrent,
                requests_per_minute=requests_per_minute,
                redis_client=redis_client,
            )
            if require_coordination and redis_client is None:
                # Fail-closed posture for production: without the
                # required coordination backend no request is admitted.
                _GLOBAL_GOVERNOR.coordination_required = True
                _GLOBAL_GOVERNOR.coordination_degraded = True
    return _GLOBAL_GOVERNOR


def reset_global_rate_governor() -> None:
    """Drop the singleton (test hook — forces a fresh construction)."""
    global _GLOBAL_GOVERNOR
    with _GLOBAL_GOVERNOR_LOCK:
        _GLOBAL_GOVERNOR = None
