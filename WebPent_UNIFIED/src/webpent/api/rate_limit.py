# src/webpent/api/rate_limit.py
"""webpent.api.rate_limit

V5 Sprint 13 — Rate limiter for the FastAPI API.

Two-tier rate limiting:
  1. **Global limit**: ``N`` requests per minute per IP across ALL endpoints.
  2. **Scan limit**: ``M`` requests per minute per IP for scan-trigger
     endpoints only (stricter than global).

Backends:
  - **Redis** (distributed, multi-worker): used when ``redis_url`` is set.
    Atomic INCR + EXPIRE on a per-IP key.
  - **In-memory** (single-instance): a sliding-window dict. Suitable for
    dev / single-worker deployments. Not safe for multi-worker setups.

Both backends are O(1) per request.

V6 Titanium P1 FIX (CISO audit — Race Condition):
    The in-memory backend (``_check_memory``) mutated ``_global_hits``
    and ``_scan_hits`` without any lock. FastAPI / uvicorn with
    multiple async workers (or a threaded ASGI server) could interleave
    the read-prune-append sequence across concurrent requests for the
    same IP, allowing N+1 requests through a limit of N. A
    ``threading.Lock`` now serialises the entire
    prune → limit-check → append sequence so the sliding-window count
    is always consistent. The lock is held only for the duration of
    the in-memory check (microseconds) — Redis-path requests are
    unaffected.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

_WINDOW_SECONDS = 60  # 1-minute sliding window


class RateLimiter:
    """Two-tier rate limiter with Redis or in-memory backend.

    V5 Sprint 13: Constructed once at app startup (see ``api/app.py``).
    The ``check_global`` and ``check_scan`` methods are called from
    middleware + handlers respectively.
    """

    def __init__(
        self,
        enabled: bool = True,
        global_per_minute: int = 60,
        scan_per_minute: int = 5,
        redis_url: str = "",
        login_per_minute: int = 10,
    ) -> None:
        self.enabled = enabled
        self.global_per_minute = global_per_minute
        self.scan_per_minute = scan_per_minute
        self.login_per_minute = login_per_minute
        self.redis_url = redis_url
        self._redis_required = bool(redis_url)
        self._redis_unavailable = False

        # In-memory backend: {ip: [timestamp, ...]}
        self._global_hits: dict[str, list[float]] = defaultdict(list)
        self._scan_hits: dict[str, list[float]] = defaultdict(list)
        self._login_ip_hits: dict[str, list[float]] = defaultdict(list)
        self._login_account_hits: dict[str, list[float]] = defaultdict(list)

        # V6 Titanium P1: lock guarding the in-memory backend.
        # Held for the duration of _check_memory so concurrent
        # requests for the same IP cannot interleave the
        # read-prune-append sequence and slip N+1 requests through a
        # limit of N. The lock is uncontended in the Redis-path
        # (Redis's own INCR is atomic) and uncontended in the
        # steady-state in-memory path (held for microseconds).
        self._memory_lock = threading.Lock()

        # Redis backend (lazy-init on first use).
        self._redis: Any = None
        if redis_url:
            try:
                import redis as redis_lib

                self._redis = redis_lib.from_url(redis_url, decode_responses=True)
                self._redis.ping()  # fail fast if Redis is unreachable
                logger.info("RateLimiter: Redis backend connected at %s", redis_url)
            except Exception as exc:
                logger.warning(
                    "RateLimiter: Redis backend unavailable (%s) — "
                    "falling back to in-memory (single-instance only)",
                    exc,
                )
                self._redis = None
                self._redis_unavailable = True

    def _check_redis(self, key: str, limit: int) -> bool:
        """Redis-backed check: atomic INCR + EXPIRE.

        Returns True if the request is allowed (under the limit), False
        if it should be rejected.
        """
        try:
            pipe = self._redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, _WINDOW_SECONDS)
            results = pipe.execute()
            current = results[0]
            return current <= limit
        except Exception as exc:
            logger.error(
                "RateLimiter Redis check failed (%s) — denying request because "
                "distributed rate limiting is a security dependency",
                exc,
            )
            self._redis_unavailable = True
            return False

    def _check_memory(self, key: str, limit: int, store: dict[str, list[float]]) -> bool:
        """In-memory sliding-window check.

        Returns True if the request is allowed.

        V6 Titanium P1: the entire prune → limit-check → append
        sequence is wrapped in ``self._memory_lock`` so concurrent
        threads cannot interleave and slip N+1 requests through a
        limit of N. Without the lock, two threads could both read
        ``len(hits) == limit - 1``, both pass the limit check, and
        both append — producing ``len(hits) == limit + 1`` and
        admitting one request over the limit. The lock is held for
        microseconds (no I/O inside the critical section), so
        contention is negligible even under high load.
        """
        with self._memory_lock:
            now = time.monotonic()
            window_start = now - _WINDOW_SECONDS

            # Prune entries outside the window.
            hits = store[key]
            while hits and hits[0] < window_start:
                hits.pop(0)

            if len(hits) >= limit:
                return False
            hits.append(now)
            return True

    def check_global(self, client_ip: str) -> bool:
        """Check the global per-IP rate limit.

        Returns True if the request is allowed, False if it exceeds
        ``global_per_minute`` requests in the last 60 seconds.
        """
        if not self.enabled:
            return True
        if self._redis is not None:
            return self._check_redis(
                f"webpent:ratelimit:global:{client_ip}", self.global_per_minute
            )
        if self._redis_required and self._redis_unavailable:
            logger.error("Global rate limit denied: Redis backend unavailable")
            return False
        return self._check_memory(client_ip, self.global_per_minute, self._global_hits)

    def check_scan(self, client_ip: str) -> bool:
        """Check the scan-trigger per-IP rate limit (stricter than global).

        Returns True if the request is allowed, False if it exceeds
        ``scan_per_minute`` scan-trigger requests in the last 60 seconds.
        """
        if not self.enabled:
            return True
        if self._redis is not None:
            return self._check_redis(f"webpent:ratelimit:scan:{client_ip}", self.scan_per_minute)
        if self._redis_required and self._redis_unavailable:
            logger.error("Scan rate limit denied: Redis backend unavailable")
            return False
        return self._check_memory(client_ip, self.scan_per_minute, self._scan_hits)

    def check_login(self, client_ip: str, username: str) -> bool:
        """Apply independent per-IP and per-account login throttles.

        The account key is hashed before it reaches Redis or logs, avoiding
        disclosure of submitted usernames while keeping attempts for the same
        account grouped. Both buckets are consumed for every attempt so the
        response does not reveal whether an account exists.
        """
        if not self.enabled:
            return True
        account_key = hashlib.sha256(username.strip().lower().encode("utf-8")).hexdigest()
        if self._redis is not None:
            ip_allowed = self._check_redis(
                f"webpent:ratelimit:login:ip:{client_ip}", self.login_per_minute
            )
            account_allowed = self._check_redis(
                f"webpent:ratelimit:login:account:{account_key}", self.login_per_minute
            )
            return ip_allowed and account_allowed
        if self._redis_required and self._redis_unavailable:
            logger.error("Login rate limit denied: Redis backend unavailable")
            return False
        ip_allowed = self._check_memory(client_ip, self.login_per_minute, self._login_ip_hits)
        account_allowed = self._check_memory(
            account_key, self.login_per_minute, self._login_account_hits
        )
        return ip_allowed and account_allowed

    def reset(self) -> None:
        """Clear all in-memory rate-limit state (for tests)."""
        # V6 Titanium P1: acquire the lock before clearing so we don't
        # race with an in-flight _check_memory call.
        with self._memory_lock:
            self._global_hits.clear()
            self._scan_hits.clear()
            self._login_ip_hits.clear()
            self._login_account_hits.clear()
