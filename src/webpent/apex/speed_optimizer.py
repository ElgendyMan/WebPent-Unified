"""The Apex Predator — U-APEX-9, the Speed Optimizer (v87).

APEX-L-8 SPEED IS THE EDGE, applied honestly: a result cache with a TTL
driven by an injected clock (no hidden wall-clock reads, tests are
deterministic), predictive prefetch that warms the cache for likely chain
steps, adaptive timeouts that learn each (target, tool) pair's observed
speed inside hard clamps, smart batching that collapses many cache misses
into one executor call, and chain ordering fastest-first. The executor is
injected: nothing here runs a tool on its own (APEX-L-9).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass

from webpent.apex.tool_chain_builder import ToolChain
from webpent.apex.tool_registry import ToolRegistry

PREAMBLE_LINE = (
    "advisory: caching, prefetch and timeout tuning accelerate approved "
    "runs; the operator still approves what runs."
)

#: hard clamps so adaptive timeouts can never go silly
MIN_TIMEOUT_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 3600.0
#: observed-duration history window per (target, tool)
_HISTORY_WINDOW = 20
#: adaptive timeout = clamp(observed_p50 * factor)
_TIMEOUT_FACTOR = 2.0


@dataclass
class _CacheEntry:
    value: object
    written_at: float
    ttl_seconds: float


class SpeedOptimizer:
    """Cache + prefetch + adaptive timeouts + batching + chain ordering."""

    def __init__(
        self,
        clock: Callable[[], float] | None = None,
        executor: Callable[[str], object] | None = None,
        batch_executor: Callable[[list[str]], list[object]] | None = None,
        ttl_seconds: float = 300.0,
    ) -> None:
        self._clock = clock or time.monotonic
        self._executor = executor
        self._batch_executor = batch_executor
        self._ttl = ttl_seconds
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        self._history: dict[tuple[str, str], deque[float]] = {}
        self.advisory_note = PREAMBLE_LINE

    # -- cache -----------------------------------------------------------------

    def cache_key(self, tool_id: str, target: str) -> str:
        return f"{tool_id}|{target}"

    def cache_get(self, key: str) -> object | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if self._clock() - entry.written_at > entry.ttl_seconds:
                del self._cache[key]
                self._misses += 1
                return None
            self._hits += 1
            return entry.value

    def cached_call(self, key: str) -> object:
        """Return the cached value or execute through the injected executor."""
        cached = self.cache_get(key)
        if cached is not None:
            return cached
        if self._executor is None:
            raise ValueError("no executor wired for cache misses")
        value = self._executor(key)
        with self._lock:
            self._cache[key] = _CacheEntry(
                value=value, written_at=self._clock(), ttl_seconds=self._ttl
            )
        return value

    def cached_many(self, keys: list[str]) -> list[object]:
        """One batched call for everything the cache misses (smart batching)."""
        results: dict[str, object] = {}
        missing: list[str] = []
        for key in keys:
            cached = self.cache_get(key)
            if cached is not None:
                results[key] = cached
            else:
                missing.append(key)
        if missing:
            if self._batch_executor is None:
                if self._executor is None:
                    raise ValueError("no executor wired for cache misses")
                fetched = [self._executor(k) for k in missing]
            else:
                fetched = self._batch_executor(missing)
            now = self._clock()
            with self._lock:
                for key, value in zip(missing, fetched, strict=True):
                    self._cache[key] = _CacheEntry(
                        value=value, written_at=now, ttl_seconds=self._ttl
                    )
                    results[key] = value
        return [results[k] for k in keys]

    def prefetch(self, likely_chains: list[ToolChain]) -> None:
        """Warm the cache for the steps of likely chains (predictive)."""
        for chain in likely_chains:
            for step in chain.steps:
                self.cached_call(self.cache_key(step.tool_id, chain.target))

    # -- adaptive timeouts -------------------------------------------------------

    def record_duration(self, target: str, tool_id: str, seconds: float) -> None:
        key = (target, tool_id)
        with self._lock:
            history = self._history.setdefault(
                key, deque(maxlen=_HISTORY_WINDOW)
            )
            history.append(float(seconds))

    def adaptive_timeout(self, target: str, tool_id: str) -> float:
        """clamp(observed median * factor, MIN, MAX); the base before any
        observation is the geometric middle of the clamps."""
        key = (target, tool_id)
        with self._lock:
            history = list(self._history.get(key, ()))
        observed = _median(sorted(history)) if history else None
        if observed is None:
            base = (MIN_TIMEOUT_SECONDS * MAX_TIMEOUT_SECONDS) ** 0.5
            return min(max(base, MIN_TIMEOUT_SECONDS), MAX_TIMEOUT_SECONDS)
        return min(
            max(observed * _TIMEOUT_FACTOR, MIN_TIMEOUT_SECONDS),
            MAX_TIMEOUT_SECONDS,
        )

    @staticmethod
    def timeout_clamps() -> tuple[float, float]:
        return MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS

    # -- chain ordering ------------------------------------------------------------

    def optimize(
        self,
        chains: list[ToolChain],
        registry: ToolRegistry | None = None,
    ) -> list[ToolChain]:
        """Order chains fastest-first by their estimated duration."""
        if registry is None:
            return sorted(chains, key=lambda c: c.chain_id)
        return sorted(
            chains,
            key=lambda c: (
                c.estimated_duration_seconds(registry),
                c.chain_id,
            ),
        )

    # -- observation ------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses,
                    "entries": len(self._cache)}


def _median(values: list[float]) -> float:
    if not values:
        raise ValueError("median of empty list")
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0
