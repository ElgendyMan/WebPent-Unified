"""webpent.production.parallel_orchestrator — TC-3 §2 V-3.

The Parallel Request Orchestrator: N identical requests released in a
synchronized window (the single-packet pattern at the HTTP layer — a
:class:`threading.Barrier` releases every worker simultaneously, so the
server-side handlers race inside one window).  Every request still goes
through the caller-provided executor (the spine's
``execute_real_request`` — ToolBoundary + ScopeLaw); concurrency happens
at the CALLER layer only, never by bypassing the boundary.

Evidence contract (per the charter): the response differential under
PARALLELISM vs SEQUENTIAL is the evidence; the sequential run is the
control.  A single-use resource that over-succeeds in parallel but
honours its bound sequentially is a race condition; the sequential run
proves the bound exists and the parallel run proves it is not enforced
atomically.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

Executor = Callable[..., dict[str, Any]]


class ParallelRequestOrchestrator:
    """The bounded, synchronized burst executor (the single-packet
    pattern).  Bounded by construction: ``max_burst`` caps the window's
    request count."""

    MAX_BURST = 5

    def __init__(self, executor: Executor, *, max_burst: int = MAX_BURST):
        self.executor = executor
        self.max_burst = max(2, min(self.MAX_BURST, int(max_burst)))

    def burst(self, *, n: int, url: str, method: str = "POST",
              headers: dict[str, str] | None = None,
              body: str | None = None,
              hypothesis_id: str = "parallel_burst") -> list[dict[str, Any]]:
        """Release ``n`` identical requests inside ONE synchronized window
        (the barrier is the single-packet analog)."""
        n = max(2, min(self.max_burst, int(n)))
        headers = headers or {}
        barrier = threading.Barrier(n)
        results: list[dict[str, Any]] = [None] * n  # type: ignore[list-item]

        def _one(idx: int) -> None:
            barrier.wait()  # every worker released together
            results[idx] = self.executor(
                method=method, target_url=url, headers=dict(headers),
                body=body, hypothesis_id=hypothesis_id)

        with ThreadPoolExecutor(max_workers=n) as pool:
            futures = [pool.submit(_one, i) for i in range(n)]
            for f in futures:
                f.result()
        return [r for r in results if isinstance(r, dict)]

    def sequential(self, *, n: int, url: str, method: str = "POST",
                   headers: dict[str, str] | None = None,
                   body: str | None = None,
                   hypothesis_id: str = "sequential_control") -> list[dict[str, Any]]:
        """The CONTROL: the same request executed ``n`` times strictly
        sequentially.  A single-use resource must honour its bound here."""
        headers = headers or {}
        out = []
        for _ in range(max(1, int(n))):
            out.append(self.executor(
                method=method, target_url=url, headers=dict(headers),
                body=body, hypothesis_id=hypothesis_id))
        return out

    @staticmethod
    def _successes(results: list[dict[str, Any]]) -> int:
        count = 0
        for r in results:
            try:
                if 200 <= int(r.get("status_code") or 0) < 300:
                    count += 1
            except (TypeError, ValueError):
                continue
        return count

    def differential_report(self, *, url: str, method: str = "POST",
                            headers: dict[str, str] | None = None,
                            body: str | None = None, n: int = 5,
                            expected_successes: int = 1) -> dict[str, Any]:
        """THE EVIDENCE: the parallel burst vs the sequential control.
        NOTE the control is executed FIRST on its own resource instance by
        the caller when the resource is single-use (the lane issues one
        code per surface); this report only aggregates what the caller
        ran."""
        parallel = self.burst(n=n, url=url, method=method, headers=headers,
                              body=body)
        par_ok = self._successes(parallel)
        return {
            "parallel_attempts": len(parallel),
            "parallel_successes": par_ok,
            "expected_successes": expected_successes,
            "over_accepted": par_ok > expected_successes,
            "parallel_statuses": [int(r.get("status_code") or 0)
                                  for r in parallel],
            "pattern": "single_packet_barrier_window",
        }

