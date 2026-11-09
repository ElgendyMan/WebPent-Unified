# src/webpent/benchmark/live_runner.py
"""Local-only live benchmark runner (PROPOSALS_ULTIMATE_V2 §8, 2026-10-30).

Runs the framework's benchmark campaign against a LOCAL target only
(Juice Shop, DVWA, a solved PortSwigger lab on the loopback) and scores
the run against the target's declared ground truth. STRICT by design:

- ``enable_live_benchmarks`` must be ON (default False): no benchmark
  traffic is ever generated from a default configuration.
- the target must come from the explicit ``benchmark_target`` setting
  (e.g. ``http://127.0.0.1:3000`` for a local Juice Shop container) and
  MUST resolve to ``localhost`` / ``127.0.0.1`` / ``::1`` — any other
  host is a hard refusal (fail-closed). A benchmark runner that could
  be pointed at a production target by a stray config value is a
  footgun; this one cannot be.
- the runner itself never contacts the target: it times and scores a
  caller-supplied ``campaign`` callable, the seam where the real
  framework invocation is wired. That keeps the gating and scoring
  testable offline and the network behaviour attributable to one
  explicit dependency.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from webpent.benchmark.ground_truth import TargetGroundTruth
from webpent.benchmark.scoreboard import (
    PredictedFinding,
    build_scoreboard,
)

__all__ = [
    "LOCAL_HOSTNAMES",
    "BenchmarkRunResult",
    "CampaignResult",
    "LiveBenchmarkError",
    "assert_local_target",
    "run_live_benchmark",
]

# Hostnames a benchmark target is allowed to resolve to. Anything else
# (production hosts, intranet names, DNS-rebinding tricks like
# 127.0.0.1.evil.com) is refused.
LOCAL_HOSTNAMES = frozenset({"localhost", "127.0.0.1", "::1"})

ALLOWED_SCHEMES = frozenset({"http", "https"})


class LiveBenchmarkError(ValueError):
    """Raised when a live benchmark cannot run fail-closed."""


@dataclass(frozen=True)
class CampaignResult:
    """What one benchmark campaign invocation returned."""

    findings: "tuple[PredictedFinding, ...]"
    llm_tokens: int = 0


# campaign(target_url) -> CampaignResult
Campaign = Callable[[str], CampaignResult]


@dataclass(frozen=True)
class BenchmarkRunResult:
    """One completed (gated, timed, scored) benchmark run."""

    target: str
    scoreboard: dict[str, Any]
    findings: "tuple[PredictedFinding, ...]"
    elapsed_seconds: float
    llm_tokens: int


def assert_local_target(target: str) -> str:
    """Refuse any target that is not a local loopback URL (fail-closed).

    Parsing uses :func:`urllib.parse.urlsplit`'s ``hostname`` property,
    which strips credentials and brackets: ``http://user@127.0.0.1:3000``
    is allowed (host ``127.0.0.1``) while ``http://127.0.0.1@evil.com``
    and ``http://127.0.0.1.evil.com`` are refused (host ``evil.com``).
    """
    if not target or not target.strip():
        raise LiveBenchmarkError("benchmark_target_required")
    parts = urlsplit(target.strip())
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise LiveBenchmarkError(
            f"benchmark_target_unsupported_scheme: {parts.scheme!r} "
            "(http/https only)"
        )
    hostname = (parts.hostname or "").lower()
    if hostname not in LOCAL_HOSTNAMES:
        raise LiveBenchmarkError(
            f"benchmark_target_not_localhost: {hostname!r} — live "
            "benchmarks run against LOCAL targets only (localhost/127.0.0.1/"
            "::1). Point benchmark_target at a locally started lab."
        )
    return target.strip()


def run_live_benchmark(
    *,
    enable_live_benchmarks: bool,
    benchmark_target: str,
    ground_truth: TargetGroundTruth,
    campaign: Campaign,
) -> BenchmarkRunResult:
    """Gate, run, time, and score one benchmark against a LOCAL target.

    Refusals (fail-closed, never silently skipped): flag off, empty
    target, non-local target, unsupported scheme. On success the
    campaign callable is invoked once with the target URL, timed with a
    monotonic clock, and scored against ``ground_truth``.
    """
    if not enable_live_benchmarks:
        raise LiveBenchmarkError("enable_live_benchmarks_flag_off")
    target = assert_local_target(benchmark_target)
    started = time.monotonic()
    result = campaign(target)
    elapsed = time.monotonic() - started
    board = build_scoreboard(
        ground_truth,
        result.findings,
        elapsed_seconds=elapsed,
        llm_tokens=result.llm_tokens,
    )
    return BenchmarkRunResult(
        target=target,
        scoreboard=board,
        findings=result.findings,
        elapsed_seconds=elapsed,
        llm_tokens=result.llm_tokens,
    )
