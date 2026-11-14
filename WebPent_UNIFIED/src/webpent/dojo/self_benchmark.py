# src/webpent/dojo/self_benchmark.py
"""webpent.dojo.self_benchmark — ق5 continuous self-benchmark (FEATURE_PROPOSALS ق5).

Proposal contract (ق5، WebPent_FEATURE_PROPOSALS.md):

    ربط dojo بالإنتاج كـself-benchmark مستمر: dojo موجود للتدريب؛ اجعل
    nightly canary يشغل dojo scenarios كـregression للأداء الصيادي
    (قياس: عائلات مكتشفة/وقت/تكلفة) مع منحنى اتجاه في dashboard
    الـworkers.

    ("Wire the dojo into production as a continuous self-benchmark: the
    dojo exists for training; make the nightly canary run dojo scenarios
    as a regression on HUNTING performance — measured as families
    discovered / time / cost — with a trend curve on the workers
    dashboard.")

New module composing the existing (free) dojo core — ``ScenarioLibrary``,
``PracticeRunner`` (the spec score formula), fresh per-scenario agents
from an injected factory. Everything is offline and deterministic given
the same agent factory and library.

What "regression on hunting performance" means here, precisely:

* **discovery** — per-family share of scenarios the agent concluded
  correctly (judged by the dojo's own truth judge, L-6: a claim that
  does not match ground truth is a false positive, never a success);
* **time** — average ``time_steps`` per scenario (planning waves);
* **cost** — average ``requests_used`` per scenario (the lab budget the
  agent consumed);
* **regression** — a family whose discovery_rate dropped by more than
  the tolerance (default 0.1) versus the previous recorded run.

The :class:`BenchmarkLedger` is the workers-dashboard side: an
append-only, bounded JSONL of run summaries with a read-only ``curve()``
view. The ledger never rewrites history; a corrupted line is skipped
and counted as a gap (fail-soft), never silent.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.dojo.practice_runner import PracticeResult, PracticeRunner
from webpent.dojo.scenario_library import ScenarioLibrary

logger = logging.getLogger(__name__)

__all__ = [
    "FamilyBenchmark",
    "BenchmarkRun",
    "SelfBenchmark",
    "BenchmarkLedger",
    "DEFAULT_REGRESSION_TOLERANCE",
    "MAX_LEDGER_RUNS",
]

DEFAULT_REGRESSION_TOLERANCE = 0.10
MAX_LEDGER_RUNS = 180  # ~6 months of nightly runs, oldest evicted

AgentFactory = Callable[[], Any]  # -> AttackAgent (fresh per scenario)


def _utc_iso(now: float | None) -> str:
    if now is None:
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
    return datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class FamilyBenchmark:
    """Per-family aggregates over one benchmark run."""

    family: str
    scenarios: int
    discovered: int
    discovery_rate: float
    avg_score: float
    avg_time_steps: float
    avg_requests: float
    false_positive_rate: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "scenarios": self.scenarios,
            "discovered": self.discovered,
            "discovery_rate": round(self.discovery_rate, 4),
            "avg_score": round(self.avg_score, 2),
            "avg_time_steps": round(self.avg_time_steps, 2),
            "avg_requests": round(self.avg_requests, 2),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


@dataclass
class BenchmarkRun:
    """One nightly self-benchmark execution (aggregates + trace)."""

    run_id: str
    executed_at: str
    results: list[dict[str, Any]] = field(default_factory=list)
    family_benchmarks: list[FamilyBenchmark] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)

    @property
    def overall_rate(self) -> float:
        if not self.results:
            return 0.0
        discovered = sum(1 for r in self.results if r.get("success"))
        return discovered / len(self.results)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "executed_at": self.executed_at,
            "overall_discovery_rate": round(self.overall_rate, 4),
            "family_benchmarks": [f.as_dict() for f in self.family_benchmarks],
            "results": list(self.results),
            "coverage_gaps": list(self.coverage_gaps),
            "advisory_only": True,
        }

    # the dashboard-facing projection: no per-scenario transcript
    def as_summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "executed_at": self.executed_at,
            "overall_discovery_rate": round(self.overall_rate, 4),
            "families": {f.family: f.as_dict() for f in self.family_benchmarks},
            "scenarios": len(self.results),
            "coverage_gaps": list(self.coverage_gaps),
        }


class SelfBenchmark:
    """Run the dojo as a hunting-performance regression suite (nightly)."""

    def __init__(
        self,
        *,
        library: ScenarioLibrary,
        agent_factory: AgentFactory,
        runner: PracticeRunner | None = None,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._library = library
        if agent_factory is None:
            raise ValueError("agent_factory is required (fresh agent per scenario)")
        self._agent_factory = agent_factory
        self._runner = runner or PracticeRunner()
        self._now = now or (lambda: datetime.now(timezone.utc).timestamp())

    def run(
        self,
        *,
        families: Iterable[str] | None = None,
        max_scenarios: int | None = None,
        run_id: str | None = None,
        executed_at: str | None = None,
    ) -> BenchmarkRun:
        """Execute every (selected) scenario with a FRESH agent each.

        A scenario whose agent factory fails is recorded as an explicit
        coverage gap PLUS a failed synthetic result — a broken agent
        must show up as a performance regression, never as a crash or a
        silent skip.
        """
        wanted = set(families) if families is not None else None
        scenarios = [
            s
            for s in self._library.all()
            if wanted is None or s.family in wanted
        ]
        if max_scenarios is not None:
            scenarios = scenarios[: max(0, int(max_scenarios))]

        stamp = executed_at or _utc_iso(self._now())
        run = BenchmarkRun(
            run_id=run_id or f"selfbench-{stamp}",
            executed_at=stamp,
        )

        for scenario in scenarios:
            try:
                agent = self._agent_factory()
            except Exception as exc:  # noqa: BLE001 — factory failure is data
                run.coverage_gaps.append(
                    f"agent_factory_failed:{scenario.scenario_id}:{type(exc).__name__}"
                )
                run.results.append(
                    {
                        "scenario_id": scenario.scenario_id,
                        "family": scenario.family,
                        "success": False,
                        "score": 0.0,
                        "requests_used": 0,
                        "false_positives": 0,
                        "time_steps": 0,
                        "budget": int(scenario.request_budget),
                        "synthetic_failure": True,
                    }
                )
                continue
            try:
                result = self._runner.run(agent, scenario)
            except Exception as exc:  # noqa: BLE001 — per-scenario fail-soft
                run.coverage_gaps.append(
                    f"scenario_run_failed:{scenario.scenario_id}:{type(exc).__name__}"
                )
                run.results.append(
                    {
                        "scenario_id": scenario.scenario_id,
                        "family": scenario.family,
                        "success": False,
                        "score": 0.0,
                        "requests_used": 0,
                        "false_positives": 0,
                        "time_steps": 0,
                        "budget": int(scenario.request_budget),
                        "synthetic_failure": True,
                    }
                )
                continue
            run.results.append(_result_row(result, scenario.family))

        run.family_benchmarks = _aggregate(run.results)
        return run


def _result_row(result: PracticeResult, family: str) -> dict[str, Any]:
    row = result.as_dict()
    row["family"] = family
    row["synthetic_failure"] = False
    return row


def _aggregate(rows: list[dict[str, Any]]) -> list[FamilyBenchmark]:
    by_family: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_family.setdefault(str(row.get("family") or "unknown"), []).append(row)
    benchmarks: list[FamilyBenchmark] = []
    for family in sorted(by_family):
        group = by_family[family]
        count = len(group)
        discovered = sum(1 for r in group if r.get("success"))
        fps = sum(1 for r in group if int(r.get("false_positives") or 0) > 0)
        benchmarks.append(
            FamilyBenchmark(
                family=family,
                scenarios=count,
                discovered=discovered,
                discovery_rate=discovered / count if count else 0.0,
                avg_score=sum(float(r.get("score") or 0.0) for r in group) / count,
                avg_time_steps=sum(float(r.get("time_steps") or 0.0) for r in group) / count,
                avg_requests=sum(float(r.get("requests_used") or 0.0) for r in group) / count,
                false_positive_rate=fps / count if count else 0.0,
            )
        )
    return benchmarks


def compare(
    current: BenchmarkRun, previous: BenchmarkRun | None
) -> dict[str, Any]:
    """Per-family trend of one run versus the previous run.

    A family absent from the previous run has ``delta: None`` (a new
    family is never a regression). ``regressions`` lists families whose
    discovery_rate dropped by more than the tolerance.
    """
    current_by = {f.family: f for f in current.family_benchmarks}
    previous_by = {f.family: f for f in (previous.family_benchmarks if previous else [])}
    per_family: dict[str, Any] = {}
    regressions: list[str] = []
    for family, bench in current_by.items():
        prior = previous_by.get(family)
        delta = None if prior is None else bench.discovery_rate - prior.discovery_rate
        per_family[family] = {
            "current_rate": round(bench.discovery_rate, 4),
            "previous_rate": (round(prior.discovery_rate, 4) if prior else None),
            "delta": (round(delta, 4) if delta is not None else None),
            "current_avg_requests": round(bench.avg_requests, 2),
            "current_avg_time_steps": round(bench.avg_time_steps, 2),
        }
        if delta is not None and delta < -DEFAULT_REGRESSION_TOLERANCE:
            regressions.append(family)
    return {
        "run_id": current.run_id,
        "previous_run_id": (previous.run_id if previous else None),
        "overall_rate": round(current.overall_rate, 4),
        "overall_delta": (
            None
            if previous is None
            else round(current.overall_rate - previous.overall_rate, 4)
        ),
        "per_family": per_family,
        "regressions": sorted(regressions),
        "tolerance": DEFAULT_REGRESSION_TOLERANCE,
        "advisory_only": True,
    }


class BenchmarkLedger:
    """Append-only JSONL of run summaries + read-only trend curve.

    One file per engagement (or one global file); entries are the
    ``as_summary()`` projections so no per-scenario transcript is
    stored. Oldest entries are evicted beyond :data:`MAX_LEDGER_RUNS`
    on append (bounded storage); a corrupted line is skipped and
    counted as a gap on read.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def append(self, run: BenchmarkRun) -> dict[str, Any]:
        """Record one run summary; evict oldest beyond the cap."""
        summary = run.as_summary()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        summaries = self._read_all()
        summaries.append(summary)
        if len(summaries) > MAX_LEDGER_RUNS:
            summaries = summaries[-MAX_LEDGER_RUNS:]
        lines = [json.dumps(item, sort_keys=True) for item in summaries]
        self._path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return summary

    def history(self) -> list[dict[str, Any]]:
        """All recorded summaries, oldest → newest, with a gap count."""
        return self._read_all()

    def latest(self) -> dict[str, Any] | None:
        summaries = self._read_all()
        return summaries[-1] if summaries else None

    def curve(self, family: str | None = None) -> dict[str, Any]:
        """The trend curve for the workers dashboard.

        ``labels`` are run_ids (chronological); ``overall`` is the
        overall discovery-rate series; ``families[family]`` is the
        per-family series when a family is named; ``families_all`` maps
        every seen family to its series.
        """
        summaries = self._read_all()
        families_all: dict[str, list[float | None]] = {}
        for summary in summaries:
            families_map = summary.get("families") or {}
            seen_this_run = set()
            for name, bench in families_map.items():
                families_all.setdefault(name, []).append(
                    float(bench.get("discovery_rate") or 0.0)
                )
                seen_this_run.add(name)
            for name, series in families_all.items():
                if name not in seen_this_run:
                    series.append(None)  # family absent this run
        curve: dict[str, Any] = {
            "labels": [s.get("run_id") for s in summaries],
            "executed_at": [s.get("executed_at") for s in summaries],
            "overall": [s.get("overall_discovery_rate") for s in summaries],
            "families": (
                families_all.get(family, [])
                if family is not None
                else families_all
            ),
            "families_all": families_all,
            "gaps": self._gap_count,
            "advisory_only": True,
        }
        return curve

    # ------------------------------------------------------------------

    _gap_count: int = 0

    def _read_all(self) -> list[dict[str, Any]]:
        self._gap_count = 0
        if not self._path.exists():
            return []
        summaries: list[dict[str, Any]] = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except ValueError:
                self._gap_count += 1
                continue
            if isinstance(item, dict):
                summaries.append(item)
            else:
                self._gap_count += 1
        return summaries
