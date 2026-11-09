"""FEATURE_PROPOSALS ق5 — dojo as continuous self-benchmark.

Pins:
  * the nightly canary runs dojo scenarios as a hunting-performance
    regression: per-family discovery rate / avg time / avg requests,
    judged by the dojo's own truth judge (false positives are never
    successes),
  * a FRESH agent per scenario via the injected factory — no
    cross-scenario memory can inflate the benchmark,
  * factory or runner failure on one scenario ⇒ explicit coverage gap
    PLUS a synthetic failed result (a broken agent is a regression,
    never a crash or a silent skip),
  * compare() pins regression semantics: a family whose discovery_rate
    dropped by more than the tolerance (0.1) is a regression; a family
    absent from the previous run is NEVER a regression (delta None),
  * BenchmarkLedger is append-only, bounded (oldest evicted), fails
    soft on corrupted lines (counted as gaps), and exposes a read-only
    trend curve() for the workers dashboard,
  * everything offline; deterministic given the same factory+library.
"""

from __future__ import annotations

import json

import pytest

from webpent.dojo.scenario_library import Scenario, ScenarioLibrary
from webpent.dojo.self_benchmark import (
    MAX_LEDGER_RUNS,
    BenchmarkLedger,
    BenchmarkRun,
    SelfBenchmark,
    compare,
)


# ---------------------------------------------------------------------------
# fixtures — real dojo scenarios (the yaml library) and scripted agents
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def library() -> ScenarioLibrary:
    return ScenarioLibrary.load_dir("config/dojo/scenarios")


class ScriptedAgent:
    """An AttackAgent that always claims a fixed (class, location)."""

    def __init__(self, claims: bool = True, vuln_class: str = "idbac") -> None:
        self.claims = claims
        self.vuln_class = vuln_class
        self.plan_calls = 0

    def plan(self, lab_view: dict, scenario: Scenario):
        self.plan_calls += 1
        from webpent.dojo.engine import DojoRequest

        return [DojoRequest(method="GET", path="/")]

    def conclude(self, responses):
        from webpent.dojo.practice_runner import Conclusion

        return Conclusion(claims_finding=self.claims, vuln_class=self.vuln_class)


def _factory_of(agent: ScriptedAgent):
    return lambda: agent


# ---------------------------------------------------------------------------
# run + aggregation
# ---------------------------------------------------------------------------


def test_run_executes_every_scenario_with_fresh_agents(library) -> None:
    created: list[ScriptedAgent] = []

    def factory() -> ScriptedAgent:
        agent = ScriptedAgent()
        created.append(agent)
        return agent

    benchmark = SelfBenchmark(library=library, agent_factory=factory)
    run = benchmark.run(max_scenarios=6, run_id="run-1", executed_at="2026-11-04T00:00:00+00:00")
    assert run.run_id == "run-1"
    assert len(run.results) == 6
    assert len(created) == 6  # one FRESH agent per scenario
    assert len({id(a) for a in created}) == 6
    assert run.family_benchmarks
    total = sum(f.scenarios for f in run.family_benchmarks)
    assert total == 6


def test_family_aggregates_measure_discovery_time_cost(library) -> None:
    # A truth-telling adaptive agent on the smallest slice: its per-family
    # aggregates must be internally consistent.
    from webpent.dojo.tournament import BUILTIN_AGENTS

    benchmark = SelfBenchmark(
        library=library, agent_factory=lambda: BUILTIN_AGENTS["adaptive"]
    )
    run = benchmark.run(families=["idor"], run_id="run-idor")
    bench = next(f for f in run.family_benchmarks if f.family == "idor")
    assert bench.scenarios == len(library.by_family("idor"))
    assert 0.0 <= bench.discovery_rate <= 1.0
    assert bench.discovered <= bench.scenarios
    assert bench.avg_requests >= 0.0
    assert bench.avg_time_steps >= 0.0
    assert 0.0 <= bench.false_positive_rate <= 1.0
    assert run.overall_rate == bench.discovery_rate


def test_factory_failure_is_gap_plus_synthetic_failure(library) -> None:
    calls = {"n": 0}

    def flaky_factory():
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("agent exploded")
        return ScriptedAgent()

    benchmark = SelfBenchmark(library=library, agent_factory=flaky_factory)
    run = benchmark.run(max_scenarios=3, run_id="run-2")
    assert any(g.startswith("agent_factory_failed:") for g in run.coverage_gaps)
    failed = [r for r in run.results if r.get("synthetic_failure")]
    assert len(failed) == 1
    assert failed[0]["success"] is False
    assert failed[0]["score"] == 0.0
    # the failure counts against discovery (it must hurt the rate)
    bench = next(f for f in run.family_benchmarks if f.family == failed[0]["family"])
    assert bench.discovered == sum(
        1 for r in run.results if r["family"] == bench.family and r["success"]
    )


def test_run_is_deterministic_for_same_factory(library) -> None:
    from webpent.dojo.tournament import BUILTIN_AGENTS

    def factory() -> object:
        return BUILTIN_AGENTS["adaptive"]

    first = SelfBenchmark(library=library, agent_factory=factory).run(
        families=["info_disclosure"], run_id="same"
    )
    second = SelfBenchmark(library=library, agent_factory=factory).run(
        families=["info_disclosure"], run_id="same"
    )
    assert first.as_dict() == second.as_dict()


def test_family_filter_and_cap(library) -> None:
    from webpent.dojo.tournament import BUILTIN_AGENTS

    benchmark = SelfBenchmark(
        library=library, agent_factory=lambda: BUILTIN_AGENTS["adaptive"]
    )
    run = benchmark.run(families=["idor", "jwt"], max_scenarios=3, run_id="cap")
    assert len(run.results) == 3
    assert {r["family"] for r in run.results} <= {"idor", "jwt"}


# ---------------------------------------------------------------------------
# compare — regression semantics
# ---------------------------------------------------------------------------


def _run_with_rates(rates: dict[str, float], run_id: str) -> BenchmarkRun:
    from webpent.dojo.self_benchmark import FamilyBenchmark

    benches = [
        FamilyBenchmark(
            family=family,
            scenarios=10,
            discovered=round(rate * 10),
            discovery_rate=rate,
            avg_score=50.0,
            avg_time_steps=1.0,
            avg_requests=3.0,
            false_positive_rate=0.0,
        )
        for family, rate in rates.items()
    ]
    run = BenchmarkRun(run_id=run_id, executed_at="2026-11-04T00:00:00+00:00")
    run.family_benchmarks = benches
    run.results = [
        {"scenario_id": f"{f.family}-{i}", "family": f.family, "success": i < f.discovered,
         "score": 50.0, "requests_used": 3, "false_positives": 0, "time_steps": 1,
         "budget": 16, "synthetic_failure": False}
        for f in benches
        for i in range(10)
    ]
    return run


def test_compare_flags_dropped_family_as_regression() -> None:
    previous = _run_with_rates({"idor": 0.8, "jwt": 0.5}, "prev")
    current = _run_with_rates({"idor": 0.6, "jwt": 0.5}, "curr")
    trend = compare(current, previous)
    assert trend["regressions"] == ["idor"]
    assert trend["per_family"]["idor"]["delta"] == pytest.approx(-0.2)
    assert trend["per_family"]["jwt"]["delta"] == 0.0


def test_small_drop_within_tolerance_is_not_a_regression() -> None:
    previous = _run_with_rates({"idor": 0.8}, "prev")
    current = _run_with_rates({"idor": 0.75}, "curr")
    trend = compare(current, previous)
    assert trend["regressions"] == []
    assert trend["per_family"]["idor"]["delta"] == pytest.approx(-0.05)


def test_new_family_is_never_a_regression() -> None:
    previous = _run_with_rates({"idor": 0.8}, "prev")
    current = _run_with_rates({"idor": 0.0, "jwt": 0.0}, "curr")
    trend = compare(current, previous)
    # the NEW family (jwt) is never a regression — no baseline to drop from
    assert "jwt" not in trend["regressions"]
    assert trend["per_family"]["jwt"]["delta"] is None
    # but a known family dropping to zero IS one
    assert "idor" in trend["regressions"]
    assert trend["per_family"]["idor"]["delta"] == pytest.approx(-0.8)


def test_compare_without_previous_has_no_regressions() -> None:
    current = _run_with_rates({"idor": 0.3}, "first")
    trend = compare(current, None)
    assert trend["regressions"] == []
    assert trend["overall_delta"] is None
    assert trend["previous_run_id"] is None


# ---------------------------------------------------------------------------
# ledger — append-only history + dashboard curve
# ---------------------------------------------------------------------------


def test_ledger_appends_and_curves(tmp_path, library) -> None:
    from webpent.dojo.tournament import BUILTIN_AGENTS

    benchmark = SelfBenchmark(
        library=library, agent_factory=lambda: BUILTIN_AGENTS["adaptive"]
    )
    ledger = BenchmarkLedger(tmp_path / "selfbench.jsonl")
    first = benchmark.run(families=["idor"], run_id="night-1")
    second = benchmark.run(families=["idor"], run_id="night-2")
    ledger.append(first)
    ledger.append(second)

    history = ledger.history()
    assert [h["run_id"] for h in history] == ["night-1", "night-2"]
    curve = ledger.curve(family="idor")
    assert curve["labels"] == ["night-1", "night-2"]
    assert curve["overall"] == [first.overall_rate, second.overall_rate]
    assert curve["families"] == [
        first.family_benchmarks[0].discovery_rate,
        second.family_benchmarks[0].discovery_rate,
    ]
    assert ledger.latest()["run_id"] == "night-2"


def test_ledger_is_bounded_oldest_evicted(tmp_path, monkeypatch) -> None:
    import webpent.dojo.self_benchmark as mod

    ledger = BenchmarkLedger(tmp_path / "selfbench.jsonl")
    for i in range(MAX_LEDGER_RUNS + 5):
        run = _run_with_rates({"idor": 0.5}, f"r-{i}")
        ledger.append(run)
    history = ledger.history()
    assert len(history) == MAX_LEDGER_RUNS
    assert history[0]["run_id"] == "r-5"  # oldest five evicted
    assert history[-1]["run_id"] == f"r-{MAX_LEDGER_RUNS + 4}"


def test_ledger_fails_soft_on_corrupted_lines(tmp_path) -> None:
    path = tmp_path / "selfbench.jsonl"
    good = _run_with_rates({"idor": 0.5}, "good-1").as_summary()
    path.write_text(
        json.dumps(good) + "\n{not json\n" + json.dumps({}) + "\n", encoding="utf-8"
    )
    ledger = BenchmarkLedger(path)
    history = ledger.history()
    assert len(history) == 2
    curve = ledger.curve()
    assert curve["gaps"] == 1


def test_ledger_missing_file_is_empty_history(tmp_path) -> None:
    ledger = BenchmarkLedger(tmp_path / "absent.jsonl")
    assert ledger.history() == []
    assert ledger.latest() is None
    curve = ledger.curve()
    assert curve["labels"] == []
    assert curve["overall"] == []


def test_run_summary_projection_has_no_transcripts(tmp_path, library) -> None:
    from webpent.dojo.tournament import BUILTIN_AGENTS

    benchmark = SelfBenchmark(
        library=library, agent_factory=lambda: BUILTIN_AGENTS["adaptive"]
    )
    ledger = BenchmarkLedger(tmp_path / "selfbench.jsonl")
    summary = ledger.append(benchmark.run(families=["idor"], run_id="s1"))
    text = (tmp_path / "selfbench.jsonl").read_text(encoding="utf-8")
    assert "evidence" not in text  # no per-scenario transcripts on disk
    assert summary["scenarios"] == len(library.by_family("idor"))
    assert set(summary["families"]) == {"idor"}


def test_agent_factory_is_required(library) -> None:
    try:
        SelfBenchmark(library=library, agent_factory=None)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("agent_factory is required")
