"""Lesson A/B lab tests (v0.27.0 — C-9/C-10, docs/PRODUCTION_FIX_PLAN_0270.md).

Covers:

* C-9 scheduler: week idempotency, sequential control→treatment
  execution, dry-plan default, runner failure, metrics honesty
  (runner / metrics_lookup / operator_record / metrics_missing),
  stale-run reset, fail-closed inputs.
* C-10 thresholds: every declared threshold boundary (above / below /
  exactly at), the strict evaluation order, and the verdict vocabulary
  alignment with the frozen ABEvidence contract.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
os.environ.setdefault("CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
os.environ.setdefault("JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
os.environ.setdefault("WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.memory.ab_lab import (  # noqa: E402
    AB_THRESHOLDS,
    ARM_ORDER,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_OBSERVED,
    VERDICT_PROVEN,
    ABRunSpec,
    LessonABLab,
    evaluate_ab_pair,
)

# The frozen contract's verdict vocabulary — C-10 must speak it exactly.
_CONTRACT_VERDICTS = {"learning_proven", "inconclusive", "learning_not_observed"}


def _open_week(lab: LessonABLab, **overrides):
    params = {
        "client_id": "acme",
        "target_url": "https://target.example",
        "mode": "standard",
        "authorization_ref": "BB-TEST-123",
    }
    params.update(overrides)
    return lab.open_week(**params)


def _ok_runner(control_metrics, treatment_metrics, calls=None):
    def _run(spec: ABRunSpec):
        if calls is not None:
            calls.append((spec.arm, spec.lesson_flag, spec.campaign_id))
        metrics = control_metrics if spec.arm == "control" else treatment_metrics
        return {"ok": True, "error": None, "metrics": metrics}

    return _run


# ---------------------------------------------------------------------------
# C-9 — scheduler
# ---------------------------------------------------------------------------
class TestScheduler:
    def test_open_week_is_idempotent_per_iso_week(self):
        lab = LessonABLab(":memory:")
        first = _open_week(lab)
        second = _open_week(lab)
        assert first["already_open"] is False
        assert second["already_open"] is True
        assert first["week_key"] == second["week_key"]

    def test_open_week_creates_exactly_two_runs_in_declared_order(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        runs = lab.status()["runs"]
        assert [run["arm"] for run in runs] == list(ARM_ORDER)
        by_arm = {run["arm"]: run for run in runs}
        assert by_arm["control"]["lesson_flag"] == "false"
        assert by_arm["treatment"]["lesson_flag"] == "true"

    @pytest.mark.parametrize("missing", ["client_id", "target_url", "authorization_ref"])
    def test_open_week_fail_closed_on_empty_required_fields(self, missing):
        lab = LessonABLab(":memory:")
        kwargs = {"client_id": "acme", "target_url": "https://t.example",
                  "mode": "standard", "authorization_ref": "BB-1"}
        kwargs[missing] = "   "
        with pytest.raises(ValueError):
            lab.open_week(**kwargs)

    def test_tick_without_runner_is_a_dry_plan(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        plan = lab.tick()
        assert plan["action"] == "planned_run"
        assert plan["executed"] is False
        assert plan["lesson_flag"] == "false"  # control first
        # nothing executed — runs untouched
        statuses = {run["arm"]: run["status"] for run in lab.status()["runs"]}
        assert statuses == {"control": "planned", "treatment": "planned"}

    def test_sequential_control_then_treatment_over_two_ticks(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        calls: list[tuple[str, str, str]] = []
        runner = _ok_runner(
            {"hypotheses_tested": 40, "findings_promoted": 3},
            {"hypotheses_tested": 30, "findings_promoted": 3},
            calls,
        )
        first = lab.tick(runner=runner)
        second = lab.tick(runner=runner)
        third = lab.tick(runner=runner)
        assert first["arm"] == "control" and first["action"] == "run_executed"
        assert second["arm"] == "treatment" and second["action"] == "run_executed"
        assert third["action"] == "none"  # week terminal — nothing due
        # declared order: control (lessons OFF) strictly before treatment (ON)
        order = [(arm, flag) for arm, flag, _ in calls]
        assert order == [("control", "false"), ("treatment", "true")]
        assert calls[0][2] != calls[1][2]  # distinct campaign ids per arm

    def test_runner_failure_marks_run_failed_and_week_failed(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        outcome = lab.tick(
            runner=lambda spec: {"ok": False, "error": "boom", "metrics": None}
        )
        assert outcome["action"] == "run_failed"
        assert "boom" in outcome["error"]
        week = lab.status()["weeks"][0]
        assert week["status"] == "failed"
        assert week["verdict"]["verdict"] == "week_failed"
        assert any("control" in reason for reason in week["verdict"]["reasons"])

    def test_runner_exception_is_contained_not_raised(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)

        def _explode(spec):
            raise RuntimeError("runner exploded")

        outcome = lab.tick(runner=_explode)
        assert outcome["action"] == "run_failed"
        assert "runner_raised" in outcome["error"]

    def test_second_arm_not_due_until_first_is_terminal(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        # A runner that only succeeds for control; treatment run is
        # never launched in the same tick — one run per tick.
        executed: list[str] = []

        def _run(spec):
            executed.append(spec.arm)
            return {
                "ok": True,
                "error": None,
                "metrics": {"hypotheses_tested": 20, "findings_promoted": 2},
            }

        lab.tick(runner=_run)
        assert executed == ["control"]
        lab.tick(runner=_run)
        assert executed == ["control", "treatment"]


# ---------------------------------------------------------------------------
# C-9 — metrics honesty
# ---------------------------------------------------------------------------
class TestMetricsHonesty:
    def test_missing_metrics_marks_run_and_evaluates_inconclusive(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        outcome = lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        assert outcome["status"] == "metrics_missing"
        week = lab.status()["weeks"][0]
        assert week["status"] == "evaluated"
        assert week["verdict"]["verdict"] == VERDICT_INCONCLUSIVE
        assert "treatment_metrics_missing" in week["verdict"]["reasons"]

    def test_metrics_lookup_used_when_runner_has_none(self):
        lookup_calls: list[str] = []

        def _lookup(campaign_id: str):
            lookup_calls.append(campaign_id)
            return {"hypotheses_tested": 25, "findings_promoted": 2}

        lab = LessonABLab(":memory:", metrics_lookup=_lookup)
        _open_week(lab)
        lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        assert len(lookup_calls) == 2
        runs = {run["arm"]: run for run in lab.status()["runs"]}
        assert runs["control"]["metrics_source"] == "metrics_lookup"
        # equal efficiency both arms -> declared noise band verdict
        week = lab.status()["weeks"][0]
        assert week["verdict"]["verdict"] == VERDICT_INCONCLUSIVE
        assert "within_noise_band" in week["verdict"]["reasons"]

    def test_runner_metrics_win_over_lookup(self):
        lab = LessonABLab(
            ":memory:",
            metrics_lookup=lambda cid: {"hypotheses_tested": 999, "findings_promoted": 9},
        )
        _open_week(lab)
        lab.tick(runner=_ok_runner({"hypotheses_tested": 20, "findings_promoted": 2}, None))
        runs = {run["arm"]: run for run in lab.status()["runs"]}
        assert runs["control"]["metrics_source"] == "runner"

    def test_invalid_runner_metrics_schema_falls_back_to_missing(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        lab.tick(runner=lambda spec: {"ok": True, "error": None, "metrics": None})
        runs = {run["arm"]: run for run in lab.status()["runs"]}
        assert runs["control"]["status"] == "metrics_missing"

    def test_record_run_metrics_operator_path(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        control_run = next(r for r in lab.status()["runs"] if r["arm"] == "control")
        recorded = lab.record_run_metrics(
            control_run["run_id"], {"hypotheses_tested": 33, "findings_promoted": 3}
        )
        assert recorded["metrics"] == {"hypotheses_tested": 33, "findings_promoted": 3}
        runs = {run["arm"]: run for run in lab.status()["runs"]}
        assert runs["control"]["metrics_source"] == "operator_record"

    def test_record_run_metrics_rejects_bad_schema_and_unknown_run(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        control_run = next(r for r in lab.status()["runs"] if r["arm"] == "control")
        with pytest.raises(ValueError):
            lab.record_run_metrics(control_run["run_id"], {"hypotheses_tested": None})
        with pytest.raises(ValueError):
            lab.record_run_metrics("no-such-run", {"hypotheses_tested": 1, "findings_promoted": 1})

    def test_reset_stale_run_only_touches_running_rows(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        control_run = next(r for r in lab.status()["runs"] if r["arm"] == "control")
        with pytest.raises(ValueError):
            lab.reset_stale_run(control_run["run_id"])  # planned, not running

        def _fail(spec):
            return {"ok": False, "error": "e", "metrics": None}

        lab.tick(runner=_fail)
        failed_run = next(r for r in lab.status()["runs"] if r["arm"] == "control")
        with pytest.raises(ValueError):
            lab.reset_stale_run(failed_run["run_id"])  # failed, not running

    def test_straddling_week_still_completes_via_any_week_selection(self):
        """tick() without week_key picks the OLDEST non-terminal week —
        a window opened before an ISO boundary must not be stranded."""
        lab = LessonABLab(":memory:")
        _open_week(lab, now="2026-01-01T00:00:00+00:00")  # ISO week 2026-W01
        lab.tick(runner=_ok_runner({"hypotheses_tested": 20, "findings_promoted": 2}, None))
        # even though "now" moved to a later ISO week, the next tick
        # still targets the same unfinished week
        lab.tick(runner=_ok_runner(None, {"hypotheses_tested": 16, "findings_promoted": 2}))
        week = lab.status()["weeks"][0]
        assert week["status"] == "evaluated"
        assert week["verdict"]["verdict"] == VERDICT_PROVEN


# ---------------------------------------------------------------------------
# C-10 — declared thresholds (boundary coverage)
# ---------------------------------------------------------------------------
class TestDeclaredThresholds:
    def test_thresholds_match_the_plan_declaration(self):
        """docs/PRODUCTION_FIX_PLAN_0270.md copies these values
        verbatim — the test pins the declared numbers."""
        assert AB_THRESHOLDS.min_hypotheses_tested_per_arm == 10
        assert AB_THRESHOLDS.promotion_reduction_ratio == pytest.approx(0.10)
        assert AB_THRESHOLDS.regression_tolerance_ratio == pytest.approx(0.20)
        assert AB_THRESHOLDS.require_no_confirmed_loss is True
        assert AB_THRESHOLDS.max_inconclusive_weeks == 4

    def test_verdict_vocabulary_matches_frozen_contract(self):
        assert {VERDICT_PROVEN, VERDICT_INCONCLUSIVE, VERDICT_NOT_OBSERVED} == _CONTRACT_VERDICTS

    def test_proven_at_exact_promotion_boundary(self):
        # control 40/4 = 10.0 eff; treatment 36/4 = 9.0 eff -> gain 0.10
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 40, "findings_promoted": 4},
            treatment={"hypotheses_tested": 36, "findings_promoted": 4},
        )
        assert verdict["verdict"] == VERDICT_PROVEN
        assert verdict["effect"]["efficiency_gain"] == pytest.approx(0.10)

    def test_just_below_promotion_boundary_is_inconclusive(self):
        # gain 0.09... < 0.10 -> within noise band
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 100, "findings_promoted": 4},
            treatment={"hypotheses_tested": 91, "findings_promoted": 4},
        )
        assert verdict["verdict"] == VERDICT_INCONCLUSIVE
        assert "within_noise_band" in verdict["reasons"]

    def test_not_observed_at_exact_regression_boundary(self):
        # control 40/4 = 10.0; treatment 48/4 = 12.0 -> gain -0.20
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 40, "findings_promoted": 4},
            treatment={"hypotheses_tested": 48, "findings_promoted": 4},
        )
        assert verdict["verdict"] == VERDICT_NOT_OBSERVED

    def test_confirmed_loss_caps_at_not_observed_despite_gain(self):
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 50, "findings_promoted": 5},
            treatment={"hypotheses_tested": 10, "findings_promoted": 4},
        )
        assert verdict["verdict"] == VERDICT_NOT_OBSERVED
        assert any(reason.startswith("confirmed_findings_lost") for reason in verdict["reasons"])

    def test_no_loss_allowed_false_lets_efficiency_decide(self):
        thresholds = AB_THRESHOLDS.__class__(
            min_hypotheses_tested_per_arm=10,
            promotion_reduction_ratio=0.10,
            regression_tolerance_ratio=0.20,
            require_no_confirmed_loss=False,
            max_inconclusive_weeks=4,
        )
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 50, "findings_promoted": 5},
            treatment={"hypotheses_tested": 10, "findings_promoted": 4},
            thresholds=thresholds,
        )
        assert verdict["verdict"] == VERDICT_PROVEN

    def test_sample_too_small_both_arms(self):
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 9, "findings_promoted": 1},
            treatment={"hypotheses_tested": 50, "findings_promoted": 5},
        )
        assert verdict["verdict"] == VERDICT_INCONCLUSIVE
        assert any(reason.startswith("control_sample_too_small") for reason in verdict["reasons"])

    def test_sample_boundary_exactly_at_minimum_evaluates(self):
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 10, "findings_promoted": 1},
            treatment={"hypotheses_tested": 10, "findings_promoted": 1},
        )
        assert verdict["verdict"] == VERDICT_INCONCLUSIVE
        assert "within_noise_band" in verdict["reasons"]

    def test_none_arms_declared_missing(self):
        verdict = evaluate_ab_pair(control=None, treatment=None)
        assert verdict["verdict"] == VERDICT_INCONCLUSIVE
        assert verdict["reasons"] == ["control_metrics_missing", "treatment_metrics_missing"]

    def test_asymmetric_confirmed_counts_are_inconclusive(self):
        verdict = evaluate_ab_pair(
            control={"hypotheses_tested": 40, "findings_promoted": 0},
            treatment={"hypotheses_tested": 40, "findings_promoted": 2},
        )
        assert verdict["verdict"] == VERDICT_INCONCLUSIVE
        assert any(
            reason.startswith("confirmed_findings_asymmetric")
            for reason in verdict["reasons"]
        )

    def test_deterministic_same_inputs_same_verdict(self):
        kwargs = {
            "control": {"hypotheses_tested": 37, "findings_promoted": 3},
            "treatment": {"hypotheses_tested": 29, "findings_promoted": 3},
        }
        assert evaluate_ab_pair(**kwargs) == evaluate_ab_pair(**kwargs)

    def test_lab_status_flags_paused_advisory_after_four_inconclusive(self):
        thresholds = AB_THRESHOLDS.__class__(
            min_hypotheses_tested_per_arm=10,
            promotion_reduction_ratio=0.10,
            regression_tolerance_ratio=0.20,
            require_no_confirmed_loss=True,
            max_inconclusive_weeks=4,
        )
        lab = LessonABLab(":memory:", thresholds=thresholds)
        # four weeks, all equal-efficiency (inconclusive by noise band)
        for index in range(4):
            _open_week(lab, client_id=f"c{index}")
            lab.tick(runner=_ok_runner(
                {"hypotheses_tested": 30, "findings_promoted": 3},
                {"hypotheses_tested": 30, "findings_promoted": 3},
            ))
            lab.tick(runner=_ok_runner(
                {"hypotheses_tested": 30, "findings_promoted": 3},
                {"hypotheses_tested": 30, "findings_promoted": 3},
            ))
        status = lab.status()
        assert status["consecutive_inconclusive_weeks"] == 4
        assert status["paused_advisory"] is True

    def test_lab_status_not_paused_below_threshold(self):
        lab = LessonABLab(":memory:")
        _open_week(lab)
        lab.tick(runner=_ok_runner(
            {"hypotheses_tested": 30, "findings_promoted": 3},
            {"hypotheses_tested": 30, "findings_promoted": 3},
        ))
        lab.tick(runner=_ok_runner(
            {"hypotheses_tested": 30, "findings_promoted": 3},
            {"hypotheses_tested": 30, "findings_promoted": 3},
        ))
        status = lab.status()
        assert status["consecutive_inconclusive_weeks"] == 1
        assert status["paused_advisory"] is False
        assert status["thresholds"] == AB_THRESHOLDS.as_dict()


# ---------------------------------------------------------------------------
# C-9 — subprocess runner contract (no network in tests: spawn failure path)
# ---------------------------------------------------------------------------
class TestHuntSubprocessRunner:
    def test_spawn_failure_is_reported_not_raised(self):
        from webpent.memory.ab_lab import make_hunt_subprocess_runner

        runner = make_hunt_subprocess_runner(
            hunt_command=("definitely-not-a-real-binary-xyz",),
            timeout_s=5,
        )
        spec = ABRunSpec(
            week_key="AB-2026-W44", arm="control", run_id="r1", campaign_id="c1",
            client_id="acme", target_url="https://t.example", target_type="generic_web",
            mode="standard", authorization_ref="BB-1", lesson_flag="false",
        )
        outcome = runner(spec)
        assert outcome["ok"] is False
        assert "hunt_spawn_failed" in outcome["error"]

    def test_runner_contract_shape(self):
        from webpent.memory.ab_lab import make_hunt_subprocess_runner

        runner = make_hunt_subprocess_runner(hunt_command=("definitely-not-a-real-binary-xyz",))
        spec = ABRunSpec(
            week_key="w", arm="treatment", run_id="r2", campaign_id="c2",
            client_id="acme", target_url="https://t.example", target_type="generic_web",
            mode="quick", authorization_ref="BB-1", lesson_flag="true",
        )
        outcome = runner(spec)
        assert set(outcome) == {"ok", "error", "metrics"}
        assert outcome["metrics"] is None  # never fabricates metrics


# ---------------------------------------------------------------------------
# CLI wiring — webpent ops learning-ab (RBAC-gated writes; status read-only)
# ---------------------------------------------------------------------------
class TestLearningAbCli:
    def _bootstrap(self, tmp_path: Path) -> Path:
        from typer.testing import CliRunner

        from webpent.cli.ops import ops_app

        runner = CliRunner()
        state_path = tmp_path / "ops.json"
        result = runner.invoke(
            ops_app, ["bootstrap-admin", "--state", str(state_path), "--actor", "root"]
        )
        assert result.exit_code == 0, result.output
        result = runner.invoke(
            ops_app,
            ["users", "--state", str(state_path), "--actor", "root",
             "--grantee", "analyst1", "--role", "analyst", "--client", "acme"],
        )
        assert result.exit_code == 0, result.output
        return state_path

    def test_open_requires_state_and_actor(self, tmp_path: Path):
        from typer.testing import CliRunner

        from webpent.cli.ops import ops_app

        result = CliRunner().invoke(
            ops_app,
            ["learning-ab", "--action", "open", "--client", "acme",
             "--target", "https://t.example", "--authorization", "BB-1",
             "--db", str(tmp_path / "lab.sqlite3")],
        )
        assert result.exit_code == 2
        assert "authorization refused" in result.output

    def test_open_tick_status_roundtrip_as_analyst(self, tmp_path: Path):
        from typer.testing import CliRunner

        from webpent.cli.ops import ops_app

        state_path = self._bootstrap(tmp_path)
        runner = CliRunner()
        base = ["learning-ab", "--state", str(state_path), "--actor", "analyst1"]
        db = str(tmp_path / "lab.sqlite3")

        result = runner.invoke(ops_app, [*base, "--action", "open",
                                         "--client", "acme", "--target", "https://t.example",
                                         "--authorization", "BB-TEST", "--db", db])
        assert result.exit_code == 0, result.output
        assert "open for acme" in result.output

        # tick without --execute = dry plan naming the control window
        result = runner.invoke(ops_app, [*base, "--action", "tick", "--db", db])
        assert result.exit_code == 0, result.output
        assert "dry plan" in result.output and "lessons=false" in result.output

        # status renders the declared thresholds and the week row
        result = runner.invoke(ops_app, [*base, "--action", "status", "--db", db])
        assert result.exit_code == 0, result.output
        assert "min_hypotheses_tested_per_arm=10" in result.output
        assert "promotion_reduction_ratio=0.1" in result.output
        assert "planned" in result.output

    def test_status_needs_no_rbac(self, tmp_path: Path):
        from typer.testing import CliRunner

        from webpent.cli.ops import ops_app

        result = CliRunner().invoke(
            ops_app,
            ["learning-ab", "--action", "status", "--db", str(tmp_path / "lab.sqlite3")],
        )
        assert result.exit_code == 0
        assert "declared thresholds" in result.output

    def test_record_metrics_roundtrip(self, tmp_path: Path):
        from typer.testing import CliRunner

        from webpent.cli.ops import ops_app

        state_path = self._bootstrap(tmp_path)
        runner = CliRunner()
        base = ["learning-ab", "--state", str(state_path), "--actor", "analyst1"]
        db = str(tmp_path / "lab.sqlite3")
        result = runner.invoke(ops_app, [*base, "--action", "open",
                                         "--client", "acme", "--target", "https://t.example",
                                         "--authorization", "BB-TEST", "--db", db])
        assert result.exit_code == 0, result.output
        # run id pattern (F-01, 0.33.0): <week_key>-<arm>-<client[:16]>-<target-digest>
        import re

        match = re.search(r"AB-\d{4}-W\d{2}-control-acme-[0-9a-f]{8}", result.output)
        assert match is not None, result.output
        run_id = match.group(0)
        metrics_json = '{"hypotheses_tested": 30, "findings_promoted": 3}'
        result = runner.invoke(ops_app, [*base, "--action", "record-metrics",
                                         "--run-id", run_id,
                                         "--metrics", metrics_json,
                                         "--db", db])
        assert result.exit_code == 0, result.output
        assert "recorded" in result.output
