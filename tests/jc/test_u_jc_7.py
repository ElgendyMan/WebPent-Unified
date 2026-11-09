"""U-JC-7: the Confidence Calibrator — Brier score, drift, min-sample guard."""

from __future__ import annotations

import pytest

from webpent.jc.calibration import (
    DRIFT_THRESHOLD,
    MIN_SAMPLES,
    ConfidenceCalibrator,
)

TS = 1_800_000_000.0


def feed(calibrator, predicted, actual, n=MIN_SAMPLES, base=TS):
    for i in range(n):
        calibrator.record(predicted, actual, ts=base + i)


def test_record_appends(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    calibrator.record(0.8, True, ts=TS)
    assert len((tmp_path / "cal.jsonl").read_text().splitlines()) == 1


def test_report_empty(tmp_path):
    report = ConfidenceCalibrator(tmp_path / "cal.jsonl").report(now_ts=TS)
    assert report.n_samples == 0
    assert report.brier_score == 0.0
    assert "no calibration data" in report.recommendation


def test_brier_perfect_predictions(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    for i in range(10):
        calibrator.record(1.0, True, ts=TS + i)
        calibrator.record(0.0, False, ts=TS + 10 + i)
    report = calibrator.report(now_ts=TS + 100)
    assert report.brier_score == pytest.approx(0.0)
    assert report.n_samples == 20


def test_brier_worst_predictions(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    for i in range(10):
        calibrator.record(1.0, False, ts=TS + i)
        calibrator.record(0.0, True, ts=TS + 10 + i)
    report = calibrator.report(now_ts=TS + 100)
    assert report.brier_score == pytest.approx(1.0)


def test_min_samples_guard_blocks_adjust(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    feed(calibrator, 0.9, False, n=MIN_SAMPLES - 1)
    assert calibrator.adjust(0.9, now_ts=TS) == 0.9


def test_adjust_shifts_after_minimum(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    feed(calibrator, 0.9, False, n=MIN_SAMPLES)
    assert calibrator.adjust(0.9, now_ts=TS) == pytest.approx(0.0)


def test_adjust_clamped(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    for i in range(MIN_SAMPLES):
        calibrator.record(0.0, True, ts=TS + i)
    assert calibrator.adjust(0.2, now_ts=TS) == pytest.approx(1.0)


def test_drift_detected(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    feed(calibrator, 0.9, False, n=MIN_SAMPLES)
    report = calibrator.report(now_ts=TS + 100)
    assert report.drift_detected
    assert report.mean_predicted - report.mean_actual > DRIFT_THRESHOLD
    assert "drift" in report.recommendation


def test_no_drift_when_aligned(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    # mean predicted 0.5, mean actual 0.5: perfectly aligned
    for i in range(MIN_SAMPLES):
        calibrator.record(0.5, i % 2 == 0, ts=TS + i)
    report = calibrator.report(now_ts=TS + 100)
    assert not report.drift_detected
    assert "no action" in report.recommendation


def test_buckets_structure(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    feed(calibrator, 0.95, True, n=MIN_SAMPLES)
    report = calibrator.report(now_ts=TS + 100)
    bucket = report.buckets["0.9-1.0"]
    assert bucket["n"] == 20
    assert bucket["predicted"] == pytest.approx(0.95)
    assert bucket["actual"] == pytest.approx(1.0)


def test_window_excludes_old_records(tmp_path):
    calibrator = ConfidenceCalibrator(tmp_path / "cal.jsonl")
    feed(calibrator, 0.9, False, n=MIN_SAMPLES, base=TS - 60 * 86400)
    report = calibrator.report(window_days=30, now_ts=TS)
    assert report.n_samples == 0


def test_corrupt_lines_ignored(tmp_path):
    (tmp_path / "cal.jsonl").write_text("garbage\n")
    report = ConfidenceCalibrator(tmp_path / "cal.jsonl").report(now_ts=TS)
    assert report.n_samples == 0
