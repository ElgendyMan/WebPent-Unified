"""v83 T9 / U-CEM-9: the deployment rhythm detector."""

from __future__ import annotations

from datetime import datetime, timezone

from webpent.autonomous.cem.deployment_rhythm import (
    day_histogram,
    detect_deploys,
    hour_histogram,
    in_deploy_window,
    peak_day,
    peak_hour,
    regression_rate_after_deploys,
    rhythm_report,
)


def _ts(*args) -> float:
    return datetime(*args, tzinfo=timezone.utc).timestamp()


def _series(changes):
    """[(ts, hash)] -> snapshot-like series."""
    return [{"ts": ts, "hash": h} for ts, h in changes]


BASE = [(_ts(2023, 11, 6, 3), "h1"), (_ts(2023, 11, 6, 4), "h2"), (_ts(2023, 11, 6, 5), "h2")]


def test_detect_deploys_only_counts_transitions() -> None:
    deploys = detect_deploys(_series(BASE))
    assert deploys == [_ts(2023, 11, 6, 4)]
    # first snapshot alone is never a deploy
    assert detect_deploys(_series(BASE[:1])) == []


def test_hour_histogram_and_peak() -> None:
    deploys = [
        _ts(2023, 11, 6, 3), _ts(2023, 11, 13, 3),
        _ts(2023, 11, 6, 14),
    ]
    histogram = hour_histogram(deploys)
    assert histogram[3] == 2 and histogram[14] == 1
    assert sum(histogram) == 3
    assert peak_hour(deploys) == 3
    assert peak_hour([]) is None


def test_day_histogram_monday_indexed() -> None:
    deploys = [_ts(2023, 11, 6, 3), _ts(2023, 11, 7, 3), _ts(2023, 11, 13, 4)]
    histogram = day_histogram(deploys)
    assert histogram[0] == 2  # two Mondays
    assert histogram[1] == 1
    assert peak_day(deploys) == 0


def test_deploy_window_around_peak() -> None:
    deploys = [_ts(2023, 11, 6, 3), _ts(2023, 11, 13, 3)]
    assert in_deploy_window(_ts(2023, 11, 20, 3), deploys)
    assert in_deploy_window(_ts(2023, 11, 20, 4), deploys)  # +1 tolerance
    assert not in_deploy_window(_ts(2023, 11, 20, 12), deploys)
    assert not in_deploy_window(_ts(2023, 11, 20, 3), [])


def test_regression_rate_within_24h_window() -> None:
    deploys = [_ts(2023, 11, 6, 3), _ts(2023, 11, 7, 3), _ts(2023, 11, 8, 3)]
    regressions = [_ts(2023, 11, 6, 20), _ts(2023, 11, 9, 10)]  # after 1st and past window of 3rd
    rate = regression_rate_after_deploys(deploys, regressions)
    assert rate["deploys"] == 3
    assert rate["followed_by_regression"] == 1
    assert rate["rate"] == round(1 / 3, 3)


def test_garbage_inputs_degrade_to_empty() -> None:
    assert detect_deploys(None) == []
    assert detect_deploys("junk") == []
    assert detect_deploys([42, "x", {"ts": "no"}, {"hash": "h"}]) == []
    assert hour_histogram(None) == [0] * 24
    assert day_histogram(3.14) == [0] * 7
    assert regression_rate_after_deploys(None, None)["rate"] == 0.0


def test_rhythm_report_bounded_summary() -> None:
    report = rhythm_report(_series(BASE), regression_times=[_ts(2023, 11, 6, 10)])
    assert report["deploys_observed"] == 1
    assert len(report["hour_histogram"]) == 24
    assert len(report["day_histogram"]) == 7
    assert report["peak_hour_utc"] == 4
    assert report["advisory"] is True
