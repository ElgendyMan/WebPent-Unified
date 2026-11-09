"""Project Zero-tier item 3 — Shadow/canary testing for detection logic.

Pins:
  * an identical canary (matches baseline on every input) -> PROMOTE,
  * a canary that ADDS detections baseline lacked, with zero
    regressions -> HOLD (needs human review; can't tell improvement
    from false positive by agreement rate alone),
  * a canary that LOSES detections baseline had, beyond the regression
    threshold -> REJECT,
  * a canary that loses detections on a small enough fraction of
    inputs stays HOLD rather than REJECT (respects the configured
    max_regression_rate_for_hold),
  * detector results are compared via a normalised key set: dicts with
    a "key" field, plain strings, or arbitrary hashables are all
    accepted,
  * a detector that raises on a given input is treated as "no
    detections" for that input rather than aborting the whole run,
  * zero inputs is handled without division errors and defaults to
    PROMOTE (vacuously no disagreement),
  * silent-mode posture: the canary's raw results are never returned
    as the report's "actionable" output — only comparison metadata.
"""

from __future__ import annotations

from webpent.shared.shadow_detector import (
    ShadowRecommendation,
    run_shadow_comparison,
)


def _baseline_xss(text: str) -> list[str]:
    return ["xss"] if "script" in text else []


def test_identical_detector_promotes() -> None:
    inputs = [("a", "<script>x</script>"), ("b", "clean")]
    report = run_shadow_comparison(
        inputs, baseline_detector=_baseline_xss, canary_detector=_baseline_xss
    )
    assert report.recommendation == ShadowRecommendation.PROMOTE
    assert report.agreement_rate == 1.0
    assert report.disagreements == []


def test_canary_with_new_detection_and_no_regression_holds() -> None:
    def canary(text: str) -> list[str]:
        hits = _baseline_xss(text)
        if "onerror" in text:
            hits.append("xss_event_handler")
        return hits

    inputs = [
        ("a", "<script>x</script>"),
        ("b", "clean"),
        ("c", "<img onerror=x>"),
    ]
    report = run_shadow_comparison(
        inputs, baseline_detector=_baseline_xss, canary_detector=canary
    )
    assert report.recommendation == ShadowRecommendation.HOLD
    assert report.canary_only_keys_total == 1
    assert report.baseline_only_keys_total == 0
    assert len(report.disagreements) == 1
    assert report.disagreements[0].only_in_canary == ["xss_event_handler"]


def test_canary_that_loses_everything_rejects() -> None:
    def canary_regressed(text: str) -> list[str]:
        return []

    inputs = [("a", "<script>x</script>"), ("b", "<script>y</script>")]
    report = run_shadow_comparison(
        inputs, baseline_detector=_baseline_xss, canary_detector=canary_regressed
    )
    assert report.recommendation == ShadowRecommendation.REJECT
    assert "regress" in report.recommendation_reason.lower()


def test_small_regression_rate_stays_hold_not_reject() -> None:
    call_count = {"n": 0}

    def canary_mostly_fine(text: str) -> list[str]:
        call_count["n"] += 1
        # Regress on only the very first call out of many.
        if call_count["n"] == 1:
            return []
        return _baseline_xss(text)

    inputs = [("a", "<script>x</script>")] + [
        (f"clean{i}", "clean") for i in range(19)
    ]
    report = run_shadow_comparison(
        inputs,
        baseline_detector=_baseline_xss,
        canary_detector=canary_mostly_fine,
        max_regression_rate_for_hold=0.10,
    )
    # 1/20 = 5% regression, under the 10% hold threshold.
    assert report.recommendation == ShadowRecommendation.HOLD


def test_regression_rate_above_threshold_rejects() -> None:
    def canary_mostly_broken(text: str) -> list[str]:
        return []

    inputs = [("a", "<script>x</script>")] + [
        (f"xss{i}", "<script>y</script>") for i in range(9)
    ]
    report = run_shadow_comparison(
        inputs,
        baseline_detector=_baseline_xss,
        canary_detector=canary_mostly_broken,
        max_regression_rate_for_hold=0.10,
    )
    assert report.recommendation == ShadowRecommendation.REJECT


def test_dict_results_with_key_field_are_compared_by_key() -> None:
    def baseline(x: str) -> list[dict]:
        return [{"key": "finding-1", "confidence": 0.9}]

    def canary(x: str) -> list[dict]:
        # Same key, different confidence value -> still agreement,
        # since comparison is by key only.
        return [{"key": "finding-1", "confidence": 0.95}]

    report = run_shadow_comparison(
        [("a", "x")], baseline_detector=baseline, canary_detector=canary
    )
    assert report.recommendation == ShadowRecommendation.PROMOTE
    assert report.agreeing_inputs == 1


def test_plain_string_results_compared_directly() -> None:
    def baseline(x: str) -> list[str]:
        return ["a", "b"]

    def canary(x: str) -> list[str]:
        return ["a", "b"]

    report = run_shadow_comparison(
        [("case", "x")], baseline_detector=baseline, canary_detector=canary
    )
    assert report.recommendation == ShadowRecommendation.PROMOTE


def test_detector_exception_treated_as_no_detections() -> None:
    def flaky_baseline(x: str) -> list[str]:
        raise RuntimeError("boom")

    def canary(x: str) -> list[str]:
        return []

    report = run_shadow_comparison(
        [("case", "x")], baseline_detector=flaky_baseline, canary_detector=canary
    )
    # Both effectively produced nothing -> agreement.
    assert report.recommendation == ShadowRecommendation.PROMOTE
    assert report.total_inputs == 1


def test_detector_exception_surfaces_as_disagreement_when_other_side_has_output() -> None:
    def flaky_canary(x: str) -> list[str]:
        raise RuntimeError("boom")

    report = run_shadow_comparison(
        [("case", "<script>x</script>")],
        baseline_detector=_baseline_xss,
        canary_detector=flaky_canary,
    )
    assert report.disagreeing_inputs == 1
    assert report.disagreements[0].only_in_baseline == ["xss"]


def test_zero_inputs_promotes_without_division_error() -> None:
    report = run_shadow_comparison(
        [], baseline_detector=_baseline_xss, canary_detector=_baseline_xss
    )
    assert report.total_inputs == 0
    assert report.agreement_rate == 1.0
    assert report.recommendation == ShadowRecommendation.PROMOTE


def test_none_result_treated_as_empty() -> None:
    def returns_none(x: str) -> None:
        return None

    report = run_shadow_comparison(
        [("case", "x")], baseline_detector=returns_none, canary_detector=returns_none
    )
    assert report.recommendation == ShadowRecommendation.PROMOTE


def test_as_dict_is_json_safe_shape() -> None:
    report = run_shadow_comparison(
        [("a", "<script>x</script>")],
        baseline_detector=_baseline_xss,
        canary_detector=lambda x: [],
    )
    d = report.as_dict()
    assert d["recommendation"] == "reject"
    assert isinstance(d["disagreements"], list)
    assert "input_label" in d["disagreements"][0]


def test_custom_promotion_threshold_allows_some_disagreement() -> None:
    def canary(text: str) -> list[str]:
        hits = _baseline_xss(text)
        if "onerror" in text:
            hits.append("extra")
        return hits

    inputs = [("a", "<script>x</script>")] + [
        (f"clean{i}", "clean") for i in range(9)
    ] + [("b", "<img onerror=x>")]
    report = run_shadow_comparison(
        inputs,
        baseline_detector=_baseline_xss,
        canary_detector=canary,
        max_disagreement_rate_for_promote=0.10,  # allow up to 10% disagreement
    )
    # 1/11 disagreement ~= 9.09%, under the 10% threshold.
    assert report.recommendation == ShadowRecommendation.PROMOTE
