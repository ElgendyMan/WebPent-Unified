from __future__ import annotations

from webpent.production.validators import (
    VALIDATORS,
    ValidationOutcome,
    validate_sqli,
    validate_xss,
)


def _ev(status: int, body: str = "", *, content_type: str = "text/html", **extra):
    return {
        "status_code": status,
        "response_body": body,
        "headers": {"content-type": content_type},
        **extra,
    }


def test_xss_unencoded_script_is_confirmed():
    payload = "<script>alert(1)</script>"
    result = validate_xss(
        baseline=_ev(200, "<html>safe</html>"),
        candidate=_ev(200, f"<html>{payload}</html>", structured_fields={"payload": payload}),
        negative_control=_ev(200, "<html>safe</html>", structured_fields={"payload": payload}),
    )
    assert result.outcome is ValidationOutcome.CONFIRMED
    assert result.details["reflection_context"] == "html_body"


def test_xss_encoded_script_is_refuted():
    payload = "<script>alert(1)</script>"
    result = validate_xss(
        baseline=_ev(200, "<html>safe</html>"),
        candidate=_ev(200, "<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>", structured_fields={"payload": payload}),
        negative_control=_ev(200, "<html>safe</html>", structured_fields={"payload": payload}),
    )
    assert result.outcome is ValidationOutcome.REFUTED


def test_xss_missing_reflection_is_inconclusive():
    payload = "webpent_xss_test_12345"
    result = validate_xss(
        baseline=_ev(200, "<html>safe</html>"),
        candidate=_ev(200, "<html>still safe</html>", structured_fields={"payload": payload}),
        negative_control=_ev(200, "<html>safe</html>", structured_fields={"payload": payload}),
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_xss_passive_marker_is_not_promoted_as_executable_xss():
    payload = "webpent_xss_probe_7f1"
    result = validate_xss(
        baseline=_ev(200, "<html>safe</html>"),
        candidate=_ev(200, f"<html>{payload}</html>", structured_fields={"payload": payload}),
        negative_control=_ev(200, "<html>safe</html>", structured_fields={"payload": payload}),
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_xss_comment_reflection_is_not_confirmed():
    payload = "webpent_xss_test_12345"
    result = validate_xss(
        baseline=_ev(200, "<html>safe</html>"),
        candidate=_ev(200, f"<!--{payload}-->", structured_fields={"payload": payload}),
        negative_control=_ev(200, "<html>safe</html>", structured_fields={"payload": payload}),
    )
    assert result.outcome is ValidationOutcome.REFUTED


def test_sqli_candidate_only_sqlstate_is_confirmed():
    result = validate_sqli(
        baseline=_ev(200, "login failed", content_type="application/json"),
        candidate=_ev(500, "SQLSTATE[42000]: syntax error", content_type="application/json"),
        negative_control=_ev(400, "invalid input", content_type="application/json"),
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_sqli_identical_response_is_refuted():
    result = validate_sqli(
        baseline=_ev(200, "no results", content_type="application/json"),
        candidate=_ev(200, "no results", content_type="application/json", structured_fields={"payload": "' OR '1'='1"}),
        negative_control=_ev(200, "no results", content_type="application/json"),
    )
    assert result.outcome is ValidationOutcome.REFUTED


def test_sqli_boolean_differential_is_confirmed():
    result = validate_sqli(
        baseline=_ev(200, "one result", content_type="application/json"),
        candidate=_ev(200, "many results " + ("x" * 200), content_type="application/json", structured_fields={"payload": "' OR '1'='1"}),
        negative_control=_ev(200, "one result", content_type="application/json"),
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_sqli_generic_response_differential_needs_clean_control():
    result = validate_sqli(
        baseline=_ev(200, "zero matches", content_type="text/plain"),
        candidate=_ev(200, "three matches: A B C", content_type="text/plain", structured_fields={"payload": "' OR 1=1--"}),
        negative_control=_ev(200, "zero matches", content_type="text/plain", structured_fields={"payload": "'"}),
    )
    assert result.outcome is ValidationOutcome.CONFIRMED


def test_sqli_differing_control_is_not_false_positive():
    result = validate_sqli(
        baseline=_ev(200, "zero matches", content_type="text/plain"),
        candidate=_ev(200, "three matches: A B C", content_type="text/plain", structured_fields={"payload": "' OR 1=1--"}),
        negative_control=_ev(200, "validation message", content_type="text/plain", structured_fields={"payload": "'"}),
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_sqli_ambiguous_difference_is_inconclusive():
    result = validate_sqli(
        baseline=_ev(200, "short", content_type="application/json"),
        candidate=_ev(200, "slightly different", content_type="application/json"),
        negative_control=_ev(200, "control", content_type="application/json"),
    )
    assert result.outcome is ValidationOutcome.INCONCLUSIVE


def test_xss_and_sqli_are_registered():
    assert "XSS" in VALIDATORS
    assert "SQLI" in VALIDATORS
