"""U-9 de-DVWA + A/B instrument tests.

Restored after the workspace reset. 7 tests covering two related
de-biasing invariants:

  * DVWA literals stripped (5 tests): the generic hypothesis producers
    must NOT depend on DVWA-specific route vocabulary. A structurally
    rich target with zero DVWA-shaped segments must still receive
    diverse, parameter-shaped coverage; the producer tables themselves
    must contain no DVWA literals.
  * A/B instrument (2 tests): the AVI validator framework instruments
    an A/B/C (baseline / candidate / negative_control) causal triple
    and refuses to confirm when any arm is missing — the framework
    fails closed rather than silently degrading to a single-arm probe.
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

from webpent.agents.hypothesis_analyzer.agent import (  # noqa: E402
    _generic_form_field_hypotheses,
    _generic_parameter_hypotheses,
    _generic_path_parameter_hypotheses,
)
from webpent.production.validators import (  # noqa: E402
    ValidatorError,
    validate_ssrf,
)


# ---------------------------------------------------------------------------
# DVWA literals stripped (5 tests)
# ---------------------------------------------------------------------------
_DVWA_LITERALS = (
    "dvwa",
    "sqli_blind",
    "xss_r",
    "xss_s",
    "xss_d",
    "weak_id",
    "open_redirect/",
    "vulnerabilities/",
)


def test_generic_parameter_producers_contain_no_dvwa_literals():
    """The parameter-name signal table contains no DVWA-specific vocabulary."""
    from webpent.agents.hypothesis_analyzer import agent as ha

    corpus = " ".join(fragment for fragment, _, _ in ha._PARAM_NAME_SIGNALS).lower()
    for literal in _DVWA_LITERALS:
        assert literal not in corpus, (
            f"_PARAM_NAME_SIGNALS contains target-specific literal {literal!r}"
        )


def test_generic_form_field_producers_contain_no_dvwa_literals():
    """The form-field signal table contains no DVWA-specific vocabulary."""
    from webpent.agents.hypothesis_analyzer import agent as ha

    corpus = " ".join(fragment for fragment, _, _ in ha._FORM_FIELD_SIGNALS).lower()
    for literal in _DVWA_LITERALS:
        assert literal not in corpus, (
            f"_FORM_FIELD_SIGNALS contains target-specific literal {literal!r}"
        )


def test_rest_api_target_without_dvwa_routes_yields_hypotheses():
    """A structurally rich REST API URL (no DVWA segments) yields IDOR
    via the UUID path parameter producer, without depending on any
    DVWA-shaped route vocabulary.
    """
    url = (
        "http://10.20.30.40:8080/api/v2/customers/"
        "550e8400-e29b-41d4-a716-446655440000?expand=profile"
    )
    # Query-param producer: ``expand`` is structure-only — no DVWA literal.
    param_hits = _generic_parameter_hypotheses(url)
    # Path-param producer: the UUID resource identifier yields IDOR.
    path_hits = _generic_path_parameter_hypotheses(url)
    path_classes = {c for c, _, _ in path_hits}
    assert "idor" in path_classes, (
        "UUID resource identifier in path must yield an IDOR hypothesis "
        "without any DVWA route segment"
    )
    # Sanity: no DVWA literal in either producer's reason text.
    for _, reason, _ in path_hits + param_hits:
        assert not any(lit in reason.lower() for lit in _DVWA_LITERALS), (
            f"producer reason contains a DVWA literal: {reason!r}"
        )


def test_path_parameter_producer_does_not_depend_on_dvwa_segments():
    """``/orders/12345/`` (no DVWA segment) yields a SQLi path hypothesis."""
    hits = _generic_path_parameter_hypotheses("https://app.internal/orders/12345/")
    assert {c for c, _, _ in hits} == {"sqli"}


def test_negative_control_meaningless_param_yields_nothing():
    """A meaningless parameter (``?rapid=1``) yields NO hypothesis — the
    producers do not invent DVWA-shaped structure where none exists.
    """
    assert _generic_parameter_hypotheses("https://app.internal/?rapid=1") == []


# ---------------------------------------------------------------------------
# A/B instrument (2 tests)
# ---------------------------------------------------------------------------
class TestAbInstrument:
    """The AVI validator framework instruments an A/B/C causal triple."""

    def test_validator_requires_all_three_arms(self):
        """Missing any of baseline / candidate / negative_control fails
        closed with ``ValidatorError`` rather than silently degrading.
        """
        with pytest.raises(ValidatorError):
            validate_ssrf(baseline=None, candidate={}, negative_control={})
        with pytest.raises(ValidatorError):
            validate_ssrf(baseline={}, candidate=None, negative_control={})
        with pytest.raises(ValidatorError):
            validate_ssrf(baseline={}, candidate={}, negative_control=None)

    def test_validator_distinctly_tracks_each_arm_evidence(self):
        """Each arm's evidence is preserved distinctly in the result — the
        A/B/C instrumentation does not collapse arms into a single blob.
        """
        b = {"status_code": 200, "response_body": '{"ok":true}', "headers": {}}
        c = {
            "status_code": 200,
            "response_body": '{"metadata":{"iam":"role"},"internal-ip":"10.0.0.1"}',
            "headers": {},
        }
        nc = {"status_code": 400, "response_body": '{"error":"bad scheme"}', "headers": {}}
        result = validate_ssrf(baseline=b, candidate=c, negative_control=nc)
        # The three arms are preserved distinctly on the result object.
        assert result.baseline_evidence == b
        assert result.candidate_evidence == c
        assert result.negative_control_evidence == nc
        # And the validator's discriminating signal references the
        # candidate arm specifically (not a single-arm probe).
        assert "indicator" in result.discriminating_signal
