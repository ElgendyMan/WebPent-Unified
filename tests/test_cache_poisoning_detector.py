"""Tests for the deterministic cache-poisoning / cache-deception
analyzer (Ultimate plan 2026-10-27, proposal 7 phase 2).

Mirrors the structure of ``tests/test_tech_stack_cve.py`` — the pure
detector over injected response evidence. Every fixture is a captured
response record of the documented shape
``{"url", "status", "headers" (lowercased), "body"}``; no network is
ever touched (the analyzer is pure by design).
"""

from __future__ import annotations

from webpent.production.validators import EvidenceQuality, ValidationOutcome
from webpent.shared.cache_poisoning_detector import (
    analyze_cache_behavior,
    cache_poisoning_detection_enabled,
    detect_web_cache_deception,
)

BASELINE = {
    "url": "https://target.test/",
    "status": 200,
    "headers": {"cache-control": "max-age=60", "content-type": "text/html"},
    "body": "<html><body>Welcome to the real site</body></html>",
}


def _reflected_probe(*, cache_control: str = "max-age=60", body: str | None = None) -> dict:
    """A probe response where X-Forwarded-Host reached the rendered body."""
    return {
        "url": "https://target.test/",
        "status": 200,
        "headers": {"cache-control": cache_control, "content-type": "text/html"},
        "body": body
        if body is not None
        else "<html><body>Canonical host: poison-canary.example</body></html>",
        "probe_header": "X-Forwarded-Host",
        "probe_value": "poison-canary.example",
    }


# ---------------------------------------------------------------------------
# analyze_cache_behavior — verdict discipline
# ---------------------------------------------------------------------------


def test_confirmed_when_unkeyed_header_reflected_in_cacheable_response():
    analysis = analyze_cache_behavior([_reflected_probe()], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.CONFIRMED
    assert analysis.verdict.vulnerability_class == "cache_poisoning"
    assert analysis.verdict.evidence_quality is EvidenceQuality.OBSERVED_DIFFERENTIAL
    assert analysis.verdict.is_confirmation_grade() is True
    assert analysis.cacheable is True
    assert analysis.signals, "a reflected unkeyed header must produce a signal"
    signal = analysis.signals[0]
    assert signal.signal_type == "unkeyed_header_reflection"
    assert signal.header == "x-forwarded-host"
    assert signal.reflected_in_body is True
    assert signal.body_changed_vs_baseline is True
    # The refutation path must be present on a confirmation-grade result.
    assert analysis.verdict.refutation_path


def test_inconclusive_when_no_cache_headers_at_all():
    probe = _reflected_probe()
    probe["headers"] = {"content-type": "text/html"}  # no Cache-Control, no Age
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.INCONCLUSIVE
    assert analysis.verdict.details["reason"] == "no-cache-headers"
    assert analysis.cacheable is False


def test_inconclusive_when_cache_control_forbids_storage_with_reflection():
    # Cache-Control: no-cache IS a cache header (so not the "no cache
    # headers" branch) but the response is not cacheable — the
    # reflection alone cannot confirm poisoning.
    probe = _reflected_probe(cache_control="no-cache, no-store")
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.INCONCLUSIVE
    assert analysis.verdict.details["reason"] == "reflection-without-differential"
    assert analysis.cacheable is False


def test_refuted_when_cache_present_but_no_reflection():
    probe = {
        "url": "https://target.test/",
        "status": 200,
        "headers": {"cache-control": "max-age=60", "content-type": "text/html"},
        "body": "<html><body>Welcome to the real site</body></html>",
        "probe_header": "X-Forwarded-Host",
        "probe_value": "poison-canary.example",  # never reflected anywhere
    }
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.REFUTED
    assert analysis.verdict.details["reason"] == "cache-present-no-reflection"
    assert analysis.cacheable is True


def test_inconclusive_without_baseline_even_with_full_reflection():
    analysis = analyze_cache_behavior([_reflected_probe()], None)
    assert analysis.verdict.outcome is ValidationOutcome.INCONCLUSIVE
    assert analysis.verdict.details["reason"] == "reflection-without-differential"


def test_inconclusive_when_reflected_body_matches_baseline():
    # The canary appears in BOTH the baseline and the probe body — the
    # unkeyed header did not actually change the render.
    shared_body = "<html>poison-canary.example appears here too</html>"
    baseline = dict(BASELINE, body=shared_body)
    probe = _reflected_probe(body=shared_body)
    analysis = analyze_cache_behavior([probe], baseline)
    assert analysis.verdict.outcome is ValidationOutcome.INCONCLUSIVE


def test_age_header_alone_proves_cacheability():
    probe = _reflected_probe()
    probe["headers"] = {"age": "42", "content-type": "text/html"}
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert analysis.cacheable is True
    assert analysis.verdict.outcome is ValidationOutcome.CONFIRMED


def test_header_only_echo_is_a_signal_but_never_a_confirmation():
    probe = {
        "url": "https://target.test/",
        "status": 200,
        "headers": {
            "cache-control": "max-age=60",
            "x-forwarded-host": "poison-canary.example",  # echoed, not rendered
        },
        "body": "<html><body>Welcome to the real site</body></html>",
    }
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.REFUTED
    assert analysis.signals[0].signal_type == "unkeyed_header_echo"
    assert analysis.signals[0].reflected_in_body is False


def test_header_values_are_bounded_to_512_chars():
    huge = "a" * 5000
    probe = {
        "url": "https://target.test/",
        "status": 200,
        "headers": {"cache-control": "max-age=60"},
        "body": f"<html>{huge}</html>",
        "probe_header": "X-Forwarded-Host",
        "probe_value": huge,
    }
    analysis = analyze_cache_behavior([probe], BASELINE)
    assert len(analysis.signals[0].observed_value) <= 512


def test_empty_probe_list_is_inconclusive():
    analysis = analyze_cache_behavior([], BASELINE)
    assert analysis.verdict.outcome is ValidationOutcome.INCONCLUSIVE


def test_detection_flag_defaults_on():
    # The settings flag gates the (future) node wiring, not the pure
    # analyzer — assert the real default matches the plan (detection
    # ON by default: new detection, no legacy behavior change).
    assert cache_poisoning_detection_enabled() is True


# ---------------------------------------------------------------------------
# detect_web_cache_deception — advisory candidates
# ---------------------------------------------------------------------------


def test_deception_flags_static_suffix_with_dynamic_content_type():
    findings = detect_web_cache_deception(
        [
            {
                "url": "https://target.test/profile/logo.png",
                "status": 200,
                "headers": {
                    "content-type": "text/html",
                    "cache-control": "max-age=300",
                },
                "body": "<html>{'email': 'victim@target.test'}</html>",
            }
        ]
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["class"] == "web_cache_deception"
    assert finding["severity"] == "medium"
    assert finding["suffix"] == ".png"
    assert finding["advisory_only"] is True
    assert finding["auto_promote"] is False  # never auto-promoted


def test_deception_ignores_genuinely_static_response():
    findings = detect_web_cache_deception(
        [
            {
                "url": "https://target.test/logo.png",
                "status": 200,
                "headers": {
                    "content-type": "image/png",
                    "cache-control": "max-age=300",
                },
                "body": "<binary>",
            }
        ]
    )
    assert findings == []


def test_deception_requires_cacheable_headers():
    findings = detect_web_cache_deception(
        [
            {
                "url": "https://target.test/profile/cache.css",
                "status": 200,
                "headers": {"content-type": "text/html", "cache-control": "no-store"},
                "body": "<html>private</html>",
            }
        ]
    )
    assert findings == []


def test_deception_requires_200_and_static_suffix():
    records = [
        {  # 404 — not a candidate
            "url": "https://target.test/profile/logo.png",
            "status": 404,
            "headers": {"content-type": "text/html", "cache-control": "max-age=60"},
            "body": "nope",
        },
        {  # no static suffix — not a candidate
            "url": "https://target.test/profile",
            "status": 200,
            "headers": {"content-type": "text/html", "cache-control": "max-age=60"},
            "body": "<html>profile</html>",
        },
    ]
    assert detect_web_cache_deception(records) == []


def test_deception_json_content_type_also_counts():
    findings = detect_web_cache_deception(
        [
            {
                "url": "https://target.test/api/me/cache.js",
                "status": 200,
                "headers": {
                    "content-type": "application/json; charset=utf-8",
                    "cache-control": "max-age=120",
                },
                "body": '{"email": "victim@target.test"}',
            }
        ]
    )
    assert len(findings) == 1
    assert findings[0]["suffix"] == ".js"
    assert findings[0]["content_type"].startswith("application/json")
