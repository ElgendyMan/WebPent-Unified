"""webpent.shared.cache_poisoning_detector — deterministic web-cache
poisoning / cache-deception header analysis.

Ultimate plan 2026-10-27, proposal 7 (modern bug-bounty vulnerability
coverage), phase 2: "Cache Poisoning / Web Cache Deception — very
common and high impact, and detectable with simple header analysis
(no heavy external tools required)."

This module is the deterministic half of that pipeline, mirroring
``tech_stack_cve.py``'s posture exactly (pure dataclass signals + pure
functions over INJECTED response evidence — no network calls, no LLM,
no subprocess):

  * ``analyze_cache_behavior()`` inspects probe responses the caller
    has ALREADY captured (an unkeyed-header probe such as
    ``X-Forwarded-Host: canary`` plus, ideally, a clean baseline
    response). It emits ``CachePoisoningSignal`` records and a
    ``ValidationResult`` verdict using the canonical
    ``webpent.production.validators`` outcome/quality vocabulary, so
    the result flows through the same evidence pipeline as every
    other validator in the framework.
  * ``detect_web_cache_deception()`` inspects already-captured
    responses for the classic web-cache-deception shape: an
    authenticated path with a cacheable-looking static suffix
    (``/profile/logo.png``) that the server answered with the
    ORIGINAL dynamic content type and cacheable headers. Those are
    returned as advisory finding-shaped dicts only — the deep/
    family's ``deep/cache_deception.py`` (U-DEEP-18) owns the
    body-equality deception contract with a live transport; this
    module only annotates captured header evidence and NEVER
    auto-promotes anything.

Confirmation discipline (deliberately conservative):

  * CONFIRMED requires an unkeyed header (``X-Forwarded-Host``,
    ``X-Forwarded-Scheme``, ``X-Original-URL``, ``X-Rewrite-URL``) to
    be BOTH reflected in a cacheable response (``Cache-Control``
    without ``no-store``/``no-cache``/``private``, or an ``Age``
    header present) AND to change the rendered body versus the
    injected baseline — an observed baseline-vs-candidate
    differential, exactly the philosophy of
    ``production/validators.py``.
  * REFUTED when cache headers are present but unkeyed input is
    never reflected (or caching is explicitly disabled with
    ``no-store``/``no-cache``/``private`` everywhere).
  * INCONCLUSIVE when no cache headers are observed at all, when no
    baseline is supplied, or when a reflection exists but the body
    did not measurably change.

Bounds (documented, enforced in code):
  * body comparisons use at most the first 4096 characters of each
    injected body sample;
  * every header value is truncated to 512 characters before it can
    reach a signal, an evidence dict, or a log line;
  * at most 50 probe responses and 50 deception candidates are
    analyzed per call.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_BODY_COMPARE_CHARS = 4096
"""Body samples are compared/echoed using at most this many characters."""

_MAX_HEADER_VALUE_CHARS = 512
"""Every header value is truncated to this length before any use."""

_MAX_RESPONSES = 50
"""At most this many probe responses are analyzed per call."""

_MAX_DECEPTION_FINDINGS = 50
"""At most this many web-cache-deception candidates are returned."""

_MAX_URL_CHARS = 512
"""URLs echoed into findings/evidence are truncated to this length."""

# ---------------------------------------------------------------------------
# Cache-poisoning signature tables
# ---------------------------------------------------------------------------

# Headers that caches commonly fail to include in the cache key while
# origin servers DO act on them — the classic unkeyed-input surface.
_UNKEYED_HEADERS: tuple[str, ...] = (
    "x-forwarded-host",
    "x-forwarded-scheme",
    "x-original-url",
    "x-rewrite-url",
)

# Cache-Control directives that explicitly forbid a shared/local cache
# from storing the response. Presence of any of these means "not
# cacheable" no matter what else the header says.
_NON_CACHEABLE_DIRECTIVES: tuple[str, ...] = ("no-store", "no-cache", "private")

# Header names whose mere presence is evidence that a caching layer is
# in front of the origin (used to distinguish "no cache at all"
# (INCONCLUSIVE) from "cache present but clean" (REFUTED)).
_CACHE_EVIDENCE_HEADERS: tuple[str, ...] = ("cache-control", "age")

# Static-looking suffixes used by web-cache-deception probes: an
# authenticated path plus one of these suffixes is what a cache might
# store while serving the victim's dynamic body.
_STATIC_SUFFIXES: tuple[str, ...] = (
    ".css",
    ".js",
    ".mjs",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".ico",
    ".gif",
    ".webp",
    ".woff",
    ".woff2",
)

# Content types that indicate the ORIGINAL dynamic body was served for
# a static-suffixed path (the deception signal). A .css request that
# answers text/css is normal; a .css request that answers text/html or
# application/json is the victim's rendered page.
_DYNAMIC_CONTENT_TYPES: tuple[str, ...] = ("text/html", "application/json")


@dataclass
class CachePoisoningSignal:
    """One observed unkeyed-header behavior on a single probe response."""

    signal_type: str
    """``"unkeyed_header_reflection"`` when the injected/echoed unkeyed
    value reached the rendered body, ``"unkeyed_header_echo"`` when the
    server only echoed it back in response headers, and
    ``"unkeyed_header_ignored"`` when the probe found no reflection at
    all (the negative-control observation)."""

    header: str
    """Lowercased unkeyed header name the signal is about."""

    observed_value: str
    """The bounded (<=512 chars) value that was observed/echoed."""

    reflected_in_body: bool
    """True when ``observed_value`` appears verbatim in the bounded
    body sample — the prerequisite for body-level poisoning."""

    cacheable: bool
    """Whether THIS response carried cacheable headers (see module
    docstring for the exact rule)."""

    confidence: float
    """0..1 heuristic confidence for the signal alone: 0.9 for a
    body reflection on a cacheable response, 0.6 for a body
    reflection without cacheability, 0.4 for a header-only echo,
    0.1 for an ignored probe."""

    url: str = ""
    """Bounded URL of the probe response the signal came from."""

    body_changed_vs_baseline: bool = False
    """True when this response's bounded body differs from the
    baseline's bounded body (differential evidence)."""


@dataclass
class CachePoisoningAnalysis:
    """Aggregate result of ``analyze_cache_behavior``."""

    signals: list[CachePoisoningSignal] = field(default_factory=list)
    cacheable: bool = False
    """True when at least one analyzed response was cacheable."""

    verdict: ValidationResult = field(
        default_factory=lambda: ValidationResult(
            vulnerability_class="cache_poisoning",
            outcome=ValidationOutcome.INCONCLUSIVE,
            evidence_quality=EvidenceQuality.STRUCTURAL_HINT,
            discriminating_signal="no probe responses supplied",
            baseline_evidence={},
            candidate_evidence={},
            negative_control_evidence={},
        )
    )


def _bounded(value: Any, limit: int) -> str:
    """Coerce to str and truncate — the single choke point for bounds."""
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


# A structural alias kept local: probe/deception records are plain dicts
# with the documented key shape (never arbitrary Mapping types — callers
# inject captured response records).
MappingLike = dict[str, Any]


def _normalize_headers(record: MappingLike) -> dict[str, str]:
    """Lowercase header names and bound header values to 512 chars."""
    raw = record.get("headers")
    if not isinstance(raw, dict):
        return {}
    normalized: dict[str, str] = {}
    for key, value in raw.items():
        name = str(key).strip().lower()
        if name:
            normalized[name] = _bounded(value, _MAX_HEADER_VALUE_CHARS)
    return normalized


def _is_cacheable(headers: dict[str, str]) -> bool:
    """Deterministic cacheability rule over normalized headers.

    A response is treated as cacheable when EITHER:

      * it has an ``Age`` header (a cache already served it — the
        strongest possible storage evidence), OR
      * it has a ``Cache-Control`` header whose directives do NOT
        include ``no-store``/``no-cache``/``private``.

    Responses with no cache headers at all are NOT assumed cacheable
    (fail-closed posture).
    """
    if "age" in headers:
        return True
    cache_control = headers.get("cache-control")
    if cache_control is None:
        return False
    directives = {
        token.strip().lower() for token in cache_control.split(",") if token.strip()
    }
    return not any(directive in directives for directive in _NON_CACHEABLE_DIRECTIVES)


def _has_cache_headers(headers: dict[str, str]) -> bool:
    """True when any cache-evidence header is present at all."""
    return any(name in headers for name in _CACHE_EVIDENCE_HEADERS)


def _reflection(
    record: MappingLike, headers: dict[str, str], body: str
) -> CachePoisoningSignal | None:
    """Build one signal for a probe response, or None when the record
    carries no unkeyed-header information.

    Two mutually-documented input modes:

      1. Explicit probe metadata: the caller records what was injected
         via the optional ``"probe_header"``/``"probe_value"`` keys
         (recommended — the canary is known exactly).
      2. Header echo fallback: the server echoed the unkeyed request
         header back into the RESPONSE headers (some frameworks do);
         the echoed value becomes the candidate canary.
    """
    url = _bounded(record.get("url", ""), _MAX_URL_CHARS)
    cacheable = _is_cacheable(headers)

    probe_header = str(record.get("probe_header", "") or "").strip().lower()
    probe_value = _bounded(record.get("probe_value", ""), _MAX_HEADER_VALUE_CHARS)
    if not probe_header or not probe_value:
        # Fallback: look for an unkeyed header echoed in the response.
        for name in _UNKEYED_HEADERS:
            echoed = headers.get(name)
            if echoed:
                probe_header = name
                probe_value = echoed
                break
    if not probe_header or not probe_value:
        return None
    if probe_header not in _UNKEYED_HEADERS:
        return None

    reflected_in_body = probe_value in body
    header_echo = probe_value in (headers.get(probe_header) or "")
    if reflected_in_body and cacheable:
        signal_type = "unkeyed_header_reflection"
        confidence = 0.9
    elif reflected_in_body:
        signal_type = "unkeyed_header_reflection"
        confidence = 0.6
    elif header_echo or probe_header in headers:
        signal_type = "unkeyed_header_echo"
        confidence = 0.4
    else:
        signal_type = "unkeyed_header_ignored"
        confidence = 0.1
    return CachePoisoningSignal(
        signal_type=signal_type,
        header=probe_header,
        observed_value=probe_value,
        reflected_in_body=reflected_in_body,
        cacheable=cacheable,
        confidence=confidence,
        url=url,
    )


def analyze_cache_behavior(
    probe_responses: list[dict[str, Any]] | None,
    baseline_response: dict[str, Any] | None = None,
) -> CachePoisoningAnalysis:
    """Analyze captured unkeyed-header probe responses for cache poisoning.

    Pure function, no network. The caller injects:

      * ``probe_responses``: a list of response records of the shape
        ``{"url": str, "status": int, "headers": dict[str, str]
        (lowercased keys), "body": str (bounded sample)}``. Each record
        MAY additionally carry ``"probe_header"``/``"probe_value"``
        recording the unkeyed header/value that was injected for that
        probe (recommended — see ``_reflection``).
      * ``baseline_response``: the SAME shape, captured WITHOUT any
        unkeyed header. Required for the body-differential half of the
        CONFIRMED rule; without it the analysis cannot distinguish a
        poisoned render from a normal one and stays INCONCLUSIVE.

    Verdict rules (see module docstring for the full discipline):

      * CONFIRMED — an unkeyed header is reflected in a cacheable
        response AND that response's bounded body differs from the
        baseline's bounded body.
      * REFUTED — cache headers are present but unkeyed input is
        never reflected (or caching is explicitly disabled).
      * INCONCLUSIVE — no cache headers at all, no baseline for a
        reflection, or a reflection that never changed the body.
    """
    records = [r for r in (probe_responses or []) if isinstance(r, dict)][:_MAX_RESPONSES]

    baseline_body = ""
    baseline_headers: dict[str, str] = {}
    if isinstance(baseline_response, dict):
        baseline_body = _bounded(
            baseline_response.get("body", ""), _MAX_BODY_COMPARE_CHARS
        )
        baseline_headers = _normalize_headers(baseline_response)

    analysis = CachePoisoningAnalysis()
    any_cache_header = False
    confirmed_signal: CachePoisoningSignal | None = None
    negative_control: CachePoisoningSignal | None = None

    for record in records:
        headers = _normalize_headers(record)
        body = _bounded(record.get("body", ""), _MAX_BODY_COMPARE_CHARS)
        any_cache_header = any_cache_header or _has_cache_headers(headers)
        if _is_cacheable(headers):
            analysis.cacheable = True

        signal = _reflection(record, headers, body)
        if signal is None:
            continue
        signal.body_changed_vs_baseline = bool(baseline_body) and body != baseline_body
        analysis.signals.append(signal)

        if (
            signal.reflected_in_body
            and signal.cacheable
            and signal.body_changed_vs_baseline
            and confirmed_signal is None
        ):
            confirmed_signal = signal
        if (
            negative_control is None
            and not signal.reflected_in_body
            and signal.signal_type == "unkeyed_header_ignored"
        ):
            negative_control = signal

    bounded_note = (
        f"body comparisons capped at {_MAX_BODY_COMPARE_CHARS} chars; "
        f"header values capped at {_MAX_HEADER_VALUE_CHARS} chars; "
        f"at most {_MAX_RESPONSES} probe responses analyzed"
    )

    if not records or not any_cache_header:
        analysis.verdict = ValidationResult(
            vulnerability_class="cache_poisoning",
            outcome=ValidationOutcome.INCONCLUSIVE,
            evidence_quality=EvidenceQuality.STRUCTURAL_HINT,
            discriminating_signal="no cache headers (Cache-Control/Age) observed",
            baseline_evidence={"body_sample": baseline_body[:256]},
            candidate_evidence={"responses_analyzed": len(records)},
            negative_control_evidence={},
            details={
                "bounded": bounded_note,
                "responses_analyzed": len(records),
                "reason": "no-cache-headers",
            },
        )
        return analysis

    if confirmed_signal is not None:
        analysis.verdict = ValidationResult(
            vulnerability_class="cache_poisoning",
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.OBSERVED_DIFFERENTIAL,
            discriminating_signal=(
                f"unkeyed header {confirmed_signal.header!r} reflected in a "
                "cacheable response whose body differs from the clean baseline"
            ),
            baseline_evidence={
                "body_sample": baseline_body[:256],
                "cache_control": baseline_headers.get("cache-control", ""),
            },
            candidate_evidence={
                "url": confirmed_signal.url,
                "header": confirmed_signal.header,
                "observed_value": confirmed_signal.observed_value[:128],
                "cacheable": True,
            },
            negative_control_evidence=(
                {
                    "url": negative_control.url,
                    "header": negative_control.header,
                    "reflected_in_body": False,
                }
                if negative_control is not None
                else {}
            ),
            refutation_path=(
                "replay the poisoned URL from a second clean session; if the "
                "served body differs from the poisoned candidate or the cache "
                "key turns out to include the probe header, the poisoning "
                "does not affect other users"
            ),
            details={
                "bounded": bounded_note,
                "reason": "unkeyed-reflection-plus-body-differential",
                "signals": [s.signal_type for s in analysis.signals[:20]],
                "signal_count": len(analysis.signals),
            },
        )
        return analysis

    reflected = [s for s in analysis.signals if s.reflected_in_body]
    if reflected:
        # Reflection exists but is not confirmable (not cacheable, no
        # baseline, or no body change) — surface, do not conclude.
        analysis.verdict = ValidationResult(
            vulnerability_class="cache_poisoning",
            outcome=ValidationOutcome.INCONCLUSIVE,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "unkeyed input reflected but cacheable-body differential "
                "not established (missing baseline, non-cacheable response, "
                "or unchanged body)"
            ),
            baseline_evidence={"body_sample": baseline_body[:256]},
            candidate_evidence={
                "reflected_headers": sorted({s.header for s in reflected})[:8],
            },
            negative_control_evidence={},
            details={
                "bounded": bounded_note,
                "reason": "reflection-without-differential",
                "signal_count": len(analysis.signals),
            },
        )
        return analysis

    analysis.verdict = ValidationResult(
        vulnerability_class="cache_poisoning",
        outcome=ValidationOutcome.REFUTED,
        evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
        discriminating_signal=(
            "cache headers present but unkeyed header input was never "
            "reflected (or caching explicitly disabled via no-store/"
            "no-cache/private)"
        ),
        baseline_evidence={"body_sample": baseline_body[:256]},
        candidate_evidence={"cacheable": analysis.cacheable},
        negative_control_evidence=(
            {
                "url": negative_control.url,
                "header": negative_control.header,
                "reflected_in_body": False,
            }
            if negative_control is not None
            else {}
        ),
        refutation_path=None,
        details={
            "bounded": bounded_note,
            "reason": "cache-present-no-reflection",
            "signal_count": len(analysis.signals),
        },
    )
    return analysis


def detect_web_cache_deception(
    responses: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Flag captured responses shaped like web-cache-deception candidates.

    Pure function, no network. The caller injects response records
    (same shape as ``analyze_cache_behavior``) captured for
    static-suffix-appended variants of authenticated paths (e.g.
    ``/profile/logo.png``). A record is flagged when ALL hold:

      1. the URL path ends with a static-looking suffix
         (``.css``/``.js``/``.png``/...);
      2. the response status is 200;
      3. the ``Content-Type`` is one of the ORIGINAL dynamic content
         types (``text/html``/``application/json``) — i.e. the server
         rendered the authenticated page, not a static asset;
      4. the response is cacheable per ``_is_cacheable``.

    Returns advisory finding-shaped dicts only (severity ``medium``,
    class ``web_cache_deception``). These observations are NEVER
    auto-promoted to findings — confirming a deception requires the
    body-equality + sensitivity contract owned by
    ``deep/cache_deception.py`` (U-DEEP-18) plus a human operator.
    """
    findings: list[dict[str, Any]] = []
    for record in [r for r in (responses or []) if isinstance(r, dict)][
        :_MAX_DECEPTION_FINDINGS
    ]:
        url = _bounded(record.get("url", ""), _MAX_URL_CHARS)
        path = urlparse(url).path if url else ""
        if not path:
            path = _bounded(record.get("path", ""), _MAX_URL_CHARS)
        lowered = path.lower()
        suffix = next((s for s in _STATIC_SUFFIXES if lowered.endswith(s)), "")
        if not suffix:
            continue

        try:
            status = int(record.get("status", 0))
        except (TypeError, ValueError):
            status = 0
        if status != 200:
            continue

        headers = _normalize_headers(record)
        content_type = headers.get("content-type", "")
        if not any(content_type.startswith(ct) for ct in _DYNAMIC_CONTENT_TYPES):
            continue
        if not _is_cacheable(headers):
            continue

        findings.append(
            {
                "class": "web_cache_deception",
                "severity": "medium",
                "url": url,
                "suffix": suffix,
                "content_type": content_type[:128],
                "cacheable": True,
                "advisory_only": True,
                "auto_promote": False,
                "note": (
                    "advisory observation only — a static-suffixed authed path "
                    "served the original dynamic content type with cacheable "
                    "headers; verify the cached body equality and sensitivity "
                    "manually before reporting; never auto-promoted"
                ),
                "bounded": (
                    f"urls capped at {_MAX_URL_CHARS} chars; at most "
                    f"{_MAX_DECEPTION_FINDINGS} candidates analyzed"
                ),
            }
        )
    logger.info(
        "cache-deception advisory scan: %d candidate(s) flagged", len(findings)
    )
    return findings


def cache_poisoning_detection_enabled() -> bool:
    """Return the ``enable_cache_poisoning_detection`` settings flag.

    This is the gate the orchestrating graph node consults before
    running this module's analyzers. The analysis functions themselves
    stay flag-free and deterministic (pure over injected evidence) so
    they remain unit-testable and replayable regardless of settings.
    """
    from webpent.config.settings import get_settings

    return bool(get_settings().enable_cache_poisoning_detection)


__all__ = [
    "CachePoisoningAnalysis",
    "CachePoisoningSignal",
    "analyze_cache_behavior",
    "cache_poisoning_detection_enabled",
    "detect_web_cache_deception",
]
