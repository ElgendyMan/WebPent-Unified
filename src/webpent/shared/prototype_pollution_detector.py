"""webpent.shared.prototype_pollution_detector — deterministic
prototype-pollution analysis over injected evidence.

Ultimate plan 2026-10-27, proposal 7 (modern bug-bounty vulnerability
coverage), phase 4: "Prototype Pollution — a very common JS-side
vulnerability in modern SPAs. Build on the existing
``javascript_intelligence.py``: check for unsafe merge patterns
(``__proto__``, ``constructor.prototype``) on any endpoint that takes
JSON and merges it."

This module is the deterministic half, mirroring
``tech_stack_cve.py``'s posture (pure regex/dataclass analysis over
INJECTED evidence — no network, no browser, no LLM):

  * ``analyze_client_merge_gadgets()`` scans bounded, already-captured
    JS source samples for the KNOWN unsafe-merge gadget patterns and
    returns low-severity observation dicts. It is a HINT generator
    only: every pattern is trivially present in benign code, so the
    false-positive posture is documented per-pattern below and the
    results are explicitly ``advisory_only`` — they seed hypotheses
    for a human (or the server-side validator), never findings.
  * ``validate_server_side_pollution()`` consumes captured
    request/response JSON pairs for endpoints that accept JSON bodies
    and produces a canonical ``ValidationResult`` using the
    ``webpent.production.validators`` vocabulary: CONFIRMED only when
    a ``__proto__``/``constructor.prototype`` payload was accepted AND
    the server's own response reflects a top-level key the attacker
    only sent NESTED inside the pollution probe (the pollution
    actually took effect server-side).

Bounds (documented, enforced in code):
  * each JS source sample is scanned up to its first 100_000
    characters; at most 50 samples per call;
  * at most 20 gadget observations per sample and 200 per call;
  * URLs are truncated to 512 characters; the server-side validator
    caps marker keys at 64 characters and values at 128.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_JS_SAMPLE_CHARS = 100_000
_MAX_JS_SAMPLES = 50
_MAX_OBSERVATIONS_PER_SAMPLE = 20
_MAX_TOTAL_OBSERVATIONS = 200
_MAX_URL_CHARS = 512
_MAX_MARKER_KEY_CHARS = 64
_MAX_MARKER_VALUE_CHARS = 128
_MAX_RESPONSES = 100

# ---------------------------------------------------------------------------
# Client-side gadget patterns
# ---------------------------------------------------------------------------

# (pattern name, compiled regex) pairs. FALSE-POSITIVE POSTURE, per
# pattern (these are hints, never proof):
#   * "__proto__" — matches any mention, including sanitizer code that
#     STRIPS __proto__. Observation only.
#   * "constructor.prototype" — matches both dotted and bracketed
#     traversal; also present in framework internals.
#   * "object.assign_nested_target" — Object.assign whose FIRST
#     argument (the mutation target) is a nested member expression
#     (obj.a / obj[key]); a flat target cannot pollute prototypes via
#     key traversal. Still widely used benignly.
#   * "lodash_merge" / "lodash_set" — lodash-style deep merge/set
#     entry points (`_.merge(`, `_.set(`, and the `lodash.` aliases),
#     the canonical client-side pollution gadgets when a path/object
#     is attacker-influenced. Static analysis cannot establish
#     attacker influence — observation only.
_MERGE_GADGET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("__proto__", re.compile(r"__proto__")),
    (
        "constructor.prototype",
        # Covers dotted (constructor.prototype), bracketed direct
        # (constructor['prototype']), and bracketed-string traversal
        # (obj['constructor']['prototype']) — any mix of quotes,
        # brackets, dots and whitespace between the two identifiers.
        re.compile(r"constructor\s*['\"\]\[\.\s]*prototype"),
    ),
    (
        "object.assign_nested_target",
        re.compile(
            r"Object\s*\.\s*assign\s*\(\s*"
            r"[A-Za-z_$][\w$]*\s*(?:\.\s*[\w$]+|\[[^\]]*\])+\s*,"
        ),
    ),
    (
        "lodash_merge",
        # Lookbehind (not a consuming prefix) so match.start() lands
        # exactly on the gadget token and line hints stay accurate.
        re.compile(r"(?<![\w$.])(?:_\.merge|lodash\.merge|_\.mergeWith|lodash\.mergeWith)\s*\("),
    ),
    (
        "lodash_set",
        re.compile(r"(?<![\w$.])(?:_\.set|lodash\.set|_\.setWith|lodash\.setWith)\s*\("),
    ),
)


def analyze_client_merge_gadgets(
    js_source_samples: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Scan bounded JS source samples for unsafe-merge gadget patterns.

    Pure function, no network. Input: a list of
    ``{"url": str, "source": str}`` records — JS asset samples the
    crawler already captured (``crawled_data["javascript_urls"]`` is
    the upstream convention; the caller is responsible for fetching
    and bounding the source text).

    Returns observation dicts of the shape
    ``{"url", "pattern", "line_hint", "severity": "low", "class":
    "prototype_pollution_gadget_hint", ...}`` — advisory only. Every
    pattern in the table above is trivially present in benign code, so
    these hints exist to SEED manual review / hypothesis generation,
    never to authorize a finding (the same "advisory, never proof"
    posture as ``tech_stack_cve.py``'s ``does_not_confirm`` flag).
    """
    observations: list[dict[str, Any]] = []
    samples = [s for s in (js_source_samples or []) if isinstance(s, dict)][:_MAX_JS_SAMPLES]
    for sample in samples:
        url = str(sample.get("url", ""))[:_MAX_URL_CHARS]
        source = sample.get("source")
        if not isinstance(source, str) or not source:
            continue
        bounded_source = source[:_MAX_JS_SAMPLE_CHARS]
        per_sample = 0
        for pattern_name, pattern in _MERGE_GADGET_PATTERNS:
            for match in pattern.finditer(bounded_source):
                if per_sample >= _MAX_OBSERVATIONS_PER_SAMPLE:
                    break
                line_number = bounded_source.count("\n", 0, match.start()) + 1
                observations.append(
                    {
                        "url": url,
                        "pattern": pattern_name,
                        "line_hint": f"line {line_number}",
                        "severity": "low",
                        "class": "prototype_pollution_gadget_hint",
                        "advisory_only": True,
                        "note": (
                            "static gadget hint — presence of the pattern does "
                            "NOT establish attacker-controlled input reaches "
                            "the merge; manual verification required"
                        ),
                        "bounded": (
                            f"source scanned up to {_MAX_JS_SAMPLE_CHARS} chars; "
                            f"at most {_MAX_OBSERVATIONS_PER_SAMPLE} observations "
                            "per sample"
                        ),
                    }
                )
                per_sample += 1
                if len(observations) >= _MAX_TOTAL_OBSERVATIONS:
                    logger.info(
                        "merge-gadget scan hit the %d-observation cap",
                        _MAX_TOTAL_OBSERVATIONS,
                    )
                    return observations
            if per_sample >= _MAX_OBSERVATIONS_PER_SAMPLE:
                break
    logger.info(
        "merge-gadget scan: %d observation(s) across %d sample(s)",
        len(observations),
        len(samples),
    )
    return observations


# ---------------------------------------------------------------------------
# Server-side pollution validation
# ---------------------------------------------------------------------------


def _pollution_markers(request_json: dict[str, Any]) -> dict[str, Any]:
    """Extract the attacker-chosen marker pairs from a pollution probe.

    The canonical probe shapes (the plan's phase-4 model):

      * ``{"__proto__": {"polluted": "marker"}}`` — the attacker sent
        ``polluted`` NESTED inside ``__proto__``, never at top level;
      * ``{"constructor": {"prototype": {"polluted": "marker"}}}`` —
        the prototype-traversal equivalent.

    Returns the inner ``{"polluted": "marker"}`` mapping (bounded), or
    an empty dict when the request is not a pollution probe.
    """
    markers: dict[str, Any] = {}
    proto_probe = request_json.get("__proto__")
    if isinstance(proto_probe, dict):
        for key, value in proto_probe.items():
            markers[str(key)[:_MAX_MARKER_KEY_CHARS]] = value
    constructor_probe = request_json.get("constructor")
    if isinstance(constructor_probe, dict):
        prototype_probe = constructor_probe.get("prototype")
        if isinstance(prototype_probe, dict):
            for key, value in prototype_probe.items():
                markers[str(key)[:_MAX_MARKER_KEY_CHARS]] = value
    return markers


def validate_server_side_pollution(
    responses: list[dict[str, Any]] | None,
) -> ValidationResult:
    """Validate server-side prototype pollution from captured JSON pairs.

    Input: a list of ``{"request_json": dict, "status": int,
    "response_json": dict | None}`` records — one per JSON-body probe
    the caller already made against endpoints that merge request
    bodies into objects.

    CONFIRMED (evidence_quality=DETERMINISTIC_TOOL) when a request
    containing top-level ``__proto__`` (or ``constructor`` with nested
    ``prototype``) was ACCEPTED (status < 400) AND the response JSON
    reflects a polluted key the attacker did NOT send verbatim at top
    level — modeled as: request ``{"__proto__": {"polluted":
    "marker"}}`` and response containing top-level
    ``"polluted": "marker"``. The server demonstrably merged the
    prototype probe into the object itself.

    REFUTED when the server rejected (status >= 400) or sanitized
    (accepted, response JSON present, but neither a top-level marker
    key NOR a verbatim ``__proto__`` echo came back) every probe.

    INCONCLUSIVE when there is no JSON-endpoint evidence in the
    records at all (no pollution probes), or when the outcomes are
    ambiguous (e.g. accepted with no response body to inspect).
    """
    records = [r for r in (responses or []) if isinstance(r, dict)][:_MAX_RESPONSES]

    probe_count = 0
    confirmed: dict[str, Any] | None = None
    refuted_records = 0
    ambiguous_records = 0

    for record in records:
        request_json = record.get("request_json")
        if not isinstance(request_json, dict):
            continue
        markers = _pollution_markers(request_json)
        if not markers:
            continue
        probe_count += 1
        try:
            status = int(record.get("status", 0))
        except (TypeError, ValueError):
            status = 0
        response_json = record.get("response_json")

        if status < 400 and isinstance(response_json, dict):
            reflected = {
                str(key)[:_MAX_MARKER_KEY_CHARS]: value
                for key, value in markers.items()
                if key in response_json and response_json[key] == value
            }
            if reflected:
                if confirmed is None:
                    confirmed = {
                        "reflected_keys": sorted(reflected)[:10],
                        "status": status,
                        "marker_sample": {
                            key: str(value)[:_MAX_MARKER_VALUE_CHARS]
                            for key, value in list(reflected.items())[:3]
                        },
                    }
                continue
            # Accepted but no reflection: sanitized ONLY if we got a
            # parseable response dict to judge against (a verbatim
            # __proto__ echo is also "no pollution effect").
            refuted_records += 1
        elif status >= 400:
            refuted_records += 1
        else:
            # Accepted but no response JSON to inspect — ambiguous.
            ambiguous_records += 1

    if confirmed is not None:
        return ValidationResult(
            vulnerability_class="prototype_pollution",
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.DETERMINISTIC_TOOL,
            discriminating_signal=(
                "server accepted a __proto__/constructor.prototype probe and "
                "its response JSON reflects a top-level key the attacker only "
                "sent nested inside the pollution probe"
            ),
            baseline_evidence={
                "request_shape": "markers nested inside __proto__ (never top level)"
            },
            candidate_evidence=confirmed,
            negative_control_evidence={
                "expected": "a clean JSON body without __proto__ produces a "
                "response without the marker keys"
            },
            refutation_path=(
                "replay with a fresh marker value; a properly sanitizing "
                "server drops the __proto__ key entirely and the response "
                "never contains the marker at top level"
            ),
            details={
                "bounded": (
                    f"marker keys capped at {_MAX_MARKER_KEY_CHARS} chars, "
                    f"values at {_MAX_MARKER_VALUE_CHARS}; at most "
                    f"{_MAX_RESPONSES} records analyzed"
                ),
                "probe_count": probe_count,
            },
        )

    if probe_count and refuted_records and not ambiguous_records:
        return ValidationResult(
            vulnerability_class="prototype_pollution",
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "every pollution probe was rejected or sanitized — no marker "
                "key ever reached a response at top level"
            ),
            baseline_evidence={},
            candidate_evidence={"probes_rejected_or_sanitized": refuted_records},
            negative_control_evidence={},
            refutation_path=None,
            details={
                "bounded": f"at most {_MAX_RESPONSES} records analyzed",
                "probe_count": probe_count,
                "reason": "rejected-or-sanitized",
            },
        )

    return ValidationResult(
        vulnerability_class="prototype_pollution",
        outcome=ValidationOutcome.INCONCLUSIVE,
        evidence_quality=EvidenceQuality.STRUCTURAL_HINT,
        discriminating_signal=(
            "no JSON-endpoint pollution evidence in records (no probes, or "
            "ambiguous accepted-without-body outcomes)"
        ),
        baseline_evidence={},
        candidate_evidence={},
        negative_control_evidence={},
        details={
            "bounded": f"at most {_MAX_RESPONSES} records analyzed",
            "probe_count": probe_count,
            "ambiguous_records": ambiguous_records,
            "reason": (
                "no-json-endpoint-evidence" if not probe_count else "ambiguous-outcomes"
            ),
        },
    )


def prototype_pollution_detection_enabled() -> bool:
    """Return the ``enable_prototype_pollution_detection`` settings flag.

    This is the gate the orchestrating graph node consults before
    running this module's analyzers. The analysis functions themselves
    stay flag-free and deterministic (pure over injected evidence) so
    they remain unit-testable and replayable regardless of settings.
    """
    from webpent.config.settings import get_settings

    return bool(get_settings().enable_prototype_pollution_detection)


__all__ = [
    "analyze_client_merge_gadgets",
    "prototype_pollution_detection_enabled",
    "validate_server_side_pollution",
]
