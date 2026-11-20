"""webpent.validators.graphql_validator — deterministic GraphQL
misconfiguration validators.

Ultimate plan 2026-10-27, proposal 7 (modern bug-bounty vulnerability
coverage), phase 3: GraphQL-specific vulnerabilities (introspection
abuse, batching attacks, field-suggestion leakage, nested-query DoS)
were completely absent from ``VulnClass`` even though
``shared/schema_ingestion.py::parse_graphql_introspection()`` already
works and is wired into target understanding. This module closes that
gap with four validators that follow the ``production/validators.py``
contract EXACTLY (deterministic function, real injected evidence in, a
``ValidationResult`` with CONFIRMED/REFUTED/INCONCLUSIVE out):

  * ``validate_introspection_exposure`` — reuses
    ``parse_graphql_introspection()`` (never re-parses the schema
    differently from the rest of the framework) over an injected
    introspection payload.
  * ``validate_batching_abuse`` — batch-vs-sequential rate-limit
    differential over injected request/response records.
  * ``validate_field_suggestion_leak`` — "Did you mean <field>"
    error-message leakage over injected error bodies.
  * ``validate_depth_complexity_dos`` — timing degradation analysis
    over an injected depth-probe record. DoS-ADJACENT: this validator
    NEVER constructs, deepens, or replays a query (see the hard cap
    below) and every result carries an explicit authorization warning.
  * ``analyze_graphql_surface`` — orchestrator running the applicable
    validators over one evidence bundle.

No network, no LLM, no subprocess — every input is an evidence dict
the caller already captured, which keeps the module runnable in CI
sandboxes with zero egress (the same posture as
``shared/tech_stack_cve.py``).

Bounds (documented, enforced in code):
  * bodies are scanned using at most the first 4096 characters;
  * operation-name samples are capped at 10 entries / 160 chars each;
  * batch records, error responses and timing samples are capped at
    100 / 100 / 200 entries respectively;
  * ``validate_depth_complexity_dos`` HARD-CAPS the depth it will
    attest as framework-generated evidence at 50 (see its docstring —
    the plan explicitly demands a very strict maximum so the check
    itself can never become a denial-of-service against the target).
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
from webpent.shared.schema_ingestion import parse_graphql_introspection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_BODY_SCAN_CHARS = 4096
"""Error bodies are matched using at most this many characters."""

_MAX_OPERATION_SAMPLE = 10
"""Bounded sample of operation names echoed into details."""

_MAX_OPERATION_NAME_CHARS = 160
"""Matches schema_ingestion's own per-name bound."""

_MAX_BATCH_RECORDS = 100
_MAX_ERROR_RESPONSES = 100
_MAX_TIMING_SAMPLES = 200

_MAX_FRAMEWORK_PROBE_DEPTH = 50
"""HARD CAP (plan-mandated, proposal 7 phase 3): WebPent's own probe
discipline NEVER constructs GraphQL queries deeper than this, and this
validator never attests framework-generated evidence beyond it. Any
injected record claiming a deeper maximum necessarily originated from
an authorized out-of-band operator run and is flagged as such in
``details`` instead of being silently attributed to the framework."""

_CONFIRMATION_DEPTH_FLOOR = 100
"""Confirmation requires degradation evidence at depth >= 100 — an
order of magnitude beyond the framework's own probe cap, reachable
only through operator-supplied evidence, never through WebPent's own
probing."""

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_GRAPHQL_VULN_CLASSES = {
    "introspection": "graphql_introspection_exposure",
    "batching": "graphql_batching_abuse",
    "field_suggestion": "graphql_field_suggestion_leak",
    "depth": "graphql_depth_complexity_dos",
}

_BOUNDED_NOTE = (
    f"bodies scanned up to {_MAX_BODY_SCAN_CHARS} chars; operation-name "
    f"samples capped at {_MAX_OPERATION_SAMPLE}; records capped at "
    f"{_MAX_BATCH_RECORDS} batch / {_MAX_ERROR_RESPONSES} error / "
    f"{_MAX_TIMING_SAMPLES} timing entries"
)


def _inconclusive(
    vuln_class: str,
    signal: str,
    details: dict[str, Any],
) -> ValidationResult:
    """Uniform INCONCLUSIVE result with the bounded note attached."""
    details = dict(details)
    details.setdefault("bounded", _BOUNDED_NOTE)
    return ValidationResult(
        vulnerability_class=vuln_class,
        outcome=ValidationOutcome.INCONCLUSIVE,
        evidence_quality=EvidenceQuality.STRUCTURAL_HINT,
        discriminating_signal=signal,
        baseline_evidence={},
        candidate_evidence={},
        negative_control_evidence={},
        details=details,
    )


def _bounded_str(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


# ---------------------------------------------------------------------------
# Introspection exposure
# ---------------------------------------------------------------------------


def validate_introspection_exposure(
    introspection_payload: dict[str, Any] | None,
    endpoint_url: str,
    *,
    is_production: bool = True,
) -> ValidationResult:
    """Validate GraphQL introspection exposure from an injected payload.

    The payload is parsed with the framework's own
    ``parse_graphql_introspection()`` — the same projection the target
    understanding node uses — so this validator can never disagree
    with the rest of the system about what the schema contains.

    Outcome rules:

      * CONFIRMED (evidence_quality=DETERMINISTIC_TOOL) when the
        parser returns a non-empty operation list AND the endpoint is
        a production endpoint (``is_production=True``): a fully
        enumerated production schema is directly reproducible
        evidence.
      * INCONCLUSIVE when the payload is empty/malformed (the parser
        returns no operations) or when the endpoint is not production
        (a dev/staging schema exposure is advisory, not a production
        finding).
    """
    payload = introspection_payload if isinstance(introspection_payload, dict) else {}
    operations = parse_graphql_introspection(payload)
    endpoint = _bounded_str(endpoint_url, 512)
    names = [
        _bounded_str(op.get("operation", ""), _MAX_OPERATION_NAME_CHARS)
        for op in operations[:_MAX_OPERATION_SAMPLE]
        if isinstance(op, dict)
    ]

    if not operations:
        return _inconclusive(
            _GRAPHQL_VULN_CLASSES["introspection"],
            "introspection payload empty or malformed — no operations parsed",
            {"endpoint": endpoint, "operation_count": 0},
        )

    if not is_production:
        return _inconclusive(
            _GRAPHQL_VULN_CLASSES["introspection"],
            "introspection succeeded on a NON-production endpoint — advisory only",
            {
                "endpoint": endpoint,
                "operation_count": len(operations),
                "operation_name_sample": names,
                "reason": "non-production-endpoint",
            },
        )

    return ValidationResult(
        vulnerability_class=_GRAPHQL_VULN_CLASSES["introspection"],
        outcome=ValidationOutcome.CONFIRMED,
        evidence_quality=EvidenceQuality.DETERMINISTIC_TOOL,
        discriminating_signal=(
            f"introspection query returned a parseable schema with "
            f"{len(operations)} operation(s) from a production endpoint"
        ),
        baseline_evidence={"expected": "introspection disabled in production"},
        candidate_evidence={
            "endpoint": endpoint,
            "operation_count": len(operations),
            "operation_name_sample": names,
        },
        negative_control_evidence={
            "expected": "an empty/errors payload when introspection is disabled"
        },
        refutation_path=(
            "replay the introspection query with the same authorization; a "
            "disabled schema should return an introspection-disabled error "
            "and zero parsed operations"
        ),
        details={
            "endpoint": endpoint,
            "operation_count": len(operations),
            "operation_name_sample": names,
            "bounded": (
                f"operation-name sample capped at {_MAX_OPERATION_SAMPLE} names "
                f"x {_MAX_OPERATION_NAME_CHARS} chars; names bounded by "
                "schema_ingestion's own projection limits"
            ),
        },
    )


# ---------------------------------------------------------------------------
# Batching abuse
# ---------------------------------------------------------------------------


def _record_int(record: dict[str, Any], key: str, default: int = 0) -> int:
    value = record.get(key, default)
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _is_rate_limited(record: dict[str, Any], status: int) -> bool:
    """Deterministic rate-limit rejection detector over one record.

    A record counts as rate-limited when the status is 429 OR the
    injected rate-limit headers show an exhausted budget (a
    ``retry-after`` header, or ``x-ratelimit-remaining`` == 0).
    """
    if status == 429:
        return True
    raw = record.get("rate_limit_headers")
    if not isinstance(raw, dict):
        return False
    lowered = {str(k).lower(): str(v) for k, v in raw.items()}
    if "retry-after" in lowered:
        return True
    remaining = lowered.get("x-ratelimit-remaining")
    if remaining is not None:
        try:
            return int(remaining) <= 0
        except (TypeError, ValueError):
            return False
    return False


def validate_batching_abuse(
    responses: list[dict[str, Any]] | None,
) -> ValidationResult:
    """Validate GraphQL batching abuse (rate-limit bypass) from records.

    Input: a list of request/response records of the shape
    ``{"batch_size": int, "status": int, "elapsed_ms": float,
    "rate_limit_headers": dict}`` — one record per probe the caller
    already made (sequential single-query probes AND multi-query batch
    probes).

    Outcome rules:

      * CONFIRMED when a batch of >= 10 queries in ONE request
        succeeded (status < 400, not rate-limited) while equivalent
        SEQUENTIAL requests were rate-limited — the bypass
        differential.
      * REFUTED when the batch request itself was rejected (the
        server enforces batch/request limits).
      * INCONCLUSIVE otherwise (no batch evidence, or a successful
        batch without sequential-limiting evidence to differential
        against).
    """
    records = [r for r in (responses or []) if isinstance(r, dict)][:_MAX_BATCH_RECORDS]
    if not records:
        return _inconclusive(
            _GRAPHQL_VULN_CLASSES["batching"],
            "no batching request records supplied",
            {"record_count": 0},
        )

    sequential_limited = False
    batch_ok: dict[str, Any] | None = None
    batch_rejected = False
    for record in records:
        batch_size = _record_int(record, "batch_size", 1)
        status = _record_int(record, "status", 0)
        limited = _is_rate_limited(record, status)
        if batch_size <= 1:
            if limited or status == 429:
                sequential_limited = True
            continue
        if batch_size >= 10 and status < 400 and not limited:
            if batch_ok is None:
                batch_ok = {
                    "batch_size": batch_size,
                    "status": status,
                    "elapsed_ms": record.get("elapsed_ms"),
                }
        elif batch_size >= 10 and status >= 400:
            batch_rejected = True

    if batch_ok is not None and sequential_limited:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["batching"],
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.OBSERVED_DIFFERENTIAL,
            discriminating_signal=(
                f"a single request batching {batch_ok['batch_size']} queries "
                "succeeded without rate-limit rejection while equivalent "
                "sequential requests were rate-limited"
            ),
            baseline_evidence={
                "sequential_probes": "rate-limited (429 / exhausted budget)"
            },
            candidate_evidence=batch_ok,
            negative_control_evidence={
                "expected": "batch request rejected or rate-limited like the "
                "sequential equivalents"
            },
            refutation_path=(
                "re-run the batch probe after the rate-limit window resets; a "
                "correctly enforced limiter rejects or throttles the batch too"
            ),
            details={
                "bounded": f"at most {_MAX_BATCH_RECORDS} records analyzed",
                "batch_record": batch_ok,
                "sequential_limited": True,
            },
        )

    if batch_rejected and batch_ok is None:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["batching"],
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal="batch request was rejected by the server",
            baseline_evidence={"sequential_probes": "rate-limited or successful"},
            candidate_evidence={"batch_status": "rejected (>= 400)"},
            negative_control_evidence={},
            refutation_path=None,
            details={
                "bounded": f"at most {_MAX_BATCH_RECORDS} records analyzed",
                "reason": "batch-rejected",
            },
        )

    return _inconclusive(
        _GRAPHQL_VULN_CLASSES["batching"],
        (
            "no rate-limit bypass differential established — either no batch "
            "evidence, or the batch succeeded without sequential-limiting "
            "evidence to compare against"
        ),
        {
            "record_count": len(records),
            "reason": (
                "no-batch-evidence" if batch_ok is None else "no-sequential-limited-evidence"
            ),
        },
    )


# ---------------------------------------------------------------------------
# Field suggestion leak
# ---------------------------------------------------------------------------

# "Did you mean 'userEmail'?" — the classic GraphQL/library suggestion
# leak. The captured token must be field-name-shaped: a letter/underscore
# followed by 1..64 word characters (bounded so a matched blob can never
# be an unbounded capture).
_FIELD_SUGGESTION_RE = re.compile(
    r"did\s+you\s+mean\s*[\"'`(\s:]*\s*([A-Za-z_][A-Za-z0-9_]{1,64})",
    re.IGNORECASE,
)

# A record counts as an error-bearing response when the status is an
# HTTP error OR the body carries a GraphQL ``errors`` array (GraphQL
# servers conventionally answer 200 with errors in the payload).
_ERROR_BODY_MARKER_RE = re.compile(r"\"errors\"\s*:", re.IGNORECASE)


def validate_field_suggestion_leak(
    responses: list[dict[str, Any]] | None,
) -> ValidationResult:
    """Validate GraphQL field-suggestion leakage from error bodies.

    Input: a list of ``{"status": int, "body": str}`` records the
    caller already captured (GraphQL error responses, including
    200-with-errors responses — the GraphQL convention).

    Outcome rules:

      * CONFIRMED when any scanned body matches ``did you mean``
        (case-insensitive) followed by a field-name-shaped token —
        error messages are leaking valid, possibly undocumented field
        names.
      * REFUTED when error-bearing bodies exist but none of them ever
        contains a suggestion.
      * INCONCLUSIVE when there are no error bodies to inspect at all.
    """
    records = [r for r in (responses or []) if isinstance(r, dict)][:_MAX_ERROR_RESPONSES]
    if not records:
        return _inconclusive(
            _GRAPHQL_VULN_CLASSES["field_suggestion"],
            "no response records supplied",
            {"record_count": 0},
        )

    suggestions: list[str] = []
    error_bearing = 0
    for record in records:
        body = _bounded_str(record.get("body", ""), _MAX_BODY_SCAN_CHARS)
        status = _record_int(record, "status", 0)
        is_error_body = status >= 400 or bool(_ERROR_BODY_MARKER_RE.search(body))
        if is_error_body:
            error_bearing += 1
        for match in _FIELD_SUGGESTION_RE.finditer(body):
            token = match.group(1)
            if token and token not in suggestions:
                suggestions.append(token)
            if len(suggestions) >= _MAX_OPERATION_SAMPLE:
                break
        if len(suggestions) >= _MAX_OPERATION_SAMPLE:
            break

    if suggestions:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["field_suggestion"],
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.DETERMINISTIC_TOOL,
            discriminating_signal=(
                "error bodies contain 'did you mean <field>' suggestions — "
                "valid field names are being disclosed to callers"
            ),
            baseline_evidence={"expected": "generic error messages without suggestions"},
            candidate_evidence={"suggested_fields": suggestions},
            negative_control_evidence={
                "expected": "a well-formed query for a REAL field produces no "
                "suggestion in its response"
            },
            refutation_path=(
                "replay the failing query; a hardened error handler returns a "
                "generic message with no 'did you mean' clause"
            ),
            details={
                "suggested_fields": suggestions,
                "error_bodies_scanned": error_bearing,
                "bounded": (
                    f"bodies scanned up to {_MAX_BODY_SCAN_CHARS} chars; at "
                    f"most {_MAX_ERROR_RESPONSES} records; suggestion sample "
                    f"capped at {_MAX_OPERATION_SAMPLE} tokens"
                ),
            },
        )

    if error_bearing:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["field_suggestion"],
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "error-bearing bodies never contain field suggestions"
            ),
            baseline_evidence={},
            candidate_evidence={"error_bodies_scanned": error_bearing},
            negative_control_evidence={},
            refutation_path=None,
            details={
                "error_bodies_scanned": error_bearing,
                "bounded": (
                    f"bodies scanned up to {_MAX_BODY_SCAN_CHARS} chars; at "
                    f"most {_MAX_ERROR_RESPONSES} records"
                ),
            },
        )

    return _inconclusive(
        _GRAPHQL_VULN_CLASSES["field_suggestion"],
        "no error-bearing bodies in evidence — nothing to inspect for suggestions",
        {"record_count": len(records), "reason": "no-error-bodies"},
    )


# ---------------------------------------------------------------------------
# Depth / complexity DoS (DoS-ADJACENT — see hard cap)
# ---------------------------------------------------------------------------

_AUTHORIZATION_WARNING = (
    "do not reproduce without authorization — DoS-adjacent"
)


def _coerce_float(value: Any) -> float | None:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if result != result:  # NaN guard (NaN != NaN).
        return None
    return result


def validate_depth_complexity_dos(depth_probe: dict[str, Any] | None) -> ValidationResult:
    """Validate GraphQL depth/complexity DoS exposure from an injected probe.

    Input: ``{"max_tested_depth": int, "response_times_ms": list[float],
    "baseline_time_ms": float, "threshold_ratio": float = 10.0}`` plus
    an OPTIONAL ``"rejected"``/``"server_rejected"`` bool recording that
    the server refused the deep query. ``response_times_ms[i]`` is the
    response time observed at depth ``i + 1``.

    HARD CAP (plan-mandated): WebPent's own probe discipline never
    constructs queries deeper than ``_MAX_FRAMEWORK_PROBE_DEPTH = 50``,
    and this validator therefore never attests framework-generated
    evidence beyond depth 50 — it contains no code path that
    constructs, deepens, or replays a query at all. An injected record
    claiming a deeper maximum necessarily came from an authorized
    out-of-band operator run; the analysis flags that explicitly in
    ``details["evidence_exceeds_framework_probe_cap"]`` instead of
    silently attributing it to the framework.

    Outcome rules:

      * CONFIRMED only when the timing evidence shows degradation
        (>= ``threshold_ratio`` x baseline) at depth >= 100 AND the
        server never rejected the deep query. Depth >= 100 is an order
        of magnitude beyond the framework probe cap, so a CONFIRMED
        outcome can only ever be driven by operator-supplied evidence.
        Every result carries the authorization warning in details.
      * REFUTED when the server rejected the deep query (depth /
        complexity limiting is enforced).
      * INCONCLUSIVE when there is no usable timing evidence, or when
        degradation is observed only below the confirmation floor
        (advisory — deeper testing requires explicit authorization).
    """
    probe = depth_probe if isinstance(depth_probe, dict) else {}

    raw_depth = _record_int(probe, "max_tested_depth", 0)
    # HARD CAP in force: the depth this validator will attest as
    # framework-generated evidence never exceeds 50, and anything
    # deeper is explicitly marked out-of-band operator evidence.
    attested_depth = min(raw_depth, _MAX_FRAMEWORK_PROBE_DEPTH)
    exceeds_cap = raw_depth > _MAX_FRAMEWORK_PROBE_DEPTH

    rejected = bool(probe.get("rejected", probe.get("server_rejected", False)))

    raw_times = probe.get("response_times_ms")
    times: list[float] = []
    if isinstance(raw_times, list):
        for value in raw_times[:_MAX_TIMING_SAMPLES]:
            coerced = _coerce_float(value)
            if coerced is not None and coerced >= 0:
                times.append(coerced)

    baseline = _coerce_float(probe.get("baseline_time_ms")) or 0.0
    threshold = _coerce_float(probe.get("threshold_ratio")) or 10.0
    if threshold <= 0:
        threshold = 10.0

    details: dict[str, Any] = {
        "advisory": _AUTHORIZATION_WARNING,
        "framework_probe_cap": _MAX_FRAMEWORK_PROBE_DEPTH,
        "max_tested_depth_raw": raw_depth,
        "max_tested_depth_attested": attested_depth,
        "evidence_exceeds_framework_probe_cap": exceeds_cap,
        "bounded": (
            f"at most {_MAX_TIMING_SAMPLES} timing samples analyzed; "
            f"framework-attestable depth hard-capped at "
            f"{_MAX_FRAMEWORK_PROBE_DEPTH}"
        ),
    }

    if not times or baseline <= 0:
        return _inconclusive(
            _GRAPHQL_VULN_CLASSES["depth"],
            "no usable timing evidence (empty samples or zero baseline)",
            {**details, "reason": "no-timing-evidence"},
        )

    if rejected:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["depth"],
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "server rejected the deep query — depth/complexity limiting "
                "appears enforced"
            ),
            baseline_evidence={"baseline_time_ms": baseline},
            candidate_evidence={"deep_query": "rejected by server"},
            negative_control_evidence={},
            refutation_path=None,
            details={**details, "reason": "server-rejected-deep-query"},
        )

    growth_depths = [
        depth
        for depth, elapsed in enumerate(times, start=1)
        if elapsed >= threshold * baseline
    ]
    max_growth_depth = max(growth_depths) if growth_depths else 0
    worst_time = max(times)

    if max_growth_depth >= _CONFIRMATION_DEPTH_FLOOR and raw_depth >= _CONFIRMATION_DEPTH_FLOOR:
        return ValidationResult(
            vulnerability_class=_GRAPHQL_VULN_CLASSES["depth"],
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.OBSERVED_DIFFERENTIAL,
            discriminating_signal=(
                f"response time reached {worst_time:.0f}ms "
                f"(>= {threshold:g}x the {baseline:.0f}ms baseline) at depth "
                f"{max_growth_depth} with no rejection from the server"
            ),
            baseline_evidence={"baseline_time_ms": baseline},
            candidate_evidence={
                "worst_response_time_ms": worst_time,
                "growth_depth": max_growth_depth,
                "max_tested_depth": raw_depth,
            },
            negative_control_evidence={
                "expected": "a depth-limited server rejects the deep query "
                "instead of grinding through it"
            },
            refutation_path=(
                "replay the deep query with authorization; a depth-limited "
                "server should reject it — and if it still succeeds, compare "
                "against a shallow query to rule out network jitter"
            ),
            details={
                **details,
                "reason": "depth-degradation-at-confirmation-floor",
                "severity_note": _AUTHORIZATION_WARNING,
                "worst_response_time_ms": worst_time,
                "growth_depth": max_growth_depth,
            },
        )

    return _inconclusive(
        _GRAPHQL_VULN_CLASSES["depth"],
        (
            "timing degradation below the confirmation depth floor "
            f"({_CONFIRMATION_DEPTH_FLOOR}) or not established — deeper "
            "evidence requires explicitly authorized out-of-band testing "
            "(the framework's own probes are hard-capped at "
            f"{_MAX_FRAMEWORK_PROBE_DEPTH})"
        ),
        {
            **details,
            "reason": "below-confirmation-floor" if growth_depths else "no-degradation",
            "worst_response_time_ms": worst_time,
            "growth_depth": max_growth_depth,
        },
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def analyze_graphql_surface(
    operations: list[dict[str, Any]] | None,
    evidence: dict[str, Any] | None,
) -> list[ValidationResult]:
    """Run the applicable GraphQL validators over one evidence bundle.

    Args:
        operations: The operation records produced by
            ``parse_graphql_introspection`` (or an empty list when the
            target reported no GraphQL surface). Used ONLY to annotate
            each result with ``graphql_surface_reported`` — the
            orchestrating node consults that flag to stay dormant on
            pure-REST targets (zero side effect, plan-mandated).
        evidence: Bundle with keys ``"introspection_payload"`` (dict),
            ``"batch_records"`` (list), ``"error_responses"`` (list),
            ``"depth_probe"`` (dict), and optionally
            ``"endpoint_url"`` (str) / ``"is_production"`` (bool).
            Missing keys are treated as empty evidence; every affected
            validator then returns INCONCLUSIVE — so a "no GraphQL at
            all" bundle yields all-INCONCLUSIVE results and never a
            false positive.

    Returns:
        The list of ValidationResults from all four validators (each
        carrying a ``bounded`` note in ``details``), with
        ``graphql_surface_reported`` annotated onto every result.
    """
    bundle = evidence if isinstance(evidence, dict) else {}
    ops = [op for op in (operations or []) if isinstance(op, dict)]

    introspection_payload = bundle.get("introspection_payload")
    if not isinstance(introspection_payload, dict):
        introspection_payload = {}
    batch_records = bundle.get("batch_records")
    if not isinstance(batch_records, list):
        batch_records = []
    error_responses = bundle.get("error_responses")
    if not isinstance(error_responses, list):
        error_responses = []
    depth_probe = bundle.get("depth_probe")
    if not isinstance(depth_probe, dict):
        depth_probe = {}

    results = [
        validate_introspection_exposure(
            introspection_payload,
            _bounded_str(bundle.get("endpoint_url", ""), 512),
            is_production=bool(bundle.get("is_production", True)),
        ),
        validate_batching_abuse(batch_records),
        validate_field_suggestion_leak(error_responses),
        validate_depth_complexity_dos(depth_probe),
    ]
    surface_reported = bool(ops)
    for result in results:
        result.details["graphql_surface_reported"] = surface_reported
    logger.info(
        "graphql surface analysis: %d result(s), surface_reported=%s",
        len(results),
        surface_reported,
    )
    return results


def graphql_testing_enabled() -> bool:
    """Return the ``enable_graphql_testing`` settings flag.

    This is the gate the orchestrating graph node consults before
    running these validators (the node additionally requires
    schema_ingestion to have reported non-empty graphql_operations).
    The validators themselves stay flag-free and deterministic so they
    remain unit-testable and replayable regardless of settings.
    """
    from webpent.config.settings import get_settings

    return bool(get_settings().enable_graphql_testing)


__all__ = [
    "analyze_graphql_surface",
    "graphql_testing_enabled",
    "validate_batching_abuse",
    "validate_depth_complexity_dos",
    "validate_field_suggestion_leak",
    "validate_introspection_exposure",
]
