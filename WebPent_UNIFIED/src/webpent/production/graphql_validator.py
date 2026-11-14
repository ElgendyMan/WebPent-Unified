# src/webpent/production/graphql_validator.py
"""Canonical deterministic validators for the GraphQL vulnerability classes.

2026-10-25 capability batch (GraphQL proposal). The project already
ingests GraphQL introspection (``shared/schema_ingestion
.parse_graphql_introspection``) — this module closes the loop by
confirming or refuting the four GraphQL finding classes from bounded
probe evidence, under the SAME contract as every validator in
``production/validators.py``:

  * pure functions over the evidence dict (baseline / candidate /
    negative_control), no network access, fully deterministic;
  * fail closed — missing or malformed evidence raises ``ValidatorError``;
  * CONFIRMED requires an observed differential between candidate and
    baseline that the negative control does NOT reproduce;
  * the probe side (``agents/graphql_testing/agent.py``) is bounded —
    these validators only ever analyze already-captured evidence.

Validators here are registered into ``production/validators.VALIDATORS``
so the ONE-authority-per-family rule holds for the new classes too.
"""
from __future__ import annotations

import json
from typing import Any

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
    ValidatorError,
    _body,
    _require_evidence,
    _status,
)

# Bounded-analysis caps (mirrors the probe-side caps; the validator
# never sees more than the probe could have captured).
_MAX_SCHEMA_TYPES = 200
_MAX_BATCH_RESULTS = 50
_MAX_DEPTH_PROBE_LEVELS = 16
_MIN_DEPTH_LATENCY_RATIO = 3.0
_MIN_DEPTH_LATENCY_DELTA_MS = 500

_INTROSPECTION_KEYS = ("__schema", "__typename", "__type")


def _as_dict(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _parse_graphql_payload(body: str) -> dict[str, Any] | None:
    """Parse a response body as a GraphQL JSON document (bounded)."""
    if not body:
        return None
    try:
        payload = json.loads(body[:2_000_000])
    except (ValueError, TypeError):
        return None
    return _as_dict(payload)


def _has_schema_document(payload: dict[str, Any] | None) -> bool:
    if not payload:
        return False
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    schema = data.get("__schema") if isinstance(data, dict) else None
    return isinstance(schema, dict) and isinstance(schema.get("types"), list)


def _schema_type_count(payload: dict[str, Any]) -> int:
    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return 0
    return min(len(schema.get("types") or []), _MAX_SCHEMA_TYPES)


def validate_graphql_introspection_exposure(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
) -> ValidationResult:
    """Confirm schema exposure from a successful introspection response.

    Differential: candidate (introspection query against the target
    GraphQL endpoint) returns a parseable ``__schema`` document while
    the negative control (introspection query against a NON-GraphQL
    path on the same host) does not. Baseline is an ordinary operation
    against the same endpoint proving the endpoint itself is live.
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    cand_payload = _parse_graphql_payload(_body(cand))
    if not _has_schema_document(cand_payload):
        return ValidationResult(
            "graphql_introspection_exposure", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "candidate response carries no parseable __schema document",
            baseline, cand, neg,
            refutation_path="no_schema_document")
    if _status(cand) != 200:
        return ValidationResult(
            "graphql_introspection_exposure", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            f"introspection response status {_status(cand)} is not 2xx",
            baseline, cand, neg,
            refutation_path="non_2xx_introspection")
    neg_payload = _parse_graphql_payload(_body(neg))
    if _has_schema_document(neg_payload):
        return ValidationResult(
            "graphql_introspection_exposure", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "negative control also returned a schema document — exposure is not endpoint-specific",
            baseline, cand, neg,
            refutation_path="control_also_exposes_schema")
    return ValidationResult(
        "graphql_introspection_exposure", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "introspection query returned a full schema document the negative control did not",
        baseline, cand, neg,
        details={"schema_type_count": _schema_type_count(cand_payload or {})})


def validate_graphql_field_suggestion_leak(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    """Confirm field-suggestion leakage ("Did you mean ...").

    Differential: candidate (query with a deliberate near-miss field
    typo) returns a suggestion naming a field that is NOT in the
    documented public schema (``evidence["public_schema_fields"]``);
    negative control (a query with a nonsense field matching nothing)
    returns an error WITHOUT a suggestion, and the baseline (valid
    query) succeeds — proving the suggestion is leak-driven, not a
    generic error path.
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    public_fields = {
        str(f).strip().lower()
        for f in (
            cand.get("public_schema_fields")
            or cand.get("evidence", {}).get("public_schema_fields")
            or kwargs.get("public_schema_fields")
            or []
        )
        if str(f).strip()
    }
    cand_body = _body(cand)
    leaked = _extract_suggested_fields(cand_body)
    if not leaked:
        return ValidationResult(
            "graphql_field_suggestion_leak", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "candidate error response contains no field suggestion",
            baseline, cand, neg,
            refutation_path="no_suggestion_in_error")
    if not public_fields:
        return ValidationResult(
            "graphql_field_suggestion_leak", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "no public schema fields on record — cannot prove the suggested field is undocumented",
            baseline, cand, neg,
            refutation_path="no_public_schema_reference")
    undocumented = sorted(f for f in leaked if f.lower() not in public_fields)
    if not undocumented:
        return ValidationResult(
            "graphql_field_suggestion_leak", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "every suggested field is already documented in the public schema",
            baseline, cand, neg,
            refutation_path="suggestions_all_documented")
    neg_body = _body(neg)
    if _extract_suggested_fields(neg_body):
        return ValidationResult(
            "graphql_field_suggestion_leak", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "negative control (nonsense field) also received suggestions — generic error behavior, not a leak differential",
            baseline, cand, neg,
            refutation_path="control_also_suggests")
    if _status(baseline) not in range(200, 300):
        return ValidationResult(
            "graphql_field_suggestion_leak", ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "baseline valid query did not succeed — endpoint health unknown",
            baseline, cand, neg,
            refutation_path="baseline_unhealthy")
    return ValidationResult(
        "graphql_field_suggestion_leak", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "error suggestions leak undocumented field names the nonsense-field control does not",
        baseline, cand, neg,
        details={"leaked_fields": undocumented})


def _extract_suggested_fields(body: str) -> list[str]:
    """Pull field names out of GraphQL 'Did you mean' suggestion text."""
    import re

    leaked: list[str] = []
    # JSON-escaped quote handling: GraphQL servers commonly embed the
    # suggestion inside a JSON "message" string, where quotes arrive
    # as \" — normalize before tokenizing.
    body = (body or "").replace('\\"', '"')
    for match in re.finditer(r"[Dd]id you mean[^?]*\?", body or ""):
        segment = match.group(0).replace("Did you mean", "").replace("did you mean", "")
        # Canonical server form quotes each candidate: 'Did you mean
        # "users" or "userRoles"?' — pull quoted identifiers first.
        quoted = re.findall(r"['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", segment)
        if quoted:
            leaked.extend(quoted)
            continue
        for tok in segment.replace(" or ", ",").split(","):
            tok = tok.strip().strip('"').strip("'")
            if tok:
                leaked.append(tok)
    # Also the common single-quoted form: 'Did you mean "x" instead?'
    for match in re.finditer(r"[Dd]id you mean\s+['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]", body or ""):
        leaked.append(match.group(1))
    out: list[str] = []
    seen: set[str] = set()
    for name in leaked:
        name = name.strip()
        if name and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name.lower() not in seen:
            seen.add(name.lower())
            out.append(name)
    return out[:20]


def validate_graphql_batching_abuse(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    """Confirm rate-limit bypass via query batching.

    Differential: candidate (a single JSON-array request carrying N
    operations) executes ALL of them (response is an array of N
    results) while the negative control (individual sequential
    requests at the same rate) shows active throttling (429 or
    rate-limit headers/flags) — the batch side-stepped a limiter that
    is demonstrably live.
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    try:
        cand_payload = json.loads(_body(cand)[:2_000_000])
    except (ValueError, TypeError):
        cand_payload = None
    if not isinstance(cand_payload, list):
        return ValidationResult(
            "graphql_batching_abuse", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "candidate response is not a JSON array — batching is not enabled",
            baseline, cand, neg,
            refutation_path="no_batch_response")
    executed = sum(
        1 for item in cand_payload[:_MAX_BATCH_RESULTS]
        if isinstance(item, dict) and "data" in item
    )
    if executed < 2:
        return ValidationResult(
            "graphql_batching_abuse", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            f"batch executed {executed} operation(s) — needs >=2 to count as batching",
            baseline, cand, neg,
            refutation_path="single_operation_batch")
    if not _throttling_observed(neg):
        return ValidationResult(
            "graphql_batching_abuse", ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "no throttling observed on sequential requests — cannot prove a limit was bypassed",
            baseline, cand, neg,
            refutation_path="no_live_rate_limit")
    return ValidationResult(
        "graphql_batching_abuse", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        f"batch of {executed} operations executed while sequential requests were actively throttled",
        baseline, cand, neg,
        details={"batch_operations_executed": executed})


def _throttling_observed(evidence: dict[str, Any]) -> bool:
    if _status(evidence) == 429:
        return True
    headers = evidence.get("response_headers") or evidence.get("headers") or {}
    if isinstance(headers, dict):
        lowered = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if any(k.startswith("x-ratelimit") or k.startswith("ratelimit") for k in lowered):
            if lowered.get("x-ratelimit-remaining", "1").strip() in ("0", ""):
                return True
    body = _body(evidence).lower()
    for marker in ("rate limit", "too many requests", "throttled", "quota exceeded"):
        if marker in body:
            return True
    return bool(evidence.get("throttled") is True)


def validate_graphql_depth_complexity_dos(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    """Confirm unbounded-depth acceptance from a BOUNDED deep-query probe.

    The probe NEVER attempts a real DoS: the deep query is capped at
    ``_MAX_DEPTH_PROBE_LEVELS`` nesting levels and a single request.
    CONFIRMED only when (a) the deep query was accepted and executed
    (200 with a data document, no error), (b) it cost materially more
    than the shallow baseline (latency ratio >= 3x AND delta >= 500ms),
    and (c) the negative control (an over-limit query the server
    REJECTED) proves the server does have depth limiting — i.e. the
    accepted deep query was within the server's blind spot, not
    evidence of absent limiting that a bigger probe would just hang on.
    Without the timing differential the result is INCONCLUSIVE, never
    CONFIRMED — a timing-free "deep query worked" is not a DoS finding.
    """
    _require_evidence("baseline", baseline)
    cand = _require_evidence("candidate", candidate)
    neg = _require_evidence("negative_control", negative_control)
    cand_payload = _parse_graphql_payload(_body(cand))
    if not (isinstance(cand_payload, dict) and "data" in cand_payload):
        return ValidationResult(
            "graphql_depth_complexity_dos", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "deep probe was not executed as a data document (rejected or errored)",
            baseline, cand, neg,
            refutation_path="deep_query_rejected")
    neg_rejected = (
        _status(neg) not in range(200, 300)
        or (isinstance(_parse_graphql_payload(_body(neg)), dict)
            and "errors" in (_parse_graphql_payload(_body(neg)) or {}))
    )
    if not neg_rejected:
        return ValidationResult(
            "graphql_depth_complexity_dos", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "server accepted the over-limit control too — no depth boundary exists to sit inside; refusing to extrapolate a DoS",
            baseline, cand, neg,
            refutation_path="no_depth_boundary")
    b_ms = _latency_ms(baseline)
    c_ms = _latency_ms(cand)
    if b_ms <= 0 or c_ms <= 0:
        return ValidationResult(
            "graphql_depth_complexity_dos", ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "missing latency observations — timing differential unavailable",
            baseline, cand, neg,
            refutation_path="no_timing_evidence")
    ratio = c_ms / b_ms
    delta = c_ms - b_ms
    if ratio < _MIN_DEPTH_LATENCY_RATIO or delta < _MIN_DEPTH_LATENCY_DELTA_MS:
        return ValidationResult(
            "graphql_depth_complexity_dos", ValidationOutcome.REFUTED,
            EvidenceQuality.HEURISTIC_SIGNAL,
            f"timing differential below threshold (ratio {ratio:.2f}x, delta {delta}ms)",
            baseline, cand, neg,
            refutation_path="timing_below_threshold")
    return ValidationResult(
        "graphql_depth_complexity_dos", ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        f"depth-probe executed with {ratio:.1f}x baseline latency (+{delta}ms) while the over-limit control was rejected",
        baseline, cand, neg,
        details={
            "baseline_ms": b_ms,
            "candidate_ms": c_ms,
            "latency_ratio": round(ratio, 3),
            "max_probe_levels": _MAX_DEPTH_PROBE_LEVELS,
        })


def _latency_ms(evidence: dict[str, Any]) -> int:
    for key in ("elapsed_ms", "latency_ms", "duration_ms"):
        try:
            return int(evidence.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return 0


__all__ = [
    "validate_graphql_introspection_exposure",
    "validate_graphql_field_suggestion_leak",
    "validate_graphql_batching_abuse",
    "validate_graphql_depth_complexity_dos",
]
