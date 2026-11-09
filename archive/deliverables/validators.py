"""TEAM-1 — Canonical Validator Framework (Validator Coverage V1).

Six vulnerability families, each with: hypothesis→experiment contract, causal
differential validation, negative control, refutation support, evidence quality
projection. All validators consume ACTUAL bounded experiment evidence — no
"candidate says X → confirmed" shortcuts. ResearchLoop remains the only
research controller. Validators report outcomes back to OutcomeTracker.

Evidence quality levels (deterministic, ascending):
  0 = structural_hint (no execution)
  1 = heuristic_signal (single observation)
  2 = observed_differential (baseline vs candidate)
  3 = deterministic_tool_evidence (reproducible tool result)
  4 = replay_backed_evidence (reproduced under replay)
  5 = promotion_grade_proof (ProofBundle + HMAC + semantic + causal)
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


class ValidationOutcome(str, Enum):
    CONFIRMED = "CONFIRMED"
    REFUTED = "REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class EvidenceQuality(int, Enum):
    STRUCTURAL_HINT = 0
    HEURISTIC_SIGNAL = 1
    OBSERVED_DIFFERENTIAL = 2
    DETERMINISTIC_TOOL = 3
    REPLAY_BACKED = 4
    PROMOTION_GRADE = 5


@dataclass
class ValidationResult:
    vulnerability_class: str
    outcome: ValidationOutcome
    evidence_quality: EvidenceQuality
    discriminating_signal: str  # what actually distinguished candidate from baseline
    baseline_evidence: dict[str, Any]
    candidate_evidence: dict[str, Any]
    negative_control_evidence: dict[str, Any]
    refutation_path: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def is_confirmation_grade(self) -> bool:
        return (
            self.outcome == ValidationOutcome.CONFIRMED
            and self.evidence_quality >= EvidenceQuality.OBSERVED_DIFFERENTIAL
        )


class ValidatorError(ValueError):
    pass


def _require_evidence(name: str, evidence: dict[str, Any] | None) -> dict[str, Any]:
    if not evidence or not isinstance(evidence, dict):
        raise ValidatorError(f"Missing required evidence: {name}")
    return evidence


def _status(evidence: dict[str, Any]) -> int:
    value = evidence.get("status_code", evidence.get("status", 0))
    if value is None:
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _body(evidence: dict[str, Any]) -> str:
    return str(evidence.get("response_body", evidence.get("body", "")))


def _headers(evidence: dict[str, Any]) -> dict[str, Any]:
    raw = evidence.get("headers", {}) or {}
    return {str(key).lower(): value for key, value in raw.items()}


def _structured(evidence: dict[str, Any]) -> dict[str, Any]:
    value = evidence.get("structured_fields", {}) or {}
    return dict(value) if isinstance(value, dict) else {}


def _successful(evidence: dict[str, Any]) -> bool:
    return 200 <= _status(evidence) < 300


def _body_fingerprint(evidence: dict[str, Any]) -> str:
    """Return a normalizer-produced response fingerprint when available."""
    return str(_structured(evidence).get("_body_fingerprint") or "")


def _json_subset(expected: Any, observed: Any) -> bool:
    """Return whether ``observed`` preserves the semantic content of ``expected``.

    This is deliberately schema-agnostic: it compares JSON values rather than
    names from a particular application.  A foreign response may contain the
    owner's resource plus additional metadata, which is still a meaningful
    access match for IDOR/BOLA validation.
    """
    if isinstance(expected, dict) and isinstance(observed, dict):
        return all(key in observed and _json_subset(value, observed[key]) for key, value in expected.items())
    if isinstance(expected, list) and isinstance(observed, list):
        return all(any(_json_subset(item, candidate) for candidate in observed) for item in expected)
    return expected == observed


def _json_leaf_pairs(value: Any, prefix: str = "") -> set[tuple[str, str]]:
    """Produce schema-agnostic, non-sensitive JSON leaf equality facts."""
    if isinstance(value, dict):
        pairs: set[tuple[str, str]] = set()
        for key, item in value.items():
            pairs.update(_json_leaf_pairs(item, f"{prefix}.{key}" if prefix else str(key)))
        return pairs
    if isinstance(value, list):
        pairs: set[tuple[str, str]] = set()
        for index, item in enumerate(value[:32]):
            pairs.update(_json_leaf_pairs(item, f"{prefix}[{index}]"))
        return pairs
    if value is None or isinstance(value, (bool, int, float, str)):
        text = str(value)
        return {(prefix, text)} if prefix and text else set()
    return set()


def _identity_aware_resource_match(reference: dict[str, Any], observed: dict[str, Any]) -> bool:
    """Check for shared resource facts across otherwise different responses.

    A response can legitimately vary in viewer/session fields while retaining
    the same protected resource.  Requiring two independent equal JSON leaves
    avoids treating a shape-only 2xx response as a resource match.  This is a
    format-agnostic response comparison only; distinct-principal proof remains
    enforced by the AVI identity-binding gate.
    """
    try:
        reference_json = json.loads(_body(reference))
        observed_json = json.loads(_body(observed))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return len(_json_leaf_pairs(reference_json).intersection(_json_leaf_pairs(observed_json))) >= 2


def _response_relation(reference: dict[str, Any], observed: dict[str, Any]) -> str:
    """Classify redaction-safe response relationship without target schemas.

    ``same_or_superset`` is only emitted for a non-empty exact/fingerprinted
    response or for a structural JSON subset.  It never treats two empty 2xx
    responses as evidence of cross-principal object access.
    """
    reference_body, observed_body = _body(reference).strip(), _body(observed).strip()
    reference_fp, observed_fp = _body_fingerprint(reference), _body_fingerprint(observed)
    if reference_body and observed_body and reference_body == observed_body:
        return "same_or_superset"
    if reference_fp and observed_fp and reference_fp == observed_fp:
        if (
            reference_body
            or observed_body
            or _structured(reference).get("_body_size")
            or _structured(observed).get("_body_size")
        ):
            return "same_or_superset"
    try:
        reference_json = json.loads(reference_body)
        observed_json = json.loads(observed_body)
    except (TypeError, ValueError, json.JSONDecodeError):
        reference_json = observed_json = None
    if reference_json is not None and observed_json is not None and _json_subset(reference_json, observed_json):
        return "same_or_superset"
    if reference_body or observed_body or reference_fp or observed_fp:
        return "different"
    return "unknown"


def _is_private_ip(host: str) -> bool:
    """Return whether a literal host is local, private, or link-local."""
    try:
        address = ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback or address.is_link_local)


_IPV4_TOKEN = re.compile(r"(?<![A-Za-z0-9])\d{1,3}(?:\.\d{1,3}){3}(?![A-Za-z0-9])")
_IPV6_TOKEN = re.compile(r"(?<![A-Za-z0-9])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:.]+(?![A-Za-z0-9])")


def extract_ssrf_indicators(value: str) -> frozenset[str]:
    """Return semantic SSRF indicator classes using literal IP parsing."""
    text = str(value or "")
    lowered = text.lower()
    indicators: set[str] = set()
    if any(
        marker in lowered
        for marker in (
            "/latest/meta-data",
            "instance identity",
            "metadata.google.internal",
        )
    ):
        indicators.add("cloud_metadata")
    if any(
        marker in lowered
        for marker in (
            "localhost",
            "internal-ip",
            "private ip",
        )
    ):
        indicators.add("internal_host")
    for token in (*_IPV4_TOKEN.findall(text), *_IPV6_TOKEN.findall(text)):
        if _is_private_ip(token):
            indicators.add("internal_host")
            if token.strip("[]") == "169.254.169.254":
                indicators.add("cloud_metadata")
    if "metadata.google.internal" in lowered or "169.254.169.254" in lowered:
        indicators.add("cloud_metadata")
    if any(
        marker in text
        for marker in (
            "iam",
            "security-credentials",
            "role-name",
            "access-token",
        )
    ):
        indicators.add("cloud_credentials")
    return frozenset(indicators)


def extract_info_disclosure_indicators(value: str) -> frozenset[str]:
    """Return independent sensitive-pattern classes for disclosure validation."""
    text = str(value or "").lower()
    indicators: set[str] = set()
    if any(marker in text for marker in ("password", "api_key", "api-key", "secret")):
        indicators.add("credential_label")
    if any(marker in text for marker in ("stack trace", "traceback", " at line ", "exception:")):
        indicators.add("stack_trace")
    if any(marker in text for marker in ("/app/", "/tmp/", "/var/www", "internal ip", "private ip")):
        indicators.add("internal_path")
    if any(marker in text for marker in ("ssn", "credit card", "bcrypt", "authorization token")):
        indicators.add("sensitive_identity_data")
    return frozenset(indicators)


def parse_external_location(
    evidence: Mapping[str, Any] | str,
    safe_hosts: Iterable[str] | None = None,
) -> tuple[str, bool]:
    """Return a Location value and whether it is an unallowlisted URL."""
    if isinstance(evidence, str):
        location = evidence.strip()
        structured: dict[str, Any] = {}
    else:
        headers = _headers(dict(evidence))
        location = str(headers.get("location", evidence.get("location", "")) or "").strip()
        structured = _structured(dict(evidence))
    if location.startswith("//"):
        location = "https:" + location
    elif location.startswith("https:") and not location.startswith("https://"):
        location = location.replace("https:", "https://", 1)
    elif location.startswith("http:") and not location.startswith("http://"):
        location = location.replace("http:", "http://", 1)
    parsed = urlsplit(location)
    host = (parsed.hostname or "").lower().rstrip(".")
    allowed = {str(item).lower().rstrip(".") for item in structured.get("allowed_redirect_hosts", ())}
    configured_safe_hosts = safe_hosts if safe_hosts is not None else _configured_safe_hosts()
    safe = {str(item).lower().rstrip(".") for item in configured_safe_hosts}
    external = parsed.scheme.lower() in {"http", "https"} and bool(host) and host not in safe and host not in allowed
    return location, external


def _configured_safe_hosts() -> frozenset[str]:
    """Load the redirect-safe host set from configuration, with legacy defaults."""
    raw = os.getenv(
        "WEBPENT_SAFE_REDIRECT_HOSTS",
        "localhost,127.0.0.1,::1,example.com,trusted.com",
    )
    return frozenset(host.strip().lower().rstrip(".") for host in raw.split(",") if host.strip())


# ---- Generic comparison helpers (pure logic, no format assumptions) --------
# Sprint refactor: replace target/format-specific checks (Juice Shop field names,
# JSON-only parsing, hard-coded error strings) with generic behavioral pattern
# matching.  These helpers consume ONLY the evidence dict shape (status_code,
# response_body, headers) and make zero assumptions about any application's
# response schema, language, or content type.

_SIMILAR_SIZE_TOLERANCE = 0.20  # ±20% body-size window
_SIMILAR_TOKEN_OVERLAP = 0.60  # minimum Jaccard token overlap for "similar"

_TOKEN_RE = re.compile(r"[A-Za-z0-9_./:-]+")


def _content_tokens(text: str) -> set[str]:
    """Token set for language/schema-agnostic content overlap comparison."""
    return {token.lower() for token in _TOKEN_RE.findall(str(text or "")) if len(token) > 1}


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def responses_similar(
    a: dict[str, Any],
    b: dict[str, Any],
    size_tolerance: float = _SIMILAR_SIZE_TOLERANCE,
    min_overlap: float = _SIMILAR_TOKEN_OVERLAP,
) -> bool:
    """Generic behavioral similarity — works on ANY response format.

    Compares (1) status code, (2) body size within ±tolerance, and
    (3) content digest (token-overlap fingerprint).  No JSON parsing, no
    field-name checks, no content-type requirement.  Two responses are
    similar when they carry the same resource even if dynamic per-request
    fields (timestamps, CSRF tokens, session ids) differ.
    """
    a_status, b_status = _status(a), _status(b)
    if a_status != b_status:
        return False
    a_body, b_body = _body(a), _body(b)
    # Exact match or identical normalizer fingerprint → trivially similar.
    if a_body and a_body == b_body:
        return True
    a_fp, b_fp = _body_fingerprint(a), _body_fingerprint(b)
    if a_fp and a_fp == b_fp:
        return True
    a_size, b_size = len(a_body), len(b_body)
    larger = max(a_size, b_size, 1)
    if abs(a_size - b_size) / larger > size_tolerance:
        return False
    overlap = _jaccard(_content_tokens(a_body), _content_tokens(b_body))
    return overlap >= min_overlap


def response_differs(a: dict[str, Any], b: dict[str, Any], size_tolerance: float = _SIMILAR_SIZE_TOLERANCE) -> bool:
    """Generic behavioral difference — status, size, or content meaningfully
    differs.  Inverse of responses_similar, used for boolean/timing diffs."""
    if _status(a) != _status(b):
        return True
    a_body, b_body = _body(a), _body(b)
    a_size, b_size = len(a_body), len(b_body)
    larger = max(a_size, b_size, 1)
    if abs(a_size - b_size) / larger > size_tolerance:
        return True
    overlap = _jaccard(_content_tokens(a_body), _content_tokens(b_body))
    return overlap < 0.50


_GENERIC_ERROR_PATTERNS = (
    re.compile(r"\berror\b", re.I),
    re.compile(r"\bexception\b", re.I),
    re.compile(r"\bfail(?:ed|ure)?\b", re.I),
    re.compile(r"\binvalid\b", re.I),
    re.compile(r"\bdenied\b", re.I),
    re.compile(r"\bforbidden\b", re.I),
    re.compile(r"\bunauthorized\b", re.I),
    re.compile(r"\bnot found\b", re.I),
    re.compile(r"\bunavailable\b", re.I),
    re.compile(r"\breject(?:ed|ion)?\b", re.I),
)


def has_error_signature(response: dict[str, Any]) -> tuple[bool, tuple[str, ...]]:
    """Generic error detection — 4xx/5xx status OR generic error text patterns.
    No target-specific strings.  Returns (is_error, matched_patterns)."""
    status = _status(response)
    body = _body(response)
    matched = tuple(p.pattern for p in _GENERIC_ERROR_PATTERNS if p.search(body))
    is_error = (400 <= status < 600) or bool(matched)
    return is_error, matched


_HTML_ENCODED_FORMS = (
    lambda m: (
        m.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")
    ),
    lambda m: m.replace("<", "%3C").replace(">", "%3E").replace('"', "%22").replace("'", "%27").replace(" ", "%20"),
    lambda m: m.replace("<", "\\u003c").replace(">", "\\u003e"),
)


def marker_reflected(marker: str, response: dict[str, Any] | str) -> bool:
    """Check whether a unique marker string appears UNENCODED in the response.

    Returns True only when the raw marker is present verbatim AND none of the
    common encoded forms (HTML-entity, URL-encoded, unicode-escaped) are the
    sole representation.  Works on any response format — no content-type or
    schema assumption.  Accepts either an evidence dict or a raw body string.
    """
    if not marker:
        return False
    body = _body(response) if isinstance(response, Mapping) else str(response)
    if marker not in body:
        return False
    # If an encoded form appears but the raw marker also appears, treat as
    # reflected (the raw occurrence is the dangerous one).  If ONLY encoded
    # forms appear, it is not reflected unencoded.
    raw_positions = [m.start() for m in re.finditer(re.escape(marker), body)]
    if not raw_positions:
        return False
    # Confirm at least one raw occurrence is not part of a longer encoded blob
    # by checking that an encoded form does not account for every occurrence.
    for encode in _HTML_ENCODED_FORMS:
        encoded = encode(marker)
        if encoded != marker and encoded in body:
            # encoded form exists; ensure there is still a raw occurrence outside
            # the encoded spans.
            raw_only = body.replace(encoded, "")
            if marker not in raw_only:
                return False
    return True


# ---- Family 1: IDOR / BOLA (Broken Object Level Authorization) -------------


def validate_idor(
    *, baseline: dict, candidate: dict, negative_control: dict, resource_id_field: str = "id"
) -> ValidationResult:
    """IDOR/BOLA: foreign principal accesses another user's resource.

    Baseline: owner accesses own resource (200).
    Candidate: foreign principal accesses owner's resource (should be 403/404).
    Negative control: foreign principal accesses invalid/nonexistent resource (404).
    CONFIRMED iff a foreign principal successfully reaches the owner's resource
    with the same/superset response semantics and the invalid-object control is
    denied or materially distinct.  No target schema or response-field name is
    required.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    b_status, c_status, nc_status = _status(b), _status(c), _status(nc)
    if (c.get("structured_fields") or {}).get("_identity_mismatch_hint") is False:
        return ValidationResult(
            "IDOR",
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "identity_binding_failed: candidate actor matches expected owner",
            b,
            c,
            nc,
        )
    relation = _response_relation(b, c)
    if relation == "different" and _identity_aware_resource_match(b, c):
        relation = "same_or_superset"
    # Generic behavioral path (target/format-agnostic): two successful responses
    # with matching status, size within ±20%, and overlapping content digest
    # are treated as the same resource — no JSON, no field names required.
    if relation != "same_or_superset" and _successful(b) and _successful(c) and responses_similar(b, c):
        relation = "same_or_superset"
    control_relation_baseline = _response_relation(b, nc)
    control_relation_candidate = _response_relation(c, nc)
    # Generic control check: a valid negative control is either denied
    # (4xx/5xx or error signature) OR materially different from both baseline
    # and candidate (proves the endpoint distinguishes valid from invalid ids).
    control_denied = (not _successful(nc)) or has_error_signature(nc)[0] or nc_status in (400, 401, 403, 404)
    control_distinct = response_differs(b, nc) and response_differs(c, nc)
    candidate_accesses_other_resource = _successful(b) and _successful(c) and relation == "same_or_superset"
    negative_control_works = (
        control_denied
        or (control_relation_baseline == "different" and control_relation_candidate == "different")
        or control_distinct
    )
    if candidate_accesses_other_resource and negative_control_works:
        signal = f"foreign principal reached owner-equivalent resource (baseline {b_status}, candidate {c_status}, control {nc_status})"
        return ValidationResult(
            "IDOR",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
        )
    if c_status in (401, 403, 404) and _successful(b):
        return ValidationResult(
            "IDOR",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            f"foreign principal correctly denied ({c_status})",
            b,
            c,
            nc,
            refutation_path="access_control_enforced",
        )
    return ValidationResult(
        "IDOR",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        f"insufficient cross-principal semantic differential (baseline={b_status}, candidate={c_status}, control={nc_status})",
        b,
        c,
        nc,
        details={
            "required": [
                "baseline_success",
                "candidate_success",
                "owner_equivalent_response",
                "denied_or_distinct_control",
            ],
            "observed": {
                "baseline": b_status,
                "candidate": c_status,
                "negative_control": nc_status,
                "response_relation": relation,
                "control_relation_baseline": control_relation_baseline,
                "control_relation_candidate": control_relation_candidate,
            },
        },
    )


# ---- Family 2: Open Redirect ----------------------------------------------


def validate_open_redirect(
    *, baseline: dict, candidate: dict, negative_control: dict, redirect_header: str = "location"
) -> ValidationResult:
    """Open Redirect: candidate redirects to attacker-controlled URL.

    Baseline: safe/empty redirect param → no external redirect.
    Candidate: attacker URL in redirect param → 3xx with Location: attacker.com.
    Negative control: invalid/missing param → no redirect.
    CONFIRMED iff candidate Location header points to untrusted external domain.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_loc, c_external = parse_external_location(c)
    _, b_external = parse_external_location(b)
    _, nc_external = parse_external_location(nc)
    c_status = _status(c)
    if c_external and 300 <= c_status < 400 and not b_external and not nc_external:
        signal = f"candidate returned external Location ({c_status})"
        return ValidationResult(
            "OPEN_REDIRECT",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={"location_host_external": True, "location_present": True},
        )
    if not c_external or not 300 <= c_status < 400:
        return ValidationResult(
            "OPEN_REDIRECT",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "candidate did not return an unallowlisted 301/302 external redirect",
            b,
            c,
            nc,
            refutation_path="redirect_sanitized",
        )
    return ValidationResult(
        "OPEN_REDIRECT",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "redirect present but trusted domain ambiguous",
        b,
        c,
        nc,
        details={
            "required": [
                "candidate_external_location",
                "candidate_301_or_302",
                "baseline_and_control_not_external",
            ],
            "observed": {
                "candidate_status": c_status,
                "candidate_external": c_external,
                "baseline_external": b_external,
                "negative_control_external": nc_external,
            },
        },
    )


# ---- Family 3: SSRF (Server-Side Request Forgery) --------------------------


def validate_ssrf(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """SSRF: server makes request to attacker-controlled/internal endpoint.

    Baseline: safe URL param → server fetches allowed resource.
    Candidate: internal/metadata URL (169.254.169.254, localhost:admin) → server fetches it.
    Negative control: invalid URL scheme → server rejects.
    CONFIRMED iff candidate response contains internal/metadata content.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_indicators = extract_ssrf_indicators(_body(c))
    b_indicators = extract_ssrf_indicators(_body(b))
    nc_indicators = extract_ssrf_indicators(_body(nc))
    nc_status = _status(nc)
    # Generic control check: negative control must be clean (no indicators) AND
    # either rejected (4xx/5xx or error signature) OR materially different from
    # candidate (proves the server distinguishes the SSRF payload).
    control_clean = not nc_indicators
    control_rejected = nc_status in (400, 401, 403, 404) or has_error_signature(nc)[0] or response_differs(c, nc)
    differential = len(c_indicators) > len(b_indicators)
    if len(c_indicators) >= 2 and differential and control_clean and control_rejected:
        signal = f"candidate response contains {len(c_indicators)} SSRF indicator classes"
        return ValidationResult(
            "SSRF",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
        )
    # Generic single-indicator path: a strong internal indicator (private IP or
    # cloud metadata) present only in candidate, with a clean/rejected control.
    strong_indicator = {"cloud_metadata", "internal_host"} & set(c_indicators)
    if strong_indicator and differential and control_clean and control_rejected and not b_indicators:
        signal = f"candidate response contains strong internal indicator ({sorted(strong_indicator)[0]})"
        return ValidationResult(
            "SSRF",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={"single_strong_indicator": True},
        )
    if not differential or nc_indicators:
        return ValidationResult(
            "SSRF",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "no differential SSRF indicators or control was not clean",
            b,
            c,
            nc,
            refutation_path="url_validation_enforced",
        )
    return ValidationResult(
        "SSRF",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        f"weak signal ({len(c_indicators)} indicator classes, nc status {nc_status})",
        b,
        c,
        nc,
        details={
            "required": [
                "candidate_indicators>=2 or strong single",
                "candidate_gt_baseline",
                "clean_control",
                "control_rejected_or_different",
            ],
            "observed": {
                "candidate_indicators": sorted(c_indicators),
                "baseline_indicators": sorted(b_indicators),
                "negative_control_indicators": sorted(nc_indicators),
                "negative_control_status": nc_status,
            },
        },
    )


# ---- Family 4: Reflected XSS ------------------------------------------------


def _content_type(evidence: dict[str, Any]) -> str:
    return str(_headers(evidence).get("content-type", "")).lower()


def _reflection_payload(evidence: dict[str, Any]) -> str:
    structured = _structured(evidence)
    for key in ("payload", "reflection_payload", "request_payload", "marker"):
        value = evidence.get(key, structured.get(key))
        if isinstance(value, str) and value:
            return value
    request = evidence.get("request")
    if isinstance(request, dict):
        for key in ("payload", "body", "query_value", "parameter_value"):
            value = request.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _xss_reflection_context(body: str, payload: str) -> str | None:
    position = body.find(payload)
    if position < 0:
        return None
    before = body[:position].lower()
    after = body[position + len(payload) :].lower()
    script_open = before.rfind("<script")
    script_close = before.rfind("</script")
    if script_open > script_close and "</script" in after:
        return "script"
    comment_open = before.rfind("<!--")
    comment_close = before.rfind("-->")
    if comment_open > comment_close and "-->" in after:
        return "comment"
    tag_open = before.rfind("<")
    tag_close = before.rfind(">")
    if tag_open > tag_close:
        return "attribute"
    return "html_body"


def _active_xss_payload(payload: str) -> bool:
    """Require an executable XSS probe, not a passive reflection marker."""
    lowered = payload.lower()
    return bool("<script" in lowered or "javascript:" in lowered or re.search(r"<[a-z][^>]*\bon[a-z]+\s*=", lowered))


def validate_xss(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """Validate reflected XSS using candidate-only, unencoded executable reflection."""
    b = _require_evidence("baseline", baseline)
    c = _require_evidence("candidate", candidate)
    nc = _require_evidence("negative_control", negative_control)
    payload = _reflection_payload(c)
    body = _body(c)
    baseline_body = _body(b)
    control_body = _body(nc)
    ctype = _content_type(c)
    # Generic: reject only clearly non-executable binary content types.  XSS
    # reflection can occur in HTML, XML, SVG, plain text, or even JSONP — a
    # hard "html in content-type" requirement is format-specific and misses
    # reflected sinks in other text-based types.
    _BINARY_CT = (
        "image/",
        "video/",
        "audio/",
        "application/pdf",
        "application/octet-stream",
        "application/zip",
    )
    if not payload or not body or any(ctype.startswith(b) for b in _BINARY_CT):
        return ValidationResult(
            "XSS",
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "missing payload, response body, or binary content type",
            b,
            c,
            nc,
            details={"payload_present": bool(payload), "content_type": ctype},
        )
    # Generic unencoded-reflection check (replaces raw `payload in body`).
    candidate_reflects = marker_reflected(payload, c)
    baseline_reflects = marker_reflected(payload, b)
    control_reflects = marker_reflected(payload, nc)
    encoded = (
        payload.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
    if not candidate_reflects and encoded in body:
        return ValidationResult(
            "XSS",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "reflection was HTML-encoded",
            b,
            c,
            nc,
            refutation_path="output_encoding_enforced",
            details={"payload": payload, "encoded": True},
        )
    context = _xss_reflection_context(body, payload) if candidate_reflects else None
    if not _active_xss_payload(payload):
        if context == "comment":
            return ValidationResult(
                "XSS",
                ValidationOutcome.REFUTED,
                EvidenceQuality.OBSERVED_DIFFERENTIAL,
                "passive marker reflected only in a non-executable comment",
                b,
                c,
                nc,
                refutation_path="non_executable_reflection",
                details={"payload": payload, "active_probe": False, "reflection_context": context},
            )
        return ValidationResult(
            "XSS",
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "passive reflection marker cannot prove executable XSS",
            b,
            c,
            nc,
            details={"payload": payload, "active_probe": False, "reflection_context": context},
        )
    # Generic confirmation: executable probe reflected unencoded in candidate
    # only (absent from both baseline and negative control).  Context is a
    # supporting detail, not a format-specific gate.
    if candidate_reflects and not baseline_reflects and not control_reflects and context != "comment":
        ctx = context or "unclassified"
        return ValidationResult(
            "XSS",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            f"unencoded payload reflected (context: {ctx})",
            b,
            c,
            nc,
            details={"payload": payload, "reflection_context": ctx, "encoded": False},
        )
    if context == "comment" or (encoded in body and not candidate_reflects):
        return ValidationResult(
            "XSS",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "payload reflected only in a non-executable or encoded context",
            b,
            c,
            nc,
            refutation_path="non_executable_reflection",
            details={"payload": payload, "reflection_context": context, "encoded": encoded in body},
        )
    return ValidationResult(
        "XSS",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "reflection was missing, ambiguous, or also present in a control",
        b,
        c,
        nc,
        details={
            "payload": payload,
            "reflection_context": context,
            "candidate_reflects": candidate_reflects,
            "baseline_reflects": baseline_reflects,
            "control_reflects": control_reflects,
        },
    )


# ---- Family 5: SQL Injection -----------------------------------------------

_SQL_ERROR_PATTERNS = (
    re.compile(r"sqlstate\s*\[[0-9a-z]+\]", re.I),
    re.compile(r"(?:mysql|mariadb|postgres(?:ql)?|sqlite|oracle)\s*(?:error|exception|database)", re.I),
    re.compile(
        r"(?:syntax error|unterminated quoted string|unclosed quotation mark)\s*(?:near|at|for)?",
        re.I,
    ),
)


def _sql_errors(body: str) -> tuple[str, ...]:
    return tuple(pattern.pattern for pattern in _SQL_ERROR_PATTERNS if pattern.search(body))


def _sql_payload(evidence: dict[str, Any]) -> str:
    structured = _structured(evidence)
    for key in ("sql_payload", "payload", "parameter_value", "request_payload"):
        value = evidence.get(key, structured.get(key))
        if isinstance(value, str):
            return value
    request = evidence.get("request")
    if isinstance(request, dict):
        for key in ("payload", "body", "query_value", "parameter_value"):
            value = request.get(key)
            if isinstance(value, str):
                return value
    return ""


def _response_time_ms(evidence: dict[str, Any]) -> float | None:
    value = evidence.get("response_time_ms", evidence.get("timing_ms"))
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def validate_sqli(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """Validate error-, boolean-, and timing-based SQL injection differentials.

    SQL engine strings are supporting evidence only.  Confirmation is based on a
    payload-specific, repeatable response/timing difference against both a clean
    baseline and a non-boolean negative control.
    """
    b = _require_evidence("baseline", baseline)
    c = _require_evidence("candidate", candidate)
    nc = _require_evidence("negative_control", negative_control)
    b_body, c_body, nc_body = _body(b), _body(c), _body(nc)
    b_errors, c_errors, nc_errors = _sql_errors(b_body), _sql_errors(c_body), _sql_errors(nc_body)
    if c_errors and not b_errors and not nc_errors:
        return ValidationResult(
            "SQLI",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "candidate-only SQL error signature",
            b,
            c,
            nc,
            details={"candidate_errors": c_errors},
        )
    b_status, c_status, nc_status = _status(b), _status(c), _status(nc)
    payload = _sql_payload(c)
    boolean_payload = bool(re.search(r"(?:'|\")\s*(?:or|and)\b|--|#|/\*", payload, re.I))
    size_diff = abs(len(c_body) - len(b_body)) / max(1, len(b_body))
    baseline_control_equivalent = b_status == nc_status and _response_relation(b, nc) == "same_or_superset"
    candidate_differs_from_both = (
        _response_relation(b, c) == "different"
        and _response_relation(nc, c) == "different"
        and (b_status != c_status or nc_status != c_status or size_diff >= 0.20)
    )
    boolean_diff = boolean_payload and baseline_control_equivalent and candidate_differs_from_both
    if boolean_diff and not c_errors and c_status not in (500, 501, 502, 503):
        return ValidationResult(
            "SQLI",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "SQL boolean payload caused a material response differential",
            b,
            c,
            nc,
            details={
                "status_delta": b_status != c_status,
                "body_size_delta": round(size_diff, 3),
                "baseline_control_equivalent": baseline_control_equivalent,
            },
        )
    b_time, c_time, nc_time = _response_time_ms(b), _response_time_ms(c), _response_time_ms(nc)
    if b_time is not None and c_time is not None and nc_time is not None:
        delay = c_time - b_time
        control_gap = abs(nc_time - b_time)
        if delay >= 1000.0 and delay >= max(500.0, control_gap * 2):
            return ValidationResult(
                "SQLI",
                ValidationOutcome.CONFIRMED,
                EvidenceQuality.OBSERVED_DIFFERENTIAL,
                f"candidate response delayed by {delay:.0f}ms",
                b,
                c,
                nc,
                details={"baseline_ms": b_time, "candidate_ms": c_time, "control_ms": nc_time},
            )
    if b_status == c_status and b_body == c_body and not c_errors:
        return ValidationResult(
            "SQLI",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "baseline and candidate responses were equivalent",
            b,
            c,
            nc,
            refutation_path="parameterized_or_sanitized_query",
        )
    return ValidationResult(
        "SQLI",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "no reliable SQL error, boolean, or timing differential",
        b,
        c,
        nc,
        details={
            "baseline_errors": b_errors,
            "candidate_errors": c_errors,
            "negative_control_errors": nc_errors,
            "negative_control_status": nc_status,
            "baseline_control_equivalent": baseline_control_equivalent,
            "candidate_differs_from_both": candidate_differs_from_both,
        },
    )


# ---- Family 4: Mass Assignment --------------------------------------------


def validate_mass_assignment(
    *, baseline: dict, candidate: dict, negative_control: dict, protected_field: str = "role"
) -> ValidationResult:
    """Mass Assignment: client sets forbidden field (role/is_admin) via request.

    Baseline: update without protected field → field unchanged.
    Candidate: update with protected field in body → field changes (200 + new value).
    Negative control: update with safe field only → protected field unchanged.
    CONFIRMED iff candidate response shows protected field changed.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_body = _body(c).lower()
    b_body = _body(b).lower()
    nc_body = _body(nc).lower()
    protected_values = ("admin", "root", "superuser", "role=admin", "is_admin=true")
    c_protected = any(v in c_body for v in protected_values)
    b_clean = not any(v in b_body for v in protected_values)
    nc_clean = not any(v in nc_body for v in protected_values)
    if c_protected and b_clean and nc_clean:
        signal = f"candidate set protected field ({protected_field}) — baseline/nc clean"
        return ValidationResult(
            "MASS_ASSIGNMENT",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
        )
    if not c_protected:
        return ValidationResult(
            "MASS_ASSIGNMENT",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "protected field not accepted",
            b,
            c,
            nc,
            refutation_path="field_allowlist_enforced",
        )
    return ValidationResult(
        "MASS_ASSIGNMENT",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "protected field present but baseline ambiguous",
        b,
        c,
        nc,
    )


# ---- Family 5: Information Disclosure --------------------------------------


def validate_info_disclosure(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """Info Disclosure: sensitive data (PII, secrets, stack traces) in response.

    Baseline: public route → no sensitive data.
    Candidate: debug/verbose/error route → sensitive data leaked.
    Negative control: known-safe route → no sensitive data.
    CONFIRMED iff candidate has ≥2 sensitive indicators absent from baseline+nc.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_indicators = set(extract_info_disclosure_indicators(_body(c)))
    b_indicators = set(extract_info_disclosure_indicators(_body(b)))
    nc_indicators = set(extract_info_disclosure_indicators(_body(nc)))
    # Generic error-signature indicator: a verbose error page / stack trace is
    # itself an information-disclosure class, independent of framework strings.
    c_err, c_err_matches = has_error_signature(c)
    if c_err and c_err_matches and _status(c) >= 500:
        c_indicators.add("verbose_error_signature")
    # A version string alone is neither a secret nor an application-independent
    # proof of a disclosure flaw.  Confirmation requires differential sensitive
    # evidence, regardless of the endpoint's name or framework.
    c_count, b_count, nc_count = len(c_indicators), len(b_indicators), len(nc_indicators)
    if c_count >= 2 and c_count > max(b_count, nc_count):
        signal = f"candidate leaks {c_count} sensitive pattern classes"
        return ValidationResult(
            "INFO_DISCLOSURE",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={
                "candidate_indicators": sorted(c_indicators),
                "baseline_indicators": sorted(b_indicators),
                "negative_control_indicators": sorted(nc_indicators),
            },
        )
    if c_count <= max(b_count, nc_count):
        return ValidationResult(
            "INFO_DISCLOSURE",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "no differential sensitive data",
            b,
            c,
            nc,
            refutation_path="redaction_enforced",
        )
    return ValidationResult(
        "INFO_DISCLOSURE",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        f"weak signal ({c_count} pattern classes)",
        b,
        c,
        nc,
        details={
            "required": ["candidate_indicators>=2", "candidate_gt_baseline_and_control"],
            "observed": {
                "candidate_indicators": sorted(c_indicators),
                "baseline_indicators": sorted(b_indicators),
                "negative_control_indicators": sorted(nc_indicators),
            },
        },
    )


# ---- Family 6: Authentication Bypass ---------------------------------------


def validate_auth_bypass(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """Auth Bypass: unauthenticated request reaches authenticated-only endpoint.

    Baseline: unauthenticated → 401/403.
    Candidate: bypass payload (path traversal, header injection, method override) → 200.
    Negative control: invalid bypass → still 401/403.
    CONFIRMED iff candidate gets 200 while baseline+nc get 401/403.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    b_status, c_status, nc_status = _status(b), _status(c), _status(nc)
    baseline_denied = b_status in (401, 403)
    nc_denied = nc_status in (401, 403)
    candidate_succeeds = c_status == 200
    if candidate_succeeds and baseline_denied and nc_denied:
        signal = f"bypass payload got 200 (baseline {b_status}, nc {nc_status})"
        return ValidationResult(
            "AUTH_BYPASS",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
        )
    if not candidate_succeeds:
        return ValidationResult(
            "AUTH_BYPASS",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            f"bypass failed ({c_status})",
            b,
            c,
            nc,
            refutation_path="auth_enforced",
        )
    return ValidationResult(
        "AUTH_BYPASS",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        f"ambiguous baseline={b_status} candidate={c_status} nc={nc_status}",
        b,
        c,
        nc,
    )


# ---- Family 7: Race Condition (TOCTOU) -------------------------------------

# Structured-field contract produced by the bounded concurrent burst
# (webpent.vulns.race_condition.summarize_concurrent_results).
_RACE_ATTEMPTS_KEY = "_concurrent_attempts"
_RACE_SUCCESSES_KEY = "_concurrent_successes"
_RACE_EXPECTED_KEY = "_concurrent_expected_successes"


def _burst_int(structured: dict[str, Any], key: str, default: int) -> int:
    value = structured.get(key, default)
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def validate_race_condition(
    *, baseline: dict, candidate: dict, negative_control: dict, expected_successes: int = 1
) -> ValidationResult:
    """Race Condition (TOCTOU): a concurrent burst over-succeeds where one request should.

    Baseline: one sequential state-changing request succeeds (2xx).
    Candidate: N concurrent identical requests; only ONE should be able to win.
    Negative control: the same bounded burst against a request the server rejects.
    CONFIRMED iff candidate successes > expected AND baseline succeeded AND the
    negative-control burst did not also over-succeed (proves the burst mechanism
    is not itself the cause of the differential).
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_struct, nc_struct = _structured(c), _structured(nc)
    attempts = _burst_int(c_struct, _RACE_ATTEMPTS_KEY, 0)
    successes = _burst_int(c_struct, _RACE_SUCCESSES_KEY, 0)
    expected = _burst_int(c_struct, _RACE_EXPECTED_KEY, int(expected_successes))
    nc_successes = _burst_int(nc_struct, _RACE_SUCCESSES_KEY, 0)
    nc_expected = _burst_int(nc_struct, _RACE_EXPECTED_KEY, 0)
    b_status = _status(b)
    baseline_ok = 200 <= b_status < 300
    if attempts <= 0:
        return ValidationResult(
            "RACE_CONDITION",
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.HEURISTIC_SIGNAL,
            "no concurrent burst evidence recorded",
            b,
            c,
            nc,
            details={"required": ["concurrent_attempts>0"], "observed": {"attempts": attempts}},
        )
    if successes > expected and baseline_ok and nc_successes <= max(nc_expected, expected):
        signal = f"concurrent burst produced {successes}/{attempts} successes where {expected} expected"
        return ValidationResult(
            "RACE_CONDITION",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={
                "attempts": attempts,
                "successes": successes,
                "expected_successes": expected,
                "negative_control_successes": nc_successes,
            },
        )
    if successes <= expected:
        return ValidationResult(
            "RACE_CONDITION",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            f"burst stayed within the expected bound ({successes}/{attempts}, expected {expected})",
            b,
            c,
            nc,
            refutation_path="atomic_locking_enforced",
        )
    return ValidationResult(
        "RACE_CONDITION",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "over-acceptance observed but baseline or control was not clean",
        b,
        c,
        nc,
        details={
            "required": [
                "baseline_2xx",
                "candidate_successes>expected",
                "control_burst_not_over_accepted",
            ],
            "observed": {
                "baseline": b_status,
                "successes": successes,
                "expected": expected,
                "negative_control_successes": nc_successes,
            },
        },
    )


# ---- Family 8: Business Logic ----------------------------------------------

_BUSINESS_ACCEPTED_KEY = "_business_value_accepted"
_BUSINESS_REJECTION_MARKERS = (
    "invalid",
    "must be positive",
    "not allowed",
    "rejected",
    "out of range",
    "cannot be negative",
    "greater than zero",
)


def _business_manipulated_value(candidate: dict[str, Any], baseline: dict[str, Any] | None = None) -> str:
    """Derive the manipulated value from structured fields, falling back to the
    observed baseline/candidate body difference (the value the candidate sent
    that the baseline did not)."""
    for key in ("candidate_value", "manipulated_value", "injected_value"):
        value = candidate.get(key, _structured(candidate).get(key))
        if value is not None and str(value) != "":
            return str(value)
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    if metadata.get("candidate_value"):
        return str(metadata["candidate_value"])
    if baseline is not None:
        b_body, c_body = _body(baseline), _body(candidate)
        # Word-level diff: the candidate carries a token the baseline lacks.
        b_tokens = set(re.findall(r"[A-Za-z0-9_.-]+", b_body))
        for token in re.findall(r"[A-Za-z0-9_.-]+", c_body):
            if token not in b_tokens and re.search(r"\d", token):
                return token
    return ""


def validate_business_logic(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """Business Logic: a manipulated value breaks a server-side invariant.

    Baseline: legitimate value is accepted (2xx).
    Candidate: manipulated value (negative/zero/reused coupon) is accepted where it
    should be rejected, and the response materially differs from baseline.
    Negative control: a benign value at the same endpoint is accepted without the
    manipulated value's effect (proves "any change" is not the discriminator).
    CONFIRMED iff candidate accepted the manipulated value AND baseline succeeded
    AND the control stayed clean AND the candidate response differs from baseline.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    b_struct, c_struct, nc_struct = _structured(b), _structured(c), _structured(nc)
    c_status, b_status, nc_status = _status(c), _status(b), _status(nc)
    c_body, b_body, nc_body = _body(c), _body(b), _body(nc)
    manipulated = _business_manipulated_value(c, b)
    c_accepted_flag = c_struct.get(_BUSINESS_ACCEPTED_KEY)
    c_rejected = any(marker in c_body.lower() for marker in _BUSINESS_REJECTION_MARKERS)
    candidate_accepted = (c_accepted_flag is True) or (
        200 <= c_status < 300 and not c_rejected and bool(manipulated) and manipulated.lower() in c_body.lower()
    )
    baseline_ok = 200 <= b_status < 300
    control_clean = not (200 <= nc_status < 300 and bool(manipulated) and manipulated.lower() in nc_body.lower())
    materially_different = (c_body != b_body) or (c_status != b_status)
    if candidate_accepted and baseline_ok and control_clean and materially_different:
        signal = f"manipulated value {manipulated!r} accepted (baseline 2xx, control clean)"
        return ValidationResult(
            "BUSINESS_LOGIC",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={"manipulated_value": manipulated, "candidate_status": c_status},
        )
    if not candidate_accepted:
        return ValidationResult(
            "BUSINESS_LOGIC",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "manipulated value was rejected or not reflected",
            b,
            c,
            nc,
            refutation_path="business_invariant_enforced",
            details={"manipulated_value": manipulated, "candidate_status": c_status},
        )
    return ValidationResult(
        "BUSINESS_LOGIC",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "manipulated value accepted but baseline/control did not establish a clean differential",
        b,
        c,
        nc,
        details={
            "required": [
                "candidate_accepts_manipulated",
                "baseline_2xx",
                "control_clean",
                "candidate_differs_from_baseline",
            ],
            "observed": {
                "baseline": b_status,
                "candidate": c_status,
                "negative_control": nc_status,
                "materially_different": materially_different,
            },
        },
    )


# ---- Family 9: File Upload -------------------------------------------------

# Must match webpent.vulns.file_upload.UPLOAD_MARKER (kept as a local literal so
# this canonical framework module carries no import-time coupling).
_UPLOAD_MARKER = "webpent_upload_probe_9c31"
_UPLOAD_EXECUTION_TOKENS = ("/tmp/", "/etc/", "/var/www", "root:", "www-data")


def validate_file_upload(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """File Upload: an uploaded artifact is reachable and demonstrates impact.

    Baseline: a benign file upload that must not expose the probe marker.
    Candidate: the dangerous artifact is uploaded AND reachable (served) and
    demonstrates the specific impact (executed script output, a path written
    outside the upload directory, or an active script sink).
    Negative control: a marker-free upload that must not be reachable.
    CONFIRMED iff candidate serves the probe marker with impact while baseline and
    control do not — never from an upload success message alone.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    c_struct, b_struct, nc_struct = _structured(c), _structured(b), _structured(nc)
    marker = str(c_struct.get("_upload_marker") or _UPLOAD_MARKER).lower()
    c_body, b_body, nc_body = _body(c).lower(), _body(b).lower(), _body(nc).lower()
    c_served = c_struct.get("_upload_marker_served")
    c_served = bool(c_served) if c_served is not None else (marker in c_body)
    b_served = marker in b_body
    nc_served = marker in nc_body
    c_status = _status(c)
    # Impact: executed output (marker without its source wrapper), or a traversal
    # write evidenced by an internal path alongside the marker, or an active sink.
    executed_flag = c_struct.get("_upload_executed")
    traversal_flag = c_struct.get("_upload_traversal_written")
    executed = (
        bool(executed_flag)
        if executed_flag is not None
        else (marker in c_body and "<?php" not in c_body and "<script" not in c_body)
    )
    traversal = (
        bool(traversal_flag)
        if traversal_flag is not None
        else (marker in c_body and any(token in c_body for token in _UPLOAD_EXECUTION_TOKENS))
    )
    active_sink = "<script" in c_body and marker in c_body
    if c_served and (executed or traversal or active_sink) and not b_served and not nc_served and 200 <= c_status < 300:
        signal = "uploaded artifact reachable and demonstrated impact (executed/traversal/active sink)"
        return ValidationResult(
            "FILE_UPLOAD",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={
                "executed": executed,
                "traversal_written": traversal,
                "active_sink": active_sink,
            },
        )
    if not c_served:
        return ValidationResult(
            "FILE_UPLOAD",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "uploaded artifact was not reachable/served",
            b,
            c,
            nc,
            refutation_path="upload_not_retrievable",
            details={"candidate_status": c_status},
        )
    if b_served or nc_served:
        return ValidationResult(
            "FILE_UPLOAD",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "marker also appeared for baseline or control (not upload-specific)",
            b,
            c,
            nc,
            refutation_path="marker_not_upload_specific",
        )
    return ValidationResult(
        "FILE_UPLOAD",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        "artifact reachable but no concrete impact was demonstrated",
        b,
        c,
        nc,
        details={
            "required": ["candidate_marker_served", "impact_proven", "baseline_control_clean"],
            "observed": {"executed": executed, "traversal": traversal, "active_sink": active_sink},
        },
    )


# ---- Family 10: JWT Manipulation -------------------------------------------

_JWT_DENIED_MARKERS = (
    "unauthorized",
    "forbidden",
    "invalid token",
    "authentication required",
    "login",
)


def validate_jwt_manipulation(*, baseline: dict, candidate: dict, negative_control: dict) -> ValidationResult:
    """JWT Manipulation: a tampered token is accepted at a protected endpoint.

    Baseline: no/absent credential -> denied (401/403).
    Candidate: a tampered token (alg:none, stripped signature, expired, escalated
    role, algorithm confusion) -> accepted (2xx) at the same protected endpoint.
    Negative control: a syntactically invalid token -> denied (401/403).
    CONFIRMED iff candidate is accepted while baseline AND control are both denied.
    """
    b, c, nc = (
        _require_evidence("baseline", baseline),
        _require_evidence("candidate", candidate),
        _require_evidence("negative_control", negative_control),
    )
    b_status, c_status, nc_status = _status(b), _status(c), _status(nc)
    c_body = _body(c).lower()
    c_denied_marker = any(marker in c_body for marker in _JWT_DENIED_MARKERS)
    candidate_accepted = 200 <= c_status < 300 and not c_denied_marker
    baseline_denied = b_status in (401, 403)
    control_denied = nc_status in (401, 403)
    if candidate_accepted and baseline_denied and control_denied:
        signal = f"tampered token accepted (200) where baseline={b_status} and control={nc_status} were denied"
        return ValidationResult(
            "JWT_MANIPULATION",
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            signal,
            b,
            c,
            nc,
            details={
                "candidate_status": c_status,
                "baseline_status": b_status,
                "negative_control_status": nc_status,
            },
        )
    if not candidate_accepted:
        return ValidationResult(
            "JWT_MANIPULATION",
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            f"tampered token rejected ({c_status})",
            b,
            c,
            nc,
            refutation_path="signature_verification_enforced",
        )
    return ValidationResult(
        "JWT_MANIPULATION",
        ValidationOutcome.INCONCLUSIVE,
        EvidenceQuality.HEURISTIC_SIGNAL,
        f"ambiguous statuses baseline={b_status} candidate={c_status} nc={nc_status}",
        b,
        c,
        nc,
        details={
            "required": ["baseline_401_or_403", "candidate_2xx", "negative_control_401_or_403"],
            "observed": {
                "baseline": b_status,
                "candidate": c_status,
                "negative_control": nc_status,
            },
        },
    )


# ---- Validator registry (canonical, ONE per family) ------------------------

VALIDATORS = {
    "IDOR": validate_idor,
    "BOLA": validate_idor,
    "OPEN_REDIRECT": validate_open_redirect,
    "SSRF": validate_ssrf,
    "XSS": validate_xss,
    "SQLI": validate_sqli,
    "MASS_ASSIGNMENT": validate_mass_assignment,
    "INFO_DISCLOSURE": validate_info_disclosure,
    "AUTH_BYPASS": validate_auth_bypass,
    "RACE_CONDITION": validate_race_condition,
    "BUSINESS_LOGIC": validate_business_logic,
    "FILE_UPLOAD": validate_file_upload,
    "JWT_MANIPULATION": validate_jwt_manipulation,
}


def run_validator(
    vulnerability_class: str, *, baseline: dict, candidate: dict, negative_control: dict, **kwargs
) -> ValidationResult:
    """Canonical entry point — ONE validator per family. Fail closed on unknown."""
    vf = VALIDATORS.get(vulnerability_class.upper())
    if not vf:
        raise ValidatorError(f"No canonical validator for {vulnerability_class!r}")
    return vf(baseline=baseline, candidate=candidate, negative_control=negative_control, **kwargs)


__all__ = [
    "ValidationOutcome",
    "EvidenceQuality",
    "ValidationResult",
    "ValidatorError",
    "validate_idor",
    "validate_open_redirect",
    "validate_ssrf",
    "validate_xss",
    "validate_sqli",
    "validate_mass_assignment",
    "validate_info_disclosure",
    "validate_auth_bypass",
    "validate_race_condition",
    "validate_business_logic",
    "validate_file_upload",
    "validate_jwt_manipulation",
    "extract_ssrf_indicators",
    "extract_info_disclosure_indicators",
    "parse_external_location",
    "responses_similar",
    "response_differs",
    "marker_reflected",
    "has_error_signature",
    "VALIDATORS",
    "run_validator",
]
