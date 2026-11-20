"""webpent.validators.oauth_misconfig_validator — deterministic
OAuth/SSO misconfiguration validators (basic version).

Ultimate plan 2026-10-27, proposal 7 (modern bug-bounty vulnerability
coverage), phase 5: OAuth/SSO misconfiguration deserves a class of its
own, separate from the generic ``auth_bypass`` — the detection
patterns are completely different (redirect_uri manipulation, state
parameter validation). This is the deliberately BASIC deterministic
version the plan schedules after the simpler proposals: two validators
over ALREADY-CAPTURED authorization-flow evidence, following the
``production/validators.py`` contract exactly (deterministic function,
injected evidence in, ``ValidationResult`` out):

  * ``validate_redirect_uriManipulation`` — was an open-redirect-shaped
    ``redirect_uri`` accepted by the authorization server?
  * ``validate_state_parameter`` — was the anti-CSRF ``state``
    parameter missing and the callback still accepted?
  * ``analyze_oauth_flow`` — orchestrator over one evidence bundle.

No network, no LLM, no browser — the caller captures the flows (or
replays recorded ones) and injects the records. Host comparison uses
``urllib.parse`` (pure string parsing — this module never touches
``urllib.request`` or any network API).

REDACTION: every URL echoed into ``details`` is bounded to 512 chars
and has each query-parameter value longer than 4 characters replaced
with ``***`` — authorization/redirect URLs routinely carry codes,
tokens and state nonces, and evidence dicts must never become a
credential leak surface (the same immediate-redaction philosophy as
the framework's parameter redaction layer).
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------

_MAX_URL_CHARS = 512
"""URLs (before redaction) are truncated to this length."""

_MAX_RECORDS = 100
"""At most this many flow records are analyzed per call."""

_REDACTED_VALUE = "***"
_QUERY_VALUE_KEEP_CHARS = 4
"""Query values of this length or shorter are kept verbatim (e.g. short
numeric flags); anything longer is redacted."""

_VULN_CLASS = "oauth_misconfiguration"

_DANGEROUS_SCHEMES: tuple[str, ...] = ("javascript", "data")

_BOUNDED_NOTE = (
    f"URL samples redacted (query values > {_QUERY_VALUE_KEEP_CHARS} chars "
    f"replaced with {_REDACTED_VALUE!r}) and bounded to {_MAX_URL_CHARS} "
    f"chars; at most {_MAX_RECORDS} records analyzed"
)


# ---------------------------------------------------------------------------
# Redaction + helpers
# ---------------------------------------------------------------------------


def _redact_url(url: Any) -> str:
    """Bound a URL and redact long query-parameter values.

    Every query value longer than 4 characters is replaced with
    ``***`` (short flags survive so the sample stays diagnostic).
    The redacted query is rebuilt as a plain display string (values
    already unquoted by ``parse_qsl``) — this is a bounded, advisory
    sample for ``details``, never re-parsed input, so keeping the
    ``***`` marker literal and readable beats full re-encoding. URLs
    that fail to split cleanly are returned bounded-but-unparsed
    (fail-visible rather than fail-silent).
    """
    text = url if isinstance(url, str) else str(url)
    text = text[:_MAX_URL_CHARS]
    try:
        parts = urlsplit(text)
    except ValueError:
        return text
    if not parts.query:
        return text
    redacted_pairs = [
        (name, value if len(value) <= _QUERY_VALUE_KEEP_CHARS else _REDACTED_VALUE)
        for name, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    redacted_query = "&".join(f"{name}={value}" for name, value in redacted_pairs)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, redacted_query, parts.fragment)
    )


def _record_status(record: dict[str, Any]) -> int:
    value = record.get("status", 0)
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0


def _host_of(url: Any) -> str:
    """Lowercased hostname of a URL ('' when absent/unparseable)."""
    try:
        return (urlsplit(str(url or "")).hostname or "").lower()
    except ValueError:
        return ""


def _is_open_redirect_shaped(authorization_url: str, redirect_uri: str) -> bool:
    """Deterministic open-redirect classification of one redirect_uri.

    True when the redirect_uri is:

      * protocol-relative (``//evil.example/...``), or
      * scheme ``javascript:``/``data:`` (executable schemes), or
      * an absolute http(s) URL whose host DIFFERS from the
        authorization server's own host.
    """
    uri = str(redirect_uri or "").strip()
    if not uri:
        return False
    if uri.startswith("//"):
        return True
    try:
        parts = urlsplit(uri)
    except ValueError:
        return False
    scheme = parts.scheme.lower()
    if scheme in _DANGEROUS_SCHEMES:
        return True
    if scheme in {"http", "https"}:
        auth_host = _host_of(authorization_url)
        uri_host = (parts.hostname or "").lower()
        if auth_host and uri_host and uri_host != auth_host:
            return True
    return False


def _inconclusive(signal: str, details: dict[str, Any]) -> ValidationResult:
    details = dict(details)
    details.setdefault("bounded", _BOUNDED_NOTE)
    return ValidationResult(
        vulnerability_class=_VULN_CLASS,
        outcome=ValidationOutcome.INCONCLUSIVE,
        evidence_quality=EvidenceQuality.STRUCTURAL_HINT,
        discriminating_signal=signal,
        baseline_evidence={},
        candidate_evidence={},
        negative_control_evidence={},
        details=details,
    )


# ---------------------------------------------------------------------------
# redirect_uri manipulation
# ---------------------------------------------------------------------------


def validate_redirect_uriManipulation(
    records: list[dict[str, Any]] | None,
) -> ValidationResult:
    """Validate redirect_uri manipulation from captured flow records.

    Input: a list of ``{"authorization_url": str, "redirect_uri": str,
    "status": int}`` records — one per redirect_uri probe the caller
    already made against the authorization endpoint. ``status`` is the
    authorization server's disposition for that redirect_uri (302 to
    that uri, or 200 with it embedded, versus a 4xx rejection).

    Outcome rules:

      * CONFIRMED (DETERMINISTIC_TOOL — a directly observed, reliably
        reproducible server disposition) when an open-redirect-shaped
        redirect_uri (absolute URL on a different host than the
        authorization server's, a ``//`` protocol-relative URL, or a
        ``javascript:``/``data:`` scheme) was ACCEPTED
        (2xx/3xx status).
      * REFUTED when open-redirect-shaped probes exist and every one
        of them was rejected (status >= 400) — an exact-allowlist
        redirect_uri policy.
      * INCONCLUSIVE when there is no flow evidence, or no
        open-redirect-shaped redirect_uri was ever probed.
    """
    flow_records = [r for r in (records or []) if isinstance(r, dict)][:_MAX_RECORDS]

    accepted: dict[str, Any] | None = None
    rejected_sample: dict[str, Any] | None = None
    suspicious_probes = 0
    for record in flow_records:
        authorization_url = str(record.get("authorization_url", "") or "")
        redirect_uri = str(record.get("redirect_uri", "") or "")
        if not _is_open_redirect_shaped(authorization_url, redirect_uri):
            continue
        suspicious_probes += 1
        status = _record_status(record)
        if 200 <= status < 400 and accepted is None:
            accepted = {
                "authorization_url": _redact_url(authorization_url),
                "redirect_uri": _redact_url(redirect_uri),
                "status": status,
            }
        elif status >= 400 and rejected_sample is None:
            rejected_sample = {
                "redirect_uri": _redact_url(redirect_uri),
                "status": status,
            }

    if accepted is not None:
        return ValidationResult(
            vulnerability_class=_VULN_CLASS,
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.DETERMINISTIC_TOOL,
            discriminating_signal=(
                "authorization server accepted an open-redirect-shaped "
                "redirect_uri (different host / protocol-relative / "
                "javascript:-or-data: scheme)"
            ),
            baseline_evidence={
                "expected": "only pre-registered exact redirect_uri values "
                "are accepted"
            },
            candidate_evidence=accepted,
            negative_control_evidence={
                "expected": "an unregistered foreign redirect_uri is "
                "rejected with a 4xx invalid_redirect_uri error"
            },
            refutation_path=(
                "replay with the exact registered redirect_uri and with the "
                "foreign one; if both are accepted the registration is "
                "prefix/any-match — if only the registered one is, the "
                "earlier acceptance was a capture artifact"
            ),
            details={
                "bounded": _BOUNDED_NOTE,
                "suspicious_probes": suspicious_probes,
                "accepted_sample": accepted,
            },
        )

    if suspicious_probes and rejected_sample is not None and accepted is None:
        return ValidationResult(
            vulnerability_class=_VULN_CLASS,
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "every open-redirect-shaped redirect_uri probe was rejected "
                "by the authorization server"
            ),
            baseline_evidence={},
            candidate_evidence={"rejected_sample": rejected_sample},
            negative_control_evidence={},
            refutation_path=None,
            details={
                "bounded": _BOUNDED_NOTE,
                "suspicious_probes": suspicious_probes,
                "reason": "redirect-uri-rejected",
            },
        )

    return _inconclusive(
        (
            "no open-redirect-shaped redirect_uri evidence in flow records"
            if flow_records
            else "no authorization flow records supplied"
        ),
        {
            "record_count": len(flow_records),
            "suspicious_probes": suspicious_probes,
            "reason": "no-flow-evidence" if not flow_records else "no-suspicious-uri",
        },
    )


# ---------------------------------------------------------------------------
# state parameter
# ---------------------------------------------------------------------------


def validate_state_parameter(
    records: list[dict[str, Any]] | None,
) -> ValidationResult:
    """Validate the OAuth ``state`` (anti-CSRF) parameter posture.

    Input: a list of ``{"has_state": bool, "state_reflected_in_callback":
    bool}`` records — one per captured authorization round trip.
    ``has_state`` records whether the authorization request carried a
    state parameter; ``state_reflected_in_callback`` records whether
    the callback validated/echoed it.

    Outcome rules:

      * CONFIRMED when state was MISSING on the authorization request
        AND the callback was accepted without validation — the
        classic CSRF-on-the-OAuth-flow posture.
      * REFUTED when state was present AND validated in the callback.
      * INCONCLUSIVE otherwise (no records, or a partial posture such
        as state-present-but-never-validated, which needs replay
        evidence the injected records do not carry).
    """
    state_records = [r for r in (records or []) if isinstance(r, dict)][:_MAX_RECORDS]

    if not state_records:
        return _inconclusive(
            "no authorization flow records supplied",
            {"record_count": 0, "reason": "no-flow-evidence"},
        )

    missing_state_accepted = False
    state_present_validated = False
    partial_postures = 0
    for record in state_records:
        has_state = bool(record.get("has_state", False))
        reflected = bool(record.get("state_reflected_in_callback", False))
        if not has_state and not reflected:
            missing_state_accepted = True
        elif has_state and reflected:
            state_present_validated = True
        else:
            partial_postures += 1

    if missing_state_accepted:
        return ValidationResult(
            vulnerability_class=_VULN_CLASS,
            outcome=ValidationOutcome.CONFIRMED,
            evidence_quality=EvidenceQuality.DETERMINISTIC_TOOL,
            discriminating_signal=(
                "authorization request carried no state parameter and the "
                "callback was accepted without state validation"
            ),
            baseline_evidence={
                "expected": "every authorization request carries an unguessable "
                "state and every callback validates it"
            },
            candidate_evidence={
                "has_state": False,
                "state_reflected_in_callback": False,
            },
            negative_control_evidence={
                "expected": "a callback with a missing/wrong state is rejected"
            },
            refutation_path=(
                "capture a full round trip; if the provider injects a state "
                "server-side despite the client omitting one, the earlier "
                "record was client-configuration noise"
            ),
            details={
                "bounded": _BOUNDED_NOTE,
                "record_count": len(state_records),
            },
        )

    if state_present_validated and not missing_state_accepted:
        return ValidationResult(
            vulnerability_class=_VULN_CLASS,
            outcome=ValidationOutcome.REFUTED,
            evidence_quality=EvidenceQuality.HEURISTIC_SIGNAL,
            discriminating_signal=(
                "state parameter present on the authorization request and "
                "validated in the callback"
            ),
            baseline_evidence={},
            candidate_evidence={
                "has_state": True,
                "state_reflected_in_callback": True,
            },
            negative_control_evidence={},
            refutation_path=None,
            details={
                "bounded": _BOUNDED_NOTE,
                "record_count": len(state_records),
                "reason": "state-present-and-validated",
            },
        )

    return _inconclusive(
        (
            "partial state posture (e.g. state present but never validated) — "
            "replay evidence required to conclude"
        ),
        {
            "record_count": len(state_records),
            "partial_postures": partial_postures,
            "reason": "partial-posture",
        },
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def analyze_oauth_flow(evidence: dict[str, Any] | None) -> list[ValidationResult]:
    """Run the OAuth validators over one evidence bundle.

    Args:
        evidence: Bundle with keys ``"redirect_records"`` (list for
            ``validate_redirect_uriManipulation``) and
            ``"state_records"`` (list for
            ``validate_state_parameter``). Missing keys are treated as
            empty evidence; the affected validator then returns
            INCONCLUSIVE — an empty bundle never yields a false
            positive.

    Returns:
        The list of ValidationResults from both validators (each
        carrying a ``bounded`` note in ``details``).
    """
    bundle = evidence if isinstance(evidence, dict) else {}
    redirect_records = bundle.get("redirect_records")
    if not isinstance(redirect_records, list):
        redirect_records = []
    state_records = bundle.get("state_records")
    if not isinstance(state_records, list):
        state_records = []

    results = [
        validate_redirect_uriManipulation(redirect_records),
        validate_state_parameter(state_records),
    ]
    logger.info(
        "oauth flow analysis: %d result(s) over %d redirect + %d state record(s)",
        len(results),
        len(redirect_records),
        len(state_records),
    )
    return results


def oauth_misconfig_detection_enabled() -> bool:
    """Return the ``enable_oauth_misconfig_detection`` settings flag.

    This is the gate the orchestrating graph node consults before
    running these validators. The validators themselves stay flag-free
    and deterministic (pure over injected evidence) so they remain
    unit-testable and replayable regardless of settings.
    """
    from webpent.config.settings import get_settings

    return bool(get_settings().enable_oauth_misconfig_detection)


__all__ = [
    "analyze_oauth_flow",
    "oauth_misconfig_detection_enabled",
    "validate_redirect_uriManipulation",
    "validate_state_parameter",
]
