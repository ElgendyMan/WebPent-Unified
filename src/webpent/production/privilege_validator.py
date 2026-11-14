# src/webpent/production/privilege_validator.py
"""Canonical privilege-differential validator (2026-10-25 Proposal 5).

``validate_privilege_differential`` is the ONE authority for the
``PRIVILEGE_DIFFERENTIAL`` family: cross-principal access confirmed by
an observed behavioral differential, not by response sniffing alone.

The differential (fail-closed, zero-false-positive):

  baseline         privileged principal A on the restricted resource R
                   — the authorized reference (A SHOULD succeed).
  candidate        low-privilege principal B on R — the claim under
                   test. CONFIRMATION REQUIRES B to be authorized.
  negative_control principal B on a blanket-restricted resource C
                   that B is known NOT to access — the denial
                   reference. If B is authorized on C too, the
                   "restricted" classification is wrong and a
                   candidate success would not be differential.

  CONFIRMED    — candidate is authorized on R (2xx, no error
                 signature) AND the control is denied on C (denial
                 status or error signature) AND the candidate body is
                 NOT the control's denial body (the resource content
                 actually reached B). Evidence quality:
                 OBSERVED_DIFFERENTIAL.
  REFUTED      — candidate denied on R (``candidate_denied`` — there
                 is no escalation to claim); control authorized on C
                 (``control_also_authorized`` — the resource map is
                 wrong, callbacks are not differential); candidate
                 body identical to the control's denial body
                 (``candidate_body_matches_denial`` — a 2xx wrapper
                 around a denial page is NOT access); candidate not
                 actually successful (``candidate_not_authorized`` —
                 error signature inside a 2xx shell).
  INCONCLUSIVE — candidate status is 0/5xx-transport or any input is
                 structurally unjudgeable: infrastructure failure is
                 not a refutation (``judge_error`` style paths kept
                 explicit).

Pure with respect to its inputs: every response arrives as an
evidence dict (``status_code``, ``response_body``/``body``,
``headers``) in the canonical shape every other family consumes.
"""

from __future__ import annotations

from typing import Any

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
    _require_evidence,
    _status,
    _body,
    _body_fingerprint,
    _content_tokens,
    _jaccard,
    has_error_signature,
)

_DENIAL_STATUSES = (401, 403)

# Body-only similarity threshold for the denial-body check: candidate
# and control sharing a high token overlap means the "authorized" 2xx
# response carried the denial page. Tighter than responses_similar's
# generic overlap: with statuses differing there is no status corroboration,
# so the body evidence alone must be strong to refute.
_DENIAL_BODY_JACCARD = 0.85


def _denial_body_matches(
    candidate: dict[str, Any], negative_control: dict[str, Any]
) -> bool:
    """Status-independent denial-body detection.

    ``responses_similar`` cannot be used here: it fails closed on
    differing statuses (candidate 2xx vs control 4xx), which would make
    the ``candidate_body_matches_denial`` path unreachable. A candidate
    200 that actually delivered the denial page (authorization wrapper
    without resource access) is exactly the spoofed-success case this
    path exists to catch, so the comparison is body-only: exact match,
    matching normalizer fingerprint, or very high token overlap.
    """
    a_body, b_body = _body(candidate), _body(negative_control)
    if not a_body or not b_body:
        return False
    if a_body == b_body:
        return True
    a_fp, b_fp = _body_fingerprint(candidate), _body_fingerprint(negative_control)
    if a_fp and a_fp == b_fp:
        return True
    a_tokens, b_tokens = _content_tokens(a_body), _content_tokens(b_body)
    if not a_tokens or not b_tokens:
        return False
    return _jaccard(a_tokens, b_tokens) >= _DENIAL_BODY_JACCARD

__all__ = ["validate_privilege_differential"]


def _denied(evidence: dict[str, Any]) -> bool:
    """Denial shape: explicit denial status OR generic error signature."""
    return _status(evidence) in _DENIAL_STATUSES or has_error_signature(evidence)[0]


def _authorized(evidence: dict[str, Any]) -> bool:
    """Authorized shape: 2xx with no error signature in the body."""
    return _successful_shape(evidence) and not has_error_signature(evidence)[0]


def _successful_shape(evidence: dict[str, Any]) -> bool:
    return 200 <= _status(evidence) < 300


def _refute(
    vulnerability_class: str,
    path: str,
    message: str,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
) -> ValidationResult:
    return ValidationResult(
        vulnerability_class,
        ValidationOutcome.REFUTED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        message,
        baseline,
        candidate,
        negative_control,
        refutation_path=path,
    )


def validate_privilege_differential(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    vulnerability_class: str = "PRIVILEGE_DIFFERENTIAL",
    **_kwargs: Any,
) -> ValidationResult:
    """CONFIRM only on B-authorized + C-denied + body-not-denial."""
    _require_evidence("baseline", baseline)
    _require_evidence("candidate", candidate)
    _require_evidence("negative_control", negative_control)

    candidate_status = _status(candidate)
    control_status = _status(negative_control)

    # Structural judgeability gates — unjudgeable is INCONCLUSIVE,
    # never CONFIRMED and never a refutation of the family itself.
    if candidate_status == 0 or candidate_status >= 500:
        return ValidationResult(
            vulnerability_class,
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "candidate response unjudgeable (transport or server failure)",
            baseline,
            candidate,
            negative_control,
            details={"reason": "candidate_unjudgeable"},
        )
    if control_status == 0 or control_status >= 500:
        return ValidationResult(
            vulnerability_class,
            ValidationOutcome.INCONCLUSIVE,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "negative-control response unjudgeable (transport or server failure)",
            baseline,
            candidate,
            negative_control,
            details={"reason": "control_unjudgeable"},
        )

    if not _authorized(candidate):
        return _refute(
            vulnerability_class,
            "candidate_denied",
            "low-privilege principal was denied on the restricted "
            "resource — no privilege differential observed",
            baseline,
            candidate,
            negative_control,
        )

    if not _denied(negative_control):
        return _refute(
            vulnerability_class,
            "control_also_authorized",
            "control principal was authorized on the blanket-restricted "
            "resource — resource classification is wrong, success is "
            "not differential evidence",
            baseline,
            candidate,
            negative_control,
        )

    if _denial_body_matches(candidate, negative_control):
        return _refute(
            vulnerability_class,
            "candidate_body_matches_denial",
            "candidate 2xx body matches the control's denial body — "
            "authorization wrapper without resource access",
            baseline,
            candidate,
            negative_control,
        )

    return ValidationResult(
        vulnerability_class,
        ValidationOutcome.CONFIRMED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "low-privilege principal reached the restricted resource while "
        "the control was denied on its own blanket restriction; candidate "
        "body is materially different from the denial",
        baseline,
        candidate,
        negative_control,
        details={
            "candidate_status": candidate_status,
            "control_status": control_status,
        },
    )
