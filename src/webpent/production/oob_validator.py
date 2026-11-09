# src/webpent/production/oob_validator.py
"""Canonical blind-OOB validator (2026-10-25 Proposal 3).

``validate_blind_oob_confirmation`` is the ONE authority for the blind
out-of-band families (BLIND_SSRF, XXE_OOB, BLIND_SQLI); the registry in
``production/validators.py`` maps each family to a thin wrapper around
it (lazy import, same late-binding pattern as the GraphQL/advanced
validators). It is pure with respect to its inputs: callbacks arrive
either as a pre-fetched ``oob_callbacks`` list (caller-windowed mode)
or via an ``OOBCollaborator`` + ``OOBBinding`` pair (live mode).

CONFIRMATION CONTRACT (fail-closed, zero-false-positive):

  CONFIRMED   — a callback whose token EQUALS the candidate probe's
                token arrives inside the evidence window AND the
                negative-control probe (same request shape WITHOUT the
                triggering payload, its own token) produced NO callback.
                Evidence quality: OBSERVED_DIFFERENTIAL — the
                differential is callback-present vs control-silent.
  REFUTED     — no matching candidate callback (``no_oob_callback``);
                the control fired (``control_callback_fired`` — the
                host itself phones home, so callbacks are not evidence);
                or the candidate evidence carries no OOB token
                (``no_oob_token`` — the probe never carried the
                identity, so nothing can be matched).
  INCONCLUSIVE— the live collaborator raised while polling (network/
                storage failure). Per the proposal: OOB infrastructure
                failure is NOT a refutation and NOT a halt; the pair is
                retried later.

Refutation-ledger note: run_validator's capture hook records the
REFUTED outcomes here exactly like any other family, so repeated
no-callback probes on the same target are delayed (never deleted).
"""

from __future__ import annotations

from typing import Any

from webpent.production.validators import (
    EvidenceQuality,
    ValidationOutcome,
    ValidationResult,
    ValidatorError,
    _require_evidence,
)

_WINDOW_SENTINEL = object()


def _candidate_token(candidate: dict[str, Any]) -> str:
    """The OOB token the candidate probe carried (evidence or top-level)."""
    if not isinstance(candidate, dict):
        return ""
    return str(candidate.get("oob_token") or "")


def _control_token(negative_control: dict[str, Any]) -> str:
    """The negative control's own token ("" = control carried none)."""
    if not isinstance(negative_control, dict):
        return ""
    return str(negative_control.get("oob_token") or "")


def _callbacks_match_token(
    callbacks: list[dict[str, Any]], token: str
) -> bool:
    return any(str(cb.get("token") or "") == token for cb in callbacks)


def _window_anchor(candidate: dict[str, Any]) -> float | None:
    """Caller-windowed mode anchor: when the probe was registered."""
    value = candidate.get("oob_registered_at")
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _in_window(
    callback: dict[str, Any], registered_at: float | None
) -> bool:
    if registered_at is None:
        return True  # caller-windowed mode: caller did the filtering
    try:
        seen_at = float(callback.get("seen_at"))
    except (TypeError, ValueError):
        return False
    return seen_at >= registered_at


def validate_blind_oob_confirmation(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    oob_callbacks: list[dict[str, Any]] | None = None,
    oob_collaborator: Any = None,
    oob_binding: Any = None,
    window_seconds: float | None = None,
    vulnerability_class: str = "BLIND_OOB",
) -> ValidationResult:
    """CONFIRM only on a matching candidate callback + silent control.

    Args:
        baseline: the baseline evidence dict (unused for matching but
            required by the family contract; ``_require_evidence`` keeps
            the fail-closed signature identical to every other family).
        candidate: evidence dict of the probe payload; MUST carry
            ``oob_token`` (stamped by the payload_generator injection
            point) and, in caller-windowed mode, ``oob_registered_at``.
        negative_control: evidence dict of the control probe; carries
            its OWN ``oob_token`` when the control embedded one.
        oob_callbacks: pre-fetched callback records (caller-windowed
            mode) — dicts with at least ``token`` and optionally
            ``seen_at``. Mutually exclusive with the live mode args.
        oob_collaborator: live mode — an ``OOBCollaborator``.
        oob_binding: live mode — the probe's ``OOBBinding``.
        window_seconds: live mode evidence window override.
        vulnerability_class: family label for the returned result.

    Returns:
        ValidationResult with OBSERVED_DIFFERENTIAL evidence quality on
        both CONFIRMED and REFUTED paths (the differential is real in
        both directions); INCONCLUSIVE on collaborator failure.
    """
    _require_evidence("baseline", baseline)
    _require_evidence("candidate", candidate)
    _require_evidence("negative_control", negative_control)

    token = _candidate_token(candidate)
    if not token:
        return ValidationResult(
            vulnerability_class,
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "candidate probe carried no OOB token — nothing to match",
            baseline,
            candidate,
            negative_control,
            refutation_path="no_oob_token",
        )

    if oob_collaborator is not None and oob_binding is not None:
        try:
            from webpent.shared.oob import OOBBinding

            def _poll_token(token: str) -> list[dict[str, Any]]:
                pseudo = OOBBinding(
                    token=token,
                    host="",
                    engagement_id="",
                    vuln_class="",
                    probe_label="",
                    registered_at=float(oob_binding.registered_at),
                )
                return [
                    {
                        "token": cb.token,
                        "protocol": cb.protocol,
                        "seen_at": cb.seen_at,
                        "source_fingerprint": cb.source_fingerprint,
                        "details": cb.details,
                    }
                    for cb in oob_collaborator.poll_callbacks(
                        pseudo, window_seconds=window_seconds
                    )
                ]

            callbacks = _poll_token(token)
            _control_callbacks: list[dict[str, Any]] = []
            control_token = _control_token(negative_control)
            if control_token:
                # Live mode must observe the control's OWN channel: a
                # control callback is stored under its own token, so it
                # never appears in the candidate token's poll.
                _control_callbacks = _poll_token(control_token)
        except Exception:
            # OOB infrastructure failure is NOT a refutation: the probe
            # cannot be judged this round. INCONCLUSIVE, never a halt.
            return ValidationResult(
                vulnerability_class,
                ValidationOutcome.INCONCLUSIVE,
                EvidenceQuality.OBSERVED_DIFFERENTIAL,
                "OOB collaborator poll failed — evidence unavailable this round",
                baseline,
                candidate,
                negative_control,
                details={"reason": "poll_failure"},
            )
    else:
        callbacks = [dict(cb) for cb in (oob_callbacks or [])]
        _control_callbacks = None
        control_token = _control_token(negative_control)

    registered_at = _window_anchor(candidate)
    candidate_hit = any(
        _callbacks_match_token([cb], token) and _in_window(cb, registered_at)
        for cb in callbacks
    )

    if _control_callbacks is not None:
        control_fired = bool(_control_callbacks)
    elif control_token:
        control_fired = _callbacks_match_token(callbacks, control_token)
    else:
        control_fired = False
    if control_fired:
        # The control (same request shape, NO triggering payload) also
        # produced a callback: this host phones home on its own, so a
        # callback is not differential evidence. Fail closed.
        return ValidationResult(
            vulnerability_class,
            ValidationOutcome.REFUTED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "negative control produced an OOB callback — callbacks are "
            "not differential evidence on this target",
            baseline,
            candidate,
            negative_control,
            refutation_path="control_callback_fired",
        )

    if candidate_hit:
        return ValidationResult(
            vulnerability_class,
            ValidationOutcome.CONFIRMED,
            EvidenceQuality.OBSERVED_DIFFERENTIAL,
            "candidate probe received an OOB callback with a matching "
            "token inside the evidence window; control stayed silent",
            baseline,
            candidate,
            negative_control,
            details={
                "matched_callbacks": sum(
                    1
                    for cb in callbacks
                    if _callbacks_match_token([cb], token)
                    and _in_window(cb, registered_at)
                )
            },
        )

    return ValidationResult(
        vulnerability_class,
        ValidationOutcome.REFUTED,
        EvidenceQuality.OBSERVED_DIFFERENTIAL,
        "no OOB callback matched the candidate token inside the window",
        baseline,
        candidate,
        negative_control,
        refutation_path="no_oob_callback",
        details={"callbacks_observed": len(callbacks)},
    )


def validate_blind_ssrf(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    return validate_blind_oob_confirmation(
        baseline=baseline,
        candidate=candidate,
        negative_control=negative_control,
        vulnerability_class="BLIND_SSRF",
        **kwargs,
    )


def validate_xxe_oob(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    return validate_blind_oob_confirmation(
        baseline=baseline,
        candidate=candidate,
        negative_control=negative_control,
        vulnerability_class="XXE_OOB",
        **kwargs,
    )


def validate_blind_sqli(
    *,
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
    **kwargs: Any,
) -> ValidationResult:
    return validate_blind_oob_confirmation(
        baseline=baseline,
        candidate=candidate,
        negative_control=negative_control,
        vulnerability_class="BLIND_SQLI",
        **kwargs,
    )


__all__ = [
    "validate_blind_oob_confirmation",
    "validate_blind_ssrf",
    "validate_xxe_oob",
    "validate_blind_sqli",
]
