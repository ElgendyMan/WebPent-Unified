# src/webpent/integration/auth_session_contract.py
"""Authentication validation verdict contract (integration layer).

Part of the Shannon→GOED protected integration (docs/integration/).
Architectural reference: Shannon's auth-validation verdict contract
(apps/worker/src/services/validate-authentication.ts — typed
``submit_auth_result`` with ``login_success`` / ``failure_point`` /
``failure_detail`` and saved-session verification; AGPL-3.0) —
**pattern only, no code copied**. The Python contract below is
original GOED work designed to compose with GOED's own auth stack
(state ``session_cookies`` + ``merge_auth_state``, shared reauth
vault, ``vip_auth_posture``).

Purpose (capability matrix A4):

* Give the research loop a typed, bounded way to record an
  authentication-validation *observation* (success / failure taxonomy)
  without ever storing credentials, cookies, tokens, or session
  material in the research state.
* Feed GOED's research agenda: an unauthenticated or partially
  authenticated session is research-relevant state (authorization
  hypotheses depend on it), so the verdict contributes a *signal*,
  never a finding and never a verdict.

Security contract:

* This module stores NO secrets: cookie/token/credential values are
  rejected at the model level (keys are dropped + counted, never
  kept).
* Advisory only — no verdict authority (CausalGuard only, protocol
  §8). Browser-driven validation itself remains GOED's existing
  playwright-based stack (real-runtime exercise is PENDING_TEAM2).
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT_VERSION = "integration-auth-session-1.0"

# Keys that must never be persisted in research state (defense in
# depth; values are dropped and counted, not redacted-in-place, so no
# secret material ever round-trips through this contract).
SECRET_VALUE_KEYS: frozenset[str] = frozenset(
    {
        "cookie",
        "cookies",
        "session_cookie",
        "set_cookie",
        "token",
        "access_token",
        "id_token",
        "refresh_token",
        "authorization",
        "password",
        "secret",
        "api_key",
        "totp_secret",
        "credential",
        "credentials",
    }
)


class AuthFailurePoint(str, Enum):
    """Where an authentication attempt failed (Shannon-style taxonomy)."""

    NONE = "none"  # only valid with login_success=True
    USERNAME_OR_PASSWORD = "username_or_password"
    TOTP_SECRET = "totp_secret"
    OUT_OF_BAND = "out_of_band"
    UNKNOWN = "unknown"


class AuthValidationVerdict(BaseModel):
    """Typed outcome of one authentication-validation attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    login_success: bool
    failure_point: AuthFailurePoint = AuthFailurePoint.NONE
    failure_detail: str = Field(default="", max_length=240)
    session_verified: bool = False
    notes: str = Field(default="", max_length=240)

    @model_validator(mode="after")
    def _consistent(self) -> AuthValidationVerdict:
        if self.login_success:
            if self.failure_point is not AuthFailurePoint.NONE:
                raise ValueError("successful_login_must_not_carry_failure_point")
            if not self.session_verified:
                raise ValueError("successful_login_requires_session_verification")
        else:
            if self.failure_point is AuthFailurePoint.NONE:
                raise ValueError("failed_login_requires_failure_point")
            if self.session_verified:
                raise ValueError("failed_login_must_not_verify_session")
        return self

    def to_signal_strength(self) -> float:
        """Deterministic evidence-strength contribution for the agenda.

        Successful + verified auth ⇒ strong context signal (1.0);
        a classified failure ⇒ weak but non-zero signal (0.2) because
        the failure itself is informative for authorization research.
        """
        return 1.0 if self.login_success else 0.2


class AuthSessionRecord(BaseModel):
    """Secret-free auth posture snapshot for research state."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    contract_version: str = Field(default=CONTRACT_VERSION, min_length=1)
    login_success: bool
    failure_point: AuthFailurePoint
    session_verified: bool
    redacted_value_keys_dropped: int = Field(default=0, ge=0)
    notes: str = Field(default="", max_length=240)


def record_from_verdict(
    verdict: AuthValidationVerdict,
    raw_details: dict[str, Any] | None = None,
) -> AuthSessionRecord:
    """Convert a verdict into a secret-free record.

    Any secret-looking keys in ``raw_details`` are counted and dropped
    (never stored, never redacted-in-place — dropped entirely).
    """
    dropped = 0
    if raw_details:
        for key in raw_details:
            if str(key).lower() in SECRET_VALUE_KEYS:
                dropped += 1
    return AuthSessionRecord(
        login_success=verdict.login_success,
        failure_point=verdict.failure_point,
        session_verified=verdict.session_verified,
        redacted_value_keys_dropped=dropped,
        notes=verdict.notes,
    )


def merge_into_state_dict(
    state: dict[str, Any],
    verdict: AuthValidationVerdict,
) -> dict[str, Any]:
    """Return a NEW state dict with the advisory auth-validation record.

    Pure function. The input ``state`` is never mutated. The record is
    stored under the additive key ``auth_validation`` (integration
    namespace) and touches none of GOED's existing keys — in
    particular it NEVER writes ``session_cookies`` or any credential
    material (protocol §4: no parallel security authority).
    """
    record = record_from_verdict(verdict, state.get("credentials"))
    updated = dict(state)
    updated["auth_validation"] = record.model_dump(mode="json")
    return updated


__all__ = [
    "CONTRACT_VERSION",
    "SECRET_VALUE_KEYS",
    "AuthFailurePoint",
    "AuthSessionRecord",
    "AuthValidationVerdict",
    "merge_into_state_dict",
    "record_from_verdict",
]
