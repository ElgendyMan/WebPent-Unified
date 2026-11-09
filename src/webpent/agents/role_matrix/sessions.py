# src/webpent/agents/role_matrix/sessions.py
"""Role session registration with fail-closed identity verification
(PROPOSALS_ULTIMATE_V2 §4, 2026-10-30).

A role session wraps an :class:`IdentityProfile` from
``webpent.shared.bac_identity_tester`` with one non-negotiable contract:
NO session enters the matrix unverified. The operator (or the calling
workflow) supplies a ``verifier`` callable that proves the session really
acts as the claimed role (e.g. a role-control marker the target returns
only to that role). A missing verifier or a failed verification is an
error, never a silent downgrade — a matrix built on an unverified session
would produce false authorization conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    cookies_from_auth_state,
    normalise_identity_profiles,
)

__all__ = ["RoleSession", "RoleSessionError", "register_role_session"]

# verifier: Callable[[RoleSession], tuple[bool, str]]
Verifier = Callable[["RoleSession"], "tuple[bool, str]"]


class RoleSessionError(ValueError):
    """Raised when a role session cannot be established fail-closed."""


@dataclass(frozen=True)
class RoleSession:
    """One verified acting identity for the authorization matrix."""

    role: str
    profile: IdentityProfile
    verified: bool = False
    verify_detail: str = ""

    @property
    def cookies(self) -> dict[str, str]:
        return dict(self.profile.cookies)

    @property
    def headers(self) -> dict[str, str]:
        return dict(self.profile.headers)


def register_role_session(
    role: str,
    *,
    cookies: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    auth_state: Any = None,
    owned_object_ids: "tuple[str, ...] | list[str]" = (),
    owned_urls: "tuple[str, ...] | list[str]" = (),
    metadata: Mapping[str, Any] | None = None,
    verifier: Verifier | None = None,
) -> RoleSession:
    """Register one verified role session; fail closed on any gap.

    ``verifier`` is mandatory. It receives the constructed (unverified)
    session and returns ``(ok, detail)``; a false result refuses the
    session. Cookie/header credentials never appear in the returned
    object's repr (IdentityProfile masks them).
    """
    if not str(role or "").strip():
        raise RoleSessionError("role_session_role_required")
    if verifier is None:
        raise RoleSessionError("session_verifier_required")
    cookie_map = dict(cookies) if cookies else {}
    if auth_state is not None and not cookie_map:
        cookie_map = cookies_from_auth_state(auth_state)
    profile = normalise_identity_profiles(
        [
            {
                "name": str(role),
                "role": str(role),
                "cookies": cookie_map,
                "headers": dict(headers) if headers else {},
                "owned_object_ids": list(owned_object_ids),
                "owned_urls": list(owned_urls),
                "metadata": dict(metadata) if metadata else {},
            }
        ]
    )[0]
    session = RoleSession(role=str(role), profile=profile)
    try:
        ok, detail = verifier(session)
    except Exception as exc:  # noqa: BLE001 - verifier failure is a refusal
        raise RoleSessionError("session_verifier_raised") from exc
    if not ok:
        raise RoleSessionError("session_identity_verification_failed")
    object.__setattr__(session, "verified", True)
    object.__setattr__(session, "verify_detail", str(detail or ""))
    return session
