"""Fail-closed boundary for legacy authentication entrypoints.

The legacy browser/auth node remains for compatibility, but a governed caller
must explicitly provide an M4 authorization projection before it can consume
credential or session material. Raw material is never accepted as proof of M4.
"""
from __future__ import annotations

from typing import Any, Mapping


def legacy_auth_m4_failure(state: Mapping[str, Any]) -> dict[str, Any] | None:
    """Return a redacted failure update when governed legacy auth lacks M4.

    Compatibility callers that do not opt into governed mode retain the legacy
    API contract. Active governed callers set ``m4_enforced`` and must provide
    an already-authorized/attached M4 projection; the legacy node cannot create
    or infer that authority itself.
    """
    if not bool(state.get("m4_enforced")):
        return None
    context = state.get("m4_context")
    authorized = isinstance(context, Mapping) and bool(context.get("authorized"))
    attached = isinstance(context, Mapping) and bool(context.get("attached"))
    if authorized and attached:
        return None
    return {
        "authentication_status": "m4_unavailable",
        "auth_state": {
            "login_attempted": False,
            "validated": False,
            "source": "legacy_auth_m4_gate",
            "failure_reason": "m4_authorization_required",
        },
        "session_cookies": {},
        "session_headers": {},
        "identity_profiles": {},
        "identity_records": {},
        "engagement_limitations": [{
            "code": "m4_authorization_required",
            "severity": "high",
            "message": "Legacy authentication path fail-closed: M4 context unavailable.",
        }],
    }


__all__ = ["legacy_auth_m4_failure"]
