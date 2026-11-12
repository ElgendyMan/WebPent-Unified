"""UM-DR-35.4 — Authentication Success Detection model.

A successful HTTP status, a new cookie, a changed URL, or an ordinary HTML
page is NOT proof of authenticated access. This module defines the explicit
auth-success lifecycle and the evidence rules that classify how far an
authentication attempt was actually PROVEN:

    NOT_ATTEMPTED
      -> AUTH_REQUEST_SUBMITTED
      -> LOGIN_RESPONSE_RETURNED
      -> SESSION_MATERIAL_CAPTURED
      -> SESSION_MATERIAL_ACCEPTED_BY_SERVER
      -> AUTHENTICATED_IDENTITY_ESTABLISHED
      -> PROTECTED_ACCESS_CONFIRMED
      -> SESSION_VALID_DURING_CAMPAIGN

Rules (fail-honest, never guessed):
  * A 2xx HTML body only advances to identity-established when it carries
    reliable identity evidence (identity-bearing HTML markers) or an
    anonymous-vs-authenticated differential distinguishes it.
  * When the evidence cannot distinguish authenticated from anonymous
    access, the assessment is INCONCLUSIVE — recorded explicitly, never
    silently converted into either success or failure.
  * No heuristic classification may mark identity-sensitive security
    experiments as authenticated without PROVEN identity evidence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AuthSuccessStage(str, Enum):
    NOT_ATTEMPTED = "not_attempted"
    AUTH_REQUEST_SUBMITTED = "auth_request_submitted"
    LOGIN_RESPONSE_RETURNED = "login_response_returned"
    SESSION_MATERIAL_CAPTURED = "session_material_captured"
    SESSION_MATERIAL_ACCEPTED = "session_material_accepted"
    AUTHENTICATED_IDENTITY_ESTABLISHED = "authenticated_identity_established"
    PROTECTED_ACCESS_CONFIRMED = "protected_access_confirmed"
    SESSION_VALID_DURING_CAMPAIGN = "session_valid_during_campaign"


_STAGE_ORDER: tuple[AuthSuccessStage, ...] = (
    AuthSuccessStage.NOT_ATTEMPTED,
    AuthSuccessStage.AUTH_REQUEST_SUBMITTED,
    AuthSuccessStage.LOGIN_RESPONSE_RETURNED,
    AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
    AuthSuccessStage.SESSION_MATERIAL_ACCEPTED,
    AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED,
    AuthSuccessStage.PROTECTED_ACCESS_CONFIRMED,
    AuthSuccessStage.SESSION_VALID_DURING_CAMPAIGN,
)


def stage_at_least(stage: AuthSuccessStage, minimum: AuthSuccessStage) -> bool:
    return _STAGE_ORDER.index(stage) >= _STAGE_ORDER.index(minimum)


#: Conservative, hard HTML markers that a page was rendered for an
#: authenticated identity. A generic 2xx HTML body (SPA catch-all, static
#: landing page) matches NONE of these by construction.
_HTML_IDENTITY_MARKER_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("logout_control", re.compile(
        r"<(?:a|button|form)[^>]{0,256}"
        r"(?:logout|log-out|log_out|signout|sign-out|sign_out|abmelden"
        r"|d[eé]connexion)", re.I)),
    ("account_settings_control", re.compile(
        r"<(?:a|button)[^>]{0,256}(?:/?(?:user|account|profile|settings"
        r"|dashboard)/?)[^>]{0,256}>", re.I)),
    # "welcome_identity_text" requires an ADDRESSABLE identity: "Welcome, name",
    # "Welcome back, name", "signed in as name". Generic marketing copy
    # ("Welcome to our site") deliberately does NOT match — stop-words are
    # excluded with a lookahead.
    ("welcome_identity_text", re.compile(
        r"(?:welcome(?:\s+back)?[\s,]+(?!to\b|the\b|our\b|you\b|your\b|guest\b|visitor\b|us\b)[a-z0-9._@-]{2,}"
        r"|(?:signed|logged)\s+in\s+as\s+[a-z0-9._@-]{2,}"
        r"|angemeldet\s+als\s+[a-z0-9._@-]{2,})", re.I)),
    ("user_identity_element", re.compile(
        r"<(?:span|div|p|strong|em)[^>]{0,256}(?:class|id|data-testid)="
        r"['\"][^'\"]{0,128}(?:user|account|profile|identity|whoami)"
        r"[^'\"]{0,128}['\"]", re.I)),
    ("csrf_authorized_form", re.compile(
        r"<form[^>]{0,512}(?:method=['\"](?:post|put|delete)['\"])", re.I)),
)


def html_identity_evidence(body: str) -> list[str]:
    """Return the identity-bearing marker names present in an HTML body.

    Deliberately conservative: a marker must indicate the page was rendered
    for a signed-in identity (logout control, account surface, identity
    element, authorized state-changing form). Returns [] for SPA
    catch-all shells and anonymous landing pages.
    """
    if not body:
        return []
    window = body[:20000]
    found: list[str] = []
    for name, pattern in _HTML_IDENTITY_MARKER_PATTERNS:
        if pattern.search(window):
            found.append(name)
    return found


@dataclass
class AuthSuccessAssessment:
    """One classification of how far authentication was PROVEN."""
    stage: AuthSuccessStage = AuthSuccessStage.NOT_ATTEMPTED
    success: bool = False
    inconclusive: bool = False
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "success": self.success,
            "inconclusive": self.inconclusive,
            "reason": self.reason[:240],
            "evidence": dict(list(self.evidence.items())[:12]),
        }


def assess_login_stage(
    *,
    request_submitted: bool,
    login_status_code: int | None,
    session_material_captured: bool,
    validation_probes: list[dict[str, Any]] | None = None,
) -> AuthSuccessAssessment:
    """Derive the furthest PROVEN lifecycle stage from login-phase facts.

    The login phase alone can never prove identity or protected access —
    those require the validation phase. This function stops at
    SESSION_MATERIAL_CAPTURED at most and is used by callers that only
    performed the login request.
    """
    stage = AuthSuccessStage.NOT_ATTEMPTED
    if request_submitted:
        stage = AuthSuccessStage.AUTH_REQUEST_SUBMITTED
    if login_status_code is not None:
        stage = AuthSuccessStage.LOGIN_RESPONSE_RETURNED
    if session_material_captured and login_status_code is not None:
        stage = AuthSuccessStage.SESSION_MATERIAL_CAPTURED
    return AuthSuccessAssessment(
        stage=stage,
        success=False,
        inconclusive=True,
        reason="login_phase_only_no_identity_evidence_yet",
        evidence={"login_status_code": login_status_code,
                  "session_material_captured": session_material_captured},
    )


def assess_validation_observation(
    *,
    status_code: int | None,
    content_type: str = "",
    body: str = "",
    json_identity_scalars: bool = False,
    login_redirect: bool = False,
    anonymous_differential: bool | None = None,
) -> AuthSuccessAssessment:
    """Classify ONE validation-surface observation under session material.

    Outcomes:
      * ``success=True`` — JSON identity scalars present, OR HTML identity
        markers present, OR an anonymous-vs-authenticated differential that
        proves the authenticated view differs.
      * ``success=False, inconclusive=True`` — a 2xx response whose shape
        cannot distinguish authenticated from anonymous access (generic
        HTML / SPA shell / non-JSON). Explicit inconclusive, never success.
      * ``success=False, inconclusive=False`` — the boundary bounced the
        session to a login surface (rejected), or the surface denied access.
    """
    status = status_code
    if login_redirect:
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
            success=False, inconclusive=False,
            reason="session_not_accepted_login_redirect",
            evidence={"status_code": status, "login_redirect": True},
        )
    if status is None or not (200 <= int(status) < 300):
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
            success=False, inconclusive=False,
            reason="validation_surface_denied_or_unavailable",
            evidence={"status_code": status},
        )
    if json_identity_scalars:
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED,
            success=True, inconclusive=False,
            reason="json_identity_scalars_established",
            evidence={"status_code": status, "json_identity_scalars": True},
        )
    markers = html_identity_evidence(body)
    if markers:
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.AUTHENTICATED_IDENTITY_ESTABLISHED,
            success=True, inconclusive=False,
            reason="html_identity_markers_established",
            evidence={"status_code": status,
                      "html_identity_markers": markers[:6]},
        )
    if anonymous_differential is True:
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.PROTECTED_ACCESS_CONFIRMED,
            success=True, inconclusive=False,
            reason="anonymous_vs_authenticated_differential_established",
            evidence={"status_code": status, "anonymous_differential": True},
        )
    if anonymous_differential is False:
        return AuthSuccessAssessment(
            stage=AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
            success=False, inconclusive=False,
            reason="differential_indicates_anonymous_view",
            evidence={"status_code": status, "anonymous_differential": False},
        )
    # 2xx with no identity evidence and no differential: EXPLICIT
    # inconclusive — a generic HTML page proves nothing about the session.
    ctype = (content_type or "").lower()
    shape = ("html" if ("html" in ctype or str(body or "").lstrip().startswith("<"))
             else ("json" if "json" in ctype else "other"))
    return AuthSuccessAssessment(
        stage=AuthSuccessStage.SESSION_MATERIAL_CAPTURED,
        success=False, inconclusive=True,
        reason=f"validation_inconclusive_{shape}_no_identity_evidence",
        evidence={"status_code": status, "shape": shape},
    )
