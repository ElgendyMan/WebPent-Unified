"""Auth edge-case resilience: API-key, OAuth2, basic-auth fallback, cookie expiry.

Additive module (not in the frozen manifest). Frozen ``recon.login_executor``
already performs form/api_jwt/basic logins and accepts operator-supplied
api-key tokens; this module adds the *missing* execution and inspection pieces
without modifying frozen code:

  * ApiKeyAuthExecutor  — explicit 4th auth type (header/query API key).
  * OAuth2FlowHandler   — authorization-code redirect flow (state-checked).
  * BasicAuthFallback   — fallback when form/api login is unavailable.
  * CookieExpiryInspector — advisory session liveness from Set-Cookie attrs.

All network access is via an injectable callable, so every component is
synthetically testable with no real HTTP. No secrets are ever logged or
returned by ``as_dict`` (digests/names only).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

__all__ = [
    "ApiKeyAuthExecutor",
    "OAuth2FlowHandler",
    "OAuth2Outcome",
    "BasicAuthFallback",
    "CookieExpiryInspector",
    "CookieLiveness",
    "AuthResilienceReport",
    "SUPPORTED_AUTH_TYPES",
]

SUPPORTED_AUTH_TYPES = ("form_session", "api_jwt", "basic", "oauth", "api_key")

HttpCallable = Callable[[str, str, Mapping[str, str], Any], Any]  # method, url, headers, body -> response-like


def _digest(value: str) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# API key (4th auth type)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ApiKeyAuthExecutor:
    """Execute API-key auth (header or query) and validate on a protected URL.

    Produces the same ``LoginMaterial`` shape the frozen M4 boundary accepts
    (``kind="api_key"`` -> ``m4_secret() == "api-key:name=value"``).
    """

    header_name: str = "X-API-Key"
    query_param: str = ""
    validation_url: str = ""
    timeout_seconds: float = 10.0

    def build_headers(self, api_key: str) -> dict[str, str]:
        key = str(api_key or "")[:16_384]
        if not key:
            return {}
        return {str(self.header_name)[:64] or "X-API-Key": key}

    def build_query(self, api_key: str) -> str:
        if not self.query_param or not api_key:
            return ""
        return urllib.parse.urlencode({str(self.query_param)[:64]: str(api_key)[:16_384]})

    def m4_secret(self, api_key: str) -> str:
        return f"api-key:{self.header_name}={api_key}"

    def login(
        self,
        *,
        alias: str,
        api_key: str,
        http: HttpCallable | None = None,
    ) -> dict[str, Any]:
        """Return a LoginResult-shaped dict (digests only, no raw key)."""
        alias = str(alias)[:128]
        if not str(api_key or "").strip():
            return {"alias": alias, "success": False, "auth_type": "api_key", "reason": "api_key_required"}
        headers = self.build_headers(api_key)
        validated = True
        status = None
        if http is not None and self.validation_url:
            try:
                resp = http("GET", self.validation_url, headers, None)
                status = int(getattr(resp, "status_code", 0) or 0)
                validated = 200 <= status < 300
            except Exception as exc:  # noqa: BLE001
                return {"alias": alias, "success": False, "auth_type": "api_key", "reason": f"validation_{type(exc).__name__}"}
        return {
            "alias": alias,
            "success": bool(validated),
            "auth_type": "api_key",
            "status_code": status,
            "reason": "api_key_validated" if validated else "api_key_rejected",
            "material": {"kind": "api_key", "name": self.header_name, "digest": _digest(api_key)},
        }


# ---------------------------------------------------------------------------
# OAuth2 authorization-code flow
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class OAuth2Outcome:
    success: bool
    token_digest: str = ""
    reason: str = ""
    state_verified: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "success": bool(self.success),
            "token_digest": self.token_digest,
            "reason": str(self.reason)[:240],
            "state_verified": bool(self.state_verified),
        }


class OAuth2FlowHandler:
    """Minimal, state-checked OAuth2 authorization-code flow.

    Redirect handling: builds the authorize URL with a random state; on
    callback, verifies state before exchanging the code for a token.
    Fail-closed on state mismatch. Synthetic via injectable ``http`` and
    ``state_generator``.
    """

    def __init__(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        authorize_url: str,
        token_url: str,
        scope: str = "",
        state_generator: Callable[[], str] | None = None,
    ) -> None:
        self.client_id = str(client_id)[:256]
        self.redirect_uri = str(redirect_uri)[:2048]
        self.authorize_url = str(authorize_url)[:2048]
        self.token_url = str(token_url)[:2048]
        self.scope = str(scope)[:256]
        self._state_generator = state_generator or (lambda: hashlib.sha256(f"{time.time_ns()}{self.client_id}".encode()).hexdigest()[:32])
        self.state = ""

    def build_authorize_url(self) -> str:
        self.state = self._state_generator()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": self.state,
        }
        if self.scope:
            params["scope"] = self.scope
        sep = "&" if "?" in self.authorize_url else "?"
        return f"{self.authorize_url}{sep}{urllib.parse.urlencode(params)}"

    def handle_callback(
        self,
        *,
        code: str,
        state: str,
        client_secret: str = "",
        http: HttpCallable | None = None,
    ) -> OAuth2Outcome:
        if not self.state:
            return OAuth2Outcome(False, reason="authorize_url_not_built")
        if not hmac.compare_digest(str(state), self.state):
            return OAuth2Outcome(False, reason="oauth_state_mismatch", state_verified=False)
        if not str(code or "").strip():
            return OAuth2Outcome(False, reason="oauth_code_missing", state_verified=True)
        if http is None:
            # Synthetic offline mode: state verified, token not exchanged.
            return OAuth2Outcome(True, token_digest=_digest(str(code)), reason="oauth_state_verified_offline", state_verified=True)
        body = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": str(code)[:1024],
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": str(client_secret)[:16_384],
        })
        try:
            resp = http("POST", self.token_url, {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}, body)
        except Exception as exc:  # noqa: BLE001
            return OAuth2Outcome(False, reason=f"token_exchange_{type(exc).__name__}", state_verified=True)
        status = int(getattr(resp, "status_code", 0) or 0)
        payload = getattr(resp, "json", None)
        token = ""
        if callable(payload):
            try:
                data = payload()
                token = str((data or {}).get("access_token") or "")
            except (ValueError, TypeError, AttributeError):  # JSONDecodeError ⊂ ValueError
                token = ""
        if 200 <= status < 300 and token:
            return OAuth2Outcome(True, token_digest=_digest(token), reason="oauth_token_exchanged", state_verified=True)
        return OAuth2Outcome(False, reason=f"oauth_token_exchange_failed_status_{status}", state_verified=True)


# ---------------------------------------------------------------------------
# Basic auth fallback
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class BasicAuthFallback:
    """Build a Basic Authorization header as a last-resort auth fallback."""

    def header(self, username: str, password: str) -> dict[str, str]:
        user = str(username or "")[:1024]
        pw = str(password or "")[:1024]
        if not user or not pw:
            return {}
        token = base64.b64encode(f"{user}:{pw}".encode()).decode("ascii")
        return {"Authorization": f"Basic {token}"}

    def m4_secret(self, username: str, password: str) -> str:
        user = str(username or "")[:1024]
        pw = str(password or "")[:1024]
        return f"basic:{base64.b64encode(f'{user}:{pw}'.encode()).decode('ascii')}"

    def applies(self, *, www_authenticate: str = "", form_detected: bool = False, api_detected: bool = False) -> bool:
        """Basic is a fallback only when no stronger form/api signal exists."""
        if form_detected or api_detected:
            return False
        return "basic" in str(www_authenticate).lower()


# ---------------------------------------------------------------------------
# Cookie expiry inspection (advisory liveness)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class CookieLiveness:
    name: str
    fresh: bool
    expires_at: float | None = None
    max_age_seconds: int | None = None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": str(self.name)[:128],
            "fresh": bool(self.fresh),
            "expires_at": self.expires_at,
            "max_age_seconds": self.max_age_seconds,
            "reason": str(self.reason)[:128],
        }


class CookieExpiryInspector:
    """Read Set-Cookie Expires/Max-Age attributes -> advisory freshness.

    Never returns cookie values — only names and expiry metadata.
    """

    def __init__(self, *, now: Callable[[], float] | None = None, expiry_warning_seconds: float = 300.0) -> None:
        self._now = now or time.time
        self.expiry_warning_seconds = float(expiry_warning_seconds)

    @staticmethod
    def _parse_set_cookie(header: str) -> tuple[str, dict[str, str]]:
        parts = [p.strip() for p in str(header or "").split(";")]
        name = ""
        attrs: dict[str, str] = {}
        for index, part in enumerate(parts):
            if "=" in part:
                key, value = part.split("=", 1)
                key = key.strip()
                value = value.strip()
            else:
                key, value = part.strip(), ""
            if index == 0:
                name = key
            else:
                attrs[key.lower()] = value
        return name[:128], attrs

    @staticmethod
    def _parse_http_date(value: str) -> float | None:
        # Minimal RFC1123/850/asctime parse; returns None if unparseable.
        import email.utils as _e
        try:
            parsed = _e.parsedate_tz(str(value))
            if parsed is None:
                return None
            return _e.mktime_tz(parsed)
        except (ValueError, TypeError, OverflowError):
            return None

    def inspect(self, set_cookie_headers: Sequence[str]) -> tuple[CookieLiveness, ...]:
        results: list[CookieLiveness] = []
        now = self._now()
        for header in set_cookie_headers or ():
            name, attrs = self._parse_set_cookie(header)
            if not name:
                continue
            expires_at = self._parse_http_date(attrs.get("expires", "")) if "expires" in attrs else None
            max_age = None
            if "max-age" in attrs:
                try:
                    max_age = int(attrs["max-age"])
                except (TypeError, ValueError):
                    max_age = None
            fresh = True
            reason = "fresh"
            if max_age is not None and max_age <= 0:
                fresh = False
                reason = "max_age_non_positive_session_dead"
            elif expires_at is not None and expires_at <= now:
                fresh = False
                reason = "expires_in_past_session_dead"
            elif expires_at is not None and (expires_at - now) <= self.expiry_warning_seconds or max_age is not None and max_age <= self.expiry_warning_seconds:
                fresh = True
                reason = "expiring_soon"
            results.append(CookieLiveness(name=name, fresh=fresh, expires_at=expires_at, max_age_seconds=max_age, reason=reason))
        return tuple(results)


# ---------------------------------------------------------------------------
# Aggregate report (advisory, no secrets)
# ---------------------------------------------------------------------------
@dataclass
class AuthResilienceReport:
    auth_types_available: tuple[str, ...] = ()
    cookie_liveness: tuple[CookieLiveness, ...] = ()
    oauth_state_verified: bool = False
    basic_fallback_applicable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "auth_types_available": list(self.auth_types_available),
            "cookie_liveness": [c.as_dict() for c in self.cookie_liveness],
            "oauth_state_verified": bool(self.oauth_state_verified),
            "basic_fallback_applicable": bool(self.basic_fallback_applicable),
        }
