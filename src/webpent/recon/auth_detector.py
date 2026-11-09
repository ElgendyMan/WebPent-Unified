"""Generic, target-agnostic authentication-surface detection.

The detector consumes only structural crawler projections and safe response
metadata. It may inspect target bytes supplied by a caller for deterministic
shape checks, but it never returns or logs those bytes, tokens, cookie values,
or credentials. Authentication is advisory discovery; M4 remains the only
credential attachment authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urljoin, urlsplit

_LOGIN_PATH_RE = re.compile(r"(?:^|/)(?:login|signin|sign-in|authenticate)(?:/|$|\?)", re.I)
_API_LOGIN_RE = re.compile(
    r"(?:^|/)(?:(?:api|rest)/|identity/api/)(?:auth/)?(?:user/)?(?:login|signin|sign-in|authenticate)(?:/|$|\?)",
    re.I,
)
_REGISTER_PATH_RE = re.compile(r"(?:^|/)(?:register|registration|signup|sign-up)(?:/|$|\?)", re.I)
_OAUTH_RE = re.compile(r"(?:^|/)(?:oauth|authorize|authorization)(?:/|$|\?)", re.I)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b")
_SESSION_COOKIE_RE = re.compile(
    r"(?:session|phpsessid|jsessionid|connect\.sid|sid|auth|token|jwt)", re.I
)
_NON_AUTH_COOKIE_RE = re.compile(r"(?:consent|language|preferences?|theme|analytics)", re.I)


@dataclass(frozen=True)
class AuthSignal:
    """A redacted authentication mechanism candidate."""

    auth_type: str
    login_url: str | None = None
    login_method: str = "POST"
    login_fields: dict[str, str] = field(default_factory=dict)
    token_type: str = "none"
    token_capture: str = "none"
    auth_header: str = ""
    source_routes: tuple[str, ...] = ()
    session_cookie_names: tuple[str, ...] = ()
    confidence: float = 0.0
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "auth_type": self.auth_type,
            "login_url": self.login_url,
            "login_method": self.login_method,
            "login_fields": dict(self.login_fields),
            "token_type": self.token_type,
            "token_capture": self.token_capture,
            "auth_header": self.auth_header,
            "source_routes": list(self.source_routes),
            "session_cookie_names": list(self.session_cookie_names),
            "confidence": self.confidence,
            "reason": self.reason[:240],
        }


@dataclass(frozen=True)
class AuthDetection:
    """Bounded redacted detector result."""

    signals: tuple[AuthSignal, ...] = ()
    target_origin: str = ""
    credential_aliases: tuple[str, ...] = ()
    registration_urls: tuple[str, ...] = ()

    @property
    def primary(self) -> AuthSignal | None:
        return self.signals[0] if self.signals else None

    @property
    def auth_type(self) -> str:
        return self.primary.auth_type if self.primary else "none"

    def as_dict(self) -> dict[str, Any]:
        primary = self.primary
        return {
            "auth_type": self.auth_type,
            "login_url": primary.login_url if primary else None,
            "login_method": primary.login_method if primary else None,
            "login_fields": dict(primary.login_fields) if primary else {},
            "token_type": primary.token_type if primary else "none",
            "token_capture": primary.token_capture if primary else "none",
            "auth_header": primary.auth_header if primary else "",
            "signals": [item.as_dict() for item in self.signals[:8]],
            "credential_aliases": list(self.credential_aliases[:32]),
            "signal_count": len(self.signals),
            "registration_urls": list(self.registration_urls[:8]),
        }


def _routes(surface_map: Any) -> list[Mapping[str, Any]]:
    raw = surface_map.get("routes", []) if isinstance(surface_map, Mapping) else getattr(surface_map, "routes", {})
    if isinstance(raw, Mapping):
        raw = list(raw.values())
    result: list[Mapping[str, Any]] = []
    for item in list(raw or [])[:300]:
        if isinstance(item, Mapping):
            result.append(item)
        elif hasattr(item, "as_dict"):
            value = item.as_dict()
            if isinstance(value, Mapping):
                result.append(value)
    return result


def _route_path(route: Mapping[str, Any]) -> str:
    return str(route.get("route") or route.get("path") or "")[:512]


def _field_names(form: Mapping[str, Any]) -> tuple[str, str]:
    fields = form.get("fields", [])
    names: list[str] = []
    for item in list(fields or [])[:64]:
        if isinstance(item, Mapping):
            name = str(item.get("name") or "").strip()
            if name:
                names.append(name[:128])
    password = next((name for name in names if "pass" in name.lower()), "password")
    username = next(
        (name for name in names if any(marker in name.lower() for marker in ("user", "email", "login", "account"))),
        next((name for name in names if name != password), "username"),
    )
    return username, password


def _absolute(base: str, value: str) -> str | None:
    if not value:
        return None
    candidate = urljoin(base, value)
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if urlsplit(base).hostname and parsed.hostname.lower() != urlsplit(base).hostname.lower():
        return None
    return candidate.split("#", 1)[0][:2048]


def _header_names_and_values(response: Any) -> tuple[set[str], list[str], str]:
    if not isinstance(response, Mapping):
        return set(), [], ""
    headers = response.get("headers") if isinstance(response.get("headers"), Mapping) else response
    names = {str(key).lower() for key in headers.keys()}
    values = [str(value)[:512] for key, value in headers.items() if str(key).lower() in {"www-authenticate", "location", "authorization", "set-cookie"}]
    body = str(response.get("body") or response.get("response_body") or "")[:200_000]
    return names, values, body


def _cookie_names(route: Mapping[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    for mechanism in list(route.get("auth_mechanisms", []) or []):
        text = str(mechanism)
        if text.lower().startswith("session-cookie:"):
            values.update(item.strip().lower() for item in text.split(":", 1)[1].split(",") if item.strip())
    return tuple(sorted(name[:80] for name in values if _SESSION_COOKIE_RE.search(name) and not _NON_AUTH_COOKIE_RE.search(name)))[:20]


class AuthDetector:
    """Detect common authentication shapes without target-specific branches."""

    def __init__(self, *, target_url: str | None = None) -> None:
        self.target_url = str(target_url or "")

    def detect(
        self,
        surface_map: Any,
        *,
        response_metadata: Sequence[Mapping[str, Any]] | None = None,
        credential_aliases: Sequence[str] | None = None,
    ) -> AuthDetection:
        base = self.target_url or str(getattr(surface_map, "target_url", "") or (surface_map.get("target_url", "") if isinstance(surface_map, Mapping) else ""))
        signals: list[AuthSignal] = []
        seen: set[tuple[str, str | None, tuple[str, ...]]] = set()
        registration_urls: list[str] = []
        routes = _routes(surface_map)
        for route in routes:
            path = _route_path(route)
            if _REGISTER_PATH_RE.search(path):
                registration_url = _absolute(base, path)
                if registration_url and registration_url not in registration_urls:
                    registration_urls.append(registration_url)
            forms = list(route.get("forms", []) or [])
            for form in forms[:32]:
                if not isinstance(form, Mapping) or not bool(form.get("login_signal")):
                    continue
                username, password = _field_names(form)
                login_url = _absolute(base, str(form.get("action") or path or "/login"))
                key = ("form_session", login_url, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(
                        auth_type="form_session", login_url=login_url, login_method=str(form.get("method") or "POST").upper(),
                        login_fields={"username_field": username, "password_field": password},
                        token_type="session_cookie", token_capture="Set-Cookie header", auth_header="Cookie: <M4-attached>",
                        source_routes=(path[:300],), confidence=0.95, reason="password form with submit-capable method",
                    ))
            cookie_names = _cookie_names(route)
            if cookie_names:
                key = ("session_cookie", None, cookie_names)
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(
                        auth_type="form_session", token_type="session_cookie", token_capture="Set-Cookie header",
                        auth_header="Cookie: <M4-attached>", session_cookie_names=cookie_names,
                        source_routes=(path[:300],), confidence=0.75, reason="session-shaped cookie name observed structurally",
                    ))
            mechanisms = " ".join(str(item) for item in list(route.get("auth_mechanisms", []) or []))
            if "http-auth-challenge" in mechanisms.lower():
                key = ("basic", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="basic", login_method="GET", token_type="basic", token_capture="WWW-Authenticate challenge", auth_header="Authorization: Basic <M4-attached>", source_routes=(path[:300],), confidence=0.9, reason="HTTP Basic challenge observed"))
            if _OAUTH_RE.search(path) or _OAUTH_RE.search(str(route.get("redirect_target") or "")):
                key = ("oauth", _absolute(base, path), ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="oauth", login_url=_absolute(base, path), token_type="oauth", token_capture="operator-authorized callback/session", auth_header="Authorization: Bearer <M4-attached>", source_routes=(path[:300],), confidence=0.8, reason="same-origin OAuth/authorize redirect shape"))
            if _API_LOGIN_RE.search(path):
                key = ("api_jwt", _absolute(base, path), ())
                if key not in seen:
                    seen.add(key)
                    login_form = next((item for item in forms[:32] if isinstance(item, Mapping) and bool(item.get("login_signal"))), None)
                    username_field, password_field = _field_names(login_form) if login_form else ("username", "password")
                    signals.append(AuthSignal(auth_type="api_jwt", login_url=_absolute(base, path), login_method="POST", login_fields={"username_field": username_field, "password_field": password_field}, token_type="jwt", token_capture="JSON token field or Authorization response shape", auth_header="Authorization: Bearer <M4-attached>", source_routes=(path[:300],), confidence=0.85, reason="bounded API auth/login route candidate"))
            if bool(route.get("api_signal")) and str(route.get("content_type") or "").lower().find("json") >= 0 and not _API_LOGIN_RE.search(path):
                # API routes are evidence for a possible API auth model, but are
                # lower-confidence than an explicit login/auth path.
                if bool(route.get("auth_required")):
                    key = ("api_jwt", None, ())
                    if key not in seen:
                        seen.add(key)
                        signals.append(AuthSignal(auth_type="api_jwt", token_type="jwt", token_capture="JSON token field", auth_header="Authorization: Bearer <M4-attached>", source_routes=(path[:300],), confidence=0.55, reason="protected JSON API surface observed"))
            # 5th auth signal (Unfreeze 2026-10-05, File 4; fixed per TEAM-RED D3):
            # api-key shape. Uses only fields present on real surface routes
            # (auth_mechanisms, parameter names) so the signal is reachable from
            # live call sites. Advisory only, conservative confidence, never
            # auto-provisioned. Generic "key" is deliberately NOT matched (FP risk).
            mechanisms_text = " ".join(str(item) for item in list(route.get("auth_mechanisms", []) or [])).lower()
            param_names = [str((p or {}).get("name", "") if isinstance(p, Mapping) else getattr(p, "name", "")).lower() for p in list(route.get("parameters", []) or [])[:64]]
            api_key_param = any(name in {"api_key", "apikey", "x-api-key", "api-key", "x_apikey"} for name in param_names)
            api_key_shape = (
                "api-key" in mechanisms_text or "apikey" in mechanisms_text or "x-api-key" in mechanisms_text
                or api_key_param
            )
            if api_key_shape:
                key = ("api_key", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="api_key", token_type="api_key", token_capture="operator-supplied key header or query param", auth_header="X-API-Key: <M4-attached>", source_routes=(path[:300],), confidence=0.45, reason="api-key mechanism/parameter shape observed (advisory, operator-gated)"))
        for response in list(response_metadata or [])[:64]:
            names, values, body = _header_names_and_values(response)
            location = next((value for value in values if _OAUTH_RE.search(value)), "")
            if any(value.lower().startswith("basic") for value in values) or "www-authenticate" in names and any("basic" in value.lower() for value in values):
                key = ("basic", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="basic", login_method="GET", token_type="basic", token_capture="WWW-Authenticate challenge", auth_header="Authorization: Basic <M4-attached>", confidence=0.95, reason="WWW-Authenticate Basic challenge observed"))
            if location:
                key = ("oauth", location.split("?", 1)[0], ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="oauth", login_url=_absolute(base, location), token_type="oauth", token_capture="operator-authorized callback/session", auth_header="Authorization: Bearer <M4-attached>", confidence=0.9, reason="OAuth authorization redirect observed"))
            if _JWT_RE.search(body) or "authorization" in names and any("bearer" in value.lower() for value in values):
                key = ("api_jwt", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="api_jwt", token_type="jwt", token_capture="JWT-shaped response only", auth_header="Authorization: Bearer <M4-attached>", confidence=0.9, reason="JWT response shape observed without retaining token"))
            if "set-cookie" in names:
                key = ("session_cookie", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="form_session", token_type="session_cookie", token_capture="Set-Cookie header", auth_header="Cookie: <M4-attached>", confidence=0.7, reason="Set-Cookie response header observed"))
            # 5th auth signal (Unfreeze 2026-10-05, File 4): api-key from response
            # metadata. Explicit key header names are robust; a non-Bearer/
            # non-Basic Authorization value is lower-confidence (advisory only).
            if any(h in names for h in ("x-api-key", "apikey", "x-apikey", "api-key")):
                key = ("api_key", None, ())
                if key not in seen:
                    seen.add(key)
                    signals.append(AuthSignal(auth_type="api_key", token_type="api_key", token_capture="operator-supplied key header", auth_header="X-API-Key: <M4-attached>", confidence=0.6, reason="api-key request header observed (advisory)"))
            elif "authorization" in names:
                non_standard_auth = [
                    v for v in values
                    if v.strip() and len(v.strip()) <= 128 and "=" not in v
                    and not v.lower().startswith(("bearer", "basic", "digest", "negotiate"))
                ]
                if non_standard_auth:
                    key = ("api_key", None, ())
                    if key not in seen:
                        seen.add(key)
                        signals.append(AuthSignal(auth_type="api_key", token_type="api_key", token_capture="operator-supplied Authorization key", auth_header="Authorization: <M4-attached>", confidence=0.4, reason="non-Bearer/non-Basic Authorization observed (advisory)"))
        # Prefer actionable login signals, then stronger confidence.
        # api_key is ranked lowest: advisory-only, conservative confidence,
        # never auto-provisioned without operator gate (Unfreeze 2026-10-05).
        priority = {"api_jwt": 0, "form_session": 1, "basic": 2, "oauth": 3, "api_key": 4}
        signals.sort(key=lambda item: (priority.get(item.auth_type, 9), -item.confidence, item.login_url or ""))
        origin = ""
        try:
            parsed = urlsplit(base)
            origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
        except ValueError:
            origin = ""
        return AuthDetection(
            tuple(signals[:8]),
            origin,
            tuple(str(item)[:128] for item in (credential_aliases or ())[:32]),
            tuple(registration_urls[:8]),
        )


__all__ = ["AuthDetection", "AuthDetector", "AuthSignal"]
