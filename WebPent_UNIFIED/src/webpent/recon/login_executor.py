"""Generic operator-authorized login execution for local/in-scope targets.

This module deliberately has no target adapters. It performs bounded same-origin
HTTPX requests using an AuthSignal and operator-provided runtime credentials.
Secrets exist only in memory until the caller immediately seals the returned
material through M4. ``to_dict`` methods contain digests and names only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from typing import Any, Mapping
from urllib.parse import urljoin, urlsplit

from webpent.recon.auth_detector import AuthSignal
from webpent.recon.identity_discovery import _has_identity_scalars, _walk_identity, decode_login_jwt_claims
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import build_cookie_header, make_safe_httpx_client
from webpent.shared.untrusted_content import wrap_httpx_response

_SECRET_KEYS = {"token", "access_token", "accessToken", "id_token", "idToken", "jwt", "api_key", "apiKey", "session_token"}
_SESSION_COOKIE_RE = re.compile(r"(?:session|phpsessid|jsessionid|connect\.sid|sid|auth|token|jwt)", re.I)
_NON_AUTH_COOKIE_RE = re.compile(r"(?:consent|language|preferences?|theme|analytics)", re.I)
SUPPORTED_AUTH_TYPES = ("form_session", "api_jwt", "basic", "oauth", "api_key")

# r9 D1 (DR-017): the bounded discovered same-origin identity-validation
# window — a bounded subset of the governed identity vocabulary, /whoami
# first, probed between the configured surface and the root.  A login URL is
# structurally excluded: a login surface is not a session-validation surface.
_IDENTITY_VALIDATION_WINDOW = ("/whoami", "/api/me", "/api/user/me", "/users/me", "/me")
_MAX_VALIDATION_PROBES = 16


def _bounded_login_payload(value: Any, *, depth: int = 0) -> Mapping[str, Any] | list[Any] | None:
    """Bound a login response body for in-memory identity mining only."""
    if depth > 4:
        return None
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:32]:
            key = str(raw_key)[:128]
            if isinstance(item, (str, int, bool)) or item is None:
                output[key] = str(item)[:512] if isinstance(item, str) else item
            elif isinstance(item, (Mapping, list)):
                nested = _bounded_login_payload(item, depth=depth + 1)
                if nested is not None:
                    output[key] = nested
        return output
    if isinstance(value, list):
        bounded: list[Any] = []
        for item in value[:16]:
            if isinstance(item, (str, int, bool)) or item is None:
                bounded.append(str(item)[:512] if isinstance(item, str) else item)
            elif isinstance(item, (Mapping, list)):
                nested = _bounded_login_payload(item, depth=depth + 1)
                if nested is not None:
                    bounded.append(nested)
        return bounded
    return None


def _response_json_payload(response: Any) -> Mapping[str, Any] | list[Any] | None:
    try:
        payload = response.json()
    except Exception:
        return None
    if not isinstance(payload, (Mapping, list)):
        return None
    return _bounded_login_payload(payload)


@dataclass(frozen=True)
class LoginMaterial:
    """Private runtime material; never serialize this object directly."""

    kind: str
    name: str
    value: str = field(repr=False, compare=False)
    source: str = ""

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.value.encode("utf-8", "replace")).hexdigest()[:16]

    def m4_secret(self) -> str:
        if self.kind == "bearer":
            return f"bearer:{self.value}"
        if self.kind == "cookie":
            return f"cookie:{self.name}={self.value}"
        if self.kind == "basic":
            return f"basic:{self.value}"
        if self.kind == "api_key":
            return f"api-key:{self.name}={self.value}"
        raise ValueError("unsupported_m4_material_kind")

    def redacted(self) -> dict[str, Any]:
        return {"kind": self.kind, "name": self.name[:128], "digest": self.digest, "source": self.source[:128]}


@dataclass(frozen=True)
class LoginResult:
    alias: str
    success: bool
    auth_type: str
    login_url: str | None
    status_code: int | None
    reason: str = ""
    material: LoginMaterial | None = field(default=None, repr=False, compare=False)
    validation_status_code: int | None = None
    validation_url: str | None = None
    # Bounded in-memory copy of the response body received at login, used ONLY
    # for identity artifact mining.  Never serialized (excluded from as_dict)
    # and never compared: it is runtime evidence, not reportable material.
    login_response_payload: Mapping[str, Any] | None = field(default=None, repr=False, compare=False)
    # r6c runtime-only capture (B1 hygiene): the bounded login response body
    # and the decoded JWT claims live on the result for the identity ladder,
    # but never serialize.  ``validation_probes`` and ``reason_chain`` ARE
    # serialized: they are value-free honesty records.
    response_payload: Mapping[str, Any] | list[Any] | None = field(default=None, repr=False, compare=False)
    identity_claims: Mapping[str, Any] | None = field(default=None, repr=False, compare=False)
    validation_probes: tuple[dict[str, Any], ...] = ()
    reason_chain: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias[:128],
            "success": self.success,
            "auth_type": self.auth_type,
            "login_url": self.login_url,
            "status_code": self.status_code,
            "reason": self.reason[:240],
            "material": self.material.redacted() if self.material else None,
            "vault_bound": False,
            "validation_status_code": self.validation_status_code,
            "validation_url": self.validation_url,
            "reason_chain": [str(item)[:240] for item in self.reason_chain[:8]],
            "validation_probes": [
                {str(key)[:64]: value for key, value in list(probe.items())[:8]}
                for probe in self.validation_probes[:_MAX_VALIDATION_PROBES]
            ],
        }


@dataclass(frozen=True)
class RegistrationResult:
    alias: str
    success: bool
    registration_url: str | None
    status_code: int | None
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias[:128],
            "success": self.success,
            "registration_url": self.registration_url,
            "status_code": self.status_code,
            "reason": self.reason[:240],
        }


class _HiddenInputParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.values: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "input":
            return
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        if values.get("type", "").lower() == "hidden" and values.get("name"):
            self.values[values["name"][:128]] = values.get("value", "")[:16_384]


def _clean_url(target_url: str, candidate: str | None) -> str | None:
    if not candidate:
        return None
    value = urljoin(target_url.rstrip("/") + "/", str(candidate))
    target = urlsplit(target_url)
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.hostname.lower() != (target.hostname or "").lower():
        return None
    if parsed.port != target.port and not (parsed.port is None and target.port in {None, 80, 443}):
        return None
    return value.split("#", 1)[0][:2048]


def _credential_value(credentials: Mapping[str, Any], *keys: str) -> str:
    nested = credentials.get("credentials") if isinstance(credentials.get("credentials"), Mapping) else credentials
    for key in keys:
        value = nested.get(key) if isinstance(nested, Mapping) else None
        if isinstance(value, str) and value:
            return value[:16_384]
    return ""


def _cookie_from_mapping(cookies: Mapping[str, Any], preferred: tuple[str, ...] = ()) -> LoginMaterial | None:
    ranked = list(preferred) + [str(name) for name in cookies.keys()]
    for name in ranked:
        value = cookies.get(name)
        if not isinstance(value, str) or not value or _NON_AUTH_COOKIE_RE.search(name) or not _SESSION_COOKIE_RE.search(name):
            continue
        return LoginMaterial("cookie", name[:128], value[:16_384], "operator_session")
    return None


def _cookie_from_client(client: Any, preferred: tuple[str, ...] = ()) -> LoginMaterial | None:
    try:
        cookies = {str(cookie.name): str(cookie.value) for cookie in client.cookies.jar}
    except (AttributeError, TypeError, ValueError):
        cookies = {}
    return _cookie_from_mapping(cookies, preferred)


def _token_from_json(value: Any) -> tuple[str, str] | None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in _SECRET_KEYS and isinstance(item, str) and item.strip():
                return str(key), item.strip()[:16_384]
            found = _token_from_json(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value[:32]:
            found = _token_from_json(item)
            if found:
                return found
    return None


class LoginExecutor:
    """Perform one bounded login with a fresh HTTPX client per principal."""

    def __init__(self, *, target_url: str, timeout_seconds: float = 10.0, max_response_bytes: int = 512_000) -> None:
        self.target_url = target_url.rstrip("/")
        if not _clean_url(self.target_url, self.target_url):
            raise ValueError("target_url must be an absolute HTTP(S) URL")
        self.timeout_seconds = max(0.1, min(float(timeout_seconds), 60.0))
        self.max_response_bytes = max(1024, min(int(max_response_bytes), 2_000_000))

    def login(self, *, alias: str, signal: AuthSignal, credentials: Mapping[str, Any]) -> LoginResult:
        alias = str(alias).strip()[:128]
        if not alias:
            return LoginResult("", False, signal.auth_type, signal.login_url, None, "principal_alias_required")
        if signal.auth_type not in SUPPORTED_AUTH_TYPES:
            return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "unsupported_auth_type")
        # Operator-supplied session material is accepted only as a starting point
        # and is still validated against a same-origin protected response.
        supplied_cookies = credentials.get("cookies") or credentials.get("session_cookies")
        if isinstance(supplied_cookies, Mapping) and supplied_cookies:
            material = _cookie_from_mapping(supplied_cookies, signal.session_cookie_names)
            if material:
                return self._validate_material(alias, signal, material, credentials)
        supplied_token = _credential_value(credentials, "token", "access_token", "jwt", "api_key")
        if supplied_token:
            kind = "api_key" if "api" in str(credentials).lower() and not supplied_token.count(".") == 2 else "bearer"
            material = LoginMaterial(kind, "Authorization" if kind == "bearer" else "X-API-Key", supplied_token, "operator_token")
            token_result = self._validate_material(alias, signal, material, credentials)
            if token_result.success:
                return token_result
            # r9 D2 (DR-017): a REJECTED operator token never short-circuits a
            # real credential login.  The rejection stays visible in the
            # honest reason chain; the credential strategy runs next.
            chain = (f"operator_token:{token_result.reason}",)
            credential_result = self._credential_login(alias, signal, credentials)
            if credential_result is not None:
                return replace(
                    credential_result,
                    reason_chain=chain + (f"credential_login:{credential_result.reason}",) + tuple(credential_result.reason_chain),
                )
            return replace(token_result, reason_chain=chain)

        username = _credential_value(credentials, "username", "email", "user", "login")
        password = _credential_value(credentials, "password", "pass")
        if signal.auth_type in {"oauth"}:
            return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "oauth_requires_operator_authorized_session_or_token")
        if signal.auth_type == "basic":
            if not username or not password:
                return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "username_and_password_required")
            return self._perform_basic(alias, signal, username, password, credentials)
        if signal.auth_type == "api_jwt":
            return self._perform_api(alias, signal, username, password, credentials)
        return self._perform_form(alias, signal, username, password, credentials)

    def login_with_api_key(
        self,
        *,
        alias: str,
        value: str,
        name: str = "X-API-Key",
        validation_url: str | None = None,
    ) -> LoginResult:
        """Validate an operator-supplied API key and return sealable M4 material.

        Additive convenience entry point (Unfreeze 2026-10-05, File 3). Delegates
        to the existing ``_validate_material`` path; introduces no new authority.
        The header ``name`` is preserved on the sealed ``LoginMaterial``
        (``api-key:name=value``). Default-off: callers must opt in.
        """
        alias = str(alias).strip()[:128]
        if not alias:
            return LoginResult("", False, "api_key", None, None, "principal_alias_required")
        clean_name = str(name or "X-API-Key").strip()[:128] or "X-API-Key"
        clean_value = str(value or "")[:16_384]
        if not clean_value:
            return LoginResult(alias, False, "api_key", None, None, "api_key_value_required")
        # Unfreeze fix 2026-10-05 (TEAM-RED D7): fail-closed. Without an
        # operator-supplied protected validation URL we would fall back to the
        # target root, where any 200 would mark any key as valid. Require it.
        if not validation_url:
            return LoginResult(alias, False, "api_key", None, None, "validation_url_required")
        material = LoginMaterial("api_key", clean_name, clean_value, "operator_api_key")
        signal = AuthSignal(
            auth_type="api_key",
            login_url=None,
            token_type="api_key",
            auth_header=f"{clean_name}: <M4-attached>",
            confidence=0.9,
            reason="operator_supplied_api_key",
        )
        credentials: dict[str, Any] = {"protected_url": validation_url} if validation_url else {}
        return self._validate_material(alias, signal, material, credentials)

    def register(
        self,
        *,
        alias: str,
        registration_url: str,
        credentials: Mapping[str, Any],
        field_map: Mapping[str, Any] | None = None,
        extra_fields: Mapping[str, Any] | None = None,
    ) -> RegistrationResult:
        """Perform one operator-authorized same-origin JSON signup attempt."""
        url = _clean_url(self.target_url, registration_url)
        username = _credential_value(credentials, "username", "email", "user", "login")
        password = _credential_value(credentials, "password", "pass")
        if not url:
            return RegistrationResult(alias, False, None, None, "same_origin_registration_url_unavailable")
        if not username or not password:
            return RegistrationResult(alias, False, url, None, "username_and_password_required")
        mapping = field_map if isinstance(field_map, Mapping) else {}
        username_field = str(mapping.get("username_field") or "email")[:128]
        password_field = str(mapping.get("password_field") or "password")[:128]
        repeat_field = str(mapping.get("password_repeat_field") or "passwordRepeat")[:128]
        body: dict[str, Any] = {
            username_field: username,
            password_field: password,
            repeat_field: password,
        }
        if isinstance(extra_fields, Mapping):
            for key, value in list(extra_fields.items())[:16]:
                if isinstance(key, str) and key and isinstance(value, (str, int, float, bool)):
                    body[key[:128]] = value
        target_token = set_engagement_target_hosts(self.target_url)
        try:
            with self._client() as client:
                response = client.post(url, json=body)
                status = int(getattr(response, "status_code", 0) or 0)
                if 200 <= status < 300:
                    return RegistrationResult(alias, True, url, status, "registration_succeeded")
                if status == 409:
                    return RegistrationResult(alias, True, url, status, "registration_already_exists")
                return RegistrationResult(alias, False, url, status, "registration_rejected")
        except Exception as exc:
            return RegistrationResult(alias, False, url, None, type(exc).__name__)
        finally:
            clear_engagement_target_hosts(target_token)

    def _client(self) -> Any:
        return make_safe_httpx_client(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": "WebPent-PrincipalProvisioner/1.0", "Accept": "text/html,application/json;q=0.9,*/*;q=0.1"},
        )

    def _credential_login(self, alias: str, signal: AuthSignal, credentials: Mapping[str, Any]) -> LoginResult | None:
        """The username/password strategies behind the D2 fall-through."""
        username = _credential_value(credentials, "username", "email", "user", "login")
        password = _credential_value(credentials, "password", "pass")
        if not username or not password:
            return None
        if signal.auth_type == "basic":
            return self._perform_basic(alias, signal, username, password, credentials)
        if signal.auth_type == "api_jwt":
            return self._perform_api(alias, signal, username, password, credentials)
        if signal.auth_type == "oauth":
            return None
        return self._perform_form(alias, signal, username, password, credentials)

    def _perform_form(self, alias: str, signal: AuthSignal, username: str, password: str, credentials: Mapping[str, Any]) -> LoginResult:
        if not username or not password:
            return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "username_and_password_required")
        login_url = _clean_url(self.target_url, signal.login_url) or _clean_url(self.target_url, "/login")
        if not login_url:
            return LoginResult(alias, False, signal.auth_type, None, None, "same_origin_login_url_unavailable")
        target_token = set_engagement_target_hosts(self.target_url)
        try:
            with self._client() as client:
                page = client.get(login_url)
                hidden = _HiddenInputParser()
                if "html" in page.headers.get("content-type", "").lower() or page.text.lstrip().startswith("<"):
                    hidden.feed(page.text[: self.max_response_bytes])
                fields = dict(hidden.values)
                username_field = signal.login_fields.get("username_field", "username")
                password_field = signal.login_fields.get("password_field", "password")
                fields[username_field] = username
                fields[password_field] = password
                response = client.post(login_url, data=fields)
                material = _cookie_from_client(client, signal.session_cookie_names) or _cookie_from_mapping({str(cookie.name): str(cookie.value) for cookie in response.cookies.jar}, signal.session_cookie_names)
                if not material:
                    return LoginResult(alias, False, signal.auth_type, login_url, response.status_code, "no_session_cookie_captured")
                return self._validate_material(alias, signal, material, credentials, client=client, login_response=response)
        except Exception as exc:
            return LoginResult(alias, False, signal.auth_type, login_url, None, type(exc).__name__)
        finally:
            clear_engagement_target_hosts(target_token)

    def _perform_api(self, alias: str, signal: AuthSignal, username: str, password: str, credentials: Mapping[str, Any]) -> LoginResult:
        if not username or not password:
            return LoginResult(alias, False, signal.auth_type, signal.login_url, None, "username_and_password_required")
        login_url = _clean_url(self.target_url, signal.login_url)
        if not login_url:
            return LoginResult(alias, False, signal.auth_type, None, None, "same_origin_api_login_url_unavailable")
        target_token = set_engagement_target_hosts(self.target_url)
        try:
            with self._client() as client:
                body = {signal.login_fields.get("username_field", "username"): username, signal.login_fields.get("password_field", "password"): password}
                response = client.post(login_url, json=body)
                material = _cookie_from_client(client, signal.session_cookie_names)
                try:
                    payload = response.json()
                except (ValueError, json.JSONDecodeError):
                    payload = None
                token = _token_from_json(payload)
                if token:
                    key, value = token
                    material = LoginMaterial("bearer", key, value, "api_response")
                if not material:
                    return LoginResult(alias, False, signal.auth_type, login_url, response.status_code, "no_token_or_session_cookie_captured")
                if token and 200 <= int(response.status_code) < 300 and not (credentials.get("protected_url") or credentials.get("validation_url")):
                    captured_payload = _response_json_payload(response)
                    return LoginResult(alias, True, signal.auth_type, login_url, response.status_code, "jwt_login_response_validated", material=material, validation_status_code=response.status_code, validation_url=login_url, login_response_payload=captured_payload, response_payload=captured_payload, identity_claims=decode_login_jwt_claims(value) if material.kind == "bearer" else None)
                return self._validate_material(alias, signal, material, credentials, client=client, login_response=response)
        except Exception as exc:
            return LoginResult(alias, False, signal.auth_type, login_url, None, type(exc).__name__)
        finally:
            clear_engagement_target_hosts(target_token)

    def _perform_basic(self, alias: str, signal: AuthSignal, username: str, password: str, credentials: Mapping[str, Any]) -> LoginResult:
        validation_url = self._validation_url(signal, credentials)
        target_token = set_engagement_target_hosts(self.target_url)
        try:
            with self._client() as client:
                response = client.get(validation_url, auth=(username, password))
                raw = f"{username}:{password}".encode("utf-8", "replace")
                encoded = base64.b64encode(raw).decode("ascii")
                material = LoginMaterial("basic", "Authorization", encoded, "basic_challenge")
                if not (200 <= response.status_code < 300):
                    return LoginResult(alias, False, signal.auth_type, validation_url, response.status_code, "basic_validation_rejected", validation_status_code=response.status_code, validation_url=validation_url)
                return LoginResult(alias, True, signal.auth_type, validation_url, response.status_code, "basic_session_validated", material=material, validation_status_code=response.status_code, validation_url=validation_url, login_response_payload=_response_json_payload(response))
        except Exception as exc:
            return LoginResult(alias, False, signal.auth_type, validation_url, None, type(exc).__name__)
        finally:
            clear_engagement_target_hosts(target_token)

    def _validation_surfaces(self, signal: AuthSignal, credentials: Mapping[str, Any]) -> list[tuple[str, str]]:
        """r9 D1 (DR-017): the ordered session-validation surface walk.

        configured surface (when real) -> the bounded discovered identity
        window -> the root.  The signal's LOGIN URL is structurally excluded
        (a login endpoint is not a session-validation surface) and the literal
        "None"/"null" string configurations are refused, so ``<base>/None``
        can never render and the r7/r8 GET-on-POST-login 500 conflation is
        structurally impossible.
        """
        surfaces: list[tuple[str, str]] = []
        configured = credentials.get("protected_url") or credentials.get("validation_url")
        configured_text = str(configured or "").strip()
        if configured_text and configured_text.lower() not in {"none", "null"}:
            configured_url = _clean_url(self.target_url, configured_text)
            if configured_url:
                surfaces.append(("configured", configured_url))
        login_url_clean = _clean_url(self.target_url, signal.login_url) if signal.login_url else None
        for candidate in _IDENTITY_VALIDATION_WINDOW:
            candidate_url = _clean_url(self.target_url, candidate)
            if not candidate_url or candidate_url == login_url_clean:
                continue
            if any(url == candidate_url for _kind, url in surfaces):
                continue
            surfaces.append(("identity_window", candidate_url))
        root = _clean_url(self.target_url, self.target_url) or self.target_url
        if not any(url == root for _kind, url in surfaces):
            surfaces.append(("root", root))
        return surfaces

    def _validation_url(self, signal: AuthSignal, credentials: Mapping[str, Any]) -> str:
        surfaces = self._validation_surfaces(signal, credentials)
        if surfaces:
            return surfaces[0][1]
        return self.target_url

    def _material_request(self, client: Any, material: LoginMaterial, url: str) -> Any:
        """One GET with the material attached (the same M4-only shapes)."""
        if material.kind == "cookie":
            return client.get(url)
        if material.kind == "api_key":
            return client.get(url, headers={material.name: material.value})
        header = "Basic " + material.value if material.kind == "basic" else "Bearer " + material.value
        return client.get(url, headers={"Authorization": header})

    def _validate_material(self, alias: str, signal: AuthSignal, material: LoginMaterial, credentials: Mapping[str, Any], *, client: Any | None = None, login_response: Any | None = None) -> LoginResult:
        """Walk the D1 validation surfaces with the material attached.

        Verdicts (r6c/r9): a JSON 2xx carrying an identity shape validates the
        session (``session_validated``); a 2xx non-JSON body proves only that
        the material keeps a page alive (``validation_inconclusive``); an
        anonymous-shape JSON 2xx did NOT bind the session and the walk
        continues; non-2xx surfaces are skipped; a walk whose every probe
        raised fails closed with ``validation_surface_unavailable``.  With no
        login response, ``status_code`` stays None (never the duplicated
        validation status — the r8 conflation defect).
        """
        login_payload = _response_json_payload(login_response) if login_response is not None else None
        surfaces = self._validation_surfaces(signal, credentials)
        target_token = set_engagement_target_hosts(self.target_url)
        owns_client = client is None
        probes: list[dict[str, Any]] = []
        saw_http_response = False
        last_status: int | None = None
        last_url: str | None = None
        try:
            active_client = client or self._client()
            if material.kind == "cookie":
                try:
                    active_client.cookies.set(material.name, material.value, domain=urlsplit(self.target_url).hostname, path="/")
                except (AttributeError, TypeError, ValueError):
                    pass
            verdict: tuple[str, str, int] | None = None
            for kind, surface_url in surfaces:
                path = urlsplit(surface_url).path or "/"
                try:
                    response = self._material_request(active_client, material, surface_url)
                    status = int(getattr(response, "status_code", 0) or 0)
                    location = str(getattr(response, "headers", {}).get("location", ""))
                    login_redirect = bool(location and re.search(r"(?:login|signin|auth)", location, re.I))
                    if 300 <= status < 400 and location and not login_redirect:
                        follow_url = _clean_url(surface_url, location)
                        if follow_url:
                            response = self._material_request(active_client, material, follow_url)
                            status = int(getattr(response, "status_code", 0) or 0)
                            location = str(getattr(response, "headers", {}).get("location", ""))
                            login_redirect = bool(location and re.search(r"(?:login|signin|auth)", location, re.I))
                except Exception as exc:
                    probes.append({"path": path, "kind": kind, "result": f"exception:{type(exc).__name__}"})
                    continue
                saw_http_response = True
                last_status = status
                last_url = surface_url
                if login_redirect:
                    # The boundary bounced us to a login surface: the session
                    # is not recognized.  Record honestly and keep walking.
                    probes.append({"path": path, "kind": kind, "status_code": status, "result": "login_redirect"})
                    continue
                if not (200 <= status < 300):
                    probes.append({"path": path, "kind": kind, "status_code": status, "result": "http_status"})
                    continue
                payload = _response_json_payload(response)
                if payload is None:
                    content_type = ""
                    try:
                        content_type = str(getattr(response, "headers", {}).get("content-type", "") or "").lower()
                    except Exception:
                        content_type = ""
                    body_text = ""
                    try:
                        body_text = str(getattr(response, "text", "") or "").lstrip()
                    except Exception:
                        body_text = ""
                    result_name = "spa_catch_all_html" if ("html" in content_type or body_text.startswith("<")) else "non_json_response"
                    probes.append({"path": path, "kind": kind, "status_code": status, "result": result_name})
                    # A 2xx non-JSON page proves the material is alive but the
                    # surface proved nothing about the session: inconclusive.
                    verdict = ("inconclusive", surface_url, status)
                    break
                if not _has_identity_scalars(payload):
                    probes.append({"path": path, "kind": kind, "status_code": status, "result": "anonymous_shape"})
                    # Anonymous shape under our material: the session did NOT
                    # bind through this surface; keep walking (the r5
                    # vacuous-whoami lesson applied to the D1 window).
                    continue
                probes.append({"path": path, "kind": kind, "status_code": status, "result": "json_identity_resolved"})
                verdict = ("validated", surface_url, status)
                break
            if verdict is None:
                if not saw_http_response:
                    return LoginResult(
                        alias, False, signal.auth_type, signal.login_url, getattr(login_response, "status_code", None),
                        "validation_surface_unavailable", material=material, validation_url=last_url,
                        validation_probes=tuple(probes[:_MAX_VALIDATION_PROBES]),
                    )
                return LoginResult(
                    alias, False, signal.auth_type, signal.login_url, getattr(login_response, "status_code", None),
                    "session_validation_rejected", material=material, validation_status_code=last_status,
                    validation_url=last_url, validation_probes=tuple(probes[:_MAX_VALIDATION_PROBES]),
                )
            verdict_name, final_url, final_status = verdict
            identity_claims = decode_login_jwt_claims(material.value) if material.kind == "bearer" else None
            reason = "session_validated" if verdict_name == "validated" else "validation_inconclusive"
            return LoginResult(
                alias, True, signal.auth_type, signal.login_url, getattr(login_response, "status_code", None),
                reason, material=material, validation_status_code=final_status, validation_url=final_url,
                login_response_payload=login_payload, response_payload=login_payload,
                identity_claims=identity_claims, validation_probes=tuple(probes[:_MAX_VALIDATION_PROBES]),
            )
        finally:
            if owns_client:
                try:
                    active_client.close()
                except Exception:
                    pass
            clear_engagement_target_hosts(target_token)


__all__ = ["LoginExecutor", "LoginMaterial", "LoginResult", "RegistrationResult"]
