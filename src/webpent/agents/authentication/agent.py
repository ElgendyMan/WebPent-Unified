# src/webpent/agents/authentication/agent.py
"""webpent.agents.authentication.agent

LangGraph node that performs active authentication against the target.

V4.5 Integration Fix: Credentials are now read directly from
``state["credentials"]`` (populated cleanly by the Typer CLI), NOT
extracted via regex from ``target.description``. The dangerous regex
extraction logic has been completely removed.

V8 Phase 4b: Operator-supplied session cookies. If the API caller
provides a ``session_cookies`` dict (e.g. ``{"PHPSESSID": "abc",
"security": "impossible"}``), auth_node validates the session via a
lightweight HTTP request and, if valid, skips Playwright login
entirely. This is the primary path for authenticated DVWA scanning
via the API — Playwright login is fragile against DVWA's CSRF token
and security-level cookie, while operator-supplied cookies (extracted
from a browser session) are reliable.

Session cookies take precedence over credentials when both are
provided. If session cookies are invalid/expired, auth_node falls
back to credentials (if provided) or unauthenticated behavior — it
never silently crawls an anonymous surface thinking it's
authenticated.

Security:
  * Raw cookie values are NEVER logged. Only cookie names and
    validity verdict appear in logs.
  * Session cookies are engagement-scoped state only — they are NOT
    persisted to the Decision Log, Mental Model, or any long-term
    store. They live in ``state["session_cookies"]`` (merge_dicts
    reducer, checkpointed by SqliteSaver, never written to ChromaDB
    or the lessons store).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from langchain_core.messages import AIMessage

from webpent.auth.reauth_vault import (
    identity_vault_key,
    seal_identity_profiles,
    unseal_identity_profiles,
    unseal_reauth_secret,
    unseal_session_cookies,
)
from webpent.state.state import PentestState
from webpent.agents.authentication.m4_boundary import legacy_auth_m4_failure

logger = logging.getLogger(__name__)


def _profiles_from_identity_records(state: dict[str, Any]) -> dict[str, Any]:
    """Project only report-safe profile refs from provisioned identity records."""
    records = state.get("identity_records") or {}
    if not isinstance(records, dict):
        return {}
    profiles: dict[str, Any] = {}
    for identity_id, record in records.items():
        if not isinstance(record, dict):
            continue
        profile_ref = record.get("profile_ref")
        if not isinstance(profile_ref, dict):
            continue
        safe_profile = {
            key: value
            for key, value in profile_ref.items()
            if key not in {"password", "password_ref", "otp", "token", "secret"}
        }
        if safe_profile.get("identity_id") or identity_id:
            profiles[str(identity_id)] = safe_profile
    return profiles


_NAV_TIMEOUT_MS = 15_000
_DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# Common login-page indicators in response bodies. Used by
# _validate_session_cookies to detect a bounce to the login page
# even when the HTTP status is 200 (some apps return 200 with a
# login form HTML instead of a 302 redirect).
#
# V9 FIX-7: Removed bare "sign in" (too broad — matches any page
# containing the text "sign in" including legitimate content pages
# like "sign in to our newsletter"). Replaced with tighter phrases
# that require the phrase to be a call-to-action, not incidental text.
_LOGIN_PAGE_INDICATORS = (
    "login.php",
    "login.html",
    "login.asp",
    "name=\"password\"",
    "id=\"password\"",
    "type=\"password\"",
    "please log in",
    "please login",
    "please sign in",
    "sign in to continue",
    "you must log in",
)


class _LoginMaterial(dict[str, str]):
    """Cookie-compatible login result with optional validated auth headers.

    The mapping itself remains the target-issued cookie jar, preserving the
    legacy ``_perform_login`` contract.  Headers are kept as a side channel so
    bearer-token SPAs can authenticate without pretending a JWT is a cookie.
    """

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(cookies or {})
        self.auth_headers = dict(headers or {})


_AUTH_STORAGE_KEYS = {
    "access_token",
    "accesstoken",
    "auth_token",
    "authtoken",
    "id_token",
    "idtoken",
    "jwt",
    "session_token",
    "sessiontoken",
    "token",
}

# Browser preferences/consent cookies are not authentication material. They
# may be present before login, so accepting them as proof would create an
# anonymous-session false positive. Keep this list deliberately narrow;
# target-issued session cookies with any other name remain eligible for
# validation.
_NON_AUTH_COOKIE_NAMES = {
    "language",
    "cookieconsent",
    "cookieconsent_status",
    "cookie_consent",
    "cc_cookie",
    "privacy_consent",
}


def _extract_bearer_headers(page: Any) -> dict[str, str]:
    """Extract a target-issued bearer token from bounded browser storage.

    This is intentionally narrow and report-safe: only known auth-shaped
    storage keys are inspected, values never enter logs, and the caller must
    validate the resulting Authorization header before using it.
    """
    try:
        entries = page.evaluate(
            """() => Object.keys(localStorage).slice(0, 100).map((key) => {
                let value = localStorage.getItem(key);
                try {
                    const parsed = JSON.parse(value);
                    if (parsed && typeof parsed === 'object') {
                        value = parsed.access_token || parsed.accessToken ||
                            parsed.id_token || parsed.token || value;
                    }
                } catch (_) {}
                return {key, value};
            })"""
        )
    except Exception:
        return {}
    if not isinstance(entries, list):
        return {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key") or "").strip().lower().replace("-", "_")
        value = entry.get("value")
        if key not in _AUTH_STORAGE_KEYS or not isinstance(value, str):
            continue
        token = value.strip()
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        if not token or len(token) > 16_384 or any(ord(char) < 0x20 for char in token):
            continue
        return {"Authorization": f"Bearer {token}"}
    return {}


def _perform_login(
    url: str,
    username: str,
    password: str,
    additional_target_origins: list[str] | None = None,
) -> dict[str, str]:
    """Perform login from sync or asyncio graph contexts.

    The implementation uses Playwright's sync API for compatibility with the
    existing login flow. LangGraph may invoke the auth node while an asyncio
    loop is already running, where Playwright rejects the sync API. Run the
    unchanged implementation in a dedicated worker thread in that case.
    Any bridge failure returns an empty result, preserving fail-closed auth.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return _perform_login_sync(
            url, username, password, additional_target_origins
        )

    try:
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="webpent-auth") as executor:
            return executor.submit(
                _perform_login_sync,
                url,
                username,
                password,
                additional_target_origins,
            ).result()
    except Exception as exc:
        logger.warning("Playwright authentication worker failed: %s", exc)
        return {}


def _perform_login_sync(
    url: str,
    username: str,
    password: str,
    additional_target_origins: list[str] | None = None,
) -> dict[str, str]:
    """Launch Playwright, perform login, and return session cookies.

    Args:
        url: Target URL to navigate to.
        username: Username credential.
        password: Password credential.

    Returns:
        A dict mapping cookie names to values. Empty dict on failure.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.error(
            "playwright is not installed. Install with 'pip install playwright' "
            "and run 'playwright install chromium'."
        )
        return {}

    pw = None
    browser = None
    cookies: dict[str, str] = {}

    try:
        pw = sync_playwright().start()
        # V6 Final-Seal-Revised: pin DNS for the login target host via
        # --host-resolver-rules at launch time rather than rewriting
        # the request URL inside the route handler, which broke TLS
        # SNI for HTTPS login pages (see shared/http.py). Closes the
        # DNS-rebinding TOCTOU race without breaking cert validation.
        launch_args: list[str] = []
        from urllib.parse import urlparse as _urlparse
        target_host = _urlparse(url).hostname
        if target_host:
            try:
                from webpent.shared.http import build_host_resolver_rules_args
                launch_args = build_host_resolver_rules_args(target_host)
            except Exception as exc:
                logger.warning(
                    "Failed to build --host-resolver-rules for %s (%s) "
                    "— launching without DNS pinning; the route-handler "
                    "block remains active.",
                    target_host, exc,
                )
        browser = pw.chromium.launch(headless=True, args=launch_args)
        context_kwargs: dict[str, str] = {}
        configured_user_agent = os.getenv("HTTP_USER_AGENT", "").strip()
        context_kwargs["user_agent"] = (
            configured_user_agent or _DEFAULT_BROWSER_USER_AGENT
        )
        context_kwargs["locale"] = "en-US"
        context_kwargs["extra_http_headers"] = {
            "Accept-Language": "en-US,en;q=0.9",
        }
        context = browser.new_context(**context_kwargs)
        # V6 Zero-Day Patched P0-1: Install SSRF route guard BEFORE
        # new_page() / goto(). The auth agent navigates to the target
        # login page; without the guard, a malicious target could
        # redirect Playwright to internal IPs (169.254.169.254 AWS
        # metadata, redis:6379, 127.0.0.1) via JS redirects or
        # meta-refresh, turning the browser into an SSRF proxy. The
        # guard aborts blocked-host requests with accessdenied.
        from webpent.shared.engagement_scope import normalize_scope_host
        from webpent.shared.http import install_playwright_ssrf_guard

        # Playwright may execute route callbacks outside the caller's
        # contextvars context (notably when auth runs inside a graph/worker
        # boundary). Pass the operator-declared login target explicitly so
        # an authorized private lab target remains reachable. The guard
        # still blocks every other private/reserved host exactly as before.
        declared_hosts = [
            normalized
            for normalized in (
                normalize_scope_host(value)
                for value in [url, *(additional_target_origins or [])]
            )
            if normalized
        ]
        install_playwright_ssrf_guard(context, target_hosts=declared_hosts)
        page = context.new_page()
        page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)

        def _navigate_with_readiness(target_url: str) -> bool:
            """Navigate after response commit without waiting on stalled assets.

            Some authorized labs keep a page subresource open indefinitely.  A
            DOMContentLoaded-only navigation therefore blocks the auth worker
            even when the document and login form are already available.  The
            response commit remains the hard navigation boundary; readiness is
            best-effort and form selectors below remain the source of truth.
            """
            page.goto(target_url, wait_until="commit")
            try:
                page.wait_for_load_state(
                    "domcontentloaded", timeout=min(_NAV_TIMEOUT_MS, 4_000)
                )
            except Exception as exc:
                logger.debug(
                    "Navigation readiness wait skipped for %s: %s",
                    target_url,
                    type(exc).__name__,
                )
            return True

        try:
            _navigate_with_readiness(url)
        except Exception as exc:
            logger.warning("Navigation to %s failed: %s", url, exc)
            return {}

        # Some targets redirect the base URL to a protected dashboard and
        # expose the login form at a sibling route. Discover only bounded,
        # same-origin login paths; never follow an arbitrary redirect or
        # broaden the engagement scope while doing so.
        def _visible(selector: str, timeout: int = 700) -> bool:
            try:
                page.locator(selector).first.wait_for(state="visible", timeout=timeout)
                return True
            except Exception:
                return False

        login_field_selector = (
            "input[type='email']:not([name='email']), "
            "input[type='email'][id='email'], input[name='username'], "
            "input[name='user'], input[name='email']"
        )
        if not _visible("input[type='password']") and not _visible(login_field_selector):
            parsed_target = _urlparse(url)
            origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
            current_url = page.url.rstrip("/")
            for login_path in ("/#/login", "/login", "/signin", "/auth/login"):
                login_url = origin + login_path
                if login_url.rstrip("/") == current_url:
                    continue
                try:
                    _navigate_with_readiness(login_url)
                except Exception:
                    continue
                if _visible("input[type='password']") or _visible(login_field_selector):
                    logger.info("Discovered login form at same-origin path %s", login_path)
                    break

        # Most login forms expose password immediately. Some targets use a
        # two-step email -> password flow, where the password input exists in
        # the DOM but is hidden until the
        # email is checked by the application. Support both forms without
        # weakening the target-agnostic selectors below.
        password_input = page.locator("input[type='password']").first
        two_step_email = False
        try:
            password_input.wait_for(state="visible", timeout=5000)
        except Exception:
            email_input = page.locator(
                "input[type='email']:not([name='email']), "
                "input[type='email'][id='email']"
            ).first
            try:
                email_input.wait_for(state="visible", timeout=3000)
                email_input.fill(username)
                continue_button = page.locator(
                    "#nextBtn, button:has-text('Continue'), button:has-text('Next')"
                ).first
                continue_button.click(timeout=5000)
                password_input.wait_for(state="visible", timeout=5000)
                two_step_email = True
            except Exception:
                logger.info("No usable password or two-step email field at %s", url)
                return {}

        # A two-step flow already submitted the username through its email
        # check. Immediate-login forms still need a visible username field.
        username_input = None
        if not two_step_email:
            for selector in [
                "input[name='email']",
                "input[name='username']",
                "input[name='user']",
                "input[type='email']",
                "input:not([type])",
                "input[type='text']",
            ]:
                try:
                    username_input = page.locator(selector).first
                    username_input.wait_for(state="visible", timeout=2000)
                    break
                except Exception:
                    continue

            if username_input is None:
                logger.info("No username field found — cannot login")
                return {}

        # Fill credentials. The two-step flow has already filled the email
        # and only requires the newly-visible password field.
        try:
            if username_input is not None:
                username_input.fill(username)
            password_input.fill(password)
        except Exception as exc:
            logger.warning("Failed to fill login fields: %s", exc)
            return {}

        # Submit the form.
        try:
            submit = page.locator(
                "button[type='submit'], input[type='submit'], "
                "button:has-text('Login'), button:has-text('Log in')"
            ).first
            submit.click(timeout=5000)
        except Exception:
            try:
                password_input.press("Enter")
            except Exception as exc:
                logger.warning("Failed to submit login form: %s", exc)
                return {}

        # Wait for navigation/post-login state.  SPA login handlers may write
        # the token to localStorage just after the first network-idle point;
        # give that bounded, same-page state transition a short grace period.
        with contextlib.suppress(Exception):
            page.wait_for_load_state("networkidle", timeout=10_000)
        with contextlib.suppress(Exception):
            page.wait_for_function(
                """() => Object.keys(localStorage).some((key) => {
                    const normalized = key.toLowerCase().replaceAll('-', '_');
                    return [
                        'access_token', 'accesstoken', 'auth_token', 'authtoken',
                        'id_token', 'idtoken', 'jwt', 'session_token',
                        'sessiontoken', 'token',
                    ].includes(normalized);
                })""",
                timeout=2_000,
            )

        # Extract cookies and SPA bearer material from the browser context.
        browser_cookies = context.cookies()
        for cookie in browser_cookies:
            name = str(cookie.get("name", "")).strip()
            value = str(cookie.get("value", ""))
            if name:
                cookies[name] = value
        auth_headers = _extract_bearer_headers(page)
        cookies = {
            name: value
            for name, value in cookies.items()
            if name.lower() not in _NON_AUTH_COOKIE_NAMES
        }

        # V10 HOSTILE P1-1 FIX: do NOT treat non-empty cookies or localStorage
        # values as login success. Validate the target-issued material through
        # the same SSRF-safe HTTP path used for operator-supplied sessions.
        if not cookies and not auth_headers:
            logger.info("Login submitted but no session cookies or bearer token found")
            return {}

        from webpent.shared.engagement_scope import (
            clear_engagement_target_hosts,
            set_engagement_target_hosts,
        )
        validation_scope_token = set_engagement_target_hosts(
            url, *(additional_target_origins or [])
        )
        try:
            if auth_headers:
                is_valid, reason = _validate_session_cookies(
                    url,
                    cookies,
                    extra_headers=auth_headers,
                )
            else:
                is_valid, reason = _validate_session_cookies(url, cookies)
        finally:
            clear_engagement_target_hosts(validation_scope_token)
        if not is_valid:
            logger.error(
                "Login FAILED — session validation rejected the cookies: "
                "%s. Cookies extracted but NOT authenticated (wrong "
                "password? CSRF token mismatch? account locked?). "
                "Returning empty cookies — engagement will run "
                "unauthenticated or fail-loud at the validator.",
                reason,
            )
            return {}

        logger.info(
            "Login successful — validated %d session cookie(s) and %d "
            "auth header(s) against %s (%s)",
            len(cookies), len(auth_headers), url, reason,
        )

        # Do not mutate the authenticated session with lab-specific cookies.
        # A target may use a security-level cookie, a CSRF cookie, a tenant
        # selector, or no such control at all.  The authenticated values must
        # come from the target response; operator-supplied session cookies are
        # handled separately by the explicit session_cookies input path.
        return _LoginMaterial(cookies, headers=auth_headers)

    except Exception as exc:
        logger.warning("Playwright authentication failed: %s", exc)
        return {}
    finally:
        with contextlib.suppress(Exception):
            if browser is not None:
                browser.close()
        with contextlib.suppress(Exception):
            if pw is not None:
                pw.stop()


def _validate_session_cookies(
    target_url: str,
    cookies: dict[str, str],
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Validate operator-supplied session cookies via a lightweight request.

    V8 Phase 4b: Makes a single HTTP request to the target URL with the
    supplied cookies. If the response is a redirect to a login page or
    contains login-page indicators in the body, the session is invalid.

    Args:
        target_url: The target URL to probe (typically the engagement's
            primary target).
        cookies: The operator-supplied session cookie dict.

    Returns:
        A tuple of ``(is_valid, reason)``. ``is_valid`` is True only if
        the session appears active. ``reason`` is a short human-readable
        explanation (never contains raw cookie values).
    """
    safe_extra_headers = {
        str(name): str(value)
        for name, value in (extra_headers or {}).items()
        if str(name).lower() in {"authorization", "x-auth-token", "x-api-key"}
        and str(value).strip()
    }
    auth_cookies = {
        name: value
        for name, value in cookies.items()
        if str(name).strip().lower() not in _NON_AUTH_COOKIE_NAMES
        and str(value).strip()
    }
    if not auth_cookies and not safe_extra_headers:
        return False, "no authentication material provided"

    try:
        from webpent.config.settings import get_settings
        from webpent.shared.http import make_safe_httpx_client
    except Exception:
        # V10 P0-4 FIX (fail CLOSED): previously this branch fell back
        # to a raw ``httpx.Client``, which BYPASSES the SSRF pinning
        # transport. An operator-supplied ``target_url`` is consumed
        # directly here, so the SSRF guard is mandatory — refusing to
        # validate is strictly safer than validating through an
        # unguarded client that could be turned into an SSRF proxy.
        # Auth_node surfaces the failure to the operator; it does NOT
        # crash the engagement (the caller treats ``is_valid=False``
        # as "skip authenticated scanning" rather than aborting).
        logger.error(
            "Session validation refused for %s: SSRF-guarded httpx "
            "client (webpent.shared.http.make_safe_httpx_client) could "
            "not be imported — refusing to validate with an unguarded "
            "client. Marking session invalid.",
            target_url,
        )
        return (
            False,
            "SSRF-guarded httpx client unavailable — refusing to "
            "validate with unguarded client",
        )
    else:
        client_factory = make_safe_httpx_client

    # Cookie/header names only — NEVER log raw values.
    cookie_names = list(auth_cookies.keys())
    header_names = list(safe_extra_headers.keys())
    try:
        configured_user_agent = str(get_settings().http_user_agent or "").strip()
        validation_user_agent = configured_user_agent
        if not validation_user_agent or validation_user_agent.startswith("WebPent/0.2"):
            validation_user_agent = _DEFAULT_BROWSER_USER_AGENT
        headers = {
            "User-Agent": validation_user_agent[:256],
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Referer": target_url.rstrip("/") + "/login",
            **safe_extra_headers,
        }
        with client_factory(
            timeout=10.0, follow_redirects=False, verify=True,
        ) as client:
            response = client.get(
                target_url,
                cookies=auth_cookies,
                headers=headers,
            )
    except Exception as exc:
        logger.warning(
            "Session validation request failed for %s (cookies=%s, headers=%s): %s — "
            "treating session as invalid.",
            target_url, cookie_names, header_names, exc,
        )
        return False, f"validation request failed: {exc}"

    # Check 1: 3xx redirect to a login page.
    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get("location", "").lower()
        if "login" in location or "signin" in location or "auth" in location:
            return False, f"redirected to login page ({response.status_code} -> {location[:80]})"
        # Redirect to a non-login page: a 3xx alone does not prove an
        # authenticated state (UM-DR-35.4) — but it also does not disprove
        # it. Follow-up is handled by the caller's bounded redirect policy;
        # recorded as valid only when the destination is not a login
        # surface, which remains the historic conservative behavior.
        logger.info(
            "Session validation: redirect to non-login page (%s -> %s) — "
            "treating as valid.",
            response.status_code, location[:80],
        )
        return True, f"redirect to non-login page ({response.status_code})"

    # Check 2: 401/403 — session is invalid or lacks permissions.
    if response.status_code in (401, 403):
        return False, f"HTTP {response.status_code} — session rejected"

    # Check 3: 200 but body contains login-page indicators.
    if response.status_code == 200:
        body_lower = response.text[:5000].lower()
        for indicator in _LOGIN_PAGE_INDICATORS:
            if indicator in body_lower:
                return False, f"200 OK but body contains login indicator '{indicator}'"
        # UM-DR-35.4: a generic 200 body WITHOUT login indicators does not
        # prove an authenticated state — an SPA shell or anonymous landing
        # page also returns 200 without login markers. It validates ONLY
        # when the body carries identity evidence (identity-bearing HTML
        # markers); otherwise the session state is explicitly INCONCLUSIVE
        # and the caller must not rely on it for identity-sensitive work.
        from webpent.recon.auth_success_model import html_identity_evidence
        markers = html_identity_evidence(response.text or "")
        if markers:
            return True, (
                "200 OK with identity-bearing HTML markers "
                f"({', '.join(markers[:3])})"
            )
        return True, (
            "200 OK, no login indicators; identity evidence not established "
            "(session state inconclusive for identity-sensitive probes)"
        )

    # Any other status code (5xx, unusual codes): the validation surface
    # FAILED, it did not accept the session. Treating a 5xx as a valid
    # session fabricated authenticated state (UM-DR-35.4 removes that
    # behavior). Fail closed: the session is not proven.
    return False, (
        f"HTTP {response.status_code} — validation surface unavailable; "
        "session cannot be treated as valid"
    )


def _bootstrap_secondary_profiles(
    target_url: str,
    raw_profiles: dict[str, Any] | None,
    additional_target_origins: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Create bounded runtime-only identity profiles for BAC/IDOR probes.

    Credentials are consumed here and never returned.  Each profile contains
    only a stable label, role, validation status, and session cookies needed
    by the access-control differential tester.
    """
    if not raw_profiles:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, (profile_name, raw_profile) in enumerate(raw_profiles.items(), start=2):
        if not isinstance(raw_profile, dict):
            continue
        name = str(raw_profile.get("name") or profile_name or f"identity-{index}")
        role = str(raw_profile.get("role") or "secondary")
        supplied_cookies = raw_profile.get("cookies") or raw_profile.get("session_cookies")
        cookies: dict[str, str] = {}
        validated = False
        if isinstance(supplied_cookies, dict) and supplied_cookies:
            candidate = {str(k): str(v) for k, v in supplied_cookies.items() if v not in (None, "")}
            if candidate:
                validated, _ = _validate_session_cookies(target_url, candidate)
                if validated:
                    cookies = candidate
        if not cookies:
            raw_credentials = raw_profile.get("credentials")
            if isinstance(raw_credentials, dict):
                username = str(raw_credentials.get("username") or "")
                password = str(raw_credentials.get("password") or "")
                if username and password:
                    if additional_target_origins:
                        cookies = _perform_login(
                            target_url,
                            username,
                            password,
                            additional_target_origins=additional_target_origins,
                        )
                    else:
                        cookies = _perform_login(target_url, username, password)
                    validated = bool(cookies)
        result[name] = {
            "name": name,
            "role": role,
            "cookies": cookies,
            "validated": validated,
        }
        for key in ("owned_object_ids", "owned_ids", "owned_urls"):
            value = raw_profile.get(key)
            if isinstance(value, (list, tuple, set, frozenset)):
                result[name][key] = [str(item) for item in value if str(item).strip()]
        if isinstance(raw_profile.get("metadata"), dict):
            result[name]["metadata"] = dict(raw_profile["metadata"])
        logger.info(
            "Secondary identity %s bootstrap: validated=%s cookie_count=%s",
            name, validated, len(cookies),
        )
    return result


def _identity_records_projection(runtime_profiles: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """DEFECT SC-2 fix: report-safe identity records for state/reporting.

    The scenario contract requires every observation to be attributable to
    a principal and the final report to declare WHICH principals were
    exercised. ``identity_profiles`` carries runtime session material for
    the differential tester and must never surface in a report; this
    projection derives ``identity_records`` — identity id, role,
    validation status, auth source, and owned object ids ONLY — so the
    reporter and access-control owner gate can attribute work per
    principal without any cookie or credential material.
    """
    records: dict[str, dict[str, Any]] = {}
    for name, profile in dict(runtime_profiles or {}).items():
        if not isinstance(profile, dict):
            continue
        metadata = profile.get("metadata") if isinstance(profile.get("metadata"), dict) else {}
        record: dict[str, Any] = {
            "identity_id": str(profile.get("name") or name)[:80],
            "role": str(profile.get("role") or "secondary"),
            "validated": bool(profile.get("validated")),
            "auth_source": str(metadata.get("auth_source") or "")[:40],
        }
        for key in ("owned_object_ids", "owned_ids", "owned_urls"):
            value = profile.get(key)
            if isinstance(value, (list, tuple, set, frozenset)):
                record[key] = [str(item) for item in value if str(item).strip()]
        records[str(name)] = record
    return records


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def auth_node(state: PentestState) -> dict:
    """LangGraph node implementing active authentication.

    V4.5 Integration Fix: Reads credentials directly from
    ``state["credentials"]`` instead of extracting via regex from
    ``target.description``.

    V8 Phase 4b: Reads operator-supplied session cookies from
    ``state["session_cookies"]``. If present, validates them via a
    lightweight HTTP request and, if valid, skips Playwright login.
    Session cookies take precedence over credentials. If session
    cookies are invalid, falls back to credentials (if provided).

    Args:
        state: Current graph state. Must contain ``target`` and
            optionally ``credentials`` and ``session_cookies``.

    Returns:
        A partial state update with ``session_cookies`` and ``auth_state``.
    """
    target = state["target"]
    m4_failure = legacy_auth_m4_failure(state)
    if m4_failure is not None:
        return m4_failure
    thread_id = str(state.get("thread_id") or "")
    credentials: dict[str, str] = dict(state.get("credentials") or {})
    if not credentials.get("password") and thread_id:
        vaulted_password = unseal_reauth_secret(thread_id)
        if vaulted_password:
            credentials["password"] = vaulted_password
    # V8 Phase 4b: read operator-supplied session cookies from their
    # own state key (NOT merged into credentials). A redacted checkpoint
    # is restored from the worker-only vault at runtime.
    operator_cookies: dict[str, str] = dict(state.get("session_cookies") or {})
    if not operator_cookies and thread_id:
        operator_cookies = unseal_session_cookies(thread_id)
    request_headers: dict[str, str] = dict(state.get("session_headers") or {})
    _auth_header_names = {"authorization", "x-auth-token", "x-api-key"}
    operator_headers: dict[str, str] = {
        str(name): str(value)
        for name, value in request_headers.items()
        if str(name).lower() in _auth_header_names and str(value).strip()
    }
    request_non_auth_headers: dict[str, str] = {
        str(name): str(value)
        for name, value in request_headers.items()
        if str(name).lower() not in _auth_header_names and str(value).strip()
    }
    raw_identity_profiles: dict[str, Any] = dict(state.get("identity_profiles") or {})
    record_profiles = _profiles_from_identity_records(state)
    for identity_id, profile in record_profiles.items():
        raw_identity_profiles.setdefault(identity_id, profile)
    if not raw_identity_profiles:
        scoped_identity_key = identity_vault_key(
            str(state.get("client_id") or ""),
            str(state.get("engagement_id") or ""),
        )
        if scoped_identity_key:
            raw_identity_profiles = unseal_identity_profiles(scoped_identity_key)
    if not raw_identity_profiles and thread_id:
        raw_identity_profiles = unseal_identity_profiles(thread_id)
    if not operator_headers and raw_identity_profiles:
        for raw_profile in raw_identity_profiles.values():
            if not isinstance(raw_profile, dict) or not raw_profile.get("validated"):
                continue
            candidate_headers = raw_profile.get("headers")
            if isinstance(candidate_headers, dict):
                operator_headers = {
                    str(name): str(value)
                    for name, value in candidate_headers.items()
                    if str(name).lower() in _auth_header_names
                    and str(value).strip()
                }
                if operator_headers:
                    break
    additional_target_origins = [
        str(value).strip()
        for value in list(state.get("additional_target_origins") or [])
        if str(value).strip()
    ]
    secondary_profiles = _bootstrap_secondary_profiles(
        target.url,
        raw_identity_profiles,
        additional_target_origins=additional_target_origins,
    )
    primary_provenance: dict[str, Any] = {}
    for raw_name, raw_profile in raw_identity_profiles.items():
        if not isinstance(raw_profile, dict):
            continue
        profile_role = str(raw_profile.get("role") or "").strip().lower()
        profile_name = str(raw_profile.get("name") or raw_name).strip().lower()
        if profile_role in {"owner", "primary"} or profile_name in {
            str(credentials.get("username") or "").strip().lower(),
            "owner",
            "primary-owner",
        }:
            primary_provenance = {
                key: raw_profile[key]
                for key in (
                    "owned_object_ids",
                    "owned_ids",
                    "owned_urls",
                    "metadata",
                )
                if key in raw_profile
            }
            break

    def _primary_identity_profile(
        cookies: dict[str, str],
        *,
        headers: dict[str, str] | None = None,
        validated: bool,
        label: str,
        source: str,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return report-safe runtime metadata for the authenticated operator.

        The marker is intentionally explicit and is consumed only by the
        access-control owner-selection gate. It never grants confirmation;
        owner/foreign differential probing plus a denied negative control are
        still required downstream.
        """
        profile = {
            "name": label[:80] or "primary-owner",
            "role": "owner",
            "cookies": dict(cookies) if validated else {},
            "headers": dict(headers or {}) if validated else {},
            "validated": bool(validated),
            "metadata": {
                "authenticated_primary": bool(validated),
                "auth_source": source[:40],
            },
        }
        for key in ("owned_object_ids", "owned_ids", "owned_urls"):
            value = (provenance or {}).get(key)
            if isinstance(value, (list, tuple, set, frozenset)):
                profile[key] = [str(item) for item in value if str(item).strip()]
        if isinstance((provenance or {}).get("metadata"), dict):
            profile["metadata"].update(
                {str(key): value for key, value in provenance["metadata"].items()}
            )
        return profile

    # V9 P0 Fix 1-B: fail-closed cookie clearing.
    #
    # ``state["session_cookies"]`` is declared with the ``merge_dicts``
    # reducer (state/state.py), which merges key-by-key — returning
    # ``{}`` from this node is a NO-OP against whatever
    # ``operator_cookies`` already sits in state, because merge_dicts
    # only touches keys that are actually present in the new dict. If
    # operator-supplied cookies fail validation below and we then
    # return ``session_cookies: {}`` intending to clear them, the
    # (already known-invalid) cookies would silently survive into
    # ``state["session_cookies"]`` and flow into crawler_node /
    # validator_node as if they were still legitimate — a fail-OPEN
    # bug, not fail-closed.
    #
    # Fix: explicitly neutralise every operator-supplied key (value ->
    # "") so the merge actually overwrites them instead of leaving
    # them untouched. Every fallback return below is built on top of
    # this base. A fresh cookie obtained via Playwright login is
    # merged in afterwards and correctly wins over the neutralised
    # placeholder for the same key.
    _invalidated_operator_cookies: dict[str, str] = dict.fromkeys(operator_cookies, "")
    _invalidated_operator_headers: dict[str, str] = dict.fromkeys(operator_headers, "")

    logger.info("Authentication phase entered for target=%s", target.url)

    # SCENARIO CONTRACT (step 5: pre-auth snapshot): one bounded anonymous
    # request BEFORE any identity material is used. This is the baseline the
    # authenticated surface is diffed against (crawler -> auth_surface_diff)
    # and the honest "what an anonymous visitor sees" record for the report.
    # Best-effort: a failure becomes a DECLARED limitation, never a crash and
    # never a silent gap.
    from webpent.shared.auth_surface import capture_anonymous_snapshot

    pre_auth_snapshot = capture_anonymous_snapshot(target.url)
    snapshot_limitations: list[dict[str, str]] = []
    if pre_auth_snapshot.get("status") != "ok":
        snapshot_limitations.append(
            {
                "code": "pre_auth_snapshot_unavailable",
                "detail": (
                    "the anonymous pre-login baseline request failed; "
                    "auth-only/both surface classification will be absent "
                    "from the report"
                ),
                "source": "auth_node",
            }
        )
    else:
        logger.info(
            "Pre-auth anonymous snapshot captured: status=%s links=%d forms=%d",
            pre_auth_snapshot.get("status_code"),
            pre_auth_snapshot.get("link_count", 0),
            pre_auth_snapshot.get("form_count", 0),
        )

    # --- V8 Phase 4b: Operator-supplied session cookies (highest priority) ---
    if operator_cookies:
        cookie_names = list(operator_cookies.keys())
        logger.info(
            "Operator-supplied session cookies found (%d: %s) — "
            "validating before use.",
            len(operator_cookies), cookie_names,
        )
        is_valid, reason = _validate_session_cookies(target.url, operator_cookies)
        if is_valid:
            logger.info(
                "Session cookies VALID — skipping Playwright login. "
                "Reason: %s", reason,
            )
            auth_state: dict[str, Any] = {
                "cookies": [
                    {"name": k, "value": v, "domain": target.domain or ""}
                    for k, v in operator_cookies.items()
                ],
                "source": "operator_supplied",
                "validated": True,
            }
            runtime_profiles = {
                "primary-owner": _primary_identity_profile(
                    operator_cookies,
                    validated=True,
                    label="primary-owner",
                    source="operator_supplied",
                    provenance=primary_provenance,
                ),
                **secondary_profiles,
            }
            if thread_id:
                seal_identity_profiles(
                    identity_vault_key(
                        str(state.get("client_id") or ""),
                        str(state.get("engagement_id") or ""),
                    ) or thread_id,
                    runtime_profiles,
                )
            return {
                "session_cookies": operator_cookies,
                "auth_state": auth_state,
                "identity_profiles": runtime_profiles,
                "identity_records": _identity_records_projection(runtime_profiles),
                "session_headers": {**request_non_auth_headers, **_invalidated_operator_headers},
                "pre_auth_snapshot": pre_auth_snapshot,
                "authentication_status": "authenticated",
                "engagement_limitations": snapshot_limitations,
                "messages": [AIMessage(
                    content=f"Authentication: operator-supplied session "
                    f"cookies validated ({len(operator_cookies)} cookie(s)). "
                    f"Playwright login skipped."
                )],
                "current_phase": "authentication",
            }
        else:
            logger.warning(
                "Operator-supplied session cookies INVALID — %s. "
                "Falling back to credentials (if provided) or "
                "unauthenticated.", reason,
            )
            # Fall through to credentials or unauthenticated below.

    # --- Runtime/vault-issued auth headers (for SPA bearer sessions) ---
    if operator_headers and not operator_cookies:
        is_valid, reason = _validate_session_cookies(
            target.url,
            {},
            extra_headers=operator_headers,
        )
        if is_valid:
            runtime_profiles = {
                "primary-owner": _primary_identity_profile(
                    {},
                    headers=operator_headers,
                    validated=True,
                    label="primary-owner",
                    source="runtime_header_session",
                    provenance=primary_provenance,
                ),
                **secondary_profiles,
            }
            if thread_id:
                seal_identity_profiles(
                    identity_vault_key(
                        str(state.get("client_id") or ""),
                        str(state.get("engagement_id") or ""),
                    ) or thread_id,
                    runtime_profiles,
                )
            return {
                "session_cookies": _invalidated_operator_cookies,
                "session_headers": {**request_non_auth_headers, **operator_headers},
                "auth_state": {
                    "cookies": [],
                    "source": "runtime_header_session",
                    "validated": True,
                    "auth_material": "bearer",
                    "header_names": sorted(operator_headers),
                },
                "identity_profiles": runtime_profiles,
                "identity_records": _identity_records_projection(runtime_profiles),
                "pre_auth_snapshot": pre_auth_snapshot,
                "authentication_status": "authenticated",
                "engagement_limitations": snapshot_limitations,
                "messages": [AIMessage(
                    content=(
                        "Authentication: runtime auth headers validated "
                        f"({reason}); Playwright login skipped."
                    )
                )],
                "current_phase": "authentication",
            }
        logger.warning(
            "Runtime auth headers INVALID — %s. Falling back to credentials "
            "or unauthenticated mode.",
            reason,
        )

    # --- Credentials (Playwright login) ---
    if not credentials:
        logger.info("No credentials provided — proceeding unauthenticated")
        return {
            # V9 P0 Fix 1-B: neutralise any invalidated operator
            # cookies instead of returning {} (see comment above —
            # {} is a no-op under the merge_dicts reducer).
            "session_cookies": _invalidated_operator_cookies,
            "session_headers": {**request_non_auth_headers, **_invalidated_operator_headers},
            "auth_state": {},
            "identity_profiles": secondary_profiles,
            "identity_records": _identity_records_projection(secondary_profiles),
            "pre_auth_snapshot": pre_auth_snapshot,
            "authentication_status": "unauthenticated",
            "engagement_limitations": [
                {
                    "code": "no_credentials_supplied",
                    "detail": (
                        "no credentials or session material were supplied; the "
                        "engagement runs anonymous-only — authenticated-surface "
                        "and cross-principal coverage is absent"
                    ),
                    "source": "auth_node",
                },
                *snapshot_limitations,
            ],
            "messages": [AIMessage(content="Authentication: no credentials found.")],
            "current_phase": "authentication",
        }

    username = credentials.get("username", "")
    password = credentials.get("password", "")
    logger.info("Credentials found (user=%s) — attempting active login", username)

    if additional_target_origins:
        login_material = _perform_login(
            target.url,
            username,
            password,
            additional_target_origins=additional_target_origins,
        )
    else:
        login_material = _perform_login(target.url, username, password)
    cookies = dict(login_material or {})
    auth_headers = dict(getattr(login_material, "auth_headers", {}) or {})

    if cookies or auth_headers:
        auth_state = {
            "cookies": [
                {"name": k, "value": v, "domain": target.domain or ""}
                for k, v in cookies.items()
            ],
            "source": "playwright_login",
            "validated": True,
            "auth_material": "cookie_and_header" if cookies and auth_headers else (
                "bearer" if auth_headers else "cookie"
            ),
            "header_names": sorted(auth_headers),
        }
        message = (
            "Authentication: login successful, "
            f"{len(cookies)} cookie(s) and {len(auth_headers)} auth header(s) validated."
        )
    else:
        auth_state = {
            # SCENARIO CONTRACT (step 7): a failed login is a FIRST-CLASS
            # outcome, not an empty dict. The run continues unauthenticated
            # but the status + declared limitation make the constraint
            # impossible to miss downstream (validator honesty gates and the
            # report limitations block both read this).
            "login_attempted": True,
            "validated": False,
            "username": username,
        }
        message = "Authentication: login attempted but no validated session material obtained."
        logger.error(
            "Login FAILED for user=%s — engagement continues UNAUTHENTICATED "
            "with a declared limitation (no silent as-if-inside behaviour).",
            username,
        )
        login_failure_limitations = [
            {
                "code": "authentication_failed",
                "detail": (
                    "login was attempted with the supplied credentials but no "
                    "validated session could be obtained; the engagement "
                    "continued unauthenticated — all authenticated-surface "
                    "findings are absent and unauthenticated results must be "
                    "read with that constraint in mind"
                ),
                "source": "auth_node",
            }
        ]

    # V9 FIX-10 + V10 P0-2 Option A: After successful Playwright login,
    # scrub the password from credentials in state so it is NOT
    # persisted in the LangGraph checkpoint (SqliteSaver) at rest. The
    # username is kept for re-auth identity.
    #
    # The validator's mid-scan re-auth path (CS-4) re-reads
    # credentials["password"] from state and finds it empty here.
    # V10 P0-2 Option A resolves the resulting silent-fail by sealing
    # the password into a worker-only reauth vault
    # (src/webpent/auth/reauth_vault.py) BEFORE the graph is invoked
    # (see pentest_worker.run_pentest_task). The validator looks up
    # the vault via unseal_reauth_secret(thread_id) when state's
    # password is empty. If the vault is also empty (worker restart,
    # or operator never supplied credentials), the validator falls
    # through to the explicit fail-loud path: ERROR log +
    # evidence["reauth_unavailable"]=True + Needs Human Review.
    # The vault is cleared in the worker's ``finally`` block so the
    # plaintext password does not outlive the engagement.
    if cookies or auth_headers:
        scrubbed_credentials = {
            "username": credentials.get("username", ""),
            "password": "",  # scrubbed — V10 P0-2 Option A vault is source of truth
        }
        logger.info(
            "V9 FIX-10 + V10 P0-2: password scrubbed from credentials "
            "after successful login — reauth vault is the source of "
            "truth for mid-scan re-auth (cleared on engagement exit)."
        )
    else:
        scrubbed_credentials = credentials  # keep original if login failed

    runtime_profiles = (
        {
            username or "primary-owner": _primary_identity_profile(
                cookies,
                headers=auth_headers,
                validated=True,
                label=username or "primary-owner",
                source="playwright_login",
                provenance=primary_provenance,
                ),
            **secondary_profiles,
        }
        if cookies or auth_headers
        else secondary_profiles
    )
    if thread_id and runtime_profiles:
        # Keep secondary credentials only in the encrypted worker vault so a
        # later bounded BAC refresh can re-authenticate after a throttle. The
        # LangGraph state remains report-safe and never receives credentials.
        vault_profiles = {
            name: dict(profile) for name, profile in runtime_profiles.items()
        }
        for profile_key, raw_profile in raw_identity_profiles.items():
            if not isinstance(raw_profile, dict):
                continue
            profile_name = str(raw_profile.get("name") or profile_key)
            runtime_name = next(
                (
                    name
                    for name, profile in runtime_profiles.items()
                    if name == profile_name or name == str(profile_key)
                ),
                None,
            )
            raw_credentials = raw_profile.get("credentials")
            if (
                runtime_name is not None
                and isinstance(raw_credentials, dict)
                and raw_credentials.get("username")
                and raw_credentials.get("password")
            ):
                vault_profiles[runtime_name]["credentials"] = {
                    "username": str(raw_credentials["username"]),
                    "password": str(raw_credentials["password"]),
                }
        seal_identity_profiles(
            identity_vault_key(
                str(state.get("client_id") or ""),
                str(state.get("engagement_id") or ""),
            ) or thread_id,
            vault_profiles,
        )

    return {
        # V9 P0 Fix 1-B: neutralised operator cookies as the base,
        # with any freshly-extracted Playwright cookies layered on
        # top (and correctly winning on key collision). If
        # operator_cookies was empty to begin with, this base is {}
        # and behaviour is unchanged from before.
        "session_cookies": {**_invalidated_operator_cookies, **cookies},
        "session_headers": {
            **request_non_auth_headers,
            **_invalidated_operator_headers,
            **auth_headers,
        },
        "auth_state": auth_state,
        "identity_profiles": runtime_profiles,
        "identity_records": _identity_records_projection(runtime_profiles),
        "credentials": scrubbed_credentials,
        "pre_auth_snapshot": pre_auth_snapshot,
        "authentication_status": (
            "authenticated" if (cookies or auth_headers) else "credentials_rejected"
        ),
        "engagement_limitations": (
            snapshot_limitations
            if (cookies or auth_headers)
            else [
                *login_failure_limitations,
                *snapshot_limitations,
            ]
        ),
        "messages": [AIMessage(content=message)],
        "current_phase": "authentication",
    }
