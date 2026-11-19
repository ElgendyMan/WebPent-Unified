"""Bounded adapter-free web reconnaissance.

This module is a knowledge producer only. It discovers structural attack-surface
facts and never validates, promotes, or authorizes a vulnerability. Every target
response is wrapped as untrusted content before deterministic parsing; raw bytes
are not present in the returned surface map.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client
from webpent.shared.scope_file import ScopeFileSpec, evaluate_path_rules
from webpent.shared.untrusted_content import UntrustedContent

_CRAWL_TOOL = "httpx_bounded"
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_SECRET_NAME = re.compile(
    r"(?:pass|secret|token|key|auth|cookie|session|csrf|xsrf)", re.IGNORECASE
)
_ID_NAME = re.compile(r"(?:^|[_-])(?:id|uuid|uid|user|account|order|document|resource)(?:$|[_-])", re.I)
_URL_NAME = re.compile(r"(?:url|uri|redirect|return|next|dest|destination|callback|continue)", re.I)
_SEARCH_NAME = re.compile(r"(?:q|query|search|filter|term|keyword)", re.I)
_SCRIPT_ROUTE_MARKERS = (
    "/api", "/rest", "/graphql", "/login", "/search", "/basket", "/products",
    "/orders", "/ftp", "/redirect", "/score-board", "/security", "/admin",
    "/application-version", "/track-order",
)
_HEURISTIC_ROUTE_PATHS = (
    "/administration", "/admin", "/rest/admin", "/rest/admin/application-version",
    "/rest/basket/1", "/rest/user/login", "/login", "/signin", "/auth/login",
    "/api/auth/login", "/identity/api/auth/login", "/rest/products/search?q=webpent_route_probe",
    "/search?q=webpent_route_probe",
    "/redirect?to=https://external.example.invalid/landing", "/rest/track-order",
    "/openapi.json", "/swagger.json", "/api/docs", "/sitemap.xml",
)


@dataclass(frozen=True)
class CrawlConfig:
    """Strict crawl limits; zero/negative values are rejected."""

    max_pages: int = 50
    max_depth: int = 2
    max_response_bytes: int = 512_000
    per_host_min_interval_seconds: float = 0.15
    request_timeout_seconds: float = 10.0
    robots_timeout_seconds: float = 5.0
    respect_robots: bool = True
    max_links_per_page: int = 100
    max_parameters_per_route: int = 32
    user_agent: str = "WebPent-AutonomousRecon/1.0"
    route_seeds: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for name in ("max_pages", "max_response_bytes", "max_links_per_page", "max_parameters_per_route"):
            if int(getattr(self, name)) < 1:
                raise ValueError(f"{name} must be positive")
        if int(self.max_depth) < 0:
            raise ValueError("max_depth must be non-negative")
        for name in ("per_host_min_interval_seconds", "request_timeout_seconds", "robots_timeout_seconds"):
            if float(getattr(self, name)) < 0:
                raise ValueError(f"{name} must be non-negative")
        if not str(self.user_agent).strip():
            raise ValueError("user_agent must be non-empty")
        seeds = tuple(str(item).strip() for item in self.route_seeds if str(item).strip())
        if len(seeds) > 128:
            raise ValueError("route_seeds exceeds 128 items")
        if any(len(item) > 2048 for item in seeds):
            raise ValueError("route_seed exceeds 2048 characters")


@dataclass(frozen=True)
class SurfaceParameter:
    name: str
    location: str
    value_shape: str
    observed_length: int
    source_route: str
    candidate_hint: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SurfaceForm:
    action: str
    method: str
    fields: tuple[SurfaceParameter, ...]
    login_signal: bool
    source_route: str

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["fields"] = [item.as_dict() for item in self.fields]
        return value


@dataclass(frozen=True)
class RouteSurface:
    route: str
    method: str
    status_code: int
    content_type: str
    response_digest: str
    response_length: int
    depth: int
    auth_required: bool
    login_signal: bool
    api_signal: bool
    parameters: tuple[SurfaceParameter, ...] = ()
    forms: tuple[SurfaceForm, ...] = ()
    external_resource_count: int = 0
    execution_url: str = ""
    response_time_ms: float | None = None
    redirect_target: str = ""
    auth_mechanisms: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value.pop("execution_url", None)
        value["parameters"] = [item.as_dict() for item in self.parameters]
        value["forms"] = [item.as_dict() for item in self.forms]
        value["auth_mechanisms"] = list(self.auth_mechanisms)
        return value


@dataclass(frozen=True)
class CrawlEvent:
    event: str
    route: str
    depth: int
    status_code: int | None
    response_digest: str | None
    reason: str = ""
    recorded_at: float = field(default_factory=time.time)
    response_time_ms: float | None = None
    response_bytes: int | None = None
    redirect_target: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SurfaceMap:
    target_url: str
    target_fingerprint: str
    scope_fingerprint: str
    robots_checked: bool = False
    robots_digest: str = ""
    routes: dict[str, RouteSurface] = field(default_factory=dict)
    events: list[CrawlEvent] = field(default_factory=list)
    halted: bool = False
    budget_exhausted: bool = False
    started_at: float = field(default_factory=time.time)
    completed_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        completed = self.completed_at or time.time()
        return {
            "target_url": self.target_url,
            "target_fingerprint": self.target_fingerprint,
            "scope_fingerprint": self.scope_fingerprint,
            "robots_checked": self.robots_checked,
            "robots_digest": self.robots_digest,
            "routes": [self.routes[key].as_dict() for key in sorted(self.routes)],
            "events": [event.as_dict() for event in self.events[-500:]],
            "stats": {
                "pages": len(self.routes),
                "endpoints": len(self.routes),
                "forms": sum(len(route.forms) for route in self.routes.values()),
                "parameters": sum(len(route.parameters) for route in self.routes.values()),
                "halted": self.halted,
                "budget_exhausted": self.budget_exhausted,
                "duration_seconds": round(max(0.0, completed - self.started_at), 3),
            },
        }


@dataclass(frozen=True)
class CrawlResult:
    surface_map: SurfaceMap
    stop_reason: str

    def as_dict(self) -> dict[str, Any]:
        value = self.surface_map.as_dict()
        value["stop_reason"] = self.stop_reason
        return value


class _PageParser(HTMLParser):
    """Extract structural HTML facts; it never interprets target text as instructions."""

    def __init__(self, *, route: str, max_items: int) -> None:
        super().__init__(convert_charrefs=True)
        self.route = route
        self.max_items = max_items
        self.links: list[str] = []
        self.resources: list[str] = []
        self.forms: list[SurfaceForm] = []
        self._form_action = ""
        self._form_method = "GET"
        self._form_fields: list[SurfaceParameter] = []
        self._form_login = False
        self._text_parts: list[str] = []

    def _add_bounded(self, target: list[str], value: str) -> None:
        if value and len(target) < self.max_items:
            target.append(value[:2048])

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {str(key).lower(): str(value or "") for key, value in attrs}
        tag_name = tag.lower()
        if tag_name == "a":
            self._add_bounded(self.links, values.get("href", ""))
        elif tag_name in {"script", "img", "iframe", "link", "source"}:
            self._add_bounded(self.resources, values.get("src", "") or values.get("href", ""))
        elif tag_name == "form":
            self._finish_form()
            self._form_action = values.get("action", "") or self.route
            self._form_method = values.get("method", "GET").upper()
            self._form_fields = []
            self._form_login = False
        elif tag_name in {"input", "textarea", "select"} and self._form_action:
            name = values.get("name", "") or values.get("id", "")
            if not name or len(self._form_fields) >= self.max_items:
                return
            input_type = values.get("type", "text").lower()
            raw_value = values.get("value", "")
            field_name = f"{name} {values.get('id', '')}"
            if input_type == "password" or "password" in field_name.lower():
                self._form_login = True
            self._form_fields.append(
                SurfaceParameter(
                    name=name[:128],
                    location="body",
                    value_shape=_value_shape(name, raw_value, input_type),
                    observed_length=min(len(raw_value), 4096),
                    source_route=self.route,
                    candidate_hint=input_type[:32],
                )
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._finish_form()

    def handle_data(self, data: str) -> None:
        if len(self._text_parts) < self.max_items:
            self._text_parts.append(data[:512])

    def _finish_form(self) -> None:
        if self._form_action and self._form_fields:
            self.forms.append(
                SurfaceForm(
                    action=self._form_action[:2048],
                    method=self._form_method if self._form_method in _METHODS else "GET",
                    fields=tuple(self._form_fields[: self.max_items]),
                    login_signal=self._form_login,
                    source_route=self.route,
                )
            )
        self._form_action = ""
        self._form_fields = []
        self._form_login = False

    @property
    def text(self) -> str:
        return " ".join(self._text_parts)[:8192]


def _shape(name: str, value: str, input_type: str = "") -> str:
    value = str(value or "")
    lowered = str(name or "").lower()
    if input_type.lower() == "password" or _SECRET_NAME.search(lowered):
        return "secret-shaped"
    if _URL_NAME.search(lowered) or value.startswith(("http://", "https://")):
        return "url-shaped"
    if _ID_NAME.search(lowered) or value.isdigit() or re.fullmatch(r"[0-9a-f]{8,}-[0-9a-f-]+", value, re.I):
        return "id-shaped"
    if _SEARCH_NAME.search(lowered):
        return "query-shaped"
    return "text-shaped"


def _value_shape(name: str, value: str, input_type: str = "") -> str:
    return _shape(name, value, input_type)


def _route_key(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    query_names = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    return path + ("?" + urlencode([(name, "") for name in query_names]) if query_names else "")


def _canonical_url(url: str, base: str) -> str | None:
    try:
        joined = urljoin(base, url)
        parsed = urlsplit(joined)
        # Credentials in discovered links are never a valid recon target and
        # must not be handed to the HTTP client, even when the hostname looks
        # same-origin. Accessing ``parsed.port`` also rejects malformed ports.
        _ = parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username is not None or parsed.password is not None:
        return None
    clean_path = parsed.path or "/"
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, clean_path, parsed.query, ""))


def _fingerprint(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _extract_script_routes(text: str) -> list[str]:
    """Extract bounded route literals from JS as structural facts.

    Angular bundles commonly build paths as ``${host}/rest/...`` template
    strings. The previous parser only accepted literals beginning immediately
    after a quote, so it missed those routes. Parse each quote type separately,
    normalize interpolation to safe probe values, and retain only same-origin
    route-shaped strings. This function never executes JavaScript.
    """
    result: list[str] = []
    source = text[:2_000_000]
    for quote in ('"', "'", "`"):
        pattern = re.compile(re.escape(quote) + r"([^" + re.escape(quote) + r"\\]{1,500})" + re.escape(quote))
        for match in pattern.finditer(source):
            value = match.group(1).replace("\\/", "/")
            lowered = value.lower()
            marker_positions = [lowered.find(marker) for marker in _SCRIPT_ROUTE_MARKERS if lowered.find(marker) >= 0]
            if not marker_positions:
                continue
            candidate = value[min(marker_positions):]
            candidate = re.sub(r"\$\{[^}]{0,100}\}", "{param}", candidate)
            candidate = re.split(r"\s|[;,)]", candidate, maxsplit=1)[0].strip("\\")
            if not candidate.startswith("/") or len(candidate) > 240:
                continue
            parsed = urlsplit(candidate)
            path = re.sub(r"/\{param\}(?=/|$)", "/1", parsed.path)
            query = re.sub(r"=\{param\}", "=webpent_route_probe", parsed.query)
            normalized = urlunsplit(("", "", path or "/", query, ""))
            if normalized not in result:
                result.append(normalized)
            if len(result) >= 150:
                return result
    return result


class AutonomousCrawler:
    """Bounded crawler using the existing ScopeLaw and hardened HTTP client."""

    def __init__(
        self,
        *,
        target_url: str,
        scope_law: Any,
        engagement_id: str,
        config: CrawlConfig | None = None,
        scope_spec: ScopeFileSpec | None = None,
        program_scope: Any = None,
        should_halt: Callable[[], bool] | None = None,
        budget_check: Callable[[], bool] | None = None,
    ) -> None:
        target = _canonical_url(target_url, target_url)
        if not target:
            raise ValueError("target_url must be an absolute HTTP(S) URL")
        self.target_url = target
        self.scope_law = scope_law
        self.engagement_id = str(engagement_id).strip()
        if not self.engagement_id:
            raise ValueError("engagement_id required")
        self.config = config or CrawlConfig()
        self.scope_spec = scope_spec
        self.program_scope = program_scope
        self.should_halt = should_halt or (lambda: False)
        self.budget_check = budget_check or (lambda: True)
        self._last_request_by_host: dict[str, float] = {}
        self._robots: RobotFileParser | None = None
        self._robots_checked = False
        self._robots_digest = ""

    def _scope_allows(self, url: str) -> tuple[bool, str]:
        try:
            parsed = urlsplit(url)
            target_host = _host(self.target_url)
            if parsed.scheme not in {"http", "https"} or _host(url) != target_host:
                return False, "same_target_host_required"
            if self.program_scope is not None:
                decision = self.program_scope.check_url(url, method="GET")
                if not decision.allowed:
                    return False, f"program_scope_denied:{decision.violation_code or 'unknown_scope'}"
            if self.scope_spec is not None:
                path_rule = evaluate_path_rules(self.scope_spec, url)
                if path_rule == "denied":
                    return False, "scope_path_rule_denied"
            decision = self.scope_law.authorize_invocation(
                tool_name=_CRAWL_TOOL, target_url=url, arguments=()
            )
            if not decision.in_scope:
                return False, f"scope_law_denied:{decision.reason}"
            return True, "scope_allowed"
        except Exception as exc:
            return False, f"scope_error:{type(exc).__name__}"

    def _robots_allows(self, url: str, *, is_root: bool = False) -> tuple[bool, str]:
        if not self.config.respect_robots:
            # r6c double gate (safety/agency): the legacy lift fires only when
            # the settings flag is OFF (legacy posture) or when the flag is ON
            # and the active engagement is explicitly allowlisted.  Otherwise
            # the crawler stays robots-respecting despite its config.
            try:
                from webpent.safety.agency import robots_lift_authorized

                engagement = None
                try:
                    from webpent.shared.target_workspace_context import (
                        get_active_target_workspace,
                    )

                    workspace = get_active_target_workspace()
                    if workspace is not None:
                        engagement = str(getattr(workspace, "engagement_id", "") or "") or None
                except Exception:  # noqa: BLE001 — engagement is advisory here
                    engagement = None
                if robots_lift_authorized(engagement):
                    return True, "robots_override_authorized_assessment"
                return False, "robots_unavailable"
            except Exception:  # noqa: BLE001 — fail closed toward robots respect
                return False, "robots_unavailable"
        if is_root:
            return True, "root_allowed"
        if self._robots is None:
            return (False, "robots_unavailable") if self._robots_checked else (True, "robots_not_checked")
        try:
            return (self._robots.can_fetch(self.config.user_agent, url), "robots_allowed" if self._robots.can_fetch(self.config.user_agent, url) else "robots_denied")
        except Exception:
            return False, "robots_check_error"

    def _wait_for_rate_limit(self, url: str) -> None:
        host = _host(url)
        previous = self._last_request_by_host.get(host)
        if previous is not None:
            delay = self.config.per_host_min_interval_seconds - (time.monotonic() - previous)
            if delay > 0:
                time.sleep(delay)
        self._last_request_by_host[host] = time.monotonic()

    def _fetch_robots(self, client: Any, surface: SurfaceMap) -> None:
        robots_url = urljoin(self.target_url, "/robots.txt")
        allowed, reason = self._scope_allows(robots_url)
        if not allowed:
            surface.events.append(CrawlEvent("robots_skipped", "/robots.txt", 0, None, None, reason))
            self._robots_checked = True
            return
        try:
            self._wait_for_rate_limit(robots_url)
            request_started = time.perf_counter()
            response = client.get(robots_url, timeout=self.config.robots_timeout_seconds)
            response_time_ms = round((time.perf_counter() - request_started) * 1000.0, 3)
            body = response.text[: self.config.max_response_bytes]
            wrapped = UntrustedContent.from_text(
                body,
                source="robots",
                headers=response.headers,
                content_type=response.headers.get("content-type", ""),
                status_code=response.status_code,
            )
            self._robots_digest = _fingerprint(wrapped.raw_for_deterministic_validation())
            if 200 <= response.status_code < 300:
                parser = RobotFileParser()
                parser.set_url(robots_url)
                parser.parse(body.splitlines())
                self._robots = parser
            elif response.status_code in {404, 410}:
                # A missing robots file means no published crawl rules. Keep
                # the conservative parser object with an empty rule set so
                # authorized same-origin traversal is not silently blocked.
                parser = RobotFileParser()
                parser.set_url(robots_url)
                parser.parse([])
                self._robots = parser
            self._robots_checked = True
            surface.events.append(CrawlEvent(
                "robots_observed", "/robots.txt", 0, response.status_code,
                self._robots_digest, "", response_time_ms=response_time_ms,
                response_bytes=len(body.encode("utf-8", "replace")),
            ))
        except Exception as exc:
            self._robots_checked = True
            self._robots = None
            surface.events.append(CrawlEvent("robots_failed", "/robots.txt", 0, None, None, type(exc).__name__))

    def crawl(self) -> CrawlResult:
        target_token = set_engagement_target_hosts(self.target_url)
        surface = SurfaceMap(
            target_url=self.target_url,
            target_fingerprint=_fingerprint(self.target_url),
            scope_fingerprint=str(getattr(self.scope_spec, "fingerprint", "inferred_from_url")),
        )
        queue: list[tuple[str, int, bool]] = [(self.target_url, 0, True)]
        queued: set[str] = {self.target_url}
        stop_reason = "completed"
        try:
            with make_safe_httpx_client(
                timeout=self.config.request_timeout_seconds,
                follow_redirects=False,
                headers={"User-Agent": self.config.user_agent, "Accept": "text/html,application/json;q=0.9,*/*;q=0.1"},
            ) as client:
                self._fetch_robots(client, surface)
                heuristics_queued = False
                configured_seeds_queued = False
                while queue and len(surface.routes) < self.config.max_pages:
                    if self.should_halt():
                        surface.halted = True
                        stop_reason = "operator_halted"
                        break
                    if not self.budget_check():
                        surface.budget_exhausted = True
                        stop_reason = "budget_exhausted"
                        break
                    url, depth, is_root = queue.pop(0)
                    allowed, reason = self._scope_allows(url)
                    if not allowed:
                        surface.events.append(CrawlEvent("url_skipped", _route_key(url), depth, None, None, reason))
                        continue
                    robots_allowed, robots_reason = self._robots_allows(url, is_root=is_root)
                    if not robots_allowed:
                        surface.events.append(CrawlEvent("url_skipped", _route_key(url), depth, None, None, robots_reason))
                        continue
                    scope_acquired = False
                    try:
                        self._wait_for_rate_limit(url)
                        if self.program_scope is not None:
                            program_decision = self.program_scope.acquire(url, method="GET")
                            if not program_decision.allowed:
                                surface.events.append(CrawlEvent("scope_violation_blocked", _route_key(url), depth, None, None, program_decision.violation_code or "scope_denied"))
                                if self.program_scope.halted:
                                    surface.halted = True
                                    stop_reason = "scope_violation_threshold"
                                    break
                                continue
                            scope_acquired = True
                        request_started = time.perf_counter()
                        response = client.get(url, timeout=self.config.request_timeout_seconds)
                        response_time_ms = round((time.perf_counter() - request_started) * 1000.0, 3)
                        body_bytes = response.content[: self.config.max_response_bytes]
                        wrapped = UntrustedContent.from_text(
                            body_bytes,
                            source="page",
                            headers=response.headers,
                            content_type=response.headers.get("content-type", ""),
                            status_code=response.status_code,
                        )
                        raw_body = wrapped.raw_for_deterministic_validation()
                        digest = _fingerprint(raw_body)
                        parser = _PageParser(route=_route_key(url), max_items=self.config.max_links_per_page)
                        content_type = response.headers.get("content-type", "").lower()
                        if "html" in content_type or "text" in content_type or raw_body.lstrip().startswith("<"):
                            parser.feed(raw_body)
                        parsed_url = urlsplit(url)
                        redirect_target = ""
                        location = response.headers.get("location", "")
                        if location and response.status_code in {301, 302, 303, 307, 308}:
                            redirect_url = _canonical_url(location, url)
                            if redirect_url:
                                redirect_target = _route_key(redirect_url)
                        auth_mechanisms: list[str] = []
                        if response.headers.get("www-authenticate"):
                            auth_mechanisms.append("http-auth-challenge")
                        set_cookie = response.headers.get("set-cookie", "")
                        if set_cookie:
                            cookie_names = []
                            for cookie in set_cookie.split(",")[: self.config.max_parameters_per_route]:
                                name = cookie.split("=", 1)[0].strip().lower()
                                if name and _SECRET_NAME.search(name):
                                    cookie_names.append(name[:64])
                            if cookie_names:
                                auth_mechanisms.append("session-cookie:" + ",".join(sorted(set(cookie_names))))
                        if not any(item.startswith("session-cookie:") for item in auth_mechanisms):
                            try:
                                cookie_names = sorted({str(cookie.name).lower()[:64] for cookie in response.cookies.jar})
                            except (AttributeError, TypeError, ValueError):
                                cookie_names = []
                            if cookie_names:
                                auth_mechanisms.append("session-cookie:" + ",".join(cookie_names))
                        parameters: list[SurfaceParameter] = []
                        for name, value in parse_qsl(parsed_url.query, keep_blank_values=True)[: self.config.max_parameters_per_route]:
                            if _SECRET_NAME.search(name):
                                shape = "secret-shaped"
                            else:
                                shape = _shape(name, value)
                            parameters.append(SurfaceParameter(name[:128], "query", shape, min(len(value), 4096), _route_key(url), _candidate_hint(shape)))
                        for index, segment in enumerate(parsed_url.path.split("/")):
                            if not segment:
                                continue
                            if segment.isdigit() or re.fullmatch(r"[0-9a-f]{8,}-[0-9a-f-]+", segment, re.I):
                                parameters.append(
                                    SurfaceParameter(
                                        name=f"path_segment_{index}",
                                        location="path",
                                        value_shape="id-shaped",
                                        observed_length=min(len(segment), 128),
                                        source_route=_route_key(url),
                                        candidate_hint="alternate bounded identifier",
                                    )
                                )
                        forms = list(parser.forms[: self.config.max_links_per_page])
                        if re.search(r"/(?:login|sign[-_ ]?in)(?:/|$)", parsed_url.path, re.I) and not forms:
                            forms.append(SurfaceForm(
                                action=_route_key(url),
                                method="POST",
                                fields=(
                                    SurfaceParameter("email", "body", "text-shaped", 0, _route_key(url), "email"),
                                    SurfaceParameter("password", "body", "secret-shaped", 0, _route_key(url), "password"),
                                ),
                                login_signal=True,
                                source_route=_route_key(url),
                            ))
                        login_signal = bool(re.search(r"(?:login|sign[ -]?in|authenticate)", (url + " " + parser.text), re.I))
                        auth_required = response.status_code in {401, 403} or login_signal and any(
                            field.login_signal for field in parser.forms
                        )
                        route = RouteSurface(
                            route=_route_key(url),
                            method="GET",
                            status_code=int(response.status_code),
                            content_type=content_type[:120],
                            response_digest=digest,
                            response_length=len(raw_body),
                            depth=depth,
                            auth_required=auth_required,
                            login_signal=login_signal,
                            api_signal=("/api/" in parsed_url.path.lower() or "json" in content_type),
                            parameters=tuple(parameters),
                            forms=tuple(forms),
                            external_resource_count=len(parser.resources),
                            execution_url=url,
                            response_time_ms=response_time_ms,
                            redirect_target=redirect_target,
                            auth_mechanisms=tuple(sorted(set(auth_mechanisms))),
                        )
                        surface.routes[route.route] = route
                        surface.events.append(CrawlEvent(
                            "page_observed", route.route, depth, response.status_code,
                            digest, "", response_time_ms=response_time_ms,
                            response_bytes=len(raw_body.encode("utf-8", "replace")),
                            redirect_target=redirect_target or None,
                        ))
                        if redirect_target and depth < self.config.max_depth:
                            redirect_url = _canonical_url(location, url)
                            if redirect_url and redirect_url not in queued:
                                queued.add(redirect_url)
                                queue.append((redirect_url, depth + 1, False))
                                surface.events.append(CrawlEvent(
                                    "redirect_queued", redirect_target, depth + 1,
                                    None, None, "same_origin_redirect", redirect_target=redirect_target,
                                ))
                        if depth < self.config.max_depth and not self.should_halt() and self.budget_check():
                            structural_refs = list(parser.links) + list(parser.resources)
                            if "javascript" in content_type or url.lower().endswith((".js", ".mjs")):
                                structural_refs.extend(_extract_script_routes(raw_body))
                            elif "json" in content_type:
                                structural_refs.extend(_extract_script_routes(raw_body))
                            for href in structural_refs[: self.config.max_links_per_page]:
                                child = _canonical_url(href, url)
                                if child and child not in queued:
                                    queued.add(child)
                                    queue.append((child, depth + 1, False))
                            if is_root and not configured_seeds_queued:
                                for configured_path in self.config.route_seeds:
                                    seed_url = _canonical_url(urljoin(self.target_url, configured_path), self.target_url)
                                    if not seed_url or _host(seed_url) != _host(self.target_url) or seed_url in queued:
                                        continue
                                    queued.add(seed_url)
                                    queue.append((seed_url, 1, False))
                                    surface.events.append(CrawlEvent(
                                        "configured_route_seed_queued", _route_key(seed_url), 1, None, None,
                                        "operator_declared_same_origin_route_seed",
                                    ))
                                configured_seeds_queued = True
                            if is_root and not heuristics_queued:
                                for heuristic_path in _HEURISTIC_ROUTE_PATHS:
                                    heuristic_url = _canonical_url(urljoin(self.target_url, heuristic_path), self.target_url)
                                    if heuristic_url and heuristic_url not in queued:
                                        queued.add(heuristic_url)
                                        queue.append((heuristic_url, 1, False))
                                        surface.events.append(CrawlEvent(
                                            "heuristic_route_queued", _route_key(heuristic_url), 1, None, None,
                                            "bounded_common_route_heuristic",
                                        ))
                                heuristics_queued = True
                    except Exception as exc:
                        surface.events.append(CrawlEvent("page_failed", _route_key(url), depth, None, None, type(exc).__name__))
                    finally:
                        if scope_acquired and self.program_scope is not None:
                            self.program_scope.release()
                # A halt may arrive while the final in-flight request is
                # completing.  The post-request expansion guard above then
                # intentionally leaves the queue empty, so the loop exits
                # through the ordinary path without setting ``surface.halted``.
                # Preserve the operator's observed stop state explicitly.
                if self.should_halt() and not surface.halted:
                    surface.halted = True
                    stop_reason = "operator_halted"
                elif len(surface.routes) >= self.config.max_pages and queue:
                    surface.budget_exhausted = True
                    stop_reason = "max_pages_reached"
                elif not queue and stop_reason == "completed":
                    stop_reason = "queue_exhausted"
        finally:
            surface.completed_at = time.time()
            clear_engagement_target_hosts(target_token)
        surface.robots_checked = self._robots_checked
        surface.robots_digest = self._robots_digest
        return CrawlResult(surface, stop_reason)


def _candidate_hint(shape: str) -> str:
    return {
        "id-shaped": "alternate bounded identifier",
        "url-shaped": "external destination",
        "query-shaped": "benign differential query",
        "text-shaped": "unique benign reflection marker",
    }.get(shape, "")


__all__ = [
    "AutonomousCrawler", "CrawlConfig", "CrawlEvent", "CrawlResult", "RouteSurface",
    "SurfaceForm", "SurfaceMap", "SurfaceParameter",
]
