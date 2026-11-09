"""Bounded same-origin HTTP discovery used when optional crawler binaries are absent.

The discovery path is intentionally target-agnostic.  It starts from the
operator-declared URL, preserves the supplied session cookie jar, follows only
same-origin links and redirects, and returns structured observations rather
than treating a URL alone as a vulnerability.  It is a coverage fallback for
recon; validators still need independent, tool-backed evidence.
"""

from __future__ import annotations

import json
import re
from collections import deque
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from webpent.config.settings import get_settings

# Route seeds must be target-scoped. Operators can provide explicit seeds
# through discovery_route_seeds; the built-in discovery path never invents
# target-specific hypotheses.
_PRIORITY_ROUTE_SEEDS: tuple[str, ...] = ()

def _extract_openapi_payload(text: str) -> dict[str, Any] | None:
    """Parse a JSON OpenAPI document or an embedded Swagger UI JSON object.

    Swagger UI commonly serves ``swagger-ui-init.js`` with a JSON-compatible
    ``"swaggerDoc": { ... }`` object. We decode only that object; no JavaScript
    is evaluated and arbitrary script content is never treated as a route list.
    """
    bounded = text[:1_000_000]
    try:
        payload = json.loads(bounded)
        return payload if isinstance(payload, dict) else None
    except (TypeError, ValueError):
        marker = '"swaggerDoc"'
        marker_index = bounded.find(marker)
        if marker_index < 0:
            return None
        object_start = bounded.find("{", marker_index + len(marker))
        if object_start < 0:
            return None
        try:
            payload, _end = json.JSONDecoder().raw_decode(bounded, object_start)
        except (TypeError, ValueError):
            return None
        return payload if isinstance(payload, dict) else None


def _openapi_discovered_urls(payload: dict[str, Any], start: str) -> list[str]:
    """Return bounded same-origin URLs from an OpenAPI ``paths`` object.

    F-03 (RA-1): OpenAPI path templates carry ``{param}`` placeholders (e.g.
    ``/api/invoices/{id}``).  Used verbatim, the probe URL retains literal
    braces → the target has no such route → 404 → the probe is silently
    dropped.  We materialize each placeholder to ``1`` (the project convention
    established by ``_bounded_js_routes`` and ``_extract_script_routes``) so
    the probe hits a concrete same-origin URL that the response-aware
    discovery layer can classify.  This does NOT enumerate IDs — it produces
    exactly one read-only candidate per templated path, subject to the same
    same-origin / safe-GET guards as every other discovered URL.
    """
    paths = payload.get("paths", {})
    if not isinstance(paths, dict):
        return []
    server_bases: list[str] = [start]
    servers = payload.get("servers", [])
    if isinstance(servers, list):
        for server in servers[:5]:
            if not isinstance(server, dict):
                continue
            server_url = str(server.get("url", "")).strip()
            if server_url:
                resolved = _normalise_url(server_url, start)
                if resolved:
                    server_bases.append(resolved.rstrip("/"))
    discovered: list[str] = []
    for raw_path in list(paths)[:100]:
        path = str(raw_path).strip()
        if not path or not path.startswith("/"):
            continue
        # F-03: materialize OpenAPI path templating {param} → 1
        path = re.sub(r"\{[^{}]{1,80}\}", "1", path)
        for base in server_bases:
            candidate = _normalise_url(f"{base.rstrip('/')}{path}", start)
            if candidate and candidate not in discovered:
                discovered.append(candidate)
    return discovered


# No route is assumed to exist on an arbitrary target. Generic API/document
# probes are handled above through their own response-aware discovery paths;
# this seed list remains empty unless the operator configures explicit routes.
_DEFAULT_ROUTE_SEEDS: tuple[str, ...] = ()

# POST-P0 Phase 4: hard totals for structured schema records surfaced in
# the discovery result (bounded input for downstream hypothesis producers).
_MAX_SCHEMA_ROUTE_TOTAL = 100
_MAX_GRAPHQL_OPS_TOTAL = 50

# Common API-document locations are passive, bounded GET candidates. They are
# not target-specific attack paths: a route is queued only when the response is
# a valid document containing a bounded ``paths`` object, and every discovered
# path still goes through same-origin and safe-GET checks below.
_OPENAPI_DOCUMENT_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs/swagger.json",
    "/api-docs/openapi.json",
    "/api-docs/swagger-ui-init.js",
    "/swagger/v1/swagger.json",
)


class _SurfaceParser(HTMLParser):
    """Small HTML parser for links, scripts, and forms.

    HTMLParser is used instead of regular expressions so quoted attributes,
    casing, and nested form controls are handled without storing response
    bodies in scan state.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self._select_name: str | None = None
        self._select_value: str = ""
        self._textarea_name: str | None = None
        self._textarea_value: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "a" and attributes.get("href"):
            self.links.append(attributes["href"])
        elif tag == "link" and attributes.get("href"):
            # Stylesheets are not useful attack endpoints, but same-origin
            # preload/module links can reveal application assets.
            self.links.append(attributes["href"])
        elif tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif tag == "form":
            self._form = {
                "action": attributes.get("action", ""),
                "method": (attributes.get("method") or "GET").upper(),
                "data": {},
            }
        elif tag in {"input", "button"} and self._form is not None:
            name = attributes.get("name")
            if name:
                input_type = (attributes.get("type") or "text").lower()
                # Never copy a password value into recon state.  Empty
                # password fields remain useful as a parameter signal.
                value = "" if input_type == "password" else attributes.get("value", "")
                self._form["data"][name] = value
        elif tag == "textarea" and self._form is not None:
            name = attributes.get("name")
            if name:
                self._textarea_name = name
                self._textarea_value = []
        elif tag == "select" and self._form is not None:
            name = attributes.get("name")
            if name:
                self._select_name = name
                self._select_value = ""
        elif (
            tag == "option"
            and self._select_name is not None
            and (attributes.get("selected") is not None or not self._select_value)
        ):
            self._select_value = attributes.get("value", "")

    def handle_data(self, data: str) -> None:
        if self._textarea_name is not None:
            self._textarea_value.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "textarea" and self._form is not None and self._textarea_name:
            self._form["data"][self._textarea_name] = "".join(self._textarea_value).strip()
            self._textarea_name = None
            self._textarea_value = []
        elif tag == "select" and self._form is not None and self._select_name:
            self._form["data"][self._select_name] = self._select_value
            self._select_name = None
            self._select_value = ""
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return scheme, host, port


def _same_origin(url: str, base_url: str) -> bool:
    try:
        return _origin(url) == _origin(base_url)
    except ValueError:
        return False


def _normalise_url(url: str, base: str) -> str | None:
    if not url:
        return None
    lowered = url.strip().lower()
    if lowered.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base, url.strip())
    try:
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return None
        if not _same_origin(absolute, base):
            return None
        # Fragments are client-side state and do not identify a server route.
        return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    except ValueError:
        return None


# GET discovery must remain read-only.  Many applications expose logout,
# delete, reset, or unsubscribe actions as links, and visiting one of them can
# destroy the authenticated session or mutate target state.  This is a
# route-oriented guard, not a target-specific allowlist: it protects arbitrary
# applications while leaving normal pages and forms discoverable.
_STATE_CHANGING_ROUTE_RE = re.compile(
    r"(?:^|[\\/_.?=&-])(?:logout|log[-_]?out|sign[-_]?out|delete|destroy|remove|reset|purge|wipe|shutdown|"
    r"deactivate|unsubscribe|cancel|terminate|drop)(?:[\\/_.?=&-]|$)",
    re.IGNORECASE,
)


def _is_safe_discovery_get(url: str, *, start_url: str) -> bool:
    """Return whether a discovered GET URL is safe to fetch passively.

    The operator-supplied start URL is always allowed; the guard applies only
    to links/redirects discovered from the target.  Query values are included
    because routes such as ``account?action=delete`` can be destructive even
    when the path itself is generic.
    """
    if url == start_url:
        return True
    try:
        parts = urlsplit(url)
        route = f"{parts.path or '/'}?{parts.query}" if parts.query else (parts.path or "/")
        return _STATE_CHANGING_ROUTE_RE.search(route) is None
    except ValueError:
        return False


def _get_form_url(action: str, source_url: str, data: dict[str, str]) -> str:
    action_url = _normalise_url(action, source_url) or source_url
    parts = urlsplit(action_url)
    existing = parse_qsl(parts.query, keep_blank_values=True)
    merged = existing + [(str(k), str(v)) for k, v in data.items() if str(k)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(merged), ""))


def _redact_form_data(data: dict[str, str]) -> dict[str, str]:
    # Keep field names and values needed by read-only analysis.  Password
    # values were already removed by the parser; values are bounded to avoid
    # allowing a large hidden field to inflate the graph checkpoint.
    return {str(k)[:200]: str(v)[:500] for k, v in data.items()}


def _bounded_xml_locations(text: str, base_url: str, *, limit: int = 100) -> list[str]:
    """Extract same-origin sitemap locations without retaining XML content."""
    locations: list[str] = []
    pattern = r"<loc>\s*(.*?)\s*</loc>"
    for match in re.finditer(pattern, text[:1_000_000], re.IGNORECASE | re.DOTALL):
        candidate = _normalise_url(match.group(1), base_url)
        if candidate and candidate not in locations:
            locations.append(candidate)
        if len(locations) >= limit:
            break
    return locations


def _bounded_js_routes(text: str, base_url: str, *, limit: int = 100) -> list[str]:
    """Extract route-shaped JS literals as passive discovery hints.

    Template literals are common in SPA API clients, for example
    ``/rest/basket/${basketId}``. A bounded ``1`` materialization turns that
    observed route shape into one read-only surface candidate; it does not
    enumerate IDs and remains subject to same-origin/safe-GET guards.
    """
    routes: list[str] = []
    literal_pattern = r'''["'`]((?:/|https?://)[^"'`<>\s]{1,300})["'`]'''
    for match in re.finditer(literal_pattern, text[:1_000_000]):
        raw_route = match.group(1)
        materialized = re.sub(r"\$\{[^{}]{1,80}\}", "1", raw_route)
        candidate = _normalise_url(materialized, base_url)
        if candidate and candidate not in routes:
            routes.append(candidate)
        if len(routes) >= limit:
            break
    return routes


def discover_http_surface(
    base_url: str,
    *,
    session_cookies: dict[str, str] | None = None,
    extra_headers: dict[str, str] | None = None,
    max_pages: int = 50,
    max_depth: int = 3,
    max_links_per_page: int = 100,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Discover a bounded authenticated same-origin surface.

    The function performs GET requests only.  Forms are described but never
    submitted.  Returned ``forms`` are metadata for later, separately gated
    validators and are not Findings.
    """
    from webpent.shared.http import (
        build_cookie_header,
        make_safe_httpx_client,
        sanitize_request_headers,
    )

    start = _normalise_url(base_url, base_url)
    if not start:
        return {
            "endpoints": [],
            "forms": [],
            "pages_fetched": 0,
            "redirects_followed": 0,
            "errors": 1,
            "coverage_gaps": ["invalid_target_url"],
        }

    queue: deque[tuple[str, int]] = deque([(start, 0)])
    queued = {start}
    endpoints: list[str] = []
    seen: set[str] = set()
    forms: list[dict[str, Any]] = []
    surface_records: list[dict[str, Any]] = []
    redirects_followed = 0
    errors = 0
    skipped_off_origin = 0
    skipped_state_changing = 0
    settings = get_settings()
    configured_user_agent = str(getattr(settings, "http_user_agent", "") or "").strip()
    # Some application middleware rejects the project default UA as an
    # automated client. Keep explicit operator overrides intact, but use a
    # bounded ordinary browser profile for the built-in read-only discovery
    # path so it observes the same surface as the browser path.
    user_agent = configured_user_agent
    if not user_agent or user_agent.startswith("WebPent/0.2"):
        user_agent = (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
    headers: dict[str, str] = {
        "User-Agent": user_agent[:256],
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        # The bounded discovery parser needs decoded HTML.  The custom safe
        # transport may expose a compressed body unchanged when callers
        # explicitly advertise brotli/gzip, so request an identity response
        # instead of parsing binary content as HTML.
        "Accept-Encoding": "identity",
    }
    cookie_header = build_cookie_header(session_cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header
    headers.update(sanitize_request_headers(extra_headers))

    try:
        client_context = make_safe_httpx_client(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            headers=headers,
        )
    except Exception:
        return {
            "endpoints": [],
            "forms": [],
            "pages_fetched": 0,
            "redirects_followed": 0,
            "errors": 1,
            "coverage_gaps": ["http_client_unavailable"],
        }

    discovery_metadata: dict[str, Any] = {
        "robots_fetched": False,
        "robots_disallow_count": 0,
        "sitemap_urls": [],
        "openapi_urls": [],
        "graphql_urls": [],
        # POST-P0 Phase 4: structured schema records (bounded, deterministic
        # projection via shared/schema_ingestion.py).
        "openapi_routes": [],
        "graphql_operations": [],
        "javascript_urls": [],
        "js_route_candidates": [],
        "route_seed_candidates": [],
        "route_seed_queued": 0,
    }

    with client_context as client:
        # These are bounded read-only probes. They enrich the queue when the
        # application does not expose links in HTML, while remaining same-origin.
        origin = f"{urlsplit(start).scheme}://{urlsplit(start).netloc}"
        robots_url = f"{origin}/robots.txt"
        try:
            robots_response = client.get(robots_url)
            if 200 <= robots_response.status_code < 400:
                discovery_metadata["robots_fetched"] = True
                robots_text = str(getattr(robots_response, "text", ""))[:200_000]
                disallows = [
                    line.split(":", 1)[1].strip()
                    for line in robots_text.splitlines()
                    if line.lower().startswith("disallow:") and ":" in line
                ]
                discovery_metadata["robots_disallow_count"] = min(len(disallows), 200)
                sitemap_urls = [
                    _normalise_url(line.split(":", 1)[1].strip(), start)
                    for line in robots_text.splitlines()
                    if line.lower().startswith("sitemap:") and ":" in line
                ]
                discovery_metadata["sitemap_urls"] = [
                    item for item in sitemap_urls[:5] if item
                ]
        except Exception:
            errors += 1

        sitemap_candidates = list(discovery_metadata["sitemap_urls"])
        if not sitemap_candidates:
            sitemap_candidates = [f"{origin}/sitemap.xml"]
        for sitemap_url in sitemap_candidates[:5]:
            try:
                sitemap_response = client.get(sitemap_url)
                content_type = str(sitemap_response.headers.get("content-type", "")).lower()
                if sitemap_response.status_code < 400 and (
                    "xml" in content_type or "<loc" in str(getattr(sitemap_response, "text", ""))
                ):
                    for discovered in _bounded_xml_locations(
                        str(getattr(sitemap_response, "text", "")), start
                    ):
                        if discovered not in queued and len(queued) < max_pages * 3:
                            queue.append((discovered, 0))
                            queued.add(discovered)
            except Exception:
                errors += 1

        openapi_candidates = [
            f"{origin}{path}"
            for path in _OPENAPI_DOCUMENT_PATHS
        ]
        for openapi_url in openapi_candidates:
            try:
                api_response = client.get(openapi_url)
                if api_response.status_code >= 400:
                    continue
                payload = _extract_openapi_payload(str(getattr(api_response, "text", "")))
                discovered_paths = _openapi_discovered_urls(payload, start) if payload else []
                if discovered_paths:
                    discovery_metadata["openapi_urls"].append(openapi_url)
                    for discovered in discovered_paths:
                        if discovered not in queued and len(queued) < max_pages * 3:
                            queue.append((discovered, 0))
                            queued.add(discovered)
                # POST-P0 Phase 4: structured route projection for the
                # world model + schema-driven hypothesis producers.
                if payload:
                    from webpent.shared.schema_ingestion import parse_openapi_routes

                    schema_routes = parse_openapi_routes(payload, base_url=openapi_url)
                    if schema_routes:
                        seen_route_keys = {
                            (r.get("path"), r.get("method")) for r in discovery_metadata["openapi_routes"]
                        }
                        for route in schema_routes:
                            key = (route.get("path"), route.get("method"))
                            if key not in seen_route_keys:
                                discovery_metadata["openapi_routes"].append(route)
                                seen_route_keys.add(key)
                # POST-P0 Phase 4: a fetched document may itself be a
                # GraphQL introspection response (rare, static). Parse
                # when present — no introspection POST is issued here.
                if payload:
                    from webpent.shared.schema_ingestion import parse_graphql_introspection

                    gql_ops = parse_graphql_introspection(payload)
                    if gql_ops:
                        discovery_metadata["graphql_operations"].extend(
                            gql_ops[: _MAX_GRAPHQL_OPS_TOTAL - len(discovery_metadata["graphql_operations"])]
                        )
            except Exception:
                continue

        graphql_url = f"{origin}/graphql"
        if graphql_url not in queued:
            discovery_metadata["graphql_urls"] = [graphql_url]
            queue.append((graphql_url, 0))
            queued.add(graphql_url)

        # Bounded route seeds improve coverage only when an operator declares
        # routes for this specific target. They are GET-only observations;
        # validators still need independent evidence before promoting findings.
        # Queue them before crawling can exhaust the page budget. Otherwise a
        # noisy start page can fill ``max_pages`` and silently prevent known
        # application surfaces (for example /export-erp) from being observed.
        configured_route_seeds = [
            seed.strip()[:300]
            for seed in str(getattr(settings, "discovery_route_seeds", "") or "").split(",")
            if seed.strip()
        ]
        priority_seeds = list(dict.fromkeys(configured_route_seeds + list(_PRIORITY_ROUTE_SEEDS)))
        route_seeds = list(dict.fromkeys(priority_seeds + list(_DEFAULT_ROUTE_SEEDS)))
        discovery_metadata["route_seed_candidates"] = list(route_seeds[:40])
        priority_seed_queue: deque[tuple[str, int]] = deque()
        fallback_seed_queue: deque[tuple[str, int]] = deque()
        route_seed_queued = 0
        for seed in route_seeds[:40]:
            candidate = _normalise_url(seed, start)
            if not candidate or candidate in queued or len(queued) >= max_pages * 3:
                continue
            target_queue = priority_seed_queue if seed in priority_seeds else fallback_seed_queue
            target_queue.append((candidate, max_depth))
            route_seed_queued += 1
        discovery_metadata["route_seed_queued"] = route_seed_queued
        # Reserve a bounded number of slots for known critical surfaces, but
        # let the first natural pages run so ordinary links/forms/scripts are
        # not starved. Remaining queue entries continue after the reserve.
        priority_reserve = min(len(priority_seed_queue), 6, max(0, max_pages - 1))
        # GraphQL is queued by the legacy discovery bootstrap before this
        # route-seed planner, so reserve one additional natural slot for it.
        # The outer ``len(seen) < max_pages`` guard still enforces the hard cap.
        natural_page_budget = max(1, max_pages - priority_reserve + 1)
        priority_processed = 0

        while len(seen) < max_pages:
            if queue and len(seen) < natural_page_budget:
                current, depth = queue.popleft()
            elif priority_seed_queue and priority_processed < priority_reserve:
                current, depth = priority_seed_queue.popleft()
                priority_processed += 1
            elif queue:
                current, depth = queue.popleft()
            elif priority_seed_queue:
                current, depth = priority_seed_queue.popleft()
            elif fallback_seed_queue:
                current, depth = fallback_seed_queue.popleft()
            else:
                break
            if current in seen:
                continue
            queued.add(current)
            if not _is_safe_discovery_get(current, start_url=start):
                skipped_state_changing += 1
                continue
            seen.add(current)
            try:
                response = client.get(current)
            except Exception:
                errors += 1
                continue

            # A URL-only seed is not an observed application surface. Keep
            # reachable/error responses that prove a route exists, but discard
            # ordinary 404/410 misses before they can become hypotheses.
            if response.status_code in {404, 410}:
                continue
            endpoints.append(current)

            parsed_current = urlsplit(current)
            content_type = response.headers.get("content-type", "").lower()
            surface_records.append(
                {
                    "record_id": f"http:{len(surface_records) + 1}",
                    "source": "http_get",
                    "confidence": "observed",
                    "method": "GET",
                    "url": current,
                    "origin": f"{parsed_current.scheme}://{parsed_current.netloc}",
                    "scheme": parsed_current.scheme,
                    "port": parsed_current.port
                    or (443 if parsed_current.scheme == "https" else 80),
                    "path": parsed_current.path or "/",
                    "query_parameters": sorted({key for key, _ in parse_qsl(parsed_current.query)}),
                    "content_type": content_type[:160],
                    "status_code": response.status_code,
                    "response_headers": {
                        key.lower(): response.headers.get(key, "")[:300]
                        for key in ("content-type", "location", "allow", "server")
                        if response.headers.get(key)
                    },
                    "session_present": bool(cookie_header),
                    "identity": "authenticated" if cookie_header else "anonymous",
                    "tenant": None,
                    "workflow_state": "discovery",
                    "predecessor": None,
                    "successor": None,
                }
            )

            if 300 <= response.status_code < 400:
                location = response.headers.get("location", "")
                redirect_url = _normalise_url(location, current)
                if redirect_url and not _is_safe_discovery_get(redirect_url, start_url=start):
                    skipped_state_changing += 1
                elif redirect_url and redirect_url not in queued and depth < max_depth:
                    queue.append((redirect_url, depth + 1))
                    queued.add(redirect_url)
                    redirects_followed += 1
                elif location:
                    skipped_off_origin += 1
                continue

            if response.status_code < 200 or response.status_code >= 400:
                continue

            response_text = str(getattr(response, "text", ""))[:2_000_000]
            is_javascript = (
                "javascript" in content_type
                or (parsed_current.path or "").lower().endswith((".js", ".mjs"))
            )
            if is_javascript:
                js_routes = _bounded_js_routes(response_text, current, limit=100)
                discovery_metadata["js_route_candidates"].extend(js_routes)
                discovery_metadata["js_route_candidates"] = list(
                    dict.fromkeys(discovery_metadata["js_route_candidates"])
                )[:200]
                for discovered in js_routes:
                    if discovered not in queued and len(queued) < max_pages * 3:
                        queue.append((discovered, depth + 1))
                        queued.add(discovered)
                continue

            if not (
                "html" in content_type
                or "xhtml" in content_type
                or response_text.lstrip().startswith("<")
            ):
                continue

            parser = _SurfaceParser()
            try:
                parser.feed(response_text)
            except Exception:
                errors += 1
                continue

            for form in parser.forms:
                action = _normalise_url(str(form.get("action", "")), current) or current
                method = str(form.get("method") or "GET").upper()
                data = _redact_form_data(form.get("data") or {})
                record = {
                    "action": action,
                    "method": method,
                    "data": data,
                    "source_url": current,
                }
                if record not in forms:
                    forms.append(record)
                if method == "GET":
                    form_url = _get_form_url(action, current, data)
                    if form_url not in queued and len(seen) + len(queue) < max_pages * 2:
                        queue.append((form_url, depth + 1))
                        queued.add(form_url)

            script_urls: list[str] = []
            for script in parser.scripts[:100]:
                script_url = _normalise_url(script, current)
                if script_url and script_url not in script_urls:
                    script_urls.append(script_url)
            discovery_metadata["javascript_urls"].extend(script_urls)
            discovery_metadata["javascript_urls"] = list(
                dict.fromkeys(discovery_metadata["javascript_urls"])
            )[:200]
            discovery_metadata["js_route_candidates"].extend(
                _bounded_js_routes(response_text, current, limit=100)
            )
            candidates = parser.links + parser.scripts + discovery_metadata["js_route_candidates"]
            for candidate in candidates[:max_links_per_page]:
                discovered = _normalise_url(candidate, current)
                if not discovered:
                    try:
                        absolute = urljoin(current, candidate)
                        if absolute.startswith(("http://", "https://")) and not _same_origin(
                            absolute, base_url
                        ):
                            skipped_off_origin += 1
                    except Exception:
                        pass
                        # Intentionally suppressed — reviewed 2026-09-03
                    continue
                if discovered not in queued and depth < max_depth:
                    queue.append((discovered, depth + 1))
                    queued.add(discovered)


    gaps: list[str] = []
    if not endpoints:
        gaps.append("no_same_origin_endpoints")
    if errors:
        gaps.append("request_or_parse_errors")
    if skipped_off_origin:
        gaps.append("off_origin_links_filtered")
    if skipped_state_changing:
        gaps.append("state_changing_gets_not_fetched")
    gaps.append("forms_described_not_submitted")
    gaps.append("browser_generated_routes_not_captured")

    return {
        "endpoints": endpoints,
        "forms": forms,
        "pages_fetched": len(seen),
        "redirects_followed": redirects_followed,
        "errors": errors,
        "skipped_off_origin": skipped_off_origin,
        "skipped_state_changing": skipped_state_changing,
        "coverage_gaps": gaps,
        "coverage_blockers": [
            {
                "capability": "http_client",
                "reason": "infrastructure_failure",
            }
            for gap in gaps
            if gap == "http_client_unavailable"
        ],
        "surface_records": surface_records,
        "discovery_metadata": {
            **discovery_metadata,
            "javascript_urls": sorted(set(discovery_metadata["javascript_urls"]))[:200],
            "js_route_candidates": sorted(set(discovery_metadata["js_route_candidates"]))[:200],
        },
        # POST-P0 Phase 4: top-level structured schema keys (consumed by
        # application_intent_graph / surface graph / smart_campaigns).
        "openapi_routes": discovery_metadata["openapi_routes"][:_MAX_SCHEMA_ROUTE_TOTAL],
        "graphql_operations": discovery_metadata["graphql_operations"][:_MAX_GRAPHQL_OPS_TOTAL],
        "workflow_mode": "read_only_discovery",
    }


__all__ = ["discover_http_surface"]

# End of file
