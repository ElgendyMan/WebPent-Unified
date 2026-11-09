from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client

from .contracts import (
    DiscoveredSurface,
    DiscoverySnapshot,
    HttpObservation,
    HttpRequestSpec,
    RtaScope,
)


def _digest_payload(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _assert_loopback(base_url: str, scope: RtaScope) -> None:
    scope.validate()
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in scope.allowed_hosts:
        raise ValueError("RTA discovery accepts only an explicitly allowed loopback host")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("RTA discovery base URL must not contain a path, query, or fragment")


def _path_parameters(path: str) -> tuple[str, ...]:
    return tuple(
        part[1:-1] for part in path.split("/") if part.startswith("{") and part.endswith("}")
    )


def _surface_from_route(route: dict[str, object]) -> DiscoveredSurface:
    method = str(route.get("method", "")).upper()
    path = str(route.get("path", ""))
    relation_hints = tuple(
        hint for hint in ("object", "tenant", "workflow", "role") if hint in path.lower()
    )
    surface = DiscoveredSurface(
        method=method,
        path_template=path,
        parameters=_path_parameters(path),
        auth_required=bool(route.get("auth_required", False)),
        relation_hints=relation_hints,
    )
    surface.validate()
    return surface


def _request_observation(
    client: Any,
    base_url: str,
    path: str,
    session_handle: str = "",
) -> HttpObservation:
    request = HttpRequestSpec(
        method="GET",
        path=path,
        auth_context_id=session_handle,
        state_changing=False,
    )
    request.validate()
    headers = {"X-Synthetic-Session": session_handle} if session_handle else {}
    response = client.get(urljoin(base_url + "/", path.lstrip("/")), headers=headers)
    try:
        payload: object = response.json()
    except ValueError:
        payload = response.text
    return HttpObservation(
        request=request,
        status_code=response.status_code,
        response_content_type=response.headers.get("content-type", ""),
        response_digest=_digest_payload(payload),
        semantic_facts=(
            "http_observation",
            f"status:{response.status_code}",
            "authenticated" if session_handle else "anonymous",
        ),
    )


def discover_loopback_target(
    base_url: str,
    target_id: str,
    runtime_digest: str,
    scope: RtaScope,
    synthetic_session: str = "synthetic:user-a",
) -> DiscoverySnapshot:
    """Discover read-only surfaces through real loopback HTTP traffic."""

    _assert_loopback(base_url, scope)
    if not target_id or not runtime_digest:
        raise ValueError("discovery requires immutable target identity and runtime digest")
    if not synthetic_session.startswith("synthetic:"):
        raise ValueError("discovery accepts only synthetic session handles")

    target_token = set_engagement_target_hosts(base_url)
    try:
        with make_safe_httpx_client(timeout=3.0, follow_redirects=False) as client:
            root_observation = _request_observation(client, base_url, "/")
            openapi_observation = _request_observation(
                client, base_url, "/api/openapi-lite", synthetic_session
            )
            openapi_response = client.get(
                urljoin(base_url + "/", "api/openapi-lite"),
                headers={"X-Synthetic-Session": synthetic_session},
            )
            payload = openapi_response.json()
            routes = payload.get("routes", []) if isinstance(payload, dict) else []
            surfaces = tuple(
                _surface_from_route(route) for route in routes if isinstance(route, dict)
            )

            soup = BeautifulSoup(
                client.get(urljoin(base_url + "/", "")).text,
                "html.parser",
            )
            base_host = urlparse(base_url).hostname
            linked_paths = tuple(
                sorted(
                    {
                        parsed.path
                        for anchor in soup.find_all("a", href=True)
                        if (parsed := urlparse(str(anchor["href"]))).hostname in {None, base_host}
                        and parsed.path.startswith("/")
                    }
                )
            )
            link_observations = tuple(
                _request_observation(client, base_url, path, synthetic_session)
                for path in linked_paths
                if path not in {"/", "/api/openapi-lite"}
            )
    finally:
        clear_engagement_target_hosts(target_token)

    snapshot = DiscoverySnapshot(
        target_id=target_id,
        runtime_digest=runtime_digest,
        surfaces=surfaces,
        observations=(root_observation, openapi_observation, *link_observations),
    )
    snapshot.validate()
    return snapshot
