from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client

from .contracts import HttpObservation, HttpRequestSpec, RtaScope, SyntheticAuthContext


@dataclass(frozen=True)
class RtaAuthProfiles:
    contexts: tuple[SyntheticAuthContext, ...]

    def validate(self) -> None:
        if not self.contexts:
            raise ValueError("authenticated RTA campaign requires synthetic contexts")
        for context in self.contexts:
            context.validate()
        if any(not context.session_handle.startswith("synthetic:") for context in self.contexts):
            raise ValueError("RTA campaign cannot use non-synthetic sessions")

    def by_session(self) -> dict[str, SyntheticAuthContext]:
        self.validate()
        return {context.session_handle: context for context in self.contexts}


@dataclass(frozen=True)
class PermissionGraph:
    identities: tuple[str, ...]
    roles: tuple[str, ...]
    tenants: tuple[str, ...]
    edges: tuple[tuple[str, str, str], ...]

    def validate(self) -> None:
        if not self.identities or not self.roles or not self.tenants:
            raise ValueError("permission graph requires identities, roles and tenants")
        if any(len(edge) != 3 for edge in self.edges):
            raise ValueError("permission graph edges must be typed triples")


def build_permission_graph(profiles: RtaAuthProfiles) -> PermissionGraph:
    profiles.validate()
    edges = tuple(
        edge
        for context in profiles.contexts
        for edge in (
            (context.identity_id, "has_role", context.role),
            (context.identity_id, "member_of", context.tenant_id),
            *((context.identity_id, "permits", permission) for permission in context.permissions),
        )
    )
    graph = PermissionGraph(
        identities=tuple(sorted({context.identity_id for context in profiles.contexts})),
        roles=tuple(sorted({context.role for context in profiles.contexts})),
        tenants=tuple(sorted({context.tenant_id for context in profiles.contexts})),
        edges=edges,
    )
    graph.validate()
    return graph


def _digest(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _observation(
    client: Any,
    base_url: str,
    path: str,
    context: SyntheticAuthContext,
) -> HttpObservation:
    request = HttpRequestSpec(
        method="GET",
        path=path,
        auth_context_id=context.session_handle,
        state_changing=False,
    )
    request.validate()
    response = client.get(
        urljoin(base_url + "/", path.lstrip("/")),
        headers={"X-Synthetic-Session": context.session_handle},
    )
    try:
        payload: Any = response.json()
    except ValueError:
        payload = response.text
    semantic_facts = [
        "authenticated_http",
        f"status:{response.status_code}",
        f"role:{context.role}",
        f"tenant:{context.tenant_id}",
    ]
    if response.status_code in {401, 403}:
        semantic_facts.append("access_denied")
    elif 200 <= response.status_code < 300:
        semantic_facts.append("access_granted")
    if isinstance(payload, dict):
        for key in ("access_level", "role", "tenant_id", "stage"):
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)):
                semantic_facts.append(f"{key}:{value}")
        if payload.get("discount") == 90:
            semantic_facts.append("business_rule:elevated_discount")
        if "owner_id" in payload:
            semantic_facts.append(
                "owner_match:true"
                if payload.get("owner_id") == context.identity_id
                else "owner_match:false"
            )
        if "tenant_id" in payload:
            semantic_facts.append(
                "tenant_match:true"
                if payload.get("tenant_id") == context.tenant_id
                else "tenant_match:false"
            )
    return HttpObservation(
        request=request,
        status_code=response.status_code,
        response_content_type=response.headers.get("content-type", ""),
        response_digest=_digest(payload),
        semantic_facts=tuple(semantic_facts),
    )


def run_authenticated_read_campaign(
    base_url: str,
    scope: RtaScope,
    profiles: RtaAuthProfiles,
    paths: tuple[str, ...],
) -> tuple[PermissionGraph, tuple[HttpObservation, ...]]:
    """Run bounded GET-only probes against an explicitly owned loopback app."""

    scope.validate()
    profiles.validate()
    graph = build_permission_graph(profiles)
    if not paths:
        raise ValueError("authenticated RTA campaign requires at least one discovered path")
    if any(not path.startswith("/") or "?" in path for path in paths):
        raise ValueError("RTA campaign paths must be relative and query-free")

    observations: list[HttpObservation] = []
    target_token = set_engagement_target_hosts(base_url)
    try:
        with make_safe_httpx_client(timeout=3.0, follow_redirects=False) as client:
            for path in paths:
                for context in profiles.contexts:
                    observations.append(_observation(client, base_url, path, context))
    finally:
        clear_engagement_target_hosts(target_token)
    return graph, tuple(observations)
