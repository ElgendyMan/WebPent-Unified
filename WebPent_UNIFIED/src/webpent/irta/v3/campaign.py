"""Read-only local HTTP campaign primitives for IRTA v3."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Any

import httpx

from .targets import TargetRuntime


@dataclass(frozen=True)
class DiscoveredRoute:
    method: str
    path: str
    operation_id: str | None


@dataclass(frozen=True)
class CampaignObservation:
    target_id: str
    method: str
    path: str
    status_code: int
    response_shape: str
    body_digest: str


@dataclass(frozen=True)
class CampaignResult:
    target_id: str
    routes: tuple[DiscoveredRoute, ...]
    observations: tuple[CampaignObservation, ...]


class LocalReadOnlyCampaign:
    """Discovery and safe GET campaign over an ASGI target, with no mutation verbs."""

    def __init__(self, target: TargetRuntime) -> None:
        self._target = target

    def discover(self) -> tuple[DiscoveredRoute, ...]:
        schema: dict[str, Any] = self._target.app.openapi()
        routes: list[DiscoveredRoute] = []
        for path, item in sorted(schema.get("paths", {}).items()):
            for method, operation in sorted(item.items()):
                if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
                    continue
                routes.append(
                    DiscoveredRoute(
                        method=method.upper(),
                        path=path,
                        operation_id=operation.get("operationId"),
                    )
                )
        return tuple(routes)

    async def run(self) -> CampaignResult:
        routes = self.discover()
        observations: list[CampaignObservation] = []
        transport = httpx.ASGITransport(app=self._target.app)
        headers = {"X-Actor": "user-1", "X-Tenant": "blue"}
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            for route in routes:
                path = route.path
                if "{" in path:
                    path = path.replace("{object_id}", "alpha-1")
                    path = path.replace("{workflow_id}", "workflow-1")
                response = await client.request(route.method, path, headers=headers)
                body = response.text
                content_type = response.headers.get("content-type", "")
                shape = "json" if content_type.startswith("application/json") else "text"
                observations.append(
                    CampaignObservation(
                        target_id=self._target.target_id,
                        method=route.method,
                        path=path,
                        status_code=response.status_code,
                        response_shape=shape,
                        body_digest=sha256(body.encode("utf-8")).hexdigest(),
                    )
                )
        return CampaignResult(self._target.target_id, routes, tuple(observations))
