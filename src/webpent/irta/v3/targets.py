"""Independent local target factory for IRTA v3.

The detector-facing object is an HTTP application only. Truth labels and expected
answers are intentionally not stored on the public target handle.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class TargetRuntime:
    """Opaque local target handle exposed to the campaign harness."""

    target_id: str
    app: FastAPI
    base_path: str
    runtime_digest: str


@dataclass(frozen=True)
class _TargetConfig:
    target_id: str
    base_path: str
    role_names: tuple[str, ...]
    tenant_names: tuple[str, ...]
    item_prefix: str
    workflow_name: str


_CONFIGS = (
    _TargetConfig(
        "target-alpha",
        "/alpha",
        ("member", "reviewer", "admin"),
        ("red", "blue"),
        "alpha",
        "approval",
    ),
    _TargetConfig(
        "target-beta",
        "/beta",
        ("reader", "operator", "owner"),
        ("north", "south"),
        "beta",
        "payout",
    ),
    _TargetConfig(
        "target-gamma",
        "/gamma",
        ("viewer", "editor", "manager"),
        ("one", "two"),
        "gamma",
        "coupon",
    ),
    _TargetConfig(
        "target-delta",
        "/delta",
        ("basic", "auditor", "lead"),
        ("a", "b"),
        "delta",
        "review",
    ),
    _TargetConfig(
        "target-epsilon",
        "/epsilon",
        ("guest", "staff", "director"),
        ("east", "west"),
        "epsilon",
        "transfer",
    ),
)


def _make_app(config: _TargetConfig) -> FastAPI:
    app = FastAPI(title=f"Independent {config.target_id}", docs_url=None, redoc_url=None)
    objects: dict[str, dict[str, Any]] = {}
    for index in range(1, 5):
        object_id = f"{config.item_prefix}-{index}"
        objects[object_id] = {
            "id": object_id,
            "tenant": config.tenant_names[index % 2],
            "owner": f"user-{index}",
            "status": "pending",
            "amount": index * 10,
        }

    def actor(x_actor: str | None, x_tenant: str | None) -> tuple[str, str, str]:
        if not x_actor or not x_tenant:
            raise HTTPException(status_code=401, detail="synthetic context required")
        role = config.role_names[0]
        if x_actor.endswith("-reviewer") or x_actor.endswith("-operator"):
            role = config.role_names[1]
        if x_actor.endswith("-admin") or x_actor.endswith("-owner"):
            role = config.role_names[-1]
        return x_actor, x_tenant, role

    @app.get(f"{config.base_path}/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": config.target_id}

    @app.get(f"{config.base_path}/api/profile")
    def profile(
        x_actor: str | None = Header(default=None),
        x_tenant: str | None = Header(default=None),
    ) -> dict[str, str]:
        actor_name, tenant, role = actor(x_actor, x_tenant)
        return {"actor": actor_name, "tenant": tenant, "role": role}

    @app.get(f"{config.base_path}/api/objects")
    def list_objects(
        x_actor: str | None = Header(default=None),
        x_tenant: str | None = Header(default=None),
    ) -> dict[str, list[dict[str, Any]]]:
        _, tenant, _ = actor(x_actor, x_tenant)
        return {"items": [item for item in objects.values() if item["tenant"] == tenant]}

    @app.get(f"{config.base_path}/api/objects/{{object_id}}")
    def get_object(
        object_id: str,
        x_actor: str | None = Header(default=None),
        x_tenant: str | None = Header(default=None),
    ) -> JSONResponse:
        _, tenant, role = actor(x_actor, x_tenant)
        item = objects.get(object_id)
        if item is None:
            raise HTTPException(status_code=404, detail="not found")
        if item["tenant"] != tenant and role != config.role_names[-1]:
            return JSONResponse(status_code=403, content={"detail": "forbidden"})
        return JSONResponse(status_code=200, content=item)

    @app.get(f"{config.base_path}/api/workflows/{{workflow_id}}")
    def workflow(
        workflow_id: str,
        include: str = Query(default="summary"),
        x_actor: str | None = Header(default=None),
        x_tenant: str | None = Header(default=None),
    ) -> dict[str, Any]:
        _, tenant, role = actor(x_actor, x_tenant)
        return {
            "id": workflow_id,
            "kind": config.workflow_name,
            "tenant": tenant,
            "role": role,
            "include": include,
            "state": "pending",
        }

    return app


def build_independent_targets() -> tuple[TargetRuntime, ...]:
    """Build five deterministic applications; no ground-truth registry is returned."""
    targets: list[TargetRuntime] = []
    for config in _CONFIGS:
        app = _make_app(config)
        digest = f"irta-v3-{config.target_id}-local-v1"
        targets.append(
            TargetRuntime(
                target_id=config.target_id,
                app=app,
                base_path=config.base_path,
                runtime_digest=digest,
            )
        )
    return tuple(targets)
