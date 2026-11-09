"""Contracts for independent, deterministic IRTA target generation.

The generator describes disposable local target behavior only.  It never opens
sockets, sends requests, creates credentials, or changes the frozen ground truth.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
from typing import Any


class VulnerabilityClass(StrEnum):
    IDOR = "idor"
    BOLA = "bola"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FUNCTION_LEVEL_AUTHZ = "function_level_authorization"
    TENANT_ISOLATION = "tenant_isolation"
    WORKFLOW_AUTHZ = "workflow_authorization"
    BUSINESS_LOGIC = "business_logic"
    INFORMATION_DISCLOSURE = "information_disclosure"


@dataclass(frozen=True)
class GeneratedRole:
    role_id: str
    permissions: tuple[str, ...]

    def validate(self) -> None:
        if not self.role_id or not self.permissions:
            raise ValueError("generated roles require an id and at least one permission")
        if any(not permission for permission in self.permissions):
            raise ValueError("generated permissions must be non-empty")


@dataclass(frozen=True)
class GeneratedIdentity:
    identity_id: str
    role_id: str
    tenant_id: str

    def validate(self, roles: tuple[GeneratedRole, ...], tenants: tuple[str, ...]) -> None:
        if not all((self.identity_id, self.role_id, self.tenant_id)):
            raise ValueError("generated identities require id, role and tenant")
        if self.role_id not in {role.role_id for role in roles}:
            raise ValueError("identity references an unknown role")
        if self.tenant_id not in tenants:
            raise ValueError("identity references an unknown tenant")


@dataclass(frozen=True)
class GeneratedObject:
    object_id: str
    owner_identity_id: str
    tenant_id: str
    sensitivity: str = "private"

    def validate(self, identities: tuple[GeneratedIdentity, ...], tenants: tuple[str, ...]) -> None:
        if not all((self.object_id, self.owner_identity_id, self.tenant_id, self.sensitivity)):
            raise ValueError("generated objects require id, owner, tenant and sensitivity")
        if self.owner_identity_id not in {identity.identity_id for identity in identities}:
            raise ValueError("object references an unknown owner")
        if self.tenant_id not in tenants:
            raise ValueError("object references an unknown tenant")


@dataclass(frozen=True)
class GeneratedRoute:
    route_id: str
    method: str
    path_template: str
    required_permission: str
    vulnerability_class: VulnerabilityClass | None = None
    object_parameter: str | None = None
    response_profile: str = "normal"

    def validate(self) -> None:
        if not self.route_id or self.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("generated routes must have an id and read-only method")
        if not self.path_template.startswith("/"):
            raise ValueError("generated route paths must be relative")
        if not self.required_permission:
            raise ValueError("generated routes require a permission")
        if self.object_parameter and "{" not in self.path_template:
            raise ValueError("object parameter requires a path placeholder")


@dataclass(frozen=True)
class GeneratedTarget:
    target_id: str
    seed: int
    roles: tuple[GeneratedRole, ...]
    tenants: tuple[str, ...]
    identities: tuple[GeneratedIdentity, ...]
    objects: tuple[GeneratedObject, ...]
    routes: tuple[GeneratedRoute, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.target_id or self.seed < 0:
            raise ValueError("generated target requires a stable id and non-negative seed")
        if not all((self.roles, self.tenants, self.identities, self.objects, self.routes)):
            raise ValueError(
                "generated target must contain roles, tenants, identities, objects and routes"
            )
        for role in self.roles:
            role.validate()
        for identity in self.identities:
            identity.validate(self.roles, self.tenants)
        for obj in self.objects:
            obj.validate(self.identities, self.tenants)
        for route in self.routes:
            route.validate()
        if len({route.route_id for route in self.routes}) != len(self.routes):
            raise ValueError("generated route ids must be unique")

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "target_id": self.target_id,
            "seed": self.seed,
            "roles": [
                {"role_id": role.role_id, "permissions": list(role.permissions)}
                for role in self.roles
            ],
            "tenants": list(self.tenants),
            "identities": [identity.__dict__ for identity in self.identities],
            "objects": [obj.__dict__ for obj in self.objects],
            "routes": [
                {
                    **route.__dict__,
                    "vulnerability_class": (
                        route.vulnerability_class.value
                        if route.vulnerability_class
                        else None
                    ),
                }
                for route in self.routes
            ],
            "metadata": self.metadata,
        }

    def digest(self) -> str:
        payload = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return sha256(payload.encode("utf-8")).hexdigest()
