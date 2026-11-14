"""Independent deterministic target generator for IRTA v2."""

from __future__ import annotations

from random import Random

from .models import (
    GeneratedIdentity,
    GeneratedObject,
    GeneratedRole,
    GeneratedRoute,
    GeneratedTarget,
    VulnerabilityClass,
)


class IndependentTargetGenerator:
    """Generate portable local target specifications from a seed.

    The output is a data contract, not an executable server.  This separation
    prevents the generator from becoming an accidental network or credential
    mechanism and makes every target reproducible from ``seed``.
    """

    _PERMISSIONS = ("read:object", "read:admin", "read:workflow", "read:tenant")

    def generate(
        self,
        seed: int,
        *,
        target_id: str | None = None,
        tenant_count: int = 2,
        objects_per_tenant: int = 3,
    ) -> GeneratedTarget:
        if seed < 0:
            raise ValueError("seed must be non-negative")
        if tenant_count < 2 or objects_per_tenant < 1:
            raise ValueError("at least two tenants and one object per tenant are required")

        rng = Random(seed)
        target_id = target_id or f"irta-generated-{seed:08d}"
        tenants = tuple(f"tenant-{index + 1}" for index in range(tenant_count))
        roles = (
            GeneratedRole("owner", ("read:object", "read:workflow", "read:tenant")),
            GeneratedRole("member", ("read:object",)),
            GeneratedRole("auditor", ("read:object", "read:tenant")),
        )
        identities: list[GeneratedIdentity] = []
        for index, tenant in enumerate(tenants):
            identities.extend(
                (
                    GeneratedIdentity(f"owner-{index + 1}", "owner", tenant),
                    GeneratedIdentity(f"member-{index + 1}", "member", tenant),
                    GeneratedIdentity(f"auditor-{index + 1}", "auditor", tenant),
                )
            )

        objects: list[GeneratedObject] = []
        for tenant_index, tenant in enumerate(tenants):
            owner = f"owner-{tenant_index + 1}"
            for object_index in range(objects_per_tenant):
                sensitivity = rng.choice(("private", "confidential", "workflow"))
                objects.append(
                    GeneratedObject(
                        object_id=f"obj-{tenant_index + 1}-{object_index + 1}",
                        owner_identity_id=owner,
                        tenant_id=tenant,
                        sensitivity=sensitivity,
                    )
                )

        routes = (
            GeneratedRoute(
                "object-read",
                "GET",
                "/api/objects/{object_id}",
                "read:object",
                VulnerabilityClass.IDOR,
                "object_id",
            ),
            GeneratedRoute(
                "tenant-read",
                "GET",
                "/api/tenants/{tenant_id}/objects",
                "read:tenant",
                VulnerabilityClass.TENANT_ISOLATION,
                "tenant_id",
            ),
            GeneratedRoute(
                "workflow-read",
                "GET",
                "/api/workflows/{workflow_id}",
                "read:workflow",
                VulnerabilityClass.WORKFLOW_AUTHZ,
                "workflow_id",
            ),
            GeneratedRoute(
                "admin-read",
                "GET",
                "/api/admin/audit",
                "read:admin",
                VulnerabilityClass.FUNCTION_LEVEL_AUTHZ,
            ),
        )
        target = GeneratedTarget(
            target_id=target_id,
            seed=seed,
            roles=roles,
            tenants=tenants,
            identities=tuple(identities),
            objects=tuple(objects),
            routes=routes,
            metadata={"generator": "irta-v2", "rng": "stdlib.Random", "network": "none"},
        )
        target.validate()
        return target


def generate_target(seed: int, **kwargs: object) -> GeneratedTarget:
    """Convenience wrapper used by benchmarks and adapters."""

    return IndependentTargetGenerator().generate(seed, **kwargs)
