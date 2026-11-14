"""Tenant-isolation scenario catalog (multi-tenant boundary family)."""
from __future__ import annotations

from webpent.families.base import EvidenceRequirement, FamilyId, ScenarioSpec

TENANT_SCENARIOS: tuple[ScenarioSpec, ...] = (
    ScenarioSpec(
        scenario_id="TENANT-001-cross-tenant-object-idor",
        family=FamilyId.TENANT_ISOLATION,
        name="Cross-tenant object access via un-scoped identifier",
        description=(
            "An object identifier (UUID / sequential id) accepted without a "
            "tenant-scoping predicate lets tenant A read or modify tenant "
            "B's resource. Distinct from single-tenant IDOR: the boundary "
            "violated is the tenant boundary, not the per-user object ACL."
        ),
        preconditions=["multi_tenant", "object_reference_in_url_or_body"],
        discriminator_experiment=(
            "As tenant A user, replay a valid tenant-B resource identifier "
            "in the same endpoint; compare response shape and status."
        ),
        expected_signal="Tenant A receives 2xx with tenant-B data instead of 403/404.",
        negative_control="Same-tenant different-user same request is rejected (proves object ACL exists).",
        evidence_requirements=[
            EvidenceRequirement(kind="actor_a_replay", description="Tenant A request + response metadata"),
            EvidenceRequirement(kind="actor_b_baseline", description="Legitimate tenant B baseline response"),
            EvidenceRequirement(kind="same_tenant_negative", description="Same-tenant cross-user rejection"),
        ],
        severity="critical",
        references=["OWASP API Top10 API1-2023 BOLA", "CWE-639", "CWE-284"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="TENANT-002-tenant-header-spoof",
        family=FamilyId.TENANT_ISOLATION,
        name="Tenant context header / parameter spoofing",
        description=(
            "Tenant context carried in a client-controlled header (X-Tenant-Id, "
            "X-Workspace-Id) or query parameter is trusted without re-deriving "
            "it from the session."
        ),
        preconditions=["multi_tenant", "tenant_context_header_or_param"],
        discriminator_experiment=(
            "Authenticate as tenant A, then set X-Tenant-Id (or equivalent) "
            "to tenant B and re-request a tenant-scoped collection."
        ),
        expected_signal="Response contains tenant B's collection while session belongs to tenant A.",
        negative_control="Request with header omitted returns tenant A's own collection only.",
        evidence_requirements=[
            EvidenceRequirement(kind="spoofed_header_replay", description="Request with forged tenant context"),
            EvidenceRequirement(kind="session_tenant_baseline", description="Response with authentic context"),
        ],
        severity="critical",
        references=["CWE-472", "CWE-284"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="TENANT-003-subdomain-tenant-confusion",
        family=FamilyId.TENANT_ISOLATION,
        name="Subdomain / hostname-based tenant confusion",
        description=(
            "Tenant routing by hostname (tenantA.app.example) without "
            "session-binding permits a session issued for tenant A to be "
            "replayed against tenant B's hostname."
        ),
        preconditions=["multi_tenant", "hostname_based_routing"],
        discriminator_experiment=(
            "Authenticate on tenant A hostname, then replay the session "
            "cookie/token against tenant B hostname."
        ),
        expected_signal="Tenant B hostname accepts tenant A session and returns tenant B data.",
        negative_control="Fresh (unauthenticated) request to tenant B hostname is rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="cross_hostname_replay", description="Session replayed on foreign hostname"),
            EvidenceRequirement(kind="hostname_baseline", description="Same session on own hostname"),
        ],
        severity="high",
        references=["CWE-284", "CWE-472"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="TENANT-004-shared-resource-leak",
        family=FamilyId.TENANT_ISOLATION,
        name="Shared global resource leaks tenant-scoped data",
        description=(
            "A nominally shared endpoint (search, global feed, webhook, "
            "bulk export, logs) returns rows across tenants because the "
            "tenant predicate is applied only in the UI layer."
        ),
        preconditions=["multi_tenant", "shared_or_global_endpoint"],
        discriminator_experiment=(
            "Exercise the shared endpoint as tenant A and inspect whether "
            "results reference tenant-B identifiers or data."
        ),
        expected_signal="Tenant-A response contains tenant-B identifiers / data fragments.",
        negative_control="Tenant-scoped equivalent endpoint returns only tenant A rows.",
        evidence_requirements=[
            EvidenceRequirement(kind="shared_endpoint_response", description="Response metadata + foreign identifiers"),
            EvidenceRequirement(kind="tenant_scoped_baseline", description="Scoped endpoint baseline"),
        ],
        severity="high",
        references=["CWE-200", "CWE-284"],
        safe_in_production=True,
    ),
    ScenarioSpec(
        scenario_id="TENANT-005-invite-transfer-cross-tenant",
        family=FamilyId.TENANT_ISOLATION,
        name="Invitation / transfer token accepted cross-tenant",
        description=(
            "An invitation, workspace-transfer, or resource-share token "
            "issued by tenant B is accepted when redeemed from a session "
            "bound to tenant A, moving resources across the tenant boundary."
        ),
        preconditions=["multi_tenant", "invite_or_share_token"],
        discriminator_experiment=(
            "Redeem a tenant-B invitation/share token while authenticated "
            "as tenant A; observe whether resources cross into tenant A."
        ),
        expected_signal="Tenant B resource becomes accessible from tenant A session after redemption.",
        negative_control="Redemption from a mismatched-tenant session is rejected.",
        evidence_requirements=[
            EvidenceRequirement(kind="token_redemption", description="Cross-tenant redemption attempt"),
            EvidenceRequirement(kind="post_redemption_access", description="Access check after redemption"),
        ],
        severity="high",
        references=["CWE-284", "CWE-639"],
        safe_in_production=False,
    ),
    ScenarioSpec(
        scenario_id="TENANT-006-admin-scope-escalation",
        family=FamilyId.TENANT_ISOLATION,
        name="Tenant-admin scope escalation to platform admin",
        description=(
            "A tenant-scoped admin role can invoke platform/global admin "
            "endpoints because authorization checks the role name but not "
            "the role's tenant scope."
        ),
        preconditions=["multi_tenant", "tenant_admin_role", "platform_admin_endpoints"],
        discriminator_experiment=(
            "As tenant admin, replay platform-admin endpoints (user "
            "management, tenant list, feature flags) and compare status."
        ),
        expected_signal="Tenant admin receives 2xx from platform-admin endpoints.",
        negative_control="Non-admin tenant user receives 403 on the same endpoints.",
        evidence_requirements=[
            EvidenceRequirement(kind="tenant_admin_replay", description="Tenant admin request to platform endpoint"),
            EvidenceRequirement(kind="platform_admin_baseline", description="Legitimate platform admin baseline"),
        ],
        severity="critical",
        references=["CWE-269", "CWE-284"],
        safe_in_production=False,
    ),
)

__all__ = ["TENANT_SCENARIOS"]
