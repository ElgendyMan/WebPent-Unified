"""Disposable in-process target fixtures for DCVU v1.

These fixtures are deterministic application models, not network servers.  They expose
safe semantic probes so the validation engine can measure discovery and confirmation
without credentials, login, external callbacks, or target state mutation.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Literal

from .contracts import TargetProfile


@dataclass(frozen=True)
class SyntheticIdentity:
    identity_id: str
    role: Literal["viewer", "editor", "admin"]
    tenant_id: str


@dataclass(frozen=True)
class FixtureSurface:
    surface_id: str
    vulnerability_class: str
    vulnerable: bool
    owner_binding: bool
    tenant_binding: bool
    required_role: Literal["viewer", "editor", "admin"]
    workflow_actor: Literal["viewer", "editor", "admin"]
    expected_impact: str


@dataclass(frozen=True)
class FixtureProbe:
    surface_id: str
    requester_id: str
    object_owner_id: str
    object_tenant_id: str
    requested_role: Literal["viewer", "editor", "admin"]
    transition: str = "read"


@dataclass(frozen=True)
class FixtureResponse:
    target_id: str
    surface_id: str
    allowed: bool
    semantic_signal: str
    impact: str
    subject_fingerprint: str
    object_fingerprint: str
    response_digest: str


class DisposableTargetFixture:
    """Deterministic target model with a safe, read-only probe interface."""

    def __init__(
        self,
        profile: TargetProfile,
        identities: tuple[SyntheticIdentity, ...],
        surfaces: tuple[FixtureSurface, ...],
    ) -> None:
        profile.validate()
        if not identities or not surfaces:
            raise ValueError("fixture requires identities and surfaces")
        self.profile = profile
        self.identities = {item.identity_id: item for item in identities}
        self.surfaces = {item.surface_id: item for item in surfaces}

    def describe_surfaces(self) -> tuple[dict[str, str], ...]:
        """Return generic surface metadata without revealing ground-truth status."""
        return tuple(
            {
                "surface_id": surface.surface_id,
                "vulnerability_class": surface.vulnerability_class,
                "required_role": surface.required_role,
                "workflow_actor": surface.workflow_actor,
            }
            for surface in self.surfaces.values()
        )

    def probe(self, request: FixtureProbe) -> FixtureResponse:
        """Evaluate one semantic read-only probe; no state is changed."""
        surface = self.surfaces.get(request.surface_id)
        requester = self.identities.get(request.requester_id)
        if surface is None or requester is None:
            raise ValueError("unknown fixture surface or synthetic identity")
        role_order = {"viewer": 0, "editor": 1, "admin": 2}
        role_sufficient = role_order[requester.role] >= role_order[request.requested_role]
        owner_match = requester.identity_id == request.object_owner_id
        tenant_match = requester.tenant_id == request.object_tenant_id
        workflow_allowed = role_order[requester.role] >= role_order[surface.workflow_actor]
        authorization_ok = role_sufficient and workflow_allowed
        if surface.owner_binding:
            authorization_ok = authorization_ok and owner_match
        if surface.tenant_binding:
            authorization_ok = authorization_ok and tenant_match
        unauthorized = not (owner_match and tenant_match and authorization_ok)
        allowed = authorization_ok
        if surface.vulnerable and unauthorized:
            allowed = True
        signal = "authorized_semantic_access" if allowed else "denied_semantic_access"
        if surface.vulnerable and unauthorized and allowed:
            signal = "causal_unauthorized_access"
        subject = f"subject:{requester.identity_id}"
        obj = f"object:{request.object_owner_id}:{request.object_tenant_id}"
        digest_input = (
            f"{self.profile.target_id}|{surface.surface_id}|{allowed}|{signal}|{subject}|{obj}"
        )
        return FixtureResponse(
            target_id=self.profile.target_id,
            surface_id=surface.surface_id,
            allowed=allowed,
            semantic_signal=signal,
            impact=surface.expected_impact if signal == "causal_unauthorized_access" else "none",
            subject_fingerprint=sha256(subject.encode()).hexdigest()[:16],
            object_fingerprint=sha256(obj.encode()).hexdigest()[:16],
            response_digest=sha256(digest_input.encode()).hexdigest(),
        )


def _surfaces(target_id: str, vulnerable_classes: set[str]) -> tuple[FixtureSurface, ...]:
    definitions = (
        ("object-read", "idor_bola", "cross-owner read", "viewer", "viewer"),
        ("role-capability", "privilege_escalation", "higher-role capability", "admin", "admin"),
        (
            "admin-function",
            "function_level_authorization",
            "restricted function access",
            "admin",
            "admin",
        ),
        (
            "business-transition",
            "business_logic_abuse",
            "invalid business transition",
            "editor",
            "editor",
        ),
        ("tenant-read", "tenant_isolation", "cross-tenant read", "viewer", "viewer"),
        (
            "workflow-transition",
            "workflow_authorization",
            "unauthorized workflow transition",
            "editor",
            "editor",
        ),
    )
    result: list[FixtureSurface] = []
    for suffix, vulnerability_class, impact, required_role, workflow_actor in definitions:
        result.append(
            FixtureSurface(
                surface_id=f"{target_id}.{suffix}",
                vulnerability_class=vulnerability_class,
                vulnerable=vulnerability_class in vulnerable_classes,
                owner_binding=vulnerability_class in {"idor_bola", "business_logic_abuse"},
                tenant_binding=vulnerability_class == "tenant_isolation",
                required_role=required_role,  # type: ignore[arg-type]
                workflow_actor=workflow_actor,  # type: ignore[arg-type]
                expected_impact=impact,
            )
        )
    return tuple(result)


def build_default_fixtures() -> tuple[DisposableTargetFixture, ...]:
    """Build three distinct target models with overlapping but non-identical truths."""
    identities = (
        SyntheticIdentity("viewer-a", "viewer", "tenant-a"),
        SyntheticIdentity("editor-a", "editor", "tenant-a"),
        SyntheticIdentity("admin-a", "admin", "tenant-a"),
        SyntheticIdentity("viewer-b", "viewer", "tenant-b"),
    )
    definitions = (
        (
            "fixture-a",
            "1.0.0",
            "sha256:dcvu-fixture-a-v1",
            {
                "idor_bola",
                "privilege_escalation",
                "function_level_authorization",
                "business_logic_abuse",
                "tenant_isolation",
                "workflow_authorization",
            },
        ),
        (
            "fixture-b",
            "1.0.0",
            "sha256:dcvu-fixture-b-v1",
            {
                "idor_bola",
                "function_level_authorization",
                "tenant_isolation",
                "workflow_authorization",
            },
        ),
        (
            "fixture-c",
            "1.0.0",
            "sha256:dcvu-fixture-c-v1",
            {
                "privilege_escalation",
                "business_logic_abuse",
                "tenant_isolation",
            },
        ),
    )
    fixtures: list[DisposableTargetFixture] = []
    for target_id, version, source_digest, vulnerable_classes in definitions:
        profile = TargetProfile(
            target_id=target_id,
            version=version,
            source_digest=source_digest,
            semantic_family="authorization_fixture",
        )
        fixtures.append(
            DisposableTargetFixture(profile, identities, _surfaces(target_id, vulnerable_classes))
        )
    return tuple(fixtures)
