"""Contracts for RTA v1 realistic local target assessment.

RTA remains a local, disposable, read-only validation layer.  It may observe
real HTTP traffic against an explicitly owned loopback harness, but it never
uses real credentials, external hosts, destructive actions, or qualification
authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RtaDisposition(StrEnum):
    READY = "ready"
    BLOCKED = "blocked"
    OBSERVATION_ONLY = "observation_only"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True)
class RtaScope:
    campaign_id: str
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    loopback_only: bool = True
    external_scope: bool = False
    real_credentials_allowed: bool = False
    state_mutation_allowed: bool = False

    def validate(self) -> None:
        if not self.campaign_id:
            raise ValueError("RTA scope requires a campaign id")
        if not self.loopback_only or self.external_scope:
            raise ValueError("RTA v1 is loopback-only and external scope is forbidden")
        if self.real_credentials_allowed or self.state_mutation_allowed:
            raise ValueError("RTA v1 forbids real credentials and state mutation")
        if not self.allowed_hosts or any(
            host not in {"127.0.0.1", "localhost"} for host in self.allowed_hosts
        ):
            raise ValueError("RTA hosts must be explicit loopback hosts")


@dataclass(frozen=True)
class SyntheticAuthContext:
    identity_id: str
    role: str
    tenant_id: str
    session_handle: str
    permissions: tuple[str, ...] = ()

    def validate(self) -> None:
        if not all((self.identity_id, self.role, self.tenant_id, self.session_handle)):
            raise ValueError("synthetic auth context requires identity, role, tenant and session")
        if not self.session_handle.startswith("synthetic:"):
            raise ValueError("RTA sessions must be synthetic handles")


@dataclass(frozen=True)
class HttpRequestSpec:
    method: str
    path: str
    query: tuple[tuple[str, str], ...] = ()
    auth_context_id: str = ""
    state_changing: bool = False

    def validate(self) -> None:
        if self.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("RTA v1 execution is limited to read-only HTTP methods")
        if not self.path.startswith("/"):
            raise ValueError("HTTP path must be relative to the loopback target")
        if self.state_changing:
            raise ValueError("state-changing request requires a separate owner-approved packet")


@dataclass(frozen=True)
class HttpObservation:
    request: HttpRequestSpec
    status_code: int
    response_content_type: str
    response_digest: str
    semantic_facts: tuple[str, ...] = ()
    redacted: bool = True

    def validate(self) -> None:
        self.request.validate()
        if not 100 <= self.status_code <= 599:
            raise ValueError("HTTP status must be bounded")
        if not self.response_digest or not self.redacted:
            raise ValueError("RTA observations must be redacted and digested")


@dataclass(frozen=True)
class DiscoveredSurface:
    method: str
    path_template: str
    parameters: tuple[str, ...] = ()
    auth_required: bool = False
    relation_hints: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            raise ValueError("discovered executable surfaces must be read-only in RTA v1")
        if not self.path_template.startswith("/"):
            raise ValueError("surface path must be relative")


@dataclass(frozen=True)
class DiscoverySnapshot:
    target_id: str
    runtime_digest: str
    surfaces: tuple[DiscoveredSurface, ...]
    observations: tuple[HttpObservation, ...]
    source: str = "loopback_http"

    def validate(self) -> None:
        if not self.target_id or not self.runtime_digest or self.source != "loopback_http":
            raise ValueError("RTA discovery requires a loopback target and runtime digest")
        for surface in self.surfaces:
            surface.validate()
        for observation in self.observations:
            observation.validate()


@dataclass(frozen=True)
class RtaCase:
    case_id: str
    target_id: str
    vulnerability_class: str
    oracle_id: str
    negative_control_id: str
    disposition: RtaDisposition = RtaDisposition.READY
    requires_real_credentials: bool = False
    requires_state_mutation: bool = False

    def validate(self) -> None:
        if not all(
            (
                self.case_id,
                self.target_id,
                self.vulnerability_class,
                self.oracle_id,
                self.negative_control_id,
            )
        ):
            raise ValueError("RTA cases require identity, class, oracle and negative control")
        if self.requires_real_credentials or self.requires_state_mutation:
            raise ValueError("RTA v1 cannot execute cases needing real credentials or mutation")


@dataclass(frozen=True)
class RtaAssessment:
    campaign_id: str
    target_id: str
    discovered_surfaces: int
    observations: tuple[HttpObservation, ...]
    cases: tuple[RtaCase, ...]
    notes: tuple[str, ...] = ()
    governance: dict[str, Any] = field(
        default_factory=lambda: {
            "external_scope": False,
            "real_credentials_used": False,
            "state_mutation": False,
            "qualification_effect": False,
        }
    )

    def validate(self) -> None:
        if not self.campaign_id or not self.target_id:
            raise ValueError("RTA assessment requires campaign and target identity")
        for observation in self.observations:
            observation.validate()
        for case in self.cases:
            case.validate()
        if any(self.governance.values()):
            raise ValueError("RTA governance effects must remain false")
