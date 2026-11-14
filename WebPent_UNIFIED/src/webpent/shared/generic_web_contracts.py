"""Versioned, target-neutral contracts for generic web discovery.

The contracts in this module describe capability and case lifecycle state. They
are deliberately declarative: a capability or result is not a vulnerability
finding and never authorizes a state-changing operation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Final, Literal

if TYPE_CHECKING:
    from webpent.shared.verifier import VerificationResult

CAPABILITY_CONTRACT_VERSION: Final[str] = "generic-capability.v1"
CASE_CONTRACT_VERSION: Final[str] = "generic-case.v1"
LIFECYCLE_CONTRACT_VERSION: Final[str] = "case-lifecycle.v1"

CapabilityStatus = Literal[
    "available",
    "blocked",
    "inconclusive",
    "needs_profile",
    "needs_human_review",
    "observation_only",
    "unsupported",
]
CaseResultStatus = Literal[
    "confirmed",
    "probable",
    "observation_only",
    "blocked",
    "unsupported",
    "inconclusive",
    "needs_profile",
    "needs_human_review",
]
SurfaceClassification = Literal["html", "spa", "api", "hybrid", "unknown"]
LifecycleStageStatus = Literal[
    "ready",
    "completed",
    "blocked",
    "unsupported",
    "needs_profile",
    "observation_only",
    "inconclusive",
]


@dataclass(frozen=True)
class DiscoveryLimits:
    """Hard ceilings for one generic discovery session."""

    timeout_seconds: float = 8.0
    rate_limit_per_second: float = 2.0
    max_depth: int = 3
    max_pages: int = 50
    max_links_per_page: int = 100
    max_body_bytes: int = 1_000_000

    def __post_init__(self) -> None:
        if not 0.1 <= float(self.timeout_seconds) <= 120.0:
            raise ValueError("discovery_limits_timeout_invalid")
        if not 0.1 <= float(self.rate_limit_per_second) <= 100.0:
            raise ValueError("discovery_limits_rate_invalid")
        if not 0 <= int(self.max_depth) <= 10:
            raise ValueError("discovery_limits_depth_invalid")
        if not 1 <= int(self.max_pages) <= 500:
            raise ValueError("discovery_limits_pages_invalid")
        if not 1 <= int(self.max_links_per_page) <= 500:
            raise ValueError("discovery_limits_links_invalid")
        if not 1_024 <= int(self.max_body_bytes) <= 20_000_000:
            raise ValueError("discovery_limits_body_invalid")

    def as_dict(self) -> dict[str, float | int]:
        return asdict(self)


@dataclass(frozen=True)
class CapabilityRecord:
    """One redaction-safe capability assessment."""

    capability_id: str
    status: CapabilityStatus
    reason: str = ""
    evidence_refs: tuple[str, ...] = ()
    contract_version: str = CAPABILITY_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if not str(self.capability_id).strip():
            raise ValueError("capability_id_required")
        if not str(self.reason).strip() and self.status != "available":
            raise ValueError("capability_reason_required")
        if len(self.evidence_refs) > 12:
            raise ValueError("capability_evidence_refs_limit_exceeded")

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["evidence_refs"] = list(self.evidence_refs)
        return result


@dataclass(frozen=True)
class CaseDefinition:
    """Declarative case requirements used by the generic lifecycle planner."""

    case_id: str
    workflow_id: str
    required_capabilities: tuple[str, ...] = ()
    mutates_state: bool = False
    requires_auth: bool = False
    requires_negative_control: bool = True
    profile_id: str | None = None
    contract_version: str = CASE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if not str(self.case_id).strip():
            raise ValueError("case_id_required")
        if not str(self.workflow_id).strip():
            raise ValueError("case_workflow_id_required")
        if not self.required_capabilities:
            raise ValueError("case_required_capabilities_required")
        if any(not str(item).strip() for item in self.required_capabilities):
            raise ValueError("case_capability_id_invalid")
        if self.profile_id is not None and not str(self.profile_id).strip():
            raise ValueError("case_profile_id_invalid")

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["required_capabilities"] = list(self.required_capabilities)
        return result


@dataclass(frozen=True)
class CaseResult:
    """Structured lifecycle result; statuses never imply a confirmed finding."""

    case_id: str
    status: CaseResultStatus
    reason: str
    observation_refs: tuple[str, ...] = ()
    negative_control_ref: str | None = None
    proof_bundle_ref: str | None = None
    contract_version: str = CASE_CONTRACT_VERSION
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not str(self.case_id).strip():
            raise ValueError("case_result_case_id_required")
        if not str(self.reason).strip():
            raise ValueError("case_result_reason_required")
        if len(self.observation_refs) > 20:
            raise ValueError("case_result_observation_refs_limit_exceeded")
        for value in (self.negative_control_ref, self.proof_bundle_ref):
            if value is not None and not str(value).strip():
                raise ValueError("case_result_reference_invalid")
        if self.status in {"confirmed", "probable"} and self.proof_bundle_ref is None:
            raise ValueError("case_result_proof_required_for_promoted_status")
        if len(self.metadata) > 20:
            raise ValueError("case_result_metadata_limit_exceeded")

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["observation_refs"] = list(self.observation_refs)
        return result


@dataclass(frozen=True)
class LifecycleAuthorization:
    """Explicit authorization envelope required before adapter execution."""

    authorized: bool
    engagement_id: str = ""
    allowed_origin: str = ""
    actor: str = "operator"
    satisfied_requirements: tuple[str, ...] = ()
    contract_version: str = LIFECYCLE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.authorized and not str(self.engagement_id).strip():
            raise ValueError("lifecycle_authorization_engagement_required")
        if self.authorized and not str(self.allowed_origin).strip():
            raise ValueError("lifecycle_authorization_origin_required")
        if not str(self.actor).strip():
            raise ValueError("lifecycle_authorization_actor_required")
        if any(not str(item).strip() for item in self.satisfied_requirements):
            raise ValueError("lifecycle_authorization_requirement_invalid")
        if not str(self.contract_version).strip():
            raise ValueError("lifecycle_authorization_contract_required")

    def as_dict(self) -> dict[str, object]:
        return {
            "authorized": self.authorized,
            "engagement_id": self.engagement_id,
            "allowed_origin": self.allowed_origin,
            "actor": self.actor,
            "satisfied_requirements": list(self.satisfied_requirements),
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True)
class LifecycleRunContext:
    """Bounded identity for one case run; runtime objects are intentionally absent."""

    run_id: str
    target_id: str
    case_id: str
    engagement_id: str
    contract_version: str = LIFECYCLE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        for name in ("run_id", "target_id", "case_id", "engagement_id", "contract_version"):
            if not str(getattr(self, name)).strip():
                raise ValueError(f"lifecycle_run_{name}_required")

    def as_dict(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "case_id": self.case_id,
            "engagement_id": self.engagement_id,
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True)
class LifecycleStageResult:
    """Redaction-safe result from one lifecycle stage."""

    stage: str
    status: LifecycleStageStatus
    reason: str
    observation_refs: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)
    verification: VerificationResult | None = field(default=None, repr=False, compare=False)
    contract_version: str = LIFECYCLE_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if not str(self.stage).strip():
            raise ValueError("lifecycle_stage_required")
        if not str(self.reason).strip():
            raise ValueError("lifecycle_stage_reason_required")
        if len(self.observation_refs) > 20:
            raise ValueError("lifecycle_stage_observation_refs_limit_exceeded")
        if len(self.metadata) > 20:
            raise ValueError("lifecycle_stage_metadata_limit_exceeded")
        if not str(self.contract_version).strip():
            raise ValueError("lifecycle_stage_contract_required")

    def as_dict(self) -> dict[str, object]:
        return {
            "stage": self.stage,
            "status": self.status,
            "reason": self.reason,
            "observation_refs": list(self.observation_refs),
            "metadata": dict(self.metadata),
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True)
class SurfaceObservation:
    """Bounded categorical observation of one same-origin resource."""

    url: str
    classification: SurfaceClassification
    status_code: int | None
    content_type: str
    title_present: bool = False
    link_count: int = 0
    form_count: int = 0
    script_count: int = 0
    api_route_count: int = 0
    observations: tuple[str, ...] = ()
    error: str | None = None

    def __post_init__(self) -> None:
        if not str(self.url).strip():
            raise ValueError("surface_observation_url_required")
        if not 0 <= int(self.link_count) <= 500:
            raise ValueError("surface_observation_link_count_invalid")
        if not 0 <= int(self.form_count) <= 100:
            raise ValueError("surface_observation_form_count_invalid")
        if not 0 <= int(self.script_count) <= 500:
            raise ValueError("surface_observation_script_count_invalid")
        if not 0 <= int(self.api_route_count) <= 500:
            raise ValueError("surface_observation_api_route_count_invalid")
        if len(self.observations) > 30:
            raise ValueError("surface_observation_observations_limit_exceeded")

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["observations"] = list(self.observations)
        return result


__all__ = [
    "CAPABILITY_CONTRACT_VERSION",
    "CASE_CONTRACT_VERSION",
    "LIFECYCLE_CONTRACT_VERSION",
    "CapabilityRecord",
    "CapabilityStatus",
    "CaseDefinition",
    "LifecycleAuthorization",
    "LifecycleRunContext",
    "LifecycleStageResult",
    "LifecycleStageStatus",
    "CaseResult",
    "CaseResultStatus",
    "DiscoveryLimits",
    "SurfaceClassification",
    "SurfaceObservation",
]


# Keep a typed export visible to static checkers while preserving a compact API.
_GENERIC_CONTRACT_TYPES = (
    CapabilityRecord,
    CaseDefinition,
    CaseResult,
    DiscoveryLimits,
    SurfaceObservation,
)

if not _GENERIC_CONTRACT_TYPES:  # pragma: no cover - defensive import marker
    raise RuntimeError("generic_contracts_unavailable")
