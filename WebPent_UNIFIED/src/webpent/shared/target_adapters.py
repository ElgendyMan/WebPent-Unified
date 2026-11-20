"""Explicit, target-scoped adapter contracts for evidence workflows.

The shared proof infrastructure must not know target-specific routes, challenge
IDs, or semantic fingerprints.  A target adapter supplies those facts through
an explicit immutable registration.  Missing or mismatched registrations fail
closed; there is no default target and no cross-target fallback.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CapabilityRecord,
    CaseDefinition,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
)
from webpent.shared.semantic_observations import (
    SemanticProfileRegistry,
)


@dataclass(frozen=True)
class TargetCaseBinding:
    """Target-local case metadata used by an orchestrator."""

    case_id: str
    operation: str
    path: str
    oracle_id: str
    workflow_id: str
    semantic_profile: str | None = None
    scoring_status: str = "not_scored"

    def __post_init__(self) -> None:
        if not str(self.case_id).strip() or not str(self.path).strip():
            raise ValueError("target_case_binding_identity_required")
        if not str(self.oracle_id).strip():
            raise ValueError("target_case_binding_oracle_id_required")
        if not str(self.workflow_id).strip():
            raise ValueError("target_case_binding_workflow_id_required")
        if self.operation not in {"navigate", "typed_search"}:
            raise ValueError("target_case_binding_operation_not_allowlisted")
        if self.semantic_profile is not None and not str(self.semantic_profile).strip():
            raise ValueError("target_case_binding_semantic_profile_invalid")
        if not str(self.scoring_status).strip():
            raise ValueError("target_case_binding_scoring_status_required")


WorkflowExecutor = Callable[[Any, str, int], str | None]
CampaignTaskFactory = Callable[[Mapping[str, Any], str], Any | None]
CampaignResponseProjector = Callable[[Mapping[str, Any], Any, str], Any | None]
CampaignFindingProjector = Callable[[Any, Mapping[str, Any]], Any | None]
CampaignSurfaceSeedProvider = Callable[[Mapping[str, Any], str], Sequence[str] | None]
CampaignRequestContextProvider = Callable[[Mapping[str, Any], str], Mapping[str, Any] | None]
CampaignPathClassifier = Callable[[Mapping[str, Any], str], tuple[str, str] | None]
CampaignLedgerBuilder = Callable[..., Mapping[str, Any]]
CampaignPluginBuilder = Callable[[Sequence[Mapping[str, Any]]], Sequence[Any]]


@dataclass(frozen=True)
class CampaignProfileSpec:
    """Explicit target-local campaign profile supplied at runtime.

    Builders are deliberately kept as runtime callbacks.  Only the stable
    identity is suitable for state/checkpoint projections; callers must never
    serialize this object or infer one from a URL.
    """

    profile_id: str
    source: str
    version: str
    ledger_builder: CampaignLedgerBuilder
    plugin_builder: CampaignPluginBuilder
    execution_contracts: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    contract_version: str = "campaign-profile.v1"

    def __post_init__(self) -> None:
        for field_name in ("profile_id", "source", "version", "contract_version"):
            if not str(getattr(self, field_name) or "").strip():
                raise ValueError(f"campaign_profile_{field_name}_required")
        if not callable(self.ledger_builder):
            raise ValueError("campaign_profile_ledger_builder_not_callable")
        if not callable(self.plugin_builder):
            raise ValueError("campaign_profile_plugin_builder_not_callable")
        if not isinstance(self.execution_contracts, Mapping):
            raise ValueError("campaign_profile_execution_contracts_invalid")

    def descriptor(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "source": self.source,
            "version": self.version,
            "contract_version": self.contract_version,
        }


@dataclass(frozen=True)
class CampaignExtensionSpec:
    """Optional live campaign extension supplied by one target adapter.

    The shared planner only sees this generic contract.  Implementations may
    build a bounded task and/or project already-normalized evidence, but all
    callbacks remain live runtime objects and are never serialized.
    """

    extension_id: str
    task_factory: CampaignTaskFactory | None = None
    response_projector: CampaignResponseProjector | None = None
    finding_projector: CampaignFindingProjector | None = None
    surface_seed_provider: CampaignSurfaceSeedProvider | None = None
    request_context_provider: CampaignRequestContextProvider | None = None
    path_classifier: CampaignPathClassifier | None = None

    def __post_init__(self) -> None:

        if not str(self.extension_id or "").strip():
            raise ValueError("campaign_extension_id_required")
        if (
            self.task_factory is None
            and self.response_projector is None
            and self.finding_projector is None
            and self.surface_seed_provider is None
            and self.request_context_provider is None
            and self.path_classifier is None
        ):
            raise ValueError("campaign_extension_callback_required")
        for name, callback in (
            ("task_factory", self.task_factory),
            ("response_projector", self.response_projector),
            ("finding_projector", self.finding_projector),
            ("surface_seed_provider", self.surface_seed_provider),
            ("request_context_provider", self.request_context_provider),
            ("path_classifier", self.path_classifier),
        ):
            if callback is not None and not callable(callback):
                raise ValueError(f"campaign_extension_{name}_not_callable")


@runtime_checkable
class CaseLifecycleAdapter(Protocol):
    """Optional versioned execution lifecycle for one registered target."""

    lifecycle_contract_version: str

    def describe_target(self) -> Mapping[str, Any]:
        """Return redaction-safe target metadata."""

    def capabilities(self) -> Sequence[CapabilityRecord]:
        """Return the current redaction-safe capability map."""

    def prepare(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Validate target-local preconditions without executing the case."""

    def baseline(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Collect the bounded baseline observation."""

    def execute_safe_action(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Execute only an adapter-declared safe action."""

    def observe(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Collect bounded post-action observations."""

    def execute_negative_control(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Execute an independent negative control or report why unavailable."""

    def cleanup(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        """Dispose adapter-local state without target mutation."""


@runtime_checkable
class TargetAdapter(Protocol):
    """Minimal target-specific surface required by generic proof orchestration."""

    target_id: str
    target_origin: str
    semantic_profiles: SemanticProfileRegistry

    def workflow_ids(self) -> Sequence[str]:
        """Return reviewed workflow IDs allowed for this target."""

    def workflow_executors(self) -> Mapping[str, WorkflowExecutor]:
        """Return target-local executors for workflows that perform browser I/O."""

    def case_ids(self) -> Sequence[str]:
        """Return the immutable execution set for this target."""

    def case(self, case_id: str) -> TargetCaseBinding | None:
        """Return one target-local case binding, or ``None``."""

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        """Return an explicitly registered profile, never an inferred fallback."""

    def accepts_origin(self, origin: str) -> bool:
        """Return whether an origin belongs to this adapter."""


@dataclass(frozen=True)
class TargetManifest:
    """Declarative adapter manifest required for auditable execution."""

    target_id: str
    adapter_version: str
    supported_capabilities: frozenset[str]
    supported_case_types: frozenset[str]
    authorization_requirements: tuple[str, ...]
    allowed_scope: tuple[str, ...]
    redaction_policy: str
    cleanup_policy: str
    contract_version: str = "target-manifest.v1"
    explicit: bool = True

    def validate(self, *, expected_target_id: str) -> tuple[str, ...]:
        errors: list[str] = []
        if self.target_id != expected_target_id:
            errors.append("target_manifest:target_id_mismatch")
        if not self.adapter_version.strip():
            errors.append("target_manifest:adapter_version_required")
        if not self.supported_capabilities:
            errors.append("target_manifest:supported_capabilities_required")
        if not self.supported_case_types:
            errors.append("target_manifest:supported_case_types_required")
        if not self.authorization_requirements:
            errors.append("target_manifest:authorization_requirements_required")
        if not self.allowed_scope:
            errors.append("target_manifest:allowed_scope_required")
        if not self.redaction_policy.strip():
            errors.append("target_manifest:redaction_policy_required")
        if not self.cleanup_policy.strip():
            errors.append("target_manifest:cleanup_policy_required")
        if not self.contract_version.strip():
            errors.append("target_manifest:contract_version_required")
        return tuple(errors)

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "adapter_version": self.adapter_version,
            "supported_capabilities": sorted(self.supported_capabilities),
            "supported_case_types": sorted(self.supported_case_types),
            "authorization_requirements": list(self.authorization_requirements),
            "allowed_scope": list(self.allowed_scope),
            "redaction_policy": self.redaction_policy,
            "cleanup_policy": self.cleanup_policy,
            "contract_version": self.contract_version,
            "explicit": self.explicit,
        }


@dataclass(frozen=True)
class RegisteredTargetAdapter:
    """Auditable target adapter registration."""

    adapter: TargetAdapter
    source: str
    version: str
    policy_ref: str
    proof_contract: str
    manifest: TargetManifest | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def target_id(self) -> str:
        return str(self.adapter.target_id).strip()

    @property
    def effective_manifest(self) -> TargetManifest | None:
        return self.manifest

    def live_manifest_errors(self) -> tuple[str, ...]:
        if self.manifest is None:
            return ("target_manifest:explicit_manifest_required_for_live_execution",)
        errors = list(self.manifest.validate(expected_target_id=self.target_id))
        if not self.manifest.explicit:
            errors.append("target_manifest:explicit_manifest_required_for_live_execution")
        return tuple(errors)

    def validate(self) -> tuple[str, ...]:
        if not isinstance(self.adapter, TargetAdapter):
            return ("target_adapter:adapter_contract_invalid",)
        errors: list[str] = []
        if not self.target_id:
            errors.append("target_adapter:target_id_required")
        if not str(self.adapter.target_origin).strip():
            errors.append(f"target_adapter:{self.target_id}:origin_required")
        if not str(self.source).strip():
            errors.append(f"target_adapter:{self.target_id}:source_required")
        if not str(self.version).strip():
            errors.append(f"target_adapter:{self.target_id}:version_required")
        if not str(self.policy_ref).strip():
            errors.append(f"target_adapter:{self.target_id}:policy_ref_required")
        if not str(self.proof_contract).strip():
            errors.append(f"target_adapter:{self.target_id}:proof_contract_required")
        if self.manifest is not None:
            if not isinstance(self.manifest, TargetManifest):
                errors.append(f"target_adapter:{self.target_id}:manifest_invalid")
            else:
                errors.extend(
                    f"target_adapter:{self.target_id}:{error}"
                    for error in self.manifest.validate(expected_target_id=self.target_id)
                )
        if not isinstance(self.adapter.semantic_profiles, SemanticProfileRegistry):
            errors.append(f"target_adapter:{self.target_id}:semantic_registry_required")

        lifecycle_version = getattr(self.adapter, "lifecycle_contract_version", None)
        if lifecycle_version is not None:
            if lifecycle_version != LIFECYCLE_CONTRACT_VERSION:
                errors.append(f"target_adapter:{self.target_id}:lifecycle_contract_version_invalid")
            for method_name in (
                "describe_target",
                "capabilities",
                "prepare",
                "baseline",
                "execute_safe_action",
                "observe",
                "execute_negative_control",
                "cleanup",
            ):
                if not callable(getattr(self.adapter, method_name, None)):
                    errors.append(
                        f"target_adapter:{self.target_id}:lifecycle_method_missing:{method_name}"
                    )
        normalized_origin = _origin(self.adapter.target_origin)
        if not normalized_origin:
            errors.append(f"target_adapter:{self.target_id}:origin_invalid")
        elif self.manifest is not None and isinstance(self.manifest, TargetManifest):
            allowed_scope = frozenset(_origin(item) for item in self.manifest.allowed_scope)
            if normalized_origin not in allowed_scope:
                errors.append(f"target_adapter:{self.target_id}:origin_outside_manifest_scope")
        if normalized_origin:
            try:
                if self.adapter.accepts_origin(normalized_origin) is not True:
                    errors.append(f"target_adapter:{self.target_id}:origin_not_accepted")
            except Exception as exc:
                errors.append(
                    f"target_adapter:{self.target_id}:origin_check_failed:{type(exc).__name__}"
                )

        try:
            workflows = tuple(str(item).strip() for item in self.adapter.workflow_ids())
        except Exception as exc:
            workflows = ()
            errors.append(
                f"target_adapter:{self.target_id}:workflow_ids_failed:{type(exc).__name__}"
            )
        if not workflows or any(not item for item in workflows):
            errors.append(f"target_adapter:{self.target_id}:workflow_allowlist_required")
        if len(set(workflows)) != len(workflows):
            errors.append(f"target_adapter:{self.target_id}:workflow_allowlist_duplicate")
        workflow_set = frozenset(workflows)

        try:
            raw_executors = self.adapter.workflow_executors()
        except Exception as exc:
            raw_executors = {}
            errors.append(
                f"target_adapter:{self.target_id}:workflow_executors_failed:{type(exc).__name__}"
            )
        if not isinstance(raw_executors, Mapping):
            raw_executors = {}
            errors.append(f"target_adapter:{self.target_id}:workflow_executors_invalid")
        executor_keys = tuple(str(key).strip() for key in raw_executors)
        if len(set(executor_keys)) != len(executor_keys):
            errors.append(f"target_adapter:{self.target_id}:workflow_executor_duplicate")
        if any(key not in workflow_set for key in executor_keys):
            errors.append(f"target_adapter:{self.target_id}:workflow_executor_not_allowlisted")
        for key, executor in raw_executors.items():
            if str(key).strip() in workflow_set and not callable(executor):
                errors.append(
                    f"target_adapter:{self.target_id}:workflow_executor_not_callable:{str(key).strip()}"
                )

        extension_provider = getattr(self.adapter, "campaign_extensions", None)
        if extension_provider is not None:
            if not callable(extension_provider):
                errors.append(f"target_adapter:{self.target_id}:campaign_extensions_not_callable")
            else:
                try:
                    raw_extensions = extension_provider()
                except Exception as exc:
                    raw_extensions = {}
                    errors.append(
                        f"target_adapter:{self.target_id}:campaign_extensions_failed:{type(exc).__name__}"
                    )
                extension_errors = _campaign_extension_errors(
                    raw_extensions,
                    target_id=self.target_id,
                )
                errors.extend(extension_errors)

        try:
            case_ids = tuple(str(item).strip() for item in self.adapter.case_ids())
        except Exception as exc:
            case_ids = ()
            errors.append(f"target_adapter:{self.target_id}:case_ids_failed:{type(exc).__name__}")
        if not case_ids:
            errors.append(f"target_adapter:{self.target_id}:case_ids_required")
        if any(not item for item in case_ids):
            errors.append(f"target_adapter:{self.target_id}:case_id_invalid")
        if len(set(case_ids)) != len(case_ids):
            errors.append(f"target_adapter:{self.target_id}:case_id_duplicate")

        if isinstance(self.adapter.semantic_profiles, SemanticProfileRegistry):
            for case_id in case_ids:
                try:
                    binding = self.adapter.case(case_id)
                    declared_profile = self.adapter.semantic_profile_for_case(case_id)
                except Exception as exc:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_resolution_failed:"
                        f"{case_id}:{type(exc).__name__}"
                    )
                    continue
                if binding is None:
                    errors.append(f"target_adapter:{self.target_id}:case_missing:{case_id}")
                    continue
                if binding.case_id != case_id:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_identity_mismatch:{case_id}"
                    )
                if (
                    self.manifest is not None
                    and isinstance(self.manifest, TargetManifest)
                    and binding.operation not in self.manifest.supported_case_types
                ):
                    errors.append(
                        f"target_adapter:{self.target_id}:case_operation_not_manifested:{case_id}"
                    )
                if binding.workflow_id not in workflow_set:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_workflow_not_allowlisted:{case_id}"
                    )
                if binding.operation == "typed_search" and (
                    binding.workflow_id not in raw_executors
                    or not callable(raw_executors.get(binding.workflow_id))
                ):
                    errors.append(
                        f"target_adapter:{self.target_id}:typed_workflow_executor_missing:{case_id}"
                    )
                if declared_profile != binding.semantic_profile:
                    errors.append(
                        f"target_adapter:{self.target_id}:case_profile_mismatch:{case_id}"
                    )
                if (
                    binding.semantic_profile is not None
                    and self.adapter.semantic_profiles.contract(binding.semantic_profile) is None
                ):
                    errors.append(
                        f"target_adapter:{self.target_id}:case_profile_not_registered:{case_id}"
                    )
        return tuple(errors)


class TargetAdapterRegistry:
    """Explicit registry with origin matching and no implicit fallback."""

    def __init__(self) -> None:
        self._targets: dict[str, RegisteredTargetAdapter] = {}

    def register(self, registration: RegisteredTargetAdapter) -> None:
        errors = registration.validate()
        if errors:
            raise ValueError(";".join(errors))
        key = registration.target_id
        if key in self._targets:
            raise ValueError(f"target_adapter:{key}:duplicate_registration")
        self._targets[key] = registration

    def get(self, target_id: str) -> RegisteredTargetAdapter | None:
        return self._targets.get(str(target_id or "").strip())

    def for_origin(self, origin: str) -> RegisteredTargetAdapter | None:
        normalized = _origin(origin)
        if not normalized:
            return None
        matches: list[RegisteredTargetAdapter] = []
        for item in self._targets.values():
            # Registrations are immutable, but their injected adapter may be
            # mutable. Revalidate before every origin lookup so a post-register
            # mutation or provider failure cannot become executable implicitly.
            try:
                if item.validate():
                    continue
                accepted = item.adapter.accepts_origin(normalized)
            except Exception:
                accepted = False
            if accepted is True:
                matches.append(item)
        return matches[0] if len(matches) == 1 else None

    def require_for_origin(self, origin: str) -> RegisteredTargetAdapter:
        registration = self.for_origin(origin)
        if registration is None:
            raise ValueError("target_adapter_origin_not_registered_or_ambiguous")
        return registration

    def require_live_for_origin(self, origin: str) -> RegisteredTargetAdapter:
        registration = self.require_for_origin(origin)
        errors = registration.live_manifest_errors()
        if errors:
            raise ValueError(";".join(errors))
        return registration

    def manifest(self) -> list[dict[str, Any]]:
        return [
            {
                "target_id": item.target_id,
                "target_origin": _origin(item.adapter.target_origin),
                "source": item.source,
                "version": item.version,
                "policy_ref": item.policy_ref,
                "proof_contract": item.proof_contract,
                "case_count": len(tuple(item.adapter.case_ids())),
                "target_manifest": (
                    item.effective_manifest.as_dict()
                    if item.effective_manifest is not None
                    else None
                ),
                "live_manifest_errors": list(item.live_manifest_errors()),
            }
            for item in sorted(self._targets.values(), key=lambda value: value.target_id)
        ]


def lifecycle_adapter_for_registration(
    registration: RegisteredTargetAdapter | None,
    *,
    required: bool = True,
) -> CaseLifecycleAdapter | None:
    """Resolve a validated lifecycle provider without a legacy fallback."""
    if not isinstance(registration, RegisteredTargetAdapter):
        if required:
            raise ValueError("target_lifecycle_registration_required")
        return None
    errors = registration.validate()
    if errors:
        raise ValueError(";".join(errors))
    adapter = registration.adapter
    version = getattr(adapter, "lifecycle_contract_version", None)
    if version is None:
        if required:
            raise ValueError("target_lifecycle_provider_missing")
        return None
    if version != LIFECYCLE_CONTRACT_VERSION or not isinstance(adapter, CaseLifecycleAdapter):
        raise ValueError("target_lifecycle_provider_invalid")
    return adapter


def campaign_profile_for_registration(
    registration: RegisteredTargetAdapter | None,
) -> CampaignProfileSpec | None:
    """Resolve a validated explicit profile from one target registration.

    A missing provider means the target has no vertical profile.  A malformed
    provider is different: it is an execution defect and returns ``None`` so
    callers cannot silently fall back to another target's matrix.
    """
    if not isinstance(registration, RegisteredTargetAdapter):
        return None
    if registration.validate():
        return None
    provider = getattr(registration.adapter, "campaign_profile", None)
    if provider is None or not callable(provider):
        return None
    try:
        profile = provider()
    except Exception:
        return None
    if not isinstance(profile, CampaignProfileSpec):
        return None
    return profile


def campaign_extensions_for_registration(
    registration: RegisteredTargetAdapter | None,
) -> dict[str, CampaignExtensionSpec] | None:
    """Return a revalidated live extension map, or ``None`` on any defect."""
    if not isinstance(registration, RegisteredTargetAdapter):
        return None
    if registration.validate():
        return None
    provider = getattr(registration.adapter, "campaign_extensions", None)
    if provider is None or not callable(provider):
        return {}
    try:
        raw_extensions = provider()
    except Exception:
        return None
    if _campaign_extension_errors(raw_extensions, target_id=registration.target_id):
        return None
    return {str(key).strip(): value for key, value in raw_extensions.items()}


def campaign_surface_seeds_for_registration(
    registration: RegisteredTargetAdapter | None,
    state: Mapping[str, Any],
    target_url: str,
    *,
    max_items: int = 16,
) -> tuple[str, ...] | None:
    """Return bounded, same-origin discovery seeds from a live registration.

    A missing provider is a normal empty result. Any malformed provider output,
    exception, cross-origin URL, or duplicate is fail-closed and returns None.
    This helper performs no I/O and never serializes callback objects.
    """
    extensions = campaign_extensions_for_registration(registration)
    if extensions is None:
        return None
    registration_origin = _origin(registration.adapter.target_origin)
    if max_items <= 0:
        return ()
    seeds: list[str] = []
    for extension in extensions.values():
        provider = extension.surface_seed_provider
        if provider is None:
            continue
        try:
            raw_seeds = provider(state, target_url)
        except Exception:
            return None
        if raw_seeds is None:
            continue
        if isinstance(raw_seeds, (str, bytes)) or not isinstance(raw_seeds, Sequence):
            return None
        for raw_seed in raw_seeds:
            if not isinstance(raw_seed, str):
                return None
            seed = raw_seed.strip()
            if not seed or _origin(seed) != registration_origin:
                return None
            if seed in seeds:
                return None
            seeds.append(seed)
            if len(seeds) > max_items:
                return None
    return tuple(seeds)


def campaign_path_classification_for_registration(
    registration: RegisteredTargetAdapter | None,
    state: Mapping[str, Any],
    target_url: str,
) -> tuple[str, str] | None:
    """Return a target-provided path classification, or None on any defect."""
    extensions = campaign_extensions_for_registration(registration)
    if extensions is None:
        return None
    for extension in extensions.values():
        classifier = extension.path_classifier
        if classifier is None:
            continue
        try:
            result = classifier(state, target_url)
        except Exception:
            return None
        if result is None:
            continue
        if (
            not isinstance(result, tuple)
            or len(result) != 2
            or not all(isinstance(value, str) and value.strip() for value in result)
        ):
            return None
        return (result[0].strip(), result[1].strip())
    return None


def campaign_request_context_for_registration(
    registration: RegisteredTargetAdapter | None,
    state: Mapping[str, Any],
    target_url: str,
) -> Mapping[str, Any] | None:
    """Return one target-provided request context, or None on any defect."""
    extensions = campaign_extensions_for_registration(registration)
    if extensions is None:
        return None
    for extension in extensions.values():
        provider = extension.request_context_provider
        if provider is None:
            continue
        try:
            context = provider(state, target_url)
        except Exception:
            return None
        if context is None:
            continue
        if not isinstance(context, Mapping):
            return None
        return dict(context)
    return None


def _campaign_extension_errors(
    raw_extensions: Any,
    *,
    target_id: str,
) -> tuple[str, ...]:
    if not isinstance(raw_extensions, Mapping):
        return (f"target_adapter:{target_id}:campaign_extensions_invalid",)
    errors: list[str] = []
    normalized_keys: list[str] = []
    for raw_key, raw_spec in raw_extensions.items():
        key = str(raw_key).strip()
        normalized_keys.append(key)
        if not key:
            errors.append(f"target_adapter:{target_id}:campaign_extension_key_invalid")
            continue
        if not isinstance(raw_spec, CampaignExtensionSpec):
            errors.append(f"target_adapter:{target_id}:campaign_extension_spec_invalid:{key}")
            continue
        if raw_spec.extension_id.strip() != key:
            errors.append(f"target_adapter:{target_id}:campaign_extension_identity_mismatch:{key}")
        callbacks = (
            ("task_factory", raw_spec.task_factory),
            ("response_projector", raw_spec.response_projector),
            ("finding_projector", raw_spec.finding_projector),
            ("surface_seed_provider", raw_spec.surface_seed_provider),
            ("request_context_provider", raw_spec.request_context_provider),
            ("path_classifier", raw_spec.path_classifier),
        )
        for callback_name, callback in callbacks:
            if callback is not None and not callable(callback):
                errors.append(
                    f"target_adapter:{target_id}:campaign_extension_"
                    f"{callback_name}_not_callable:{key}"
                )
    if len(set(normalized_keys)) != len(normalized_keys):
        errors.append(f"target_adapter:{target_id}:campaign_extension_duplicate")
    return tuple(errors)


def _origin(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    suffix = "" if default else f":{port}"
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}{suffix}"


__all__ = [
    "CampaignExtensionSpec",
    "CampaignProfileSpec",
    "campaign_profile_for_registration",
    "CampaignFindingProjector",
    "CampaignPathClassifier",
    "CampaignRequestContextProvider",
    "CampaignSurfaceSeedProvider",
    "CampaignResponseProjector",
    "CampaignTaskFactory",
    "RegisteredTargetAdapter",
    "TargetAdapter",
    "TargetManifest",
    "TargetAdapterRegistry",
    "campaign_extensions_for_registration",
    "campaign_path_classification_for_registration",
    "campaign_request_context_for_registration",
    "campaign_surface_seeds_for_registration",
    "TargetCaseBinding",
    "WorkflowExecutor",
]
