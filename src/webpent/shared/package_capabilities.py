"""Capability intersection for Target Package v2 preflight.

This module is deliberately local and deterministic. A package describes the
capabilities it expects; it never grants a capability that the runtime does
not advertise. Missing or blocked capabilities become explicit coverage gaps,
not clean results.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

CAPABILITY_STATUSES = frozenset(
    {"available", "unavailable", "blocked_by_policy", "not_qualified", "optional"}
)


@dataclass(frozen=True)
class CapabilityDecision:
    name: str
    required: bool
    status: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "required": self.required,
            "status": self.status,
            "reason": self.reason,
        }


def _truthy_names(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {str(key).strip().lower() for key, enabled in value.items() if enabled}
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item).strip().lower() for item in value if str(item).strip()}
    if isinstance(value, str) and value.strip():
        return {value.strip().lower()}
    return set()


def _required_names(profile: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    required: set[str] = set()
    optional: set[str] = set()
    for field in ("qualified_capabilities", "validators", "confirmation"):
        value = profile.get(field)
        if isinstance(value, Mapping):
            for key, enabled in value.items():
                name = str(key).strip().lower()
                if not name:
                    continue
                if isinstance(enabled, Mapping):
                    if enabled.get("required") is False or enabled.get("optional") is True:
                        optional.add(name)
                    elif (
                        enabled.get("required") is True
                        or enabled.get("qualified") is True
                        or enabled.get("available") is True
                    ):
                        required.add(name)
                elif enabled:
                    required.add(name)
        else:
            required.update(_truthy_names(value))
    for field in ("optional_capabilities", "optional_validators", "optional_confirmation"):
        optional.update(_truthy_names(profile.get(field)))
    required.difference_update(optional)
    return required, optional


def _manifest_record(manifest: Mapping[str, Any], name: str) -> tuple[bool, bool, bool]:
    """Return (declared, available, qualified) for a local capability."""
    source: Any = manifest.get("capabilities", manifest)
    if isinstance(source, Mapping):
        if name not in {str(key).lower() for key in source}:
            # Preserve case-insensitive manifests without copying values.
            matching = next((key for key in source if str(key).lower() == name), None)
            if matching is None:
                return False, False, False
            value = source[matching]
        else:
            key = next(key for key in source if str(key).lower() == name)
            value = source[key]
    elif isinstance(source, (list, tuple, set, frozenset)):
        declared = name in {str(item).lower() for item in source}
        return declared, declared, declared
    else:
        return False, False, False
    if isinstance(value, Mapping):
        available = bool(
            value.get("available", value.get("enabled", value.get("installed", False)))
        )
        qualified = bool(value.get("qualified", value.get("supported", True)))
        return True, available, qualified
    return True, bool(value), bool(value)


def intersect_capabilities(
    profile: Mapping[str, Any] | None,
    local_manifest: Mapping[str, Any] | None,
    policy_constraints: Mapping[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Intersect package requirements with local capabilities.

    Required capabilities that are absent, disabled, unqualified, or
    prohibited are returned as structured knowledge gaps. Optional capabilities
    never fail preflight and are reported as ``optional`` when unavailable.
    """
    package_profile = profile if isinstance(profile, Mapping) else {}
    manifest = local_manifest if isinstance(local_manifest, Mapping) else {}
    policy = policy_constraints if isinstance(policy_constraints, Mapping) else {}
    prohibited = _truthy_names(policy.get("prohibited_capabilities")) | _truthy_names(
        policy.get("prohibited_actions")
    )
    required, optional = _required_names(package_profile)
    matrix: dict[str, dict[str, Any]] = {}
    gaps: list[dict[str, Any]] = []
    for name in sorted(required | optional):
        is_required = name in required
        if name in prohibited or "all_capabilities" in prohibited:
            status = "blocked_by_policy"
            reason = "local_or_package_policy_prohibits_capability"
        else:
            declared, available, qualified = _manifest_record(manifest, name)
            if not declared or not available:
                status = "unavailable" if is_required else "optional"
                reason = "capability_not_advertised_or_disabled"
            elif not qualified:
                status = "not_qualified"
                reason = "local_capability_not_qualified_for_engagement"
            else:
                status = "available"
                reason = "local_manifest_intersection_succeeded"
        decision = CapabilityDecision(name, is_required, status, reason)
        matrix[name] = decision.as_dict()
        if is_required and status != "available":
            gaps.append(
                {
                    "gap_id": f"target-package-capability:{name}",
                    "kind": "capability_intersection",
                    "capability": name,
                    "status": status,
                    "unknown": reason,
                    "blocking": True,
                    "source": "target_package_preflight",
                }
            )
    return matrix, gaps


__all__ = ["CAPABILITY_STATUSES", "CapabilityDecision", "intersect_capabilities"]
