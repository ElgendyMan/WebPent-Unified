"""Safe boundary for importing bbscout Target Package v2 metadata.

This module deliberately does not import or execute bbscout code.  The optional
bbscout source remains external and is treated as an untrusted provider-source
adapter.  Only a redaction-safe TargetPackageContext may cross into WebPent.

No browser, HTTP, provider, account-creation, credential, cookie, or target
operation is performed here.  Live execution still requires a verified detached
signature and the existing WebPent ActionAuthority/ActionExecutor path.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from .target_package_context import (
    TargetPackageAdmissionError,
    TargetPackageContext,
    admit_target_package,
)

BridgeMode = Literal["offline", "live"]
_MAX_PACKAGE_BYTES = 5 * 1024 * 1024
_ALLOWED_PROVIDER_SOURCE_STATES = frozenset(
    {"reviewed_as_provider_source_only", "advisory_only"}
)


class BbscoutBridgeError(ValueError):
    """Raised when bbscout metadata cannot safely cross the WebPent boundary."""


@dataclass(frozen=True)
class BbscoutPackageAdmission:
    """Redaction-safe bbscout admission result.

    ``context`` is the only object intended for runtime state.  The other fields
    are scalar/auditable metadata and never contain the raw package or secrets.
    """

    context: TargetPackageContext
    mode: BridgeMode
    live_ready: bool
    provider: str
    program_id: str
    program_handle: str
    package_status: str
    selected_score: float | None
    qualified_capabilities: tuple[str, ...]
    qualified_validators: tuple[str, ...]

    def as_state(self) -> dict[str, Any]:
        """Return a safe state projection without raw provider data."""
        return {
            "bbscout": {
                "mode": self.mode,
                "live_ready": self.live_ready,
                "provider": self.provider,
                "program_id": self.program_id,
                "program_handle": self.program_handle,
                "package_status": self.package_status,
                "selected_score": self.selected_score,
                "qualified_capabilities": list(self.qualified_capabilities),
                "qualified_validators": list(self.qualified_validators),
            },
            "target_package": self.context.as_state(),
        }


def _as_string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, Mapping):
        return ()
    return tuple(sorted(str(key) for key, enabled in value.items() if bool(enabled)))


def _validate_provider_source_policy(package: Mapping[str, Any]) -> None:
    authorization = package.get("authorization")
    policy = package.get("policy")
    if not isinstance(authorization, Mapping) or not isinstance(policy, Mapping):
        raise BbscoutBridgeError("bbscout_authorization_or_policy_missing")
    if authorization.get("read_only_discovery") is not True:
        raise BbscoutBridgeError("bbscout_discovery_must_be_read_only")
    if policy.get("enforcement_state") not in _ALLOWED_PROVIDER_SOURCE_STATES:
        raise BbscoutBridgeError("bbscout_policy_not_provider_source_only")


def admit_bbscout_package(
    package: Mapping[str, Any],
    *,
    mode: BridgeMode = "offline",
    now: datetime | None = None,
) -> BbscoutPackageAdmission:
    """Admit a bbscout package without performing external I/O.

    Offline mode accepts the archive's ``unsigned-local-mvp`` packages only for
    review/dry-run purposes.  Live mode requires the existing verified detached
    signature gate; this function never creates or grants execution authority.
    """
    if mode not in {"offline", "live"}:
        raise BbscoutBridgeError("unsupported_bbscout_bridge_mode")
    if not isinstance(package, Mapping):
        raise BbscoutBridgeError("bbscout_package_not_mapping")
    if str(package.get("package_status") or "") != "ready":
        raise BbscoutBridgeError("bbscout_package_not_ready")
    _validate_provider_source_policy(package)
    try:
        context = admit_target_package(
            package,
            now=now or datetime.now(UTC),
            require_signature=mode == "live",
        )
    except TargetPackageAdmissionError as exc:
        raise BbscoutBridgeError(str(exc)) from exc

    capability_profile = package.get("capability_profile")
    selection = package.get("selection")
    if not isinstance(capability_profile, Mapping) or not isinstance(selection, Mapping):
        raise BbscoutBridgeError("bbscout_capability_or_selection_missing")
    qualified = capability_profile.get("qualified_capabilities")
    validators = capability_profile.get("validators")
    selected_score = selection.get("score")
    if selected_score is not None:
        try:
            selected_score = float(selected_score)
        except (TypeError, ValueError) as exc:
            raise BbscoutBridgeError("bbscout_selection_score_invalid") from exc

    program = package.get("program")
    if not isinstance(program, Mapping):
        program = {}
    return BbscoutPackageAdmission(
        context=context,
        mode=mode,
        live_ready=mode == "live" and context.signature_state == "verified",
        provider=str(package.get("provider") or ""),
        program_id=context.program_id,
        program_handle=context.program_handle,
        package_status=str(package.get("package_status")),
        selected_score=selected_score,
        qualified_capabilities=_as_string_tuple(qualified),
        qualified_validators=_as_string_tuple(validators),
    )


def _parse_allowlist(value: str | None) -> frozenset[str]:
    return frozenset(
        item.strip()
        for item in str(value or "").split(",")
        if item.strip()
    )


def enforce_bbscout_allowlist(
    admission: BbscoutPackageAdmission,
    *,
    provider_ids: str | None = None,
    program_ids: str | None = None,
) -> BbscoutPackageAdmission:
    """Require explicit provider/program identity when an allowlist is configured."""
    allowed_providers = _parse_allowlist(provider_ids)
    allowed_programs = _parse_allowlist(program_ids)
    if allowed_providers and admission.provider not in allowed_providers:
        raise BbscoutBridgeError("bbscout_provider_not_allowlisted")
    if allowed_programs and admission.program_id not in allowed_programs:
        raise BbscoutBridgeError("bbscout_program_not_allowlisted")
    return admission


def load_bbscout_package(
    path: str | Path,
    *,
    mode: BridgeMode = "offline",
    now: datetime | None = None,
) -> BbscoutPackageAdmission:
    """Load one local JSON package and pass it through the safe admission gate."""
    package_path = Path(path).expanduser()
    if not package_path.is_file() or package_path.is_symlink():
        raise BbscoutBridgeError("bbscout_package_file_invalid")
    if package_path.stat().st_size > _MAX_PACKAGE_BYTES:
        raise BbscoutBridgeError("bbscout_package_too_large")
    try:
        package = json.loads(package_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BbscoutBridgeError("bbscout_package_json_invalid") from exc
    return admit_bbscout_package(package, mode=mode, now=now)


__all__ = [
    "BbscoutBridgeError",
    "BbscoutPackageAdmission",
    "admit_bbscout_package",
    "enforce_bbscout_allowlist",
    "load_bbscout_package",
]
