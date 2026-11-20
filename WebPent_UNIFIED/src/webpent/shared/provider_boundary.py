"""Provider, target-package, and proof boundary contracts.

Providers may produce advisory text or structured suggestions only.  This
module never stores raw credentials, invokes a provider implicitly, authorizes
a task, or promotes a finding.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive


@dataclass(frozen=True)
class ProviderConfig:
    provider_id: str
    model: str
    base_url: str
    credential_ref: str = ""
    enabled: bool = False
    max_tokens: int = 512

    def safe_descriptor(self) -> dict[str, Any]:
        return {
            "provider_id": self.provider_id[:120],
            "model": self.model[:160],
            "base_url": self.base_url[:240],
            "credential_ref": self.credential_ref[:120],
            "enabled": bool(self.enabled),
            "max_tokens": max(1, min(8192, int(self.max_tokens))),
        }


@dataclass(frozen=True)
class ProviderResult:
    provider_id: str
    status: str
    advisory: Mapping[str, Any]
    fallback_used: bool = False
    reason: str = ""

    @property
    def can_authorize_action(self) -> bool:
        return False

    @property
    def can_confirm_finding(self) -> bool:
        return False

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "provider_id": self.provider_id,
                "status": self.status,
                "advisory": dict(self.advisory),
                "fallback_used": self.fallback_used,
                "reason": self.reason,
                "can_authorize_action": False,
                "can_confirm_finding": False,
            }
        )
        return clean if isinstance(clean, dict) else {"status": "inconclusive"}


class ProviderBoundary:
    """Explicit opt-in provider adapter with deterministic fallback."""

    def __init__(
        self, config: ProviderConfig, *, fallback: Mapping[str, Any] | None = None
    ) -> None:
        self.config = config
        self.fallback = dict(
            fallback or {"decision": "inconclusive", "next_step": "deterministic_checks"}
        )

    def invoke(
        self,
        request: Mapping[str, Any],
        adapter: Callable[[ProviderConfig, Mapping[str, Any]], Mapping[str, Any]] | None = None,
    ) -> ProviderResult:
        clean_request, _ = redact_sensitive(dict(request))
        if not self.config.enabled:
            return ProviderResult(
                self.config.provider_id, "disabled", self.fallback, True, "provider_disabled"
            )
        if adapter is None:
            return ProviderResult(
                self.config.provider_id,
                "unavailable",
                self.fallback,
                True,
                "adapter_not_configured",
            )
        try:
            response = adapter(self.config, clean_request)
        except Exception as exc:  # provider failure must not become a finding or action
            return ProviderResult(
                self.config.provider_id,
                "fallback",
                self.fallback,
                True,
                f"provider_error:{type(exc).__name__}",
            )
        if not isinstance(response, Mapping):
            return ProviderResult(
                self.config.provider_id,
                "fallback",
                self.fallback,
                True,
                "invalid_provider_response",
            )
        advisory, _ = redact_sensitive(dict(response))
        return ProviderResult(self.config.provider_id, "advisory", advisory, False, "")


@dataclass(frozen=True)
class TargetPackageIdentity:
    package_id: str
    package_sha256: str
    scope_digest: str
    policy_digest: str

    def fingerprint(self) -> str:
        payload = {
            "package_id": self.package_id,
            "package_sha256": self.package_sha256,
            "scope_digest": self.scope_digest,
            "policy_digest": self.policy_digest,
        }
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

    def matches(self, other: TargetPackageIdentity) -> bool:
        return self == other and all(
            str(value).strip()
            for value in (
                self.package_id,
                self.package_sha256,
                self.scope_digest,
                self.policy_digest,
            )
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "package_id": self.package_id[:160],
            "package_sha256": self.package_sha256[:160],
            "scope_digest": self.scope_digest[:160],
            "policy_digest": self.policy_digest[:160],
            "fingerprint": self.fingerprint(),
        }


class TargetPackageGuard:
    def __init__(self, expected: TargetPackageIdentity) -> None:
        self.expected = expected

    def verify(self, observed: TargetPackageIdentity | None) -> tuple[bool, str]:
        if observed is None:
            return False, "target_package:missing"
        if not self.expected.matches(observed):
            return False, "target_package:identity_mismatch"
        return True, "target_package:matched"


__all__ = [
    "ProviderBoundary",
    "ProviderConfig",
    "ProviderResult",
    "TargetPackageGuard",
    "TargetPackageIdentity",
]
