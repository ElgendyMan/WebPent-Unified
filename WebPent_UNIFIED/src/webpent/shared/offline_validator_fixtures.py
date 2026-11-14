"""Generic offline validator fixture contracts.

These adapters consume synthetic, already-collected evidence bundles only. They do
not send requests, execute probes, or create findings. Target-specific campaign
inventories and oracle mappings must be injected by an explicit adapter/profile.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from webpent.shared.campaigns import GENERIC_CAMPAIGNS
from webpent.shared.proof_oracles import OracleEngine, OracleFamily

_REQUIRED_BUNDLE_KEYS: Final[tuple[str, ...]] = (
    "campaign_key",
    "probe_id",
    "control_ref",
    "variant_ref",
    "oracle",
    "cleanup",
)
OracleFamilyResolver = Callable[[str], OracleFamily | None]


@dataclass(frozen=True)
class OfflineValidatorFixtureSpec:
    """A local-only evidence adapter specification."""

    campaign_key: str
    vuln_class: str
    adapter_id: str
    live_executor_available: bool = False
    network_allowed: bool = False


def build_offline_validator_fixture_registry(
    campaigns: Iterable[Mapping[str, Any]] | None = None,
    *,
    offline_keys: frozenset[str] = frozenset(),
) -> tuple[OfflineValidatorFixtureSpec, ...]:
    """Build offline specs from an explicitly selected campaign inventory."""
    selected_campaigns = GENERIC_CAMPAIGNS if campaigns is None else campaigns
    specs: list[OfflineValidatorFixtureSpec] = []
    for campaign in selected_campaigns:
        key = str(campaign.get("key", "")).strip()
        if not key or (
            campaign.get("offline_fixture") is not True and key not in offline_keys
        ):
            continue
        vuln_class = str(campaign.get("validator") or key)
        specs.append(
            OfflineValidatorFixtureSpec(
                campaign_key=key,
                vuln_class=vuln_class,
                adapter_id=f"offline-fixture:{key}",
            )
        )
    return tuple(specs)


def _bundle_status(bundle: dict[str, Any]) -> str:
    missing = [key for key in _REQUIRED_BUNDLE_KEYS if key not in bundle]
    if missing:
        return "inconclusive"
    cleanup = bundle.get("cleanup")
    oracle = bundle.get("oracle")
    if not isinstance(cleanup, dict) or cleanup.get("status") != "completed":
        return "blocked"
    if not isinstance(oracle, dict):
        return "inconclusive"
    if oracle.get("negative_control_observed") is not True:
        return "inconclusive"
    if oracle.get("causal_signal") is not True:
        return "inconclusive"
    if oracle.get("evidence_complete") is not True:
        return "inconclusive"
    return "reviewable"


def evaluate_offline_fixture(
    bundle: dict[str, Any],
    *,
    registry: Iterable[OfflineValidatorFixtureSpec] | None = None,
    oracle_family_resolver: OracleFamilyResolver | None = None,
) -> dict[str, Any]:
    """Classify a local evidence bundle without claiming a confirmed finding."""
    campaign_key = str(bundle.get("campaign_key") or "")
    selected_registry = (
        build_offline_validator_fixture_registry() if registry is None else tuple(registry)
    )
    known = {spec.campaign_key for spec in selected_registry}
    if campaign_key not in known:
        return {
            "campaign_key": campaign_key,
            "disposition": "inconclusive",
            "reason": "unsupported-offline-fixture",
            "finding_created": False,
            "network_used": False,
        }
    typed_observations = bundle.get("typed_observations")
    family = (
        oracle_family_resolver(campaign_key)
        if oracle_family_resolver is not None
        else None
    )
    typed_oracle = None
    if family is not None and isinstance(typed_observations, dict):
        typed_oracle = OracleEngine.evaluate(family, typed_observations)
        bundle = {**bundle, "oracle": typed_oracle.model_dump(mode="json")}
    status = _bundle_status(bundle)
    return {
        "campaign_key": campaign_key,
        "disposition": status,
        "reason": "offline-evidence-contract-only",
        "finding_created": False,
        "network_used": False,
        "cleanup_completed": status == "reviewable",
        "oracle_family": family.value if family is not None else None,
        "typed_oracle": typed_oracle.model_dump(mode="json") if typed_oracle else None,
    }


__all__ = [
    "OfflineValidatorFixtureSpec",
    "OracleFamilyResolver",
    "build_offline_validator_fixture_registry",
    "evaluate_offline_fixture",
]
