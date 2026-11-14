"""Explicit WAPTLab offline fixture profile.

This module owns the WAPTLab campaign keys and oracle mapping. It is not a live
executor and must be selected explicitly by a WAPTLab adapter or test harness.
"""

from __future__ import annotations

from webpent.benchmark.waptlab_campaign_profile import WAPTLAB_CAMPAIGNS
from webpent.shared.offline_validator_fixtures import (
    OfflineValidatorFixtureSpec,
    build_offline_validator_fixture_registry,
)
from webpent.shared.offline_validator_fixtures import (
    evaluate_offline_fixture as evaluate_generic_offline_fixture,
)
from webpent.shared.proof_oracles import OracleFamily

_WAPTLAB_OFFLINE_KEYS = frozenset(
    {
        "mass_assignment",
        "request_smuggling",
        "cloud_storage_exposure",
        "subdomain_takeover",
        "jwt_key_confusion",
        "download_idor",
        "tenant_context_switching",
        "elasticsearch_snapshot_traversal",
        "public_backup_disclosure",
        "laravel_app_debug",
        "public_elasticsearch_exposure",
        "xslt_injection",
    }
)


def build_waptlab_offline_validator_fixture_registry() -> tuple[
    OfflineValidatorFixtureSpec, ...
]:
    """Return the legacy WAPTLab offline fixture profile explicitly."""
    specs = list(
        build_offline_validator_fixture_registry(
            WAPTLAB_CAMPAIGNS,
            offline_keys=_WAPTLAB_OFFLINE_KEYS,
        )
    )
    existing_keys = {spec.campaign_key for spec in specs}
    for key in (
        "mass_assignment",
        "request_smuggling",
        "cloud_storage_exposure",
        "subdomain_takeover",
        "jwt_key_confusion",
    ):
        if key in existing_keys:
            continue
        specs.insert(
            0,
            OfflineValidatorFixtureSpec(
                campaign_key=key,
                vuln_class=key,
                adapter_id=f"offline-fixture:{key}",
            ),
        )
    return tuple(specs)


def _oracle_family_for_waptlab_campaign(campaign_key: str) -> OracleFamily | None:
    if campaign_key in {"download_idor", "tenant_context_switching"}:
        return OracleFamily.IDOR
    if campaign_key == "image_fetch_ssrf":
        return OracleFamily.SSRF
    if campaign_key in {"stored_profile_xss", "stored_message_xss"}:
        return OracleFamily.STORED_XSS
    if campaign_key in {"csv_ingestion_sqli", "csv_upload_sqli"}:
        return OracleFamily.CSV_SQLI
    if campaign_key == "request_smuggling":
        return OracleFamily.REQUEST_SMUGGLING
    if campaign_key == "cloud_storage_exposure":
        return OracleFamily.CLOUD_STORAGE_EXPOSURE
    if campaign_key == "subdomain_takeover":
        return OracleFamily.SUBDOMAIN_TAKEOVER
    if campaign_key == "jwt_key_confusion":
        return OracleFamily.JWT_KEY_CONFUSION
    return None


def evaluate_waptlab_offline_fixture(bundle: dict[str, object]) -> dict[str, object]:
    """Evaluate WAPTLab synthetic evidence through the generic contract."""
    return evaluate_generic_offline_fixture(
        bundle,
        registry=build_waptlab_offline_validator_fixture_registry(),
        oracle_family_resolver=_oracle_family_for_waptlab_campaign,
    )


__all__ = [
    "build_waptlab_offline_validator_fixture_registry",
    "evaluate_waptlab_offline_fixture",
]
