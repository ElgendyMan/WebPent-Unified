from webpent.benchmark.waptlab_offline_validator_fixtures import (
    build_waptlab_offline_validator_fixture_registry as build_offline_validator_fixture_registry,
)
from webpent.benchmark.waptlab_offline_validator_fixtures import (
    evaluate_waptlab_offline_fixture as evaluate_offline_fixture,
)


def _complete_bundle(campaign_key: str) -> dict[str, object]:
    return {
        "campaign_key": campaign_key,
        "probe_id": "fixture-probe-01",
        "control_ref": "evidence:control",
        "variant_ref": "evidence:variant",
        "oracle": {
            "evidence_complete": True,
            "causal_signal": True,
            "negative_control_observed": True,
        },
        "cleanup": {"status": "completed"},
    }


def test_offline_registry_covers_exactly_current_missing_campaigns() -> None:
    specs = build_offline_validator_fixture_registry()
    # GOED expanded the explicit WAPTLab offline fixture profile from the
    # original 7 human-review-only campaigns to 12 (adding mass_assignment,
    # request_smuggling, cloud_storage_exposure, subdomain_takeover, and
    # jwt_key_confusion) — see waptlab_offline_validator_fixtures.py.
    assert {spec.campaign_key for spec in specs} == {
        "download_idor",
        "tenant_context_switching",
        "elasticsearch_snapshot_traversal",
        "public_backup_disclosure",
        "laravel_app_debug",
        "public_elasticsearch_exposure",
        "xslt_injection",
        "mass_assignment",
        "request_smuggling",
        "cloud_storage_exposure",
        "subdomain_takeover",
        "jwt_key_confusion",
    }
    assert all(not spec.live_executor_available for spec in specs)
    assert all(not spec.network_allowed for spec in specs)


def test_complete_offline_evidence_is_reviewable_not_a_finding() -> None:
    result = evaluate_offline_fixture(_complete_bundle("download_idor"))
    assert result["disposition"] == "reviewable"
    assert result["finding_created"] is False
    assert result["network_used"] is False


def test_incomplete_or_unclean_offline_evidence_cannot_be_reviewable() -> None:
    incomplete = _complete_bundle("xslt_injection")
    incomplete["oracle"] = {"evidence_complete": True}
    assert evaluate_offline_fixture(incomplete)["disposition"] == "inconclusive"

    unclean = _complete_bundle("tenant_context_switching")
    unclean["cleanup"] = {"status": "pending"}
    assert evaluate_offline_fixture(unclean)["disposition"] == "blocked"


def test_unknown_campaign_is_explicitly_inconclusive() -> None:
    result = evaluate_offline_fixture(_complete_bundle("header_sqli"))
    assert result["disposition"] == "inconclusive"
    assert result["finding_created"] is False


def test_typed_idor_oracle_is_used_and_requires_negative_control() -> None:
    bundle = _complete_bundle("download_idor")
    bundle["typed_observations"] = {
        "owner_accessible": True,
        "foreign_accessible": True,
    }
    result = evaluate_offline_fixture(bundle)
    assert result["disposition"] == "inconclusive"
    assert result["oracle_family"] == "idor"
    assert result["typed_oracle"]["negative_control_observed"] is False
