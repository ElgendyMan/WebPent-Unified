from webpent.benchmark.waptlab_campaign_profile import build_waptlab_validator_plugin_registry
from webpent.models.evidence_ledger import EvidenceLedgerEntry
from webpent.shared.evidence_ledger import merge_evidence_ledger
from webpent.shared.validator_plugins import (
    PLUGIN_STAGES,
    plugin_capability_gaps,
)


def test_validator_plugin_registry_covers_all_campaigns_without_false_confirmation() -> None:
    # build_validator_plugin_registry() now defaults to the target-neutral
    # GENERIC_CAMPAIGNS inventory (see webpent.shared.validator_plugins);
    # the explicit WAPTLab inventory (20 campaigns) must be requested
    # explicitly via the WAPTLab-specific wrapper.
    plugins = build_waptlab_validator_plugin_registry()

    assert len(plugins) == 20
    assert all(plugin.complete for plugin in plugins)
    assert all(plugin.stages == PLUGIN_STAGES for plugin in plugins)
    human_review = [plugin for plugin in plugins if plugin.evidence_mode == "human-review"]
    # GOED closed 5 of the original 7 validator gaps (download_idor,
    # tenant_context_switching, public_backup_disclosure, laravel_app_debug,
    # public_elasticsearch_exposure now have registered deterministic
    # validators). Only 2 remain unmapped as of this merge.
    assert len(human_review) == 2
    assert {plugin.campaign_key for plugin in human_review} == {
        "elasticsearch_snapshot_traversal",
        "xslt_injection",
    }


def test_plugin_gaps_are_explicit_and_bounded() -> None:
    gaps = plugin_capability_gaps(build_waptlab_validator_plugin_registry())

    assert len(gaps) == 2
    assert all(item["reason"] == "missing-deterministic-validator" for item in gaps)


def test_evidence_ledger_redacts_secrets_and_preserves_causal_metadata() -> None:
    entry = EvidenceLedgerEntry(
        entry_id="entry-idor-1",
        campaign_key="download_idor",
        vuln_class="idor",
        target="https://fixture.local/download?id=42&token=secret-value",
        identity="user-a",
        request_metadata={"method": "GET", "authorization": "Bearer secret-token"},
        response_metadata={"status": 200, "content_length": 12},
        baseline={"status": 404, "body_hash": "sha256:baseline"},
        negative_control={"status": 404},
        oracle={"differential": True, "decision": "needs_review"},
        evidence_hashes={"response": "sha256:response"},
        evidence_refs=["evref_download_1"],
        cleanup_status="complete",
        status="needs_human_review",
    )

    rendered = str(entry.model_dump(mode="json"))
    assert "secret-value" not in rendered
    assert "secret-token" not in rendered
    assert entry.oracle["differential"] is True
    assert entry.status == "needs_human_review"
    assert entry.content_digest().startswith("sha256:")


def test_evidence_ledger_merge_is_idempotent_by_id_and_content() -> None:
    first = EvidenceLedgerEntry(
        entry_id="entry-1",
        campaign_key="header_sqli",
        vuln_class="sqli",
        target="https://fixture.local",
    )
    same_content_different_id = first.model_copy(update={"entry_id": "entry-2"})
    different = first.model_copy(
        update={"entry_id": "entry-3", "campaign_key": "image_fetch_ssrf"}
    )

    merged = merge_evidence_ledger(
        [first.model_dump(mode="json")],
        [same_content_different_id.model_dump(mode="json"), different.model_dump(mode="json")],
    )

    assert [item["entry_id"] for item in merged] == ["entry-1", "entry-3"]



def test_validator_outcome_projects_to_redacted_ledger_entry() -> None:
    from webpent.agents.validator.agent import _ledger_entry_for_finding
    from webpent.models.findings import Finding, Severity, VulnClass

    finding = Finding(
        title="Fixture SQL injection",
        severity=Severity.HIGH,
        description="A bounded offline validation fixture.",
        tool_name="sqlmap",
        url="https://fixture.local/item?id=1&token=secret-value",
        vuln_class=VulnClass.SQLI,
        confidence_level="Needs Human Review",
        reasoning="negative control requires human review",
        evidence={
            "campaign_key": "header_sqli",
            "identity_ref": "identity:user-a",
            "validation_attempted": True,
            "validation_failure_reason": "tool_no_marker",
            "request_metadata": {"method": "GET", "authorization": "Bearer secret-token"},
            "evidence_refs": ["evref:fixture-1"],
        },
    )

    entry = _ledger_entry_for_finding(finding)
    rendered = str(entry.model_dump(mode="json"))

    assert entry.entry_id == f"finding:{finding.id}"
    assert entry.campaign_key == "header_sqli"
    assert entry.status == "needs_human_review"
    assert entry.evidence_refs == ["evref:fixture-1"]
    assert "secret-value" not in rendered
    assert "secret-token" not in rendered
    assert entry.content_digest().startswith("sha256:")


def test_offline_fixture_capabilities_are_not_live_validators() -> None:
    """MERGE 2026-10-26 UPDATE: superseded by the validator coverage engine.

    The l6 lineage's Phase-6 coverage engine (postp0_checks.py section 6,
    registry.py) promoted the three former offline-fixture classes to LIVE
    deterministic validators. The merged tree adopts that promotion
    deliberately (docs/vip_autonomous_bug_hunter_traceability.md + the
    coverage-engine tests). This test now pins the promoted reality:
    live status, deterministic validator ids, and the honest producer gap
    for the two classes that still have no live producer agent.
    """
    from webpent.agents.validator.registry import capability_for, validator_id_for

    elasticsearch = capability_for("elasticsearch_snapshot_traversal")
    xslt = capability_for("xslt_injection")
    unknown = capability_for("unknown_future_class")

    assert elasticsearch.status == "tested"
    assert elasticsearch.evidence_mode == "deterministic"
    assert xslt.status == "tested"
    assert xslt.evidence_mode == "deterministic"
    assert validator_id_for("elasticsearch_snapshot_traversal") is not None
    assert validator_id_for("xslt_injection") is not None
    assert unknown.status == "missing-validator"
    assert unknown.validator_id is None
