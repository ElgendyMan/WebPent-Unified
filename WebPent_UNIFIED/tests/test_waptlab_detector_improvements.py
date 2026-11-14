from __future__ import annotations

from webpent.agents.hypothesis_analyzer.agent import _classify_by_url_path
from webpent.agents.rabbit_hole.agent import _infer_rabbit_hole_vuln_class
from webpent.agents.validator import structural_checks
from webpent.models.findings import Finding, Severity, VulnClass


def _finding(url: str, vuln_class: str) -> Finding:
    return Finding(
        title=f"Candidate {vuln_class}",
        severity=Severity.HIGH,
        description="bounded regression fixture",
        tool_name="waptlab_regression",
        url=url,
        vuln_class=vuln_class,
    )


def test_common_crm_surfaces_get_specific_hypothesis_classes() -> None:
    cases = {
        "/crm/download/1": VulnClass.IDOR.value,
        "/user_profile/1": VulnClass.IDOR.value,
        "/composer.lock.bak": VulnClass.INFO_DISCLOSURE.value,
        "/swagger_ui": VulnClass.SSRF.value,
        "/email/training": VulnClass.SSTI.value,
        "/documents/xslt": VulnClass.XXE.value,
        "/js/markdown-editor-0.3.0.js": VulnClass.JAVASCRIPT.value,
    }
    for path, expected in cases.items():
        result = _classify_by_url_path(f"http://fixture.local{path}")
        assert result is not None
        assert result[0] == expected


def test_info_disclosure_confirms_public_backup_with_bounded_evidence(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (
            200,
            "PK\x03\x04 backup archive",
            {"content-type": "application/zip"},
        ),
    )
    result = structural_checks.validate_info_disclosure(
        _finding("http://fixture.local/composer.lock.bak", VulnClass.INFO_DISCLOSURE.value)
    )
    # GOED made info-disclosure detection deterministic-but-review-gated by
    # design: a single successful fetch exposing a sensitive artifact is a
    # capped observation, not causal/differential proof, so it is always
    # "Needs Human Review" (never auto-promoted to "Tool-Confirmed") — see
    # validate_info_disclosure's docstring in structural_checks.py.
    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["path_signature"] is True
    assert result.evidence["response_body_capped"] is True


def test_info_disclosure_does_not_confirm_non_sensitive_success(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (200, "ordinary page", {"content-type": "text/plain"}),
    )
    result = structural_checks.validate_info_disclosure(
        _finding("http://fixture.local/about", VulnClass.INFO_DISCLOSURE.value)
    )
    assert result.confidence_level == "Clean"


def test_idor_stays_human_review_without_owner_foreign_oracle(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (
            200,
            "object bytes",
            {"content-type": "application/octet-stream"},
        ),
    )
    result = structural_checks.validate_idor(
        _finding("http://fixture.local/crm/download/1", VulnClass.IDOR.value),
        cookies=None,
    )
    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["owner_foreign_oracle_required"] is True


def test_idor_clean_when_object_is_not_public(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (403, "forbidden", {"content-type": "text/plain"}),
    )
    result = structural_checks.validate_idor(
        _finding("http://fixture.local/crm/download/1", VulnClass.IDOR.value),
        cookies=None,
    )
    assert result.confidence_level == "Clean"


def test_registry_dispatch_capabilities_include_new_structural_classes() -> None:
    from webpent.agents.validator.registry import capability_for

    assert capability_for(VulnClass.INFO_DISCLOSURE.value).status == "tested"
    assert capability_for(VulnClass.IDOR.value).status == "tested"


def test_rabbit_hole_backup_and_archive_are_information_disclosure_candidates() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("backup", "download_and_parse_archive")
        == VulnClass.INFO_DISCLOSURE.value
    )
    assert (
        _infer_rabbit_hole_vuln_class("archive", "fetch")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_url_and_file_mappings_remain_unchanged() -> None:
    assert _infer_rabbit_hole_vuln_class("url", "fetch") == VulnClass.SSRF.value
    assert _infer_rabbit_hole_vuln_class("file", "read_only_parse") == VulnClass.LFI.value


def test_rabbit_hole_credential_mapping_remains_conservative() -> None:
    assert _infer_rabbit_hole_vuln_class("credential", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_unknown_mapping_uses_existing_safe_fallback() -> None:
    assert _infer_rabbit_hole_vuln_class("unclassified", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_source_code_parse_maps_to_information_disclosure() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("source_code", "read_only_parse")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_command_mapping_remains_rce() -> None:
    assert _infer_rabbit_hole_vuln_class("command", "run") == VulnClass.RCE.value


def test_rabbit_hole_path_mapping_remains_lfi() -> None:
    assert _infer_rabbit_hole_vuln_class("path", "read") == VulnClass.LFI.value


def test_rabbit_hole_service_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("service", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_log_and_dump_are_information_disclosure_candidates() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("log", "read_only_parse")
        == VulnClass.INFO_DISCLOSURE.value
    )
    assert (
        _infer_rabbit_hole_vuln_class("dump", "read_only_parse")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_archive_mapping_is_case_insensitive() -> None:
    assert _infer_rabbit_hole_vuln_class("ARCHIVE", "fetch") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_backup_mapping_does_not_depend_on_fetch_action() -> None:
    assert _infer_rabbit_hole_vuln_class("backup", "parse") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_endpoint_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("endpoint", "request") == VulnClass.SSRF.value


def test_rabbit_hole_shell_mapping_remains_rce() -> None:
    assert _infer_rabbit_hole_vuln_class("shell", "execute") == VulnClass.RCE.value


def test_rabbit_hole_config_mapping_remains_rce() -> None:
    assert _infer_rabbit_hole_vuln_class("config", "parse") == VulnClass.RCE.value


def test_rabbit_hole_host_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("host", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_artifact_mapping_is_not_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("artifact", "fetch") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_archive_mapping_is_not_lfi() -> None:
    assert _infer_rabbit_hole_vuln_class("archive", "read") != VulnClass.LFI.value


def test_rabbit_hole_backup_mapping_is_not_rce() -> None:
    assert _infer_rabbit_hole_vuln_class("backup", "run") != VulnClass.RCE.value


def test_rabbit_hole_disclosure_mapping_is_deterministic() -> None:
    first = _infer_rabbit_hole_vuln_class("backup", "fetch")
    second = _infer_rabbit_hole_vuln_class("backup", "fetch")
    assert first == second == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_mapping_returns_known_vulnerability_class() -> None:
    result = _infer_rabbit_hole_vuln_class("backup", "fetch")
    assert result in {member.value for member in VulnClass}


def test_rabbit_hole_info_disclosure_has_tested_registry_capability() -> None:
    from webpent.agents.validator.registry import capability_for

    assert capability_for(
        _infer_rabbit_hole_vuln_class("backup", "fetch")
    ).status == "tested"


def test_rabbit_hole_mapping_does_not_change_validator_contract() -> None:
    from webpent.agents.validator.registry import capability_for

    capability = capability_for(VulnClass.INFO_DISCLOSURE.value)
    assert capability.validator_id
    assert capability.status == "tested"


def test_rabbit_hole_backup_mapping_handles_archive_action() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("public_backup", "download_and_parse_archive")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_archive_mapping_handles_read_only_action() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("public_archive", "read_only_parse")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_public_log_mapping_handles_fetch_action() -> None:
    assert _infer_rabbit_hole_vuln_class("public_log", "fetch") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_public_dump_mapping_handles_fetch_action() -> None:
    assert _infer_rabbit_hole_vuln_class("public_dump", "fetch") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_token_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("token", "read") == VulnClass.SSRF.value


def test_rabbit_hole_link_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("link", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_port_mapping_remains_ssrf() -> None:
    assert _infer_rabbit_hole_vuln_class("port", "fetch") == VulnClass.SSRF.value


def test_rabbit_hole_cmd_mapping_remains_rce() -> None:
    assert _infer_rabbit_hole_vuln_class("cmd", "execute") == VulnClass.RCE.value


def test_rabbit_hole_dir_mapping_remains_lfi() -> None:
    assert _infer_rabbit_hole_vuln_class("dir", "read") == VulnClass.LFI.value


def test_rabbit_hole_source_mapping_remains_info_disclosure() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("source", "read_only_parse")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_rabbit_hole_backup_mapping_with_request_remains_disclosure() -> None:
    assert _infer_rabbit_hole_vuln_class("backup", "request") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_archive_mapping_with_include_remains_disclosure() -> None:
    assert _infer_rabbit_hole_vuln_class("archive", "include") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_unknown_mapping_with_read_uses_lfi_fallback() -> None:
    assert _infer_rabbit_hole_vuln_class("unclassified", "read") == VulnClass.LFI.value


def test_rabbit_hole_unknown_mapping_with_run_uses_rce_fallback() -> None:
    assert _infer_rabbit_hole_vuln_class("unclassified", "run") == VulnClass.RCE.value


def test_rabbit_hole_unknown_mapping_with_request_uses_ssrf_fallback() -> None:
    assert _infer_rabbit_hole_vuln_class("unclassified", "request") == VulnClass.SSRF.value


def test_rabbit_hole_source_code_without_parse_is_disclosure() -> None:
    assert _infer_rabbit_hole_vuln_class("source_code", "fetch") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_archive_is_disclosure_for_execute_action() -> None:
    assert _infer_rabbit_hole_vuln_class("archive", "execute") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_backup_is_disclosure_for_empty_action() -> None:
    assert _infer_rabbit_hole_vuln_class("backup", "") == VulnClass.INFO_DISCLOSURE.value


def test_rabbit_hole_archive_is_disclosure_for_empty_action() -> None:
    assert _infer_rabbit_hole_vuln_class("archive", "") == VulnClass.INFO_DISCLOSURE.value




def test_rabbit_hole_public_backup_and_archive_are_information_disclosure_candidates() -> None:
    assert (
        _infer_rabbit_hole_vuln_class("public_backup", "download_and_parse_archive")
        == VulnClass.INFO_DISCLOSURE.value
    )
    assert (
        _infer_rabbit_hole_vuln_class("public_archive", "fetch")
        == VulnClass.INFO_DISCLOSURE.value
    )


def test_info_disclosure_deterministic_promotion_requires_validator_gate() -> None:
    from webpent.shared.prioritization import _deterministic_promotion_allowed

    assert _deterministic_promotion_allowed("info_disclosure", deterministic_match=True)
    assert not _deterministic_promotion_allowed("info_disclosure", deterministic_match=False)



def test_info_disclosure_confirms_debug_trace_on_server_error(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (
            500,
            "Whoops! APP_DEBUG=true Traceback: /var/www/html/.env",
            {"content-type": "text/plain"},
        ),
    )
    result = structural_checks.validate_info_disclosure(
        _finding("http://fixture.local/debug?trigger=1", VulnClass.INFO_DISCLOSURE.value)
    )
    # See the composer.lock.bak case above: info-disclosure is always
    # "Needs Human Review" now, never auto-"Tool-Confirmed".
    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["debug_markers"]



def test_dashboard_context_switch_surface_stays_human_review(monkeypatch) -> None:
    monkeypatch.setattr(
        structural_checks,
        "_fetch_page",
        lambda *_args, **_kwargs: (200, "tenant object", {"content-type": "application/json"}),
    )
    result = structural_checks.validate_idor(
        _finding(
            "http://fixture.local/dashboard/view-crm/1?db=tenant-b",
            VulnClass.IDOR.value,
        ),
        cookies=None,
    )
    assert result.confidence_level == "Needs Human Review"
    assert result.evidence["owner_foreign_oracle_required"] is True
