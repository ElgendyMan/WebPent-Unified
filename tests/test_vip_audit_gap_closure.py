from __future__ import annotations

import time

import pytest


def test_reauth_vault_sweep_removes_expired_records_without_secret_leak() -> None:
    from webpent.auth import reauth_vault

    thread_id = "expired-gap-regression"
    reauth_vault._PASSWORD_VAULT[thread_id] = ("opaque-token", time.time() - 1)
    try:
        assert reauth_vault.sweep_expired(max_items=10) == 1
        assert reauth_vault.unseal_reauth_secret(thread_id) is None
        stats = reauth_vault.vault_stats()
        assert stats["password_records"] >= 0
    finally:
        reauth_vault.clear_reauth_secret(thread_id)


def test_raw_http_rejects_oversized_request_before_socket(monkeypatch) -> None:
    from webpent.agents.request_smuggling import agent
    from webpent.shared.engagement_scope import (
        clear_engagement_target_hosts,
        set_engagement_target_hosts,
    )

    token = set_engagement_target_hosts("https://engagement.example.test")
    connected = False

    def unexpected_connect(*_args, **_kwargs):
        nonlocal connected
        connected = True
        raise AssertionError("request budget must be enforced before connect")

    try:
        monkeypatch.setattr(agent.socket, "create_connection", unexpected_connect)
        result = agent._send_raw_http(
            "engagement.example.test",
            443,
            b"x" * (agent._RAW_MAX_REQUEST_BYTES + 1),
            use_tls=True,
        )
        assert result is None
        assert connected is False
    finally:
        clear_engagement_target_hosts(token)


def test_executable_manifest_rejects_unregistered_binary() -> None:
    from webpent.tools.utils.subprocess import validate_executable

    with pytest.raises(PermissionError):
        validate_executable("unregistered-webpent-tool")


def test_initial_state_exposes_only_opaque_secret_references_when_scrubbed() -> None:
    from webpent.models.targets import Target
    from webpent.state.initial_state import build_initial_state

    state = build_initial_state(
        Target(url="https://engagement.example.test"),
        thread_id="opaque-gap-regression",
        credentials={"username": "alice", "password": ""},
        session_cookies={},
        identity_profiles={},
    )
    assert state["credentials"]["password"] == ""
    assert state["secret_refs"]["credentials"].startswith("vault://")
    assert "password" not in state["secret_refs"]["credentials"]


def test_validator_registry_is_explicit_and_fail_closed() -> None:
    from webpent.agents.validator.registry import capability_for, validator_id_for

    assert validator_id_for("sqli") == "sqli"
    assert capability_for("sqli").status == "tested"
    # request_smuggling gained an offline-fixture fallback capability since
    # this test was written (GOED expanded the offline validator fixture
    # registry — see waptlab_offline_validator_fixtures.py). Use a vuln
    # class with no registered capability at all to test the genuinely
    # unmapped, fail-closed path.
    missing = capability_for("totally_unmapped_vuln_class_for_test")
    assert missing.validator_id is None
    assert missing.status == "missing-validator"
    assert missing.evidence_mode == "human-review"


def test_scan_registry_health_is_operator_visible_and_non_secret() -> None:
    from webpent.api.scan_registry import _set_registry_health, scan_registry_health

    _set_registry_health(ready=False, error="OperationalError")
    health = scan_registry_health()
    assert health["ready"] is False
    assert health["last_error"] == "OperationalError"
    assert "password" not in str(health).lower()
    _set_registry_health(ready=True)


def test_waptlab_campaign_inventory_is_complete_and_fail_closed() -> None:
    from webpent.benchmark.waptlab_campaign_profile import build_waptlab_campaign_ledger

    ledger = build_waptlab_campaign_ledger()
    assert len(ledger["entries"]) == 20
    assert ledger["summary"]["missing-validator"] >= 2
    assert ledger["summary"]["not_observed"] > 0
    assert all(entry["evidence_complete"] is False for entry in ledger["entries"])

    tested = build_waptlab_campaign_ledger(observed_campaigns={"image_fetch_ssrf"})
    image = next(item for item in tested["entries"] if item["key"] == "image_fetch_ssrf")
    assert image["status"] == "tested"
    assert image["evidence_complete"] is True


def test_deserialization_flags_are_structured_and_deny_escape_hatches() -> None:
    from webpent.shared.deserialization import (
        UnsafeDeserializationCommandError,
        validate_deserialization_command,
    )

    safe = validate_deserialization_command(
        "curl --fail --silent --show-error --max-time 5 --output /dev/null "
        "https://oob.example.test/callback"
    )
    assert "https://oob.example.test/callback" in safe

    unsafe_commands = (
        "curl --proxy http://proxy.example.test https://oob.example.test/callback",
        "curl --output /tmp/payload https://oob.example.test/callback",
        "wget --timeout=30 https://oob.example.test/callback",
    )
    for command in unsafe_commands:
        with pytest.raises(UnsafeDeserializationCommandError):
            validate_deserialization_command(command)
