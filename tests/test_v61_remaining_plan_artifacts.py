"""Contract checks for the remaining-plan release artifacts."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _read_json(name: str) -> dict:
    return json.loads((PROJECT_ROOT / "docs" / name).read_text(encoding="utf-8"))


def test_capability_report_exposes_validator_and_live_boundaries() -> None:
    report = _read_json("capability_report.json")

    assert report["catalog_count"] == 20
    assert report["live_qualification"] is False
    assert sum(report["validator_status_counts"].values()) == report["catalog_count"]
    assert "offline-fixture" in report["validator_status_counts"]
    assert "missing-validator" not in report["validator_status_counts"]


def test_mock_qualification_report_is_reproducible_but_not_live() -> None:
    report = _read_json("waptlab_qualification_report.json")

    assert report["run_count"] == 3
    assert report["stable_campaign_signatures"] is True
    assert report["live_qualification"] is False
    assert report["target_contacted"] is False
    assert report["waptlab_modified"] is False
    assert report["tool_confirmed_minimum"] == 5
    assert report["final_confirmed_minimum"] == 0
    assert report["precision"]["status"] == "not_measured"
    assert report["recall"]["status"] == "blocked_live"


def test_release_manifest_does_not_confuse_integrity_with_signature() -> None:
    manifest = _read_json("release_manifest.json")

    assert manifest["schema_version"] == "webpent-release-manifest-v1"
    assert manifest["file_count"] > 0
    assert manifest["qualification"]["live_qualification"] is False
    assert manifest["signature"]["status"] in {"not_configured", "operator_required"}
    assert "note" in manifest["signature"]


def test_capability_entries_cover_the_catalog() -> None:
    report = _read_json("capability_report.json")
    assert len(report["entries"]) == report["catalog_count"]


def test_capability_entries_have_stable_keys() -> None:
    report = _read_json("capability_report.json")
    keys = [entry["key"] for entry in report["entries"]]
    assert len(keys) == len(set(keys))
    assert all(keys)


def test_capability_entries_expose_evidence_mode() -> None:
    report = _read_json("capability_report.json")
    assert all(entry["evidence_mode"] for entry in report["entries"])


def test_capability_live_validator_ids_are_not_offline_ids() -> None:
    report = _read_json("capability_report.json")
    live_entries = [entry for entry in report["entries"] if entry["validator_status"] == "tested"]
    assert live_entries
    assert all(not entry["validator_id"].startswith("offline-fixture:") for entry in live_entries)


def test_qualification_runs_are_complete() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert all(run["campaign_count"] == 20 for run in report["runs"])


def test_qualification_runs_have_stable_signatures() -> None:
    report = _read_json("waptlab_qualification_report.json")
    signatures = {run["signature"] for run in report["runs"]}
    assert len(signatures) == 1


def test_qualification_runs_record_runtime_gaps() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert all(run["missing_runtime_fields"] for run in report["runs"])


def test_qualification_runs_are_non_contacting() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["target_contacted"] is False
    assert report["waptlab_modified"] is False


def test_qualification_does_not_promote_final_confirmations() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["final_confirmed_counts"] == [0, 0, 0]


def test_qualification_preserves_tool_confirmed_counts() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["tool_confirmed_counts"] == [5, 5, 5]


def test_precision_requires_known_negative_catalog() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["precision"]["status"] == "not_measured"
    assert "known-negative" in report["precision"]["reason"]


def test_recall_requires_live_runtime_qualification() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["recall"]["status"] == "blocked_live"
    assert "runtime" in report["recall"]["reason"]


def test_release_manifest_contains_file_hashes() -> None:
    manifest = _read_json("release_manifest.json")
    assert manifest["files"]
    assert all(isinstance(digest, str) and digest for digest in manifest["files"].values())


def test_environment_profile_defaults_to_lab(monkeypatch) -> None:
    from webpent.config.settings import EnvironmentProfile, Settings

    monkeypatch.delenv("ENVIRONMENT_PROFILE", raising=False)
    monkeypatch.delenv("WEBPENT_ENVIRONMENT_PROFILE", raising=False)
    assert Settings().environment_profile is EnvironmentProfile.LAB


def test_non_lab_environment_requires_authentication(monkeypatch) -> None:
    from pydantic import ValidationError

    from webpent.config.settings import Settings

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "production")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    with pytest.raises(ValidationError, match="environment_profile"):
        Settings()


def test_preflight_projects_degraded_checks_to_warning() -> None:
    from webpent.shared.preflight import _posture_state

    report = {"capability": {"status": "degraded — local fallback"}}
    posture = _posture_state(report, "lab")
    assert posture["state"] == "READY_WITH_WARNING"
    assert posture["allowed_to_start"] is True


def test_playwright_preflight_uses_installed_package_metadata(monkeypatch) -> None:
    from webpent.shared import preflight

    class _PlaywrightWithoutVersion:
        pass

    monkeypatch.setitem(__import__("sys").modules, "playwright", _PlaywrightWithoutVersion())
    monkeypatch.setattr(preflight.importlib.metadata, "version", lambda name: "1.48.0")
    result = preflight._check_playwright_ws_guard()
    assert result["version"] == "1.48.0"
    assert result["ws_guard_available"] is True


def test_checkpoint_policy_requires_strict_msgpack_outside_lab(monkeypatch) -> None:
    from webpent.graph import checkpoints

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "production")
    monkeypatch.delenv("LANGGRAPH_STRICT_MSGPACK", raising=False)
    with pytest.raises(RuntimeError, match="LANGGRAPH_STRICT_MSGPACK"):
        checkpoints._enforce_checkpoint_deserialization_policy()


def test_checkpoint_policy_allows_lab_without_strict(monkeypatch) -> None:
    from webpent.graph import checkpoints

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "lab")
    monkeypatch.delenv("LANGGRAPH_STRICT_MSGPACK", raising=False)
    checkpoints._enforce_checkpoint_deserialization_policy()


def test_checkpoint_policy_accepts_strict_msgpack(monkeypatch) -> None:
    from webpent.graph import checkpoints

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "staging")
    monkeypatch.setenv("LANGGRAPH_STRICT_MSGPACK", "true")
    checkpoints._enforce_checkpoint_deserialization_policy()


def test_checkpoint_policy_rejects_false_strict_msgpack(monkeypatch) -> None:
    from webpent.graph import checkpoints

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "production")
    monkeypatch.setenv("LANGGRAPH_STRICT_MSGPACK", "false")
    with pytest.raises(RuntimeError, match="LANGGRAPH_STRICT_MSGPACK"):
        checkpoints._enforce_checkpoint_deserialization_policy()


def test_environment_template_documents_checkpoint_policy() -> None:
    template = (PROJECT_ROOT / ".env.example").read_text(encoding="utf-8")
    assert "ENVIRONMENT_PROFILE=lab" in template
    assert "LANGGRAPH_STRICT_MSGPACK=true" in template


def test_preflight_artifact_is_fail_closed_and_explicit() -> None:
    report = _read_json("preflight_report.json")
    posture = report["posture"]
    assert posture["state"] in {
        "UNKNOWN",
        "BLOCKED",
        "PASS",
        "READY_WITH_WARNING",
        "DEGRADED",
    }
    assert isinstance(posture["allowed_to_start"], bool)
    assert posture["fail_closed"] is True


def test_release_gate_preserves_unresolved_blockers() -> None:
    gate = _read_json("vip_quality_gate.json")
    assert gate["known_blockers"]
    if gate["known_blockers"]:
        assert gate["passed"] is False


def test_offline_fixture_status_is_not_live_confirmation() -> None:
    report = _read_json("capability_report.json")
    offline = [
        entry for entry in report["entries"] if entry["validator_status"] == "offline-fixture"
    ]
    assert offline
    assert all(entry["live_waptlab_evidence"] is False for entry in offline)


def test_local_qualification_boundary_remains_explicit() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["live_qualification"] is False
    assert report["target_contacted"] is False
    assert report["waptlab_modified"] is False


def test_release_manifest_hashes_are_sha256() -> None:
    manifest = _read_json("release_manifest.json")
    assert manifest["files"]
    assert all(len(digest) == 64 for digest in manifest["files"].values())


def test_release_manifest_signature_is_operator_controlled() -> None:
    signature = _read_json("release_manifest.json")["signature"]
    assert signature["status"] in {"not_configured", "operator_required"}
    assert signature.get("note")


def test_capability_statuses_are_bounded() -> None:
    statuses = set(_read_json("capability_report.json")["validator_status_counts"])
    assert statuses <= {"tested", "offline-fixture", "missing-validator"}
    assert "missing-validator" not in statuses


def test_mock_qualification_is_reproducible_but_not_confirmed_live() -> None:
    report = _read_json("waptlab_qualification_report.json")
    assert report["run_count"] == 3
    assert report["stable_campaign_signatures"] is True
    assert report["final_confirmed_minimum"] == 0
    assert report["recall"]["status"] == "blocked_live"


def test_gate_contains_security_and_preflight_checks() -> None:
    names = {check["name"] for check in _read_json("vip_quality_gate.json")["checks"]}
    assert {"bandit-high-severity", "pip-audit-strict", "preflight-report-contract"} <= names


def test_release_manifest_file_count_matches_hash_map() -> None:
    manifest = _read_json("release_manifest.json")
    assert manifest["file_count"] == len(manifest["files"])


def test_non_lab_settings_require_auth_and_allow_secure_profile(monkeypatch) -> None:
    from pydantic import ValidationError

    from webpent.config.settings import Settings

    monkeypatch.setenv("ENVIRONMENT_PROFILE", "production")
    monkeypatch.setenv("AUTH_ENABLED", "false")
    with pytest.raises(ValidationError):
        Settings()
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret-" + "x" * 40)
    monkeypatch.setenv("AUDIT_SECRET_KEY", "test-audit-secret-" + "x" * 40)
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "test-celery-key-" + "x" * 40)
    # GOED added a hard stop requiring explicit (non-wildcard) CORS origins
    # outside lab/dev profiles — see settings.py's cors_origins validator.
    monkeypatch.setenv("CORS_ORIGINS", '["https://app.example.test"]')
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_REDIS_URL", "rediss://redis.example.test:6380/0")
    assert Settings().environment_profile.value == "production"
