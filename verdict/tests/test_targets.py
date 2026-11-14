"""U-VERDICT-3 — Target Configuration Manager tests (8 tests)."""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_target_yaml
from verdict_tool.targets import (
    Target,
    TargetConfigError,
    TargetManager,
    target_from_yaml,
)


def test_valid_target_loads(target_yaml: Path) -> None:
    target = target_from_yaml(target_yaml)
    assert target.name == "target_a"
    assert target.platform == "hackerone"
    assert target.legal_review_completed is True
    assert target.safe_harbor is True
    assert target.max_rate_rps == 5
    assert TargetManager.validate(target) == []


def test_reject_missing_legal_review(tmp_path: Path) -> None:
    path = write_target_yaml(tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(
        text.replace("legal_review_completed: true",
                     "legal_review_completed: false"),
        encoding="utf-8",
    )
    with pytest.raises(TargetConfigError, match="legal review"):
        target_from_yaml(path)


def test_reject_unsafe_harbor(tmp_path: Path) -> None:
    path = write_target_yaml(tmp_path)
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("safe_harbor: true", "safe_harbor: false"),
                    encoding="utf-8")
    with pytest.raises(TargetConfigError, match="safe harbor"):
        target_from_yaml(path)


def test_no_credentials_in_yaml(tmp_path: Path) -> None:
    path = write_target_yaml(tmp_path)
    text = path.read_text(encoding="utf-8")
    bad_secret = path.with_name("secret.yaml")
    bad_secret.write_text(
        text + "\nsecret:\n  token: abc123\n", encoding="utf-8")
    with pytest.raises(TargetConfigError, match="credential"):
        target_from_yaml(bad_secret)
    bad_key = path.with_name("apikey.yaml")
    bad_key.write_text(text.replace(
        "has_test_account: false", "api_key: sk-live-123"), encoding="utf-8")
    with pytest.raises(TargetConfigError, match="credential"):
        target_from_yaml(bad_key)


def test_reject_bad_scope_and_url(tmp_path: Path) -> None:
    path = write_target_yaml(tmp_path)
    text = path.read_text(encoding="utf-8")
    bad_scope = path.with_name("scope.yaml")
    bad_scope.write_text(text.replace(
        '  in_scope:\n    - "*.example.com"\n', "  in_scope: []\n"),
        encoding="utf-8")
    with pytest.raises(TargetConfigError, match="in_scope"):
        target_from_yaml(bad_scope)
    bad_url = path.with_name("url.yaml")
    bad_url.write_text(text.replace("https://example.com/security",
                                    "http://example.com/security"),
                       encoding="utf-8")
    with pytest.raises(TargetConfigError, match="https"):
        target_from_yaml(bad_url)


def test_duplicate_target_rejected(tmp_path: Path) -> None:
    manager = TargetManager(tmp_path / "targets")
    first = write_target_yaml(tmp_path, name="target_a", handle="handle_a")
    manager.add(first)
    again = write_target_yaml(tmp_path, name="target_b", handle="handle_a")
    with pytest.raises(TargetConfigError, match="duplicate"):
        manager.add(again)
    same_name = write_target_yaml(tmp_path, name="target_a",
                                  handle="other_handle")
    with pytest.raises(TargetConfigError, match="duplicate"):
        manager.add(same_name)


def test_validate_reports_doctored_errors() -> None:
    broken = Target(name="broken", platform="darkweb",
                    program_url="http://x", program_handle="x",
                    in_scope=[], safe_harbor=False, max_rate_rps=0,
                    automation_allowed=True, legal_review_completed=False)
    errors = TargetManager.validate(broken)
    assert len(errors) >= 6
    assert any("legal review" in e for e in errors)
    assert any("safe_harbor" in e for e in errors)


def test_webpent_mapping_and_accessibility(target_yaml: Path,
                                           monkeypatch) -> None:
    target = target_from_yaml(target_yaml)
    mapping = TargetManager.get_config_for_webpent(target)
    assert set(mapping) == {"target", "scope", "policy", "output"}
    assert mapping["policy"]["max_rate_rps"] == 5
    assert mapping["scope"]["in_scope"] == ["*.example.com"]
    # a target that cannot be reached is a clean False, never an exception
    import verdict_tool.targets as targets_mod

    monkeypatch.setattr(targets_mod, "_http_head",
                        lambda url, timeout=5: (_ for _ in ()).throw(
                            OSError("offline")))
    assert TargetManager.check_accessibility(target) is False
    monkeypatch.setattr(targets_mod, "_http_head", lambda url, timeout=5: 200)
    assert TargetManager.check_accessibility(target) is True
    monkeypatch.setattr(targets_mod, "_http_head",
                        lambda url, timeout=5: (_ for _ in ()).throw(
                            OSError("denied")))
    assert TargetManager.check_accessibility(target) is False
