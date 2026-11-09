"""Tests for the mandatory engagement authorization gate (v78, Task 1-2)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from webpent.autonomous.authorization import (
    AuthorizationError,
    EngagementAuthorization,
    load_authorization,
    origin_of,
    require_authorization,
    verify_authorization,
)

_NOW = datetime(2026, 10, 15, 12, 0, 0, tzinfo=timezone.utc)


def _write_auth(tmp_path: Path, **overrides: object) -> Path:
    document: dict[str, object] = {
        "target_origin": "https://lab.example",
        "scope": ["https://api.lab.example"],
        "operator": "ops@example.corp",
        "authorization_reference": "AUTH-2026-10-15",
        "expires_at": "2026-10-30T00:00:00+00:00",
    }
    document.update(overrides)
    path = tmp_path / "authorization.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_origin_of_strips_credentials() -> None:
    assert origin_of("http://admin:hunter2@site.test/x?a=1") == "http://site.test"
    assert origin_of("https://site.test:8443/x") == "https://site.test:8443"
    assert origin_of("not a url") == ""


def test_verify_accepts_target_and_scope_match(tmp_path: Path) -> None:
    auth = load_authorization(_write_auth(tmp_path))
    ok, reason = verify_authorization("https://lab.example/login", auth, now=_NOW)
    assert ok is True and reason == "authorized"
    ok, reason = verify_authorization("https://api.lab.example/v1", auth, now=_NOW)
    assert ok is True


def test_verify_refuses_out_of_scope_origin(tmp_path: Path) -> None:
    auth = load_authorization(_write_auth(tmp_path))
    ok, reason = verify_authorization("https://other.example/", auth, now=_NOW)
    assert ok is False
    assert "outside the authorized scope" in reason


def test_verify_refuses_expired_authorization(tmp_path: Path) -> None:
    auth = load_authorization(_write_auth(tmp_path))
    late = datetime(2026, 11, 1, tzinfo=timezone.utc)
    ok, reason = verify_authorization("https://lab.example/", auth, now=late)
    assert ok is False
    assert "expired" in reason


def test_verify_refuses_naive_expiry_boundary_exclusive(tmp_path: Path) -> None:
    auth = load_authorization(
        _write_auth(tmp_path, expires_at="2026-10-15T12:00:00")
    )
    ok, _ = verify_authorization("https://lab.example/", auth, now=_NOW)
    # Expiry is exclusive: at exactly expires_at the authorization is gone.
    assert ok is False


def test_load_refuses_missing_file_and_bad_json(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationError, match="not found"):
        load_authorization(tmp_path / "nope.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(AuthorizationError, match="not valid JSON"):
        load_authorization(bad)


def test_load_refuses_missing_required_fields(tmp_path: Path) -> None:
    path = _write_auth(tmp_path, operator="")
    with pytest.raises(AuthorizationError, match="missing required field"):
        load_authorization(path)


def test_load_refuses_empty_scope(tmp_path: Path) -> None:
    # An empty list is caught by the required-fields check first.
    path = _write_auth(tmp_path, scope=[])
    with pytest.raises(AuthorizationError, match="missing required field"):
        load_authorization(path)
    # Entries that resolve to no usable origin reach the scope check.
    path = _write_auth(tmp_path, scope=["not a url", ""])
    with pytest.raises(AuthorizationError, match="authorizes nothing"):
        load_authorization(path)


def test_require_authorization_end_to_end(tmp_path: Path) -> None:
    path = _write_auth(tmp_path)
    auth = require_authorization("https://lab.example/", path, now=_NOW)
    assert isinstance(auth, EngagementAuthorization)
    assert auth.authorization_reference == "AUTH-2026-10-15"
    with pytest.raises(AuthorizationError, match="outside the authorized scope"):
        require_authorization("https://evil.example/", path, now=_NOW)


def test_authorization_record_is_redaction_safe() -> None:
    auth = EngagementAuthorization(
        target_origin="https://lab.example",
        scope=("https://lab.example",),
        operator="ops@example.corp",
        authorization_reference="AUTH-1",
    )
    record = json.dumps(auth.as_dict())
    assert "hunter2" not in record
    assert auth.as_dict()["scope"] == ["https://lab.example"]


def test_origin_normalizes_case_and_default_ports() -> None:
    assert origin_of("https://LAB.Example:443/x") == "https://lab.example"
    assert origin_of("HTTP://SITE.TEST:80/") == "http://site.test"
    assert origin_of("https://site.test:8443") == "https://site.test:8443"


def test_naive_now_is_treated_as_utc_not_crash(tmp_path: Path) -> None:
    auth = load_authorization(_write_auth(tmp_path))
    ok, reason = verify_authorization(
        "https://lab.example/", auth, now=datetime(2026, 10, 14)
    )
    assert ok is True and reason == "authorized"
    ok, reason = verify_authorization(
        "https://lab.example/", auth, now=datetime(2026, 11, 1)
    )
    assert ok is False and "expired" in reason


def test_refusal_message_does_not_imply_target_was_in_scope(tmp_path: Path) -> None:
    auth = load_authorization(_write_auth(tmp_path))
    ok, reason = verify_authorization("https://evil.example/", auth, now=_NOW)
    assert ok is False
    # scope holds exactly the entries it holds; no "-1 more" arithmetic that
    # would imply the target itself was counted inside the scope.
    assert "1 more" not in reason
    assert "1 scope entry" in reason
