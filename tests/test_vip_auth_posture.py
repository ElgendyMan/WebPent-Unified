from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from webpent.api import auth
from webpent.config import settings as settings_module
from webpent.shared import preflight


def test_preflight_blocks_any_public_bind_when_auth_is_disabled(monkeypatch):
    monkeypatch.delenv("I_UNDERSTAND_THIS_IS_INSECURE", raising=False)
    monkeypatch.setattr(
        preflight,
        "_check_redis_security",
        lambda: {
            "status": "ok",
            "broker": {"configured": False},
            "rate_limit": {"configured": False},
        },
    )
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(
            auth_enabled=False,
            cors_origins=["https://console.example.test"],
            rate_limit_enabled=True,
        ),
    )

    with pytest.raises(SystemExit, match="auth disabled"):
        preflight.run_preflight(host="0.0.0.0")


def test_token_endpoint_is_disabled_when_auth_is_off(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(auth_enabled=False),
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.login_for_access_token(SimpleNamespace(username="dev", password="dev"))

    assert exc_info.value.status_code == 404
    assert "disabled" in str(exc_info.value.detail).lower()


def test_auth_off_still_returns_loopback_dev_stub(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(auth_enabled=False),
    )

    user = auth.get_current_user(None)

    assert user.username == "admin"
    assert user.role == "admin"
    assert user.hashed_password == ""


def test_auth_enabled_never_uses_dev_stub(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_settings",
        lambda: SimpleNamespace(auth_enabled=True),
    )

    with pytest.raises(HTTPException) as exc_info:
        auth.get_current_user(None)

    assert exc_info.value.status_code == 401
