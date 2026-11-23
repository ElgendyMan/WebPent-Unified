"""UM-DR-45 K4 — authentication startup gate and the development bypass.

State of the trunk before this window (verified in source):

* strict profiles (qualification/staging/production) hard-stop in Settings
  when ``auth_enabled`` is False, and insecure/placeholder/short secrets
  hard-stop when it is True (``config/settings.py``);
* a non-loopback bind with authentication disabled refuses to boot unless the
  operator sets ``I_UNDERSTAND_THIS_IS_INSECURE`` (``shared/preflight.py``);
* requests arriving through a proxy/tunnel are refused while auth is off
  (``api/app.py``); the token endpoint is disabled while auth is off.

What was still missing is pinned here:

1. **fail fast on a missing operator.** ``auth._ensure_seeded`` swallows a
   failed seed (fail-closed: 401 for everyone) but only runs on the first
   request. With ``AUTH_ENABLED=true`` and no ``ADMIN_PASSWORD`` and no valid
   ``WEBPENT_USERS`` entry (the ``.env.example`` CHANGE-ME placeholder is
   refused by design), the API booted cleanly and stayed unreachable forever.
   ``auth.provisioning_defects()`` applies the seeding rules without hashing
   or mutating state; ``preflight._enforce_operator_provisioning`` refuses to
   boot on any defect.
2. **the bypass is announced, not implied.** ``auth_enabled`` still defaults
   to False for lab/loopback compatibility, so the least the process owes the
   operator is a WARNING at boot saying authentication is disabled.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from webpent.api import auth
from webpent.config import settings as settings_module
from webpent.shared import preflight

STRONG = "k" * 48
BYPASS_MARKER = "authentication is DISABLED"
NO_OPERATOR = "neither WEBPENT_USERS nor ADMIN_PASSWORD provisions an operator"
PLACEHOLDER = "placeholder WEBPENT_USERS entry refused (CHANGE-ME-*)"
MALFORMED = "malformed WEBPENT_USERS entry (expected user:password:role)"
TOO_LONG = "WEBPENT_USERS password exceeds the 72-byte bcrypt limit"


def _settings(monkeypatch, **overrides) -> settings_module.Settings:
    """Real Settings with authentication enabled, installed as get_settings()."""
    values: dict = {
        "_env_file": None,
        "auth_enabled": True,
        "environment_profile": "lab",
        "jwt_secret_key": STRONG,
        "audit_secret_key": "a" * 48,
        "celery_payload_key": "c" * 48,
    }
    values.update(overrides)
    cfg = settings_module.Settings(**values)
    monkeypatch.setattr(settings_module, "get_settings", lambda: cfg)
    return cfg


def _unreadable_env() -> list[str]:
    raise OSError("env unreadable")


@pytest.fixture()
def clean_operator_env(monkeypatch):
    for name in ("WEBPENT_USERS", "ADMIN_PASSWORD", "I_UNDERSTAND_THIS_IS_INSECURE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WEBPENT_ALLOW_PLAINTEXT_REDIS", "1")


# ---------------------------------------------------------------------------
# provisioning_defects — the pure probe (same rules as _seed_users_from_env)
# ---------------------------------------------------------------------------


def test_no_operator_at_all_is_a_defect(monkeypatch, clean_operator_env) -> None:
    assert auth.provisioning_defects() == [NO_OPERATOR]


def test_the_env_example_placeholder_provisions_nobody(monkeypatch, clean_operator_env) -> None:
    monkeypatch.setenv("WEBPENT_USERS", "CHANGE-ME:CHANGE-ME:admin")
    assert auth.provisioning_defects() == [PLACEHOLDER]


def test_placeholder_list_never_falls_back_to_admin_password(
    monkeypatch, clean_operator_env
) -> None:
    """Mirrors _seed_users_from_env: a non-empty WEBPENT_USERS never falls
    back to ADMIN_PASSWORD, so a placeholder list still leaves zero users."""
    monkeypatch.setenv("WEBPENT_USERS", "CHANGE-ME:CHANGE-ME:admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-operator-password")
    assert auth.provisioning_defects() == [PLACEHOLDER]


def test_malformed_and_oversized_entries_are_reported(monkeypatch, clean_operator_env) -> None:
    monkeypatch.setenv("WEBPENT_USERS", "garbage,bob:" + "p" * 73 + ":admin")
    assert auth.provisioning_defects() == [MALFORMED, TOO_LONG]


@pytest.mark.parametrize("password", ["", "a-strong-operator-password"])
def test_whitespace_only_user_list_provisions_nobody(
    monkeypatch, clean_operator_env, password: str
) -> None:
    """A whitespace-only list yields no user, and ADMIN_PASSWORD is not used
    because WEBPENT_USERS is not exactly empty."""
    monkeypatch.setenv("WEBPENT_USERS", "   ")
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    (defect,) = auth.provisioning_defects()
    assert "no usable entry" in defect


@pytest.mark.parametrize(
    ("users", "password"),
    [
        ("alice:S3cret-pass:admin", ""),
        ("alice:pa:ss:with:colons:admin", "ignored-when-users-exist"),
        ("", "a-strong-operator-password"),
        ("CHANGE-ME:CHANGE-ME:admin,alice:S3cret-pass:admin", ""),
    ],
)
def test_a_provisionable_operator_has_no_defect(
    monkeypatch, clean_operator_env, users: str, password: str
) -> None:
    monkeypatch.setenv("WEBPENT_USERS", users)
    monkeypatch.setenv("ADMIN_PASSWORD", password)
    assert auth.provisioning_defects() == []


def test_the_probe_does_not_touch_the_user_store(monkeypatch, clean_operator_env) -> None:
    monkeypatch.setenv("WEBPENT_USERS", "alice:S3cret-pass:admin")
    before = dict(auth._USERS)
    seed_attempted = auth._SEED_ATTEMPTED
    assert auth.provisioning_defects() == []
    assert dict(auth._USERS) == before and auth._SEED_ATTEMPTED is seed_attempted


def test_probe_agrees_with_the_real_seeder(monkeypatch, clean_operator_env) -> None:
    """Differential check against the function that actually seeds: the
    probe predicts a defect exactly when the real seeder yields no user."""
    saved_users = dict(auth._USERS)
    saved_flag = auth._SEED_ATTEMPTED
    saved_admin = auth._DEFAULT_ADMIN
    try:
        for users, password in (
            ("", ""),
            ("CHANGE-ME:CHANGE-ME:admin", ""),
            ("garbage", ""),
            ("   ", "a-strong-operator-password"),
            ("alice:S3cret-pass:admin", ""),
            ("", "a-strong-operator-password"),
        ):
            monkeypatch.setenv("WEBPENT_USERS", users)
            monkeypatch.setenv("ADMIN_PASSWORD", password)
            auth._USERS.clear()
            auth._SEED_ATTEMPTED = False
            auth._DEFAULT_ADMIN = None
            auth._ensure_seeded()
            assert bool(auth._USERS) == (not auth.provisioning_defects()), (users, password)
            auth._USERS.clear()
    finally:
        auth._USERS.clear()
        auth._USERS.update(saved_users)
        auth._SEED_ATTEMPTED = saved_flag
        auth._DEFAULT_ADMIN = saved_admin


# ---------------------------------------------------------------------------
# the startup gate
# ---------------------------------------------------------------------------


def test_authenticated_boot_without_an_operator_is_refused(
    monkeypatch, clean_operator_env, caplog
) -> None:
    _settings(monkeypatch)
    with pytest.raises(SystemExit) as excinfo, caplog.at_level(logging.INFO):
        preflight.run_preflight(host="127.0.0.1")
    message = str(excinfo.value)
    assert "authentication is enabled but no operator can sign in" in message
    assert "ADMIN_PASSWORD" in message
    assert BYPASS_MARKER not in caplog.text


def test_placeholder_operator_is_refused_at_boot(monkeypatch, clean_operator_env) -> None:
    _settings(monkeypatch)
    monkeypatch.setenv("WEBPENT_USERS", "CHANGE-ME:CHANGE-ME:admin")
    with pytest.raises(SystemExit, match="placeholder WEBPENT_USERS entry refused"):
        preflight.run_preflight(host="127.0.0.1")


def test_whitespace_only_list_is_refused_at_boot(monkeypatch, clean_operator_env) -> None:
    _settings(monkeypatch)
    monkeypatch.setenv("WEBPENT_USERS", "   ")
    with pytest.raises(SystemExit, match="no operator can sign in"):
        preflight.run_preflight(host="127.0.0.1")


def test_authenticated_boot_with_an_operator_passes_and_records_it(
    monkeypatch, clean_operator_env
) -> None:
    _settings(monkeypatch)
    monkeypatch.setenv("WEBPENT_USERS", "alice:S3cret-pass:admin")
    report = preflight.run_preflight(host="127.0.0.1")
    assert report["operator_provisioning"]["status"].startswith("ok")
    assert report["operator_provisioning"]["fail_closed"] is True


def test_admin_password_alone_satisfies_the_gate(monkeypatch, clean_operator_env) -> None:
    _settings(monkeypatch)
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-operator-password")
    assert preflight.run_preflight(host="127.0.0.1")["operator_provisioning"]


def test_a_broken_probe_fails_closed(monkeypatch, clean_operator_env) -> None:
    _settings(monkeypatch)
    monkeypatch.setattr(auth, "provisioning_defects", _unreadable_env)
    with pytest.raises(SystemExit, match="could not be evaluated"):
        preflight._enforce_operator_provisioning({})


# ---------------------------------------------------------------------------
# the development bypass: logged, and still narrowed to loopback
# ---------------------------------------------------------------------------


def test_development_bypass_is_announced_at_boot(monkeypatch, clean_operator_env, caplog) -> None:
    _settings(monkeypatch, auth_enabled=False)
    with caplog.at_level(logging.WARNING, logger=preflight.logger.name):
        report = preflight.run_preflight(host="127.0.0.1")
    bypass_warnings = [
        rec
        for rec in caplog.records
        if rec.levelno == logging.WARNING and BYPASS_MARKER in rec.getMessage()
    ]
    assert len(bypass_warnings) == 1, caplog.text
    assert "stub administrator" in bypass_warnings[0].getMessage()
    # nothing is provisioned in bypass mode, so no provisioning entry is recorded
    assert "operator_provisioning" not in report


def test_bypass_is_not_announced_when_authentication_is_on(
    monkeypatch, clean_operator_env, caplog
) -> None:
    monkeypatch.setenv("WEBPENT_USERS", "alice:S3cret-pass:admin")
    _settings(monkeypatch)
    with caplog.at_level(logging.WARNING, logger=preflight.logger.name):
        preflight.run_preflight(host="127.0.0.1")
    assert BYPASS_MARKER not in caplog.text


def test_bypass_still_refuses_a_non_loopback_bind(monkeypatch, clean_operator_env) -> None:
    _settings(monkeypatch, auth_enabled=False)
    with pytest.raises(SystemExit, match="non-local bind with auth disabled"):
        preflight.run_preflight(host="0.0.0.0")


def test_bypass_override_is_explicit_and_logged_critical(
    monkeypatch, clean_operator_env, caplog
) -> None:
    _settings(monkeypatch, auth_enabled=False)
    monkeypatch.setenv("I_UNDERSTAND_THIS_IS_INSECURE", "true")
    with caplog.at_level(logging.WARNING, logger=preflight.logger.name):
        report = preflight.run_preflight(host="0.0.0.0")
    assert "INSECURE OVERRIDE" in caplog.text
    assert report["api_security_posture"]["status"].startswith("OVERRIDDEN")


def test_strict_profile_still_refuses_authentication_disabled(clean_operator_env) -> None:
    """The K4 gate does not weaken the existing profile rule: a strict profile
    still refuses to construct settings with authentication disabled."""
    with pytest.raises(
        (ValidationError, ValueError, RuntimeError), match="requires\\s+auth_enabled=True"
    ):
        settings_module.Settings(
            _env_file=None,
            auth_enabled=False,
            environment_profile="production",
            jwt_secret_key=STRONG,
            audit_secret_key="a" * 48,
            celery_payload_key="c" * 48,
            cors_origins=["https://example.test"],
            rate_limit_enabled=True,
            rate_limit_redis_url="rediss://example.test:6379/0",
        )


def test_official_api_launcher_runs_preflight_before_opening_the_socket() -> None:
    launcher = Path(preflight.__file__).resolve().parents[3] / "server.py"
    text = launcher.read_text(encoding="utf-8")
    assert text.index("run_preflight(host=host)") < text.index("uvicorn.run(")
