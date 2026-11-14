"""M1-A (H-2) placeholder-secret rejection tests (2026-11-05).

M0 finding H-2: `.env.example` ships `CHANGE-ME-generate-a-random-secret`
for JWT_SECRET_KEY / AUDIT_SECRET_KEY / CELERY_PAYLOAD_KEY (34 chars —
passes every length check) and `CHANGE-ME:CHANGE-ME:admin` for
WEBPENT_USERS, while the three insecure-default frozensets enumerate only
the legacy dev defaults. An operator who copied .env.example and enabled
auth got a clean Settings() on repo-readable, forgeable secrets — admin
compromise "in a seemingly hardened posture".

M1-A fix: the whole placeholder family is rejected by prefix
(case-insensitive) across the three secret checks whenever
auth_enabled=True or a strict profile is set; placeholder WEBPENT_USERS
entries are refused at seed time.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from webpent.api import auth as api_auth  # noqa: E402
from webpent.config.settings import Settings  # noqa: E402

STRONG = "x" * 48  # passes length + not a placeholder
PLACEHOLDER = "CHANGE-ME-generate-a-random-secret"  # the shipped form (34 chars)


def _settings(**overrides) -> Settings:
    base = {
        "auth_enabled": True,
        "jwt_secret_key": STRONG,
        "audit_secret_key": STRONG,
        "celery_payload_key": STRONG,
    }
    base.update(overrides)
    return Settings(**base)


class TestSettingsPlaceholderRejection:
    """test_settings_placeholder_rejection — the M0-named regression."""

    @pytest.mark.parametrize(
        "field",
        ["jwt_secret_key", "audit_secret_key", "celery_payload_key"],
    )
    def test_placeholder_rejected_with_auth_enabled(self, field):
        with pytest.raises(ValueError, match="CHANGE-ME|placeholder"):
            _settings(**{field: PLACEHOLDER})

    @pytest.mark.parametrize(
        "field",
        ["jwt_secret_key", "audit_secret_key", "celery_payload_key"],
    )
    def test_placeholder_variantes_rejected(self, field):
        for variant in (
            "change-me-lowercase",
            "Change-Me-Mixed",
            "CHANGEME-no-dash",
            "CHANGE-ME",
        ):
            with pytest.raises(ValueError, match="CHANGE-ME|CHANGEME|placeholder"):
                _settings(**{field: variant})

    @pytest.mark.parametrize(
        "field",
        ["jwt_secret_key", "audit_secret_key", "celery_payload_key"],
    )
    def test_legacy_named_defaults_still_rejected(self, field):
        legacy = {
            "jwt_secret_key": "webpent-dev-secret-key-change-in-production",
            "audit_secret_key": "webpent-dev-audit-key-change-in-production",
            "celery_payload_key": "webpent-dev-celery-payload-key-change-in-production",
        }[field]
        with pytest.raises(ValueError):
            _settings(**{field: legacy})

    def test_strong_secrets_pass(self):
        s = _settings()
        assert s.auth_enabled is True

    def test_dev_mode_placeholders_do_not_block_startup(self):
        """Fail-closed only where it matters: lab/dev (auth off) still boots
        with placeholders in the file — the warning path, not a crash."""
        s = Settings(
            auth_enabled=False,
            jwt_secret_key=PLACEHOLDER,
            audit_secret_key=PLACEHOLDER,
            celery_payload_key=PLACEHOLDER,
        )
        assert s.auth_enabled is False

    def test_strict_profile_rejects_placeholder_even_with_auth_flag_unset(self):
        with pytest.raises(ValueError, match="placeholder|CHANGE-ME"):
            Settings(
                environment_profile="production",
                auth_enabled=True,
                jwt_secret_key=PLACEHOLDER,
                audit_secret_key=PLACEHOLDER,
                celery_payload_key=PLACEHOLDER,
                cors_origins=["https://x.example"],
                rate_limit_enabled=True,
                rate_limit_redis_url="rediss://example.redis",
            )


class TestWebpentUsersPlaceholderRejection:
    def test_placeholder_admin_entry_refused_at_seed(self, monkeypatch):
        import webpent.api.auth as _auth_mod

        monkeypatch.setenv("WEBPENT_USERS", "CHANGE-ME:CHANGE-ME:admin")
        _auth_mod._USERS.clear()
        _auth_mod._SEED_ATTEMPTED = False
        _auth_mod._ensure_seeded()
        assert "CHANGE-ME" not in api_auth._USERS
        assert not api_auth._USERS  # nothing seeded from the placeholder

    def test_real_credentials_still_seed(self, monkeypatch):
        import webpent.api.auth as _auth_mod

        monkeypatch.setenv("WEBPENT_USERS", "operator:supersecret42:admin")
        _auth_mod._USERS.clear()
        _auth_mod._SEED_ATTEMPTED = False
        _auth_mod._ensure_seeded()
        assert "operator" in _auth_mod._USERS
        _auth_mod._USERS.clear()
        _auth_mod._SEED_ATTEMPTED = False
