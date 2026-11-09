# tests/team1_acceptance/test_sprint_i1b_part2_secrets_gate.py
"""Sprint I-1b, item 2.3 -- insecure default secrets boot-time hard gate.

Most of this gate already existed (V6/V10 hardening) before this sprint:
strict_profile-or-auth_enabled hard-stops for both audit_secret_key and
celery_payload_key. This sprint found and fixed one real, narrow gap: the
dev-mode warning for each key had an `and self.<key>` truthy check that
made it never fire for the actual out-of-the-box default (""), only for
an explicitly-set-but-still-named-insecure string -- meaning the single
most common real configuration (nothing set at all) warned about
nothing. Fixed by dropping the truthy check.
"""
from __future__ import annotations

import json
import warnings

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in (
        "WEBPENT_ENVIRONMENT_PROFILE", "AUTH_ENABLED", "AUDIT_SECRET_KEY",
        "WEBPENT_AUDIT_SECRET_KEY", "CELERY_PAYLOAD_KEY", "WEBPENT_CELERY_PAYLOAD_KEY",
        "WEBPENT_CORS_ORIGINS", "RATE_LIMIT_ENABLED", "RATE_LIMIT_REDIS_URL",
        "JWT_SECRET_KEY",
    ):
        monkeypatch.delenv(v, raising=False)
    yield


def _valid_production_env(monkeypatch):
    monkeypatch.setenv("WEBPENT_ENVIRONMENT_PROFILE", "production")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_CORS_ORIGINS", json.dumps(["https://app.example.com"]))
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_REDIS_URL", "rediss://localhost:6379")
    monkeypatch.setenv("JWT_SECRET_KEY", "a" * 40)


class TestProductionHardStop:
    def test_default_audit_secret_key_blocks_boot_in_production(self, monkeypatch):
        from webpent.config.settings import Settings

        _valid_production_env(monkeypatch)
        with pytest.raises(ValueError, match="Insecure default audit secret"):
            Settings()

    def test_default_celery_payload_key_blocks_boot_in_production(self, monkeypatch):
        from webpent.config.settings import Settings

        _valid_production_env(monkeypatch)
        monkeypatch.setenv("AUDIT_SECRET_KEY", "a" * 40)
        with pytest.raises(ValueError, match="Insecure default celery_payload_key"):
            Settings()

    def test_fully_valid_production_config_boots(self, monkeypatch):
        from webpent.config.settings import Settings

        _valid_production_env(monkeypatch)
        monkeypatch.setenv("AUDIT_SECRET_KEY", "a" * 40)
        monkeypatch.setenv("CELERY_PAYLOAD_KEY", "a" * 40)
        Settings()  # must not raise

    def test_auth_enabled_alone_also_hard_stops_regardless_of_profile(self, monkeypatch):
        """The gate fires on auth_enabled=True even outside a strict
        profile -- e.g. someone enabling auth in a lab deployment with
        the default keys still gets blocked."""
        from webpent.config.settings import Settings

        monkeypatch.setenv("AUTH_ENABLED", "true")
        with pytest.raises(ValueError, match="Insecure default"):
            Settings()


class TestDevModeWarns:
    def test_bare_defaults_warn_in_dev_mode(self):
        """The fixed gap: the out-of-the-box empty-string default for
        BOTH keys must warn, not silently pass -- previously it did not,
        because of the removed truthy check."""
        from webpent.config.settings import Settings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            Settings()
        messages = [str(w.message) for w in caught]
        assert any("INSECURE audit_secret_key" in m for m in messages)
        assert any("INSECURE celery_payload_key" in m for m in messages)

    def test_dev_mode_still_boots_despite_warning(self):
        """Never a hard-stop in dev/lab mode -- only production-intent
        (strict profile or explicit auth_enabled) blocks boot."""
        from webpent.config.settings import Settings

        Settings()  # must not raise

    def test_valid_keys_in_dev_mode_produce_no_warning(self, monkeypatch):
        from webpent.config.settings import Settings

        monkeypatch.setenv("AUDIT_SECRET_KEY", "a" * 40)
        monkeypatch.setenv("CELERY_PAYLOAD_KEY", "a" * 40)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            Settings()
        messages = [str(w.message) for w in caught]
        assert not any("INSECURE audit_secret_key" in m for m in messages)
        assert not any("INSECURE celery_payload_key" in m for m in messages)
