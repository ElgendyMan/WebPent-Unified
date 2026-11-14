from __future__ import annotations

from pathlib import Path

from webpent.config.settings import Settings, get_settings

ROOT = Path(__file__).resolve().parents[1]


def test_production_prefixed_aliases_are_consumed(monkeypatch) -> None:
    for name in (
        "AUTH_ENABLED",
        "JWT_SECRET_KEY",
        "AUDIT_SECRET_KEY",
        "WEBPENT_AUTH_ENABLED",
        "WEBPENT_JWT_SECRET_KEY",
        "WEBPENT_AUDIT_SECRET_KEY",
        "CELERY_PAYLOAD_KEY",
        "WEBPENT_CELERY_PAYLOAD_KEY",
        "WEBPENT_DATABASE_URL",
        "WEBPENT_CORS_ORIGINS",
        "WEBPENT_RATE_LIMIT_ENABLED",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("WEBPENT_AUTH_ENABLED", "true")
    monkeypatch.setenv("WEBPENT_JWT_SECRET_KEY", "j" * 40)
    monkeypatch.setenv("WEBPENT_AUDIT_SECRET_KEY", "a" * 40)
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "c" * 40)
    monkeypatch.setenv("WEBPENT_DATABASE_URL", "sqlite:///./prefixed.db")
    monkeypatch.setenv("WEBPENT_CORS_ORIGINS", '["https://scanner.example"]')
    monkeypatch.setenv("WEBPENT_RATE_LIMIT_ENABLED", "true")

    settings = Settings()

    assert settings.auth_enabled is True
    assert settings.jwt_secret_key == "j" * 40
    assert settings.audit_secret_key == "a" * 40
    assert settings.database_url == "sqlite:///./prefixed.db"
    assert settings.cors_origins == ["https://scanner.example"]
    assert settings.rate_limit_enabled is True


def test_env_example_documents_required_production_surface() -> None:
    content = (ROOT / ".env.example").read_text(encoding="utf-8")
    for variable in (
        "AUTH_ENABLED",
        "JWT_SECRET_KEY",
        "AUDIT_SECRET_KEY",
        "CELERY_PAYLOAD_KEY",
        "WEBPENT_USERS",
        "OOB_CALLBACK_SECRET",
        "WEBHOOK_SECRET",
        "FFUF_WORDLIST_PATH",
        "I_UNDERSTAND_THIS_IS_INSECURE",
    ):
        assert variable in content
    assert "correct horse battery staple" not in content
    assert "session_cookie" not in content.lower()


def test_production_compose_passes_webhook_secret_to_both_services() -> None:
    content = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert content.count("WEBHOOK_SECRET=${WEBHOOK_SECRET:-}") == 2


def test_get_settings_cache_can_be_reset_after_environment_changes(monkeypatch) -> None:
    get_settings.cache_clear()
    monkeypatch.setenv("WEBPENT_RATE_LIMIT_ENABLED", "true")
    assert get_settings().rate_limit_enabled is True
    get_settings.cache_clear()
    monkeypatch.setenv("WEBPENT_RATE_LIMIT_ENABLED", "false")
    assert get_settings().rate_limit_enabled is False
    get_settings.cache_clear()
