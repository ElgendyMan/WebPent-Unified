from webpent.config.settings import Settings


def test_insecure_tls_is_disabled_by_default():
    settings = Settings()
    assert settings.allow_insecure_tls is False


def test_insecure_tls_accepts_webpent_alias(monkeypatch):
    monkeypatch.setenv("WEBPENT_ALLOW_INSECURE_TLS", "true")
    settings = Settings()
    assert settings.allow_insecure_tls is True
