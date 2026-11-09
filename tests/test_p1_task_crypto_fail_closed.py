from __future__ import annotations

from webpent.config.settings import get_settings
from webpent.utils.task_crypto import (
    decrypt_credentials_from_task,
    encrypt_credentials_for_task,
)


def _reset_settings_cache() -> None:
    get_settings.cache_clear()


def test_credentials_round_trip_uses_encrypted_password(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-round-trip-secret-" + "a" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()

    original = {"username": "alice", "password": "correct horse battery staple"}
    encrypted = encrypt_credentials_for_task(original)

    assert encrypted["username"] == "alice"
    assert encrypted["password"].startswith("enc:v2:")
    assert encrypted["password"] != original["password"]
    assert decrypt_credentials_from_task(encrypted) == original


def test_wrong_key_drops_password_instead_of_continuing(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-encrypt-secret-" + "b" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    encrypted = encrypt_credentials_for_task({"username": "alice", "password": "do-not-leak-this"})

    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-wrong-secret-" + "c" * 32)
    _reset_settings_cache()
    decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["username"] == "alice"
    assert decrypted["password"] == ""


def test_corrupt_ciphertext_drops_password(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-corrupt-secret-" + "d" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    encrypted = encrypt_credentials_for_task(
        {"username": "alice", "password": "do-not-leak-this-either"}
    )
    encrypted["password"] = encrypted["password"][:-4] + "xxxx"

    decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["username"] == "alice"
    assert decrypted["password"] == ""


def test_decryption_failure_log_does_not_include_password(monkeypatch, caplog) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-log-secret-" + "e" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()
    secret_password = "super-secret-password-that-must-not-be-logged"
    encrypted = encrypt_credentials_for_task({"username": "alice", "password": secret_password})
    encrypted["password"] = "enc:v2:not-a-valid-token"

    with caplog.at_level("ERROR"):
        decrypted = decrypt_credentials_from_task(encrypted)

    assert decrypted["password"] == ""
    assert secret_password not in caplog.text


def test_plaintext_legacy_payload_is_preserved_for_compatibility(monkeypatch) -> None:
    monkeypatch.setenv("CELERY_PAYLOAD_KEY", "p1-legacy-secret-" + "f" * 32)
    monkeypatch.delenv("WEBPENT_CELERY_PAYLOAD_KEY", raising=False)
    _reset_settings_cache()

    credentials = {"username": "alice", "password": "legacy-password"}

    assert decrypt_credentials_from_task(credentials) == credentials
