"""Behavioral regressions for the opt-in shared re-auth vault."""

from __future__ import annotations

import sqlite3

from webpent.auth import reauth_vault


def _enable_shared_vault(monkeypatch, db_path) -> None:
    monkeypatch.setenv("WEBPENT_REAUTH_VAULT_SHARED_STORE", "true")
    monkeypatch.setenv("WEBPENT_REAUTH_VAULT_DATABASE_URL", f"sqlite:///{db_path}")
    reauth_vault._SHARED_DATABASES.clear()
    reauth_vault._PASSWORD_VAULT.clear()
    reauth_vault._COOKIE_VAULT.clear()
    reauth_vault._IDENTITY_VAULT.clear()


def test_shared_vault_survives_in_memory_worker_restart(monkeypatch, tmp_path) -> None:
    _enable_shared_vault(monkeypatch, tmp_path / "shared-vault.sqlite")
    thread_id = "shared-worker-restart"
    try:
        reauth_vault.seal_reauth_secret(thread_id, "runtime-password")
        reauth_vault._PASSWORD_VAULT.clear()
        assert reauth_vault.unseal_reauth_secret(thread_id) == "runtime-password"

        raw = (tmp_path / "shared-vault.sqlite").read_bytes()
        assert b"runtime-password" not in raw
    finally:
        reauth_vault.clear_reauth_secret(thread_id)


def test_shared_vault_sweep_and_terminal_cleanup(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "shared-vault-cleanup.sqlite"
    _enable_shared_vault(monkeypatch, db_path)
    thread_id = "shared-cleanup"
    try:
        reauth_vault.seal_session_cookies(thread_id, {"sid": "cookie"})
        manager = reauth_vault._SHARED_DATABASES[f"sqlite:///{db_path}"]
        manager.save_reauth_vault_record(thread_id, "identity", "expired-token", 0)
        assert reauth_vault.sweep_expired(max_items=10) >= 1
        assert reauth_vault.unseal_session_cookies(thread_id) == {"sid": "cookie"}
        reauth_vault.clear_reauth_secret(thread_id)
        assert reauth_vault.vault_stats()["cookie_records"] == 0
    finally:
        reauth_vault.clear_reauth_secret(thread_id)
        with sqlite3.connect(db_path) as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM reauth_vault_records WHERE thread_id = ?",
                (thread_id,),
            ).fetchone()[0]
        assert count == 0


def test_shared_vault_settings_are_opt_in(monkeypatch) -> None:
    from webpent.config.settings import Settings

    monkeypatch.delenv("WEBPENT_REAUTH_VAULT_SHARED_STORE", raising=False)
    monkeypatch.delenv("WEBPENT_REAUTH_VAULT_DATABASE_URL", raising=False)
    assert Settings().reauth_vault_shared_store is False

    monkeypatch.setenv("WEBPENT_REAUTH_VAULT_SHARED_STORE", "true")
    monkeypatch.setenv("WEBPENT_REAUTH_VAULT_DATABASE_URL", "sqlite:///./shared.sqlite")
    configured = Settings()
    assert configured.reauth_vault_shared_store is True
    assert configured.reauth_vault_database_url == "sqlite:///./shared.sqlite"


def test_typed_shared_vault_cleanup_preserves_sibling_records(monkeypatch, tmp_path) -> None:
    db_path = tmp_path / "shared-vault-typed.sqlite"
    _enable_shared_vault(monkeypatch, db_path)
    thread_id = "shared-typed-cleanup"
    try:
        reauth_vault.seal_session_cookies(thread_id, {"sid": "cookie"})
        manager = reauth_vault._SHARED_DATABASES[f"sqlite:///{db_path}"]
        assert manager.delete_reauth_vault_record(thread_id, "identity") == 0
        assert reauth_vault.unseal_session_cookies(thread_id) == {"sid": "cookie"}
    finally:
        reauth_vault.clear_reauth_secret(thread_id)
