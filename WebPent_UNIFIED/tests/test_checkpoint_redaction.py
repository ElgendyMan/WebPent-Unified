from __future__ import annotations

import sqlite3

from webpent.auth import reauth_vault
from webpent.graph.checkpoints import get_checkpointer


def _checkpoint() -> dict[str, object]:
    return {
        "v": 1,
        "id": "checkpoint-1",
        "ts": "2026-08-17T00:00:00+00:00",
        "channel_values": {
            "thread_id": "thread-redaction",
            "credentials": {"username": "alice", "password": "plain-password"},
            "session_cookies": {"PHPSESSID": "plain-cookie"},
            "identity_profiles": {
                "admin": {
                    "cookies": {"sid": "identity-cookie"},
                    "credentials": {"password": "identity-password"},
                }
            },
            "jwt_weak_secret_candidates": ["candidate-secret"],
            "current_phase": "auth",
        },
        "channel_versions": {},
        "versions_seen": {},
        "updated_channels": None,
    }


def test_checkpoint_storage_redacts_sensitive_channels(tmp_path):
    db_path = str(tmp_path / "checkpoints.sqlite")
    config = {
        "configurable": {
            "thread_id": "thread-redaction",
            "checkpoint_ns": "",
        }
    }

    with get_checkpointer(db_path) as saver:
        saved_config = saver.put(
            config,
            _checkpoint(),
            {
                "source": "input",
                "step": 1,
                "authorization": "Bearer metadata-secret",
                "headers": {"Cookie": "metadata-cookie"},
            },
            {},
        )
        saver.put_writes(
            saved_config,
            [("session_cookies", {"PHPSESSID": "write-cookie"})],
            "task-1",
        )
        raw_row = saver.conn.execute(
            "SELECT checkpoint FROM checkpoints WHERE thread_id = ?",
            ("thread-redaction",),
        ).fetchone()
        raw_writes = saver.conn.execute(
            "SELECT value FROM writes WHERE thread_id = ?",
            ("thread-redaction",),
        ).fetchall()

        assert raw_row is not None
        assert b"plain-password" not in raw_row[0]
        assert b"plain-cookie" not in raw_row[0]
        assert b"identity-password" not in raw_row[0]
        assert b"candidate-secret" not in raw_row[0]
        assert b"metadata-secret" not in raw_row[0]
        assert b"metadata-cookie" not in raw_row[0]
        assert raw_writes
        assert b"write-cookie" not in raw_writes[0][0]


def test_checkpoint_redacts_api_key_totp_and_nested_secret_keys():
    from webpent.graph.checkpoints import _redact_checkpoint

    checkpoint = {
        "channel_values": {
            "metadata": {
                "api_key": "api-secret",
                "totp_secret": "totp-secret",
                "nested_client_secret_value": "client-secret",
                "public_name": "kept",
            }
        }
    }
    safe = _redact_checkpoint(checkpoint)
    metadata = safe["channel_values"]["metadata"]
    assert metadata["api_key"] == ""
    assert metadata["totp_secret"] == ""
    assert metadata["nested_client_secret_value"] == ""
    assert metadata["public_name"] == "kept"


def test_checkpoint_runtime_restore_uses_worker_vault_only(tmp_path):
    thread_id = "thread-runtime-restore"
    db_path = str(tmp_path / "checkpoints.sqlite")
    config = {"configurable": {"thread_id": thread_id, "checkpoint_ns": ""}}
    checkpoint = _checkpoint()
    checkpoint["channel_values"] = dict(checkpoint["channel_values"])
    checkpoint["channel_values"]["thread_id"] = thread_id

    reauth_vault.seal_reauth_secret(thread_id, "runtime-password")
    reauth_vault.seal_session_cookies(thread_id, {"sid": "runtime-cookie"})
    reauth_vault.seal_identity_profiles(
        thread_id,
        {"admin": {"cookies": {"sid": "runtime-identity-cookie"}}},
    )
    try:
        with get_checkpointer(db_path) as saver:
            saver.put(config, checkpoint, {"source": "input", "step": 1}, {})
            loaded = saver.get_tuple(config)
            assert loaded is not None
            channels = loaded.checkpoint["channel_values"]
            assert channels["credentials"]["password"] == "runtime-password"
            assert channels["session_cookies"] == {"sid": "runtime-cookie"}
            assert channels["identity_profiles"]["admin"]["cookies"]["sid"] == (
                "runtime-identity-cookie"
            )
    finally:
        reauth_vault.clear_reauth_secret(thread_id)


def test_legacy_sqlite_checkpoint_remains_readable(tmp_path):
    db_path = tmp_path / "legacy.sqlite"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE marker (value TEXT)")
    conn.execute("INSERT INTO marker VALUES ('legacy')")
    conn.commit()
    conn.close()
    with get_checkpointer(str(db_path)) as saver:
        assert saver.conn.execute("SELECT value FROM marker").fetchone() == ("legacy",)
