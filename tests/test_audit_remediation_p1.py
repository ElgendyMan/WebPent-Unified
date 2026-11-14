from __future__ import annotations

from types import SimpleNamespace

import pytest

from webpent.config import settings as settings_module
from webpent.shared import preflight, resume_capability
from webpent.utils import task_crypto
from webpent.workers.pentest_worker import resume_pentest_task


@pytest.fixture
def capability_settings(monkeypatch):
    monkeypatch.setattr(
        resume_capability,
        "get_settings",
        lambda: SimpleNamespace(jwt_secret_key="p1-test-secret-" + "x" * 32),
    )


def _record() -> dict[str, str]:
    return {
        "owner_username": "alice",
        "client_id": "client-a",
        "engagement_id": "eng-a",
    }


def test_resume_capability_binds_identity(capability_settings):
    token = resume_capability.issue_resume_capability(
        thread_id="thread-a",
        owner_username="alice",
        client_id="client-a",
        engagement_id="eng-a",
    )

    assert resume_capability.verify_resume_capability(
        token,
        thread_id="thread-a",
        record=_record(),
    )
    assert not resume_capability.verify_resume_capability(
        token,
        thread_id="thread-b",
        record=_record(),
    )


def test_resume_capability_rejects_tampering(capability_settings):
    token = resume_capability.issue_resume_capability(
        thread_id="thread-a",
        owner_username="alice",
        client_id="client-a",
        engagement_id="eng-a",
    )
    parts = token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")

    assert not resume_capability.verify_resume_capability(
        ".".join(parts),
        thread_id="thread-a",
        record=_record(),
    )


def test_resume_capability_expires(capability_settings, monkeypatch):
    now = 1_700_000_000
    monkeypatch.setattr(resume_capability.time, "time", lambda: now)
    token = resume_capability.issue_resume_capability(
        thread_id="thread-a",
        owner_username="alice",
        client_id="client-a",
        engagement_id="eng-a",
        ttl_seconds=1,
    )
    monkeypatch.setattr(resume_capability.time, "time", lambda: now + 2)

    assert not resume_capability.verify_resume_capability(
        token,
        thread_id="thread-a",
        record=_record(),
    )


def test_session_cookie_map_is_encrypted_and_fail_closed(capability_settings):
    encrypted = task_crypto.encrypt_secret_map_for_task({"PHPSESSID": "secret-cookie"})
    assert encrypted["PHPSESSID"].startswith("enc:v2:")
    assert "secret-cookie" not in encrypted["PHPSESSID"]
    assert task_crypto.decrypt_secret_map_from_task(encrypted) == {"PHPSESSID": "secret-cookie"}
    corrupted = {"PHPSESSID": "enc:v2:not-a-valid-token"}
    assert task_crypto.decrypt_secret_map_from_task(corrupted) == {"PHPSESSID": ""}


def test_redis_preflight_requires_tls_when_auth_enabled(monkeypatch):
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(auth_enabled=True),
    )
    secure_report = {
        "redis_security": {
            "broker": {"configured": True, "tls": True},
            "rate_limit": {"configured": True, "tls": True},
        }
    }
    preflight._enforce_redis_security(secure_report)

    insecure_report = {
        "redis_security": {
            "broker": {"configured": True, "tls": False},
            "rate_limit": {"configured": False, "tls": False},
        }
    }
    with pytest.raises(SystemExit, match="rediss://"):
        preflight._enforce_redis_security(insecure_report)


def test_redis_preflight_allows_local_dev_plaintext(monkeypatch):
    monkeypatch.setattr(
        settings_module,
        "get_settings",
        lambda: SimpleNamespace(auth_enabled=False),
    )
    preflight._enforce_redis_security(
        {
            "redis_security": {
                "broker": {"configured": True, "tls": False},
                "rate_limit": {"configured": False, "tls": False},
            }
        }
    )


def test_resume_worker_fails_closed_without_capability(monkeypatch):
    monkeypatch.setattr(
        "webpent.api.scan_registry.get_scan_record",
        lambda thread_id: _record(),
    )

    with pytest.raises(PermissionError, match="capability"):
        resume_pentest_task.run("thread-a")
