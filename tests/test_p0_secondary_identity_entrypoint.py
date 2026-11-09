from __future__ import annotations

from webpent.agents.authentication import agent as auth_agent
from webpent.api.app import ScanRequest
from webpent.utils.task_crypto import (
    decrypt_identity_profiles_from_task,
    encrypt_identity_profiles_for_task,
)


def test_scan_request_accepts_bounded_secondary_identities_without_extra_keys():
    request = ScanRequest(
        url="http://lab.local/orders/1001",
        second_credentials=[
            {"username": "alice", "password": "alice-secret"},
            {"username": "bob", "password": "bob-secret"},
        ],
    )
    assert [item["username"] for item in request.second_credentials] == ["alice", "bob"]


def test_scan_request_rejects_unbounded_or_malformed_secondary_identities():
    too_many = [{"username": f"user-{index}", "password": "secret"} for index in range(8)]
    try:
        ScanRequest(url="http://lab.local", second_credentials=too_many)
    except ValueError as exc:
        assert "more than 7" in str(exc)
    else:
        raise AssertionError("more than seven secondary identities must be rejected")

    try:
        ScanRequest(
            url="http://lab.local",
            second_credentials=[{"username": "alice", "password": "secret", "role": "user"}],
        )
    except ValueError as exc:
        assert "only" in str(exc)
    else:
        raise AssertionError("extra credential keys must be rejected")


def test_secondary_identity_credentials_are_encrypted_at_task_boundary():
    profiles = {
        "identity-2": {
            "name": "identity-2",
            "role": "secondary",
            "credentials": {"username": "alice", "password": "alice-secret"},
        }
    }
    encrypted = encrypt_identity_profiles_for_task(profiles)
    assert "alice-secret" not in repr(encrypted)
    assert encrypted["identity-2"]["credentials"]["password"].startswith("enc:")

    restored = decrypt_identity_profiles_from_task(encrypted)
    assert restored["identity-2"]["credentials"] == {
        "username": "alice",
        "password": "alice-secret",
    }


def test_secondary_bootstrap_consumes_credentials_and_returns_runtime_only_metadata(monkeypatch):
    monkeypatch.setattr(
        auth_agent,
        "_perform_login",
        lambda url, username, password: {"session": f"runtime-{username}"},
    )
    profiles = auth_agent._bootstrap_secondary_profiles(
        "http://lab.local",
        {
            "identity-2": {
                "name": "alice",
                "role": "user",
                "credentials": {"username": "alice", "password": "alice-secret"},
            }
        },
    )
    assert profiles["alice"]["validated"] is True
    assert profiles["alice"]["cookies"] == {"session": "runtime-alice"}
    assert "alice-secret" not in repr(profiles)
    assert "credentials" not in profiles["alice"]
