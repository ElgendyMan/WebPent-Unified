"""M3 ق7 (UM-DR-17): the runner-side session_factory injection.

M0 FEATURE_DELTA ق7 disposition: «identity_orchestrator — غير موصول،
يحتاج حقن session_factory من runner» (implemented but not wired; needs
the runner to inject a session_factory).

Contract under test:

1. **The vault-backed factory** — restores live sessions from the sealed
   identity vault (cookie-restore path); fail-closed (None) when the
   vault is empty, expired, or the profile lacks validated cookies; a
   login_executor extends it; raw credentials never surface.
2. **The runner bundle** — build_worker_identity_orchestrator converts
   the state channel's profiles to handle-only IdentityProfiles, builds
   the orchestrator, and projects report-safe provenance.
3. **The worker wiring** — flag off (default): the orchestrator is never
   constructed; flag on: ensure_sessions runs and the provenance is
   attached to the task result (exercised against the real
   run_pentest_task entry with a stubbed graph backend).
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

from webpent.auth.identity_orchestrator import IdentityProfile
from webpent.auth.reauth_vault import (
    clear_reauth_secret,
    identity_vault_key,
    seal_identity_profiles,
)
from webpent.auth.worker_session_factory import (
    RestoredSession,
    build_worker_identity_orchestrator,
    profiles_from_state,
    vault_session_factory,
)
from webpent.config.settings import get_settings

PROFILES = {
    "owner": {
        "name": "owner",
        "role": "owner",
        "validated": True,
        "cookies": {"sid": "owner-secret-session", "csrf": "tok"},
        "login_flow": ["login_page", "submit_credentials", "mfa_check"],
    },
    "viewer": {
        "name": "viewer",
        "role": "viewer",
        "validated": True,
        "cookies": {"sid": "viewer-secret-session"},
    },
    "unvalidated": {
        "name": "unvalidated",
        "role": "viewer-2",
        "validated": False,
        "cookies": {"sid": "stale"},
    },
}


@pytest.fixture()
def sealed_profiles() -> str:
    key = identity_vault_key("client-q7", "eng-q7")
    seal_identity_profiles(key, PROFILES)
    yield key
    clear_reauth_secret(key)


# ---------------------------------------------------------------------------
# 1. The vault-backed factory
# ---------------------------------------------------------------------------


def test_factory_restores_sessions_from_sealed_cookies(sealed_profiles: str) -> None:
    factory = vault_session_factory(thread_id="th-q7", identity_key=sealed_profiles)
    session = factory(IdentityProfile(role="owner", credentials_handle=sealed_profiles))
    assert isinstance(session, RestoredSession)
    assert session.role == "owner"
    assert session.cookie_names == ("csrf", "sid")
    assert session.validated is True


def test_factory_is_fail_closed_when_nothing_is_sealed() -> None:
    factory = vault_session_factory(thread_id="th-q7-empty", identity_key="no-such-key")
    assert factory(IdentityProfile(role="owner", credentials_handle="no-such-key")) is None


def test_factory_refuses_unvalidated_cookie_profiles(sealed_profiles: str) -> None:
    factory = vault_session_factory(thread_id="th-q7", identity_key=sealed_profiles)
    assert (
        factory(IdentityProfile(role="viewer-2", credentials_handle=sealed_profiles))
        is None
    )


def test_factory_login_executor_path_and_failure() -> None:
    calls: list[str] = []

    def executor(profile: IdentityProfile) -> Any:
        calls.append(profile.role)
        return {"logged_in_as": profile.role}

    factory = vault_session_factory(
        thread_id="th-q7-login",
        identity_key="missing",
        login_executor=executor,
    )
    session = factory(IdentityProfile(role="admin", credentials_handle="missing"))
    assert session == {"logged_in_as": "admin"}
    assert calls == ["admin"]

    def failing(profile: IdentityProfile) -> Any:
        raise RuntimeError("login backend down")

    factory_fail = vault_session_factory(
        thread_id="th-q7-login",
        identity_key="missing",
        login_executor=failing,
    )
    assert factory_fail(IdentityProfile(role="admin", credentials_handle="x")) is None


def test_restored_session_repr_never_carries_cookie_values(sealed_profiles: str) -> None:
    factory = vault_session_factory(thread_id="th-q7", identity_key=sealed_profiles)
    session = factory(IdentityProfile(role="viewer", credentials_handle=sealed_profiles))
    assert isinstance(session, RestoredSession)
    assert "viewer-secret-session" not in repr(session)
    assert "viewer-secret-session" not in str(session.__dict__)


# ---------------------------------------------------------------------------
# 2. The runner bundle
# ---------------------------------------------------------------------------


def test_profiles_from_state_converts_handles_only() -> None:
    profiles = profiles_from_state(PROFILES, credentials_handle="vault-key")
    by_role = {p.role: p for p in profiles}
    assert set(by_role) == {"owner", "viewer", "viewer-2"}
    owner = by_role["owner"]
    assert owner.credentials_handle == "vault-key"
    assert owner.login_flow == ("login_page", "submit_credentials", "mfa_check")
    # No runtime values survive the conversion.
    dumped = [p.as_dict() for p in profiles]
    assert "owner-secret-session" not in str(dumped)
    assert all(d["raw_credentials_included"] is False for d in dumped)


def test_bundle_builds_ensures_and_projects(sealed_profiles: str) -> None:
    bundle = build_worker_identity_orchestrator(
        thread_id="th-q7",
        client_id="client-q7",
        engagement_id="eng-q7",
        identity_profiles=PROFILES,
    )
    assert bundle is not None
    assert bundle.identity_key == sealed_profiles
    outcomes = bundle.ensure_sessions()
    by_role = {o.role: o.status for o in outcomes}
    assert by_role["owner"] == "built"
    assert by_role["viewer"] == "built"
    # viewer-2's sealed profile is unvalidated → no live session, but the
    # profile itself exists (its state dict role is viewer-2).
    provenance = bundle.provenance()
    assert set(provenance["live_roles"]) == {"owner", "viewer"}
    assert provenance["raw_session_material_exposed"] is False
    assert provenance["thread_id"] == "th-q7"
    assert "owner-secret-session" not in str(provenance)


def test_bundle_returns_none_without_profiles_or_thread() -> None:
    assert build_worker_identity_orchestrator(thread_id="", identity_profiles=PROFILES) is None
    assert build_worker_identity_orchestrator(thread_id="th", identity_profiles=None) is None
    assert build_worker_identity_orchestrator(thread_id="th", identity_profiles={}) is None


# ---------------------------------------------------------------------------
# 3. The worker wiring
# ---------------------------------------------------------------------------


def test_flag_defaults_off() -> None:
    assert get_settings().enable_identity_orchestrator is False


def test_worker_signature_and_result_shape_unchanged() -> None:
    from webpent.workers.pentest_worker import run_pentest_task

    signature = inspect.signature(run_pentest_task.run)
    assert "identity_profiles" in signature.parameters
    # No new required parameters were added by the ق7 wiring.
    for name, parameter in signature.parameters.items():
        if name in {"self", "target_url", "is_portswigger", "thread_id"}:
            continue
        assert parameter.default is not inspect.Parameter.empty, name


def test_worker_flag_off_never_constructs_the_orchestrator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import webpent.auth.worker_session_factory as wsf
    from webpent.workers import pentest_worker

    monkeypatch.setattr(pentest_worker, "sweep_expired", lambda *a, **k: 0)

    def _forbidden(**kwargs: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("orchestrator must not be constructed with the flag off")

    monkeypatch.setattr(wsf, "build_worker_identity_orchestrator", _forbidden)
    assert get_settings().enable_identity_orchestrator is False

    # The fail-closed scope path raises before the graph starts — enough
    # to prove the ق7 block (which sits before graph construction) did
    # not fire on the way through with the flag off.
    with pytest.raises(RuntimeError, match="scope_file_target_url_not_in_scope"):
        pentest_worker.run_pentest_task.run(
            target_url="https://elsewhere.example.com/",
            is_portswigger=False,
            thread_id="q7-flag-off-test",
            auto_approve=True,
            skip_recon=True,
            credentials={},
            session_cookies={},
            identity_profiles=PROFILES,
            scope_entries=["app.example.com"],
        )


def test_worker_flag_on_attaches_provenance_to_result(
    monkeypatch: pytest.MonkeyPatch, sealed_profiles: str
) -> None:
    from webpent.workers import pentest_worker

    monkeypatch.setattr(pentest_worker, "sweep_expired", lambda *a, **k: 0)

    key = identity_vault_key("q7-client", "q7-eng")

    class _FakeGraph:
        def __init__(self) -> None:
            self.invoked = False

        def invoke(self, initial_state: Any, config: Any = None) -> Any:
            self.invoked = True
            return initial_state

        def get_state(self, config: Any) -> Any:
            class _Snap:
                values = {}
                next = ()
                status = "completed"

            return _Snap()

    fake_graph = _FakeGraph()
    monkeypatch.setattr(pentest_worker, "build_graph", lambda **kwargs: fake_graph)

    class _Ctx:
        def __enter__(self) -> Any:
            return None

        def __exit__(self, *args: Any) -> None:
            return None

    monkeypatch.setattr(pentest_worker, "get_checkpointer", lambda: _Ctx())

    # engage the flag via settings override the worker reads at run time
    from webpent.config.settings import activate_settings

    settings = get_settings().model_copy(update={"enable_identity_orchestrator": True})
    with activate_settings(settings):
        result = pentest_worker.run_pentest_task.run(
            target_url="https://app.example.com/",
            is_portswigger=False,
            thread_id="q7-eng",
            auto_approve=True,
            skip_recon=True,
            credentials={},
            session_cookies={},
            identity_profiles={
                "owner": {
                    "name": "owner",
                    "role": "owner",
                    "validated": True,
                    "cookies": {"sid": "x"},
                    "login_flow": ["login", "mfa"],
                }
            },
            client_id="q7-client",
            engagement_id="q7-eng",
        )

    assert fake_graph.invoked is True
    provenance = result.get("identity_session_provenance")
    assert isinstance(provenance, dict)
    assert provenance["live_roles"] == ["owner"]
    assert provenance["raw_session_material_exposed"] is False
    _ = key  # vault key shape parity asserted via the bundle tests above
