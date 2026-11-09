"""FEATURE_PROPOSALS ق7 — virtual-identity orchestrator.

Pins:
  * one orchestrator = one engagement = one pool; roles come from
    IdentityProfile rows that carry a credentials HANDLE (never raw
    secrets) plus the multi-step flow NAMES for provenance,
  * ensure_sessions() builds via the injected factory, records a
    per-role outcome, never raises (factory error = that role's
    failure; others continue), bounded by pool capacity,
  * acquire() inherits the SessionPool fail-closed contract: healthy
    session or None — never a dead session,
  * build_live_matrix() fails CLOSED per row: observations for roles
    without a live session are EXCLUDED and recorded as explicit
    ``no_live_session:<role>`` gaps; the matrix carries
    session_provenance so live-vs-assumed is always distinguishable,
  * snapshots never expose session material.
"""

from __future__ import annotations

from webpent.auth.identity_orchestrator import (
    IdentityBuildOutcome,
    IdentityOrchestrator,
    IdentityProfile,
)

PROFILES = [
    IdentityProfile(role="admin", credentials_handle="vault://admin", login_flow=("login", "mfa")),
    IdentityProfile(role="user", credentials_handle="vault://user", login_flow=("login",)),
    IdentityProfile(role="auditor", credentials_handle="vault://auditor"),
]


def _factory_ok(profile: IdentityProfile):
    return {"token": f"session-for-{profile.role}"}


def _obs(role: str, identity: str, endpoint: str = "/api/x", accessible: bool = False):
    return {
        "role": role,
        "identity_ref": identity,
        "owner_identity": identity,
        "endpoint": endpoint,
        "method": "GET",
        "accessible": accessible,
        "status_code": 200 if accessible else 403,
        "response_fingerprint": f"fp-{identity}-{accessible}",
        "evidence_refs": [f"ev-{identity}"],
    }


# ---------------------------------------------------------------------------
# profiles and construction
# ---------------------------------------------------------------------------


def test_profile_dict_carries_no_raw_credentials() -> None:
    payload = PROFILES[0].as_dict()
    assert payload["credentials_handle"] == "vault://admin"
    assert payload["raw_credentials_included"] is False
    assert payload["login_flow"] == ["login", "mfa"]


def test_factory_is_required() -> None:
    try:
        IdentityOrchestrator(profiles=PROFILES, session_factory=None)  # type: ignore[arg-type]
    except ValueError:
        pass
    else:
        raise AssertionError("session_factory is required (fail-closed)")


def test_duplicate_and_empty_roles_are_ignored() -> None:
    orchestrator = IdentityOrchestrator(
        profiles=[
            *PROFILES,
            IdentityProfile(role="admin", credentials_handle="vault://dup"),
            IdentityProfile(role="  ", credentials_handle="vault://x"),
        ],
        session_factory=_factory_ok,
    )
    assert orchestrator.roles == ["admin", "auditor", "user"]


# ---------------------------------------------------------------------------
# ensure_sessions / acquire / maintain
# ---------------------------------------------------------------------------


def test_ensure_sessions_builds_all_roles_and_records_outcomes() -> None:
    orchestrator = IdentityOrchestrator(profiles=PROFILES, session_factory=_factory_ok)
    outcomes = orchestrator.ensure_sessions()
    assert [o.status for o in outcomes] == ["built", "built", "built"]
    assert all(isinstance(o, IdentityBuildOutcome) for o in outcomes)
    assert orchestrator.acquire("admin") == {"token": "session-for-admin"}


def test_factory_error_is_per_role_fail_soft() -> None:
    def factory(profile: IdentityProfile):
        if profile.role == "admin":
            raise RuntimeError("login down")
        return _factory_ok(profile)

    orchestrator = IdentityOrchestrator(profiles=PROFILES, session_factory=factory)
    outcomes = {o.role: o for o in orchestrator.ensure_sessions()}
    assert outcomes["admin"].status == "factory_error"
    assert outcomes["user"].status == "built"
    assert orchestrator.acquire("admin") is None  # fail-closed
    assert orchestrator.acquire("user") is not None


def test_factory_none_and_missing_handle_recorded() -> None:
    orchestrator = IdentityOrchestrator(
        profiles=[
            IdentityProfile(role="ghost", credentials_handle=""),
            IdentityProfile(role="absent", credentials_handle="vault://x"),
        ],
        session_factory=lambda profile: None,
    )
    outcomes = {o.role: o.status for o in orchestrator.ensure_sessions()}
    assert outcomes["ghost"] == "factory_none"
    assert outcomes["absent"] == "factory_none"


def test_pool_capacity_caps_registration() -> None:
    profiles = [
        IdentityProfile(role=f"role-{i}", credentials_handle=f"vault://{i}")
        for i in range(10)
    ]
    orchestrator = IdentityOrchestrator(
        profiles=profiles, session_factory=_factory_ok, max_roles=3
    )
    statuses = [o.status for o in orchestrator.ensure_sessions()]
    assert statuses.count("built") == 3
    assert statuses.count("capped") == 7


def test_maintain_reports_live_and_reauth_counts() -> None:
    calls = {"n": 0}

    def factory(profile: IdentityProfile):
        calls["n"] += 1
        return {"token": f"s{calls['n']}"}

    def probe(role: str, session) -> bool:
        return False  # every health check says dead → bounded re-auth

    orchestrator = IdentityOrchestrator(
        profiles=[IdentityProfile(role="user", credentials_handle="vault://user")],
        session_factory=factory,
        health_probe=probe,
        health_interval=0.0,  # always stale → probe runs on acquire
    )
    orchestrator.ensure_sessions()
    report = orchestrator.maintain()
    assert report["user"]["live"] is True  # re-auth recovered it
    assert report["user"]["reauth_count"] >= 1


def test_snapshot_and_provenance_expose_no_session_material() -> None:
    orchestrator = IdentityOrchestrator(profiles=PROFILES, session_factory=_factory_ok)
    orchestrator.ensure_sessions()
    provenance = orchestrator.session_provenance()
    assert provenance["live_roles"] == ["admin", "auditor", "user"]
    assert provenance["raw_session_material_exposed"] is False
    assert "token" not in str(provenance)


# ---------------------------------------------------------------------------
# build_live_matrix — live sessions instead of assumptions
# ---------------------------------------------------------------------------


def test_live_matrix_excludes_rows_without_live_sessions() -> None:
    def factory(profile: IdentityProfile):
        return None if profile.role == "ghost" else _factory_ok(profile)

    orchestrator = IdentityOrchestrator(
        profiles=[
            IdentityProfile(role="admin", credentials_handle="vault://admin"),
            IdentityProfile(role="ghost", credentials_handle="vault://ghost"),
        ],
        session_factory=factory,
    )
    orchestrator.ensure_sessions()
    matrix = orchestrator.build_live_matrix(
        [_obs("admin", "id-admin"), _obs("ghost", "id-ghost")]
    )
    identities = matrix["identities"]
    assert "id-admin" in identities
    assert "id-ghost" not in identities
    assert "no_live_session:ghost" in matrix["coverage_gaps"]
    assert "identity_rows_excluded_no_live_session" in matrix["coverage_gaps"]
    provenance = matrix["session_provenance"]
    assert provenance["live_roles"] == ["admin"]
    assert provenance["excluded_roles"] == ["ghost"]
    assert provenance["rows_verified_live"] == 1
    assert provenance["rows_excluded"] == 1
    assert provenance["sessions_instead_of_assumptions"] is True


def test_live_matrix_with_all_roles_live_has_no_exclusion_gaps() -> None:
    orchestrator = IdentityOrchestrator(
        profiles=[
            IdentityProfile(role="admin", credentials_handle="vault://admin"),
            IdentityProfile(role="user", credentials_handle="vault://user"),
        ],
        session_factory=_factory_ok,
    )
    orchestrator.ensure_sessions()
    matrix = orchestrator.build_live_matrix(
        [_obs("admin", "id-admin", accessible=True), _obs("user", "id-user", accessible=False)]
    )
    assert sorted(matrix["identities"]) == ["id-admin", "id-user"]
    assert not any(
        gap.startswith("no_live_session") for gap in matrix["coverage_gaps"]
    )
    # two roles + differential access → a vertical comparison exists
    assert matrix["comparisons"], "expected at least one comparison"
    provenance = matrix["session_provenance"]
    assert provenance["rows_verified_live"] == 2
    assert provenance["rows_excluded"] == 0


def test_live_matrix_with_no_sessions_at_all_yields_empty_but_honest_matrix() -> None:
    orchestrator = IdentityOrchestrator(
        profiles=[IdentityProfile(role="user", credentials_handle="vault://user")],
        session_factory=lambda profile: None,
    )
    orchestrator.ensure_sessions()
    matrix = orchestrator.build_live_matrix([_obs("user", "id-user")])
    assert matrix["rows"] == []
    assert "no_live_session:user" in matrix["coverage_gaps"]


def test_live_matrix_skips_non_mapping_rows() -> None:
    orchestrator = IdentityOrchestrator(
        profiles=[IdentityProfile(role="user", credentials_handle="vault://user")],
        session_factory=_factory_ok,
    )
    orchestrator.ensure_sessions()
    matrix = orchestrator.build_live_matrix([_obs("user", "id-user"), "not-a-mapping"])  # type: ignore[list-item]
    assert matrix["session_provenance"]["rows_excluded"] == 1
    assert matrix["session_provenance"]["rows_verified_live"] == 1
