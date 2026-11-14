# tests/test_role_matrix.py
"""PROPOSALS_ULTIMATE_V2 §4 (2026-10-30) test suite: role matrix.

Covers fail-closed session registration (no verifier, failed verifier,
verifier that raises), the deterministic pair build (sorted, owner-pairs
excluded, owner-session-missing aborts, budget aborts), the three-probe
differential feeding assess_access_control (confirmed IDOR on a fixture
fetched through an injectable fetcher; healthy roles refuted; a public
resource not misreported), and every flag-off default.
"""

from __future__ import annotations

import pytest

from webpent.agents.role_matrix import (
    MatrixResource,
    RoleMatrixError,
    RoleSessionError,
    build_role_matrix,
    register_role_session,
    run_role_matrix,
)
from webpent.config.settings import Settings

OWNER_BODY = "admin dashboard: secret payroll 42"
FOREIGN_2XX_BODY = "admin dashboard: secret payroll 42"  # leaked verbatim
DENIED_BODY = "403 forbidden"


def _verifier_ok(session):
    return True, "role control marker matched"


def _sessions():
    return {
        "admin": register_role_session(
            "admin",
            cookies={"sid": "a1"},
            owned_urls=("https://t/admin/payroll",),
            verifier=_verifier_ok,
        ),
        "user": register_role_session(
            "user",
            cookies={"sid": "u1"},
            owned_urls=("https://t/user/profile",),
            verifier=_verifier_ok,
        ),
    }


def _resources():
    return [MatrixResource.from_url("https://t/admin/payroll", "admin")]


class TestSessions:
    def test_no_verifier_refused(self) -> None:
        with pytest.raises(RoleSessionError):
            register_role_session("admin", cookies={"sid": "a"})

    def test_failed_verifier_refused(self) -> None:
        def bad(session):
            return False, "role control marker absent"

        with pytest.raises(RoleSessionError):
            register_role_session("admin", cookies={"sid": "a"}, verifier=bad)

    def test_raising_verifier_refused(self) -> None:
        def explodes(session):
            raise RuntimeError("probe target down")

        with pytest.raises(RoleSessionError):
            register_role_session("admin", cookies={"sid": "a"}, verifier=explodes)

    def test_verified_session_carries_profile_and_detail(self) -> None:
        session = register_role_session(
            "user", cookies={"sid": "u1"},
            owned_urls=("https://t/user/profile",), verifier=_verifier_ok,
        )
        assert session.verified is True
        assert session.verify_detail == "role control marker matched"
        assert session.profile.owned_urls == frozenset({"https://t/user/profile"})
        assert "u1" not in repr(session)  # cookies never in repr


class TestPairBuild:
    def test_pairs_deterministic_owner_excluded(self) -> None:
        pairs = build_role_matrix(_resources(), _sessions())
        assert [(p.subject_role, p.resource.url) for p in pairs] == [
            ("user", "https://t/admin/payroll")
        ]
        again = build_role_matrix(_resources(), _sessions())
        assert pairs == again

    def test_missing_owner_session_aborts(self) -> None:
        sessions = _sessions()
        sessions.pop("admin")
        with pytest.raises(RoleMatrixError):
            build_role_matrix(_resources(), sessions)

    def test_budget_exceeded_aborts(self) -> None:
        with pytest.raises(RoleMatrixError):
            build_role_matrix(_resources(), _sessions(), max_pairs=0)

    def test_subject_already_owning_resource_skipped(self) -> None:
        sessions = _sessions()
        sessions["admin2"] = register_role_session(
            "admin2", cookies={"sid": "a2"},
            owned_urls=("https://t/admin/payroll",), verifier=_verifier_ok,
        )
        pairs = build_role_matrix(_resources(), sessions)
        assert {p.subject_role for p in pairs} == {"user"}


class TestRun:
    def _fetcher(self, role_bodies: dict[str, object]):
        def fetch(url, cookies, headers):
            if not cookies:
                return 403, DENIED_BODY  # anonymous denied
            sid = cookies.get("sid")
            return role_bodies[sid]

        return fetch

    def test_cross_role_idor_confirmed(self) -> None:
        bodies = {
            "a1": (200, OWNER_BODY),
            "u1": (200, FOREIGN_2XX_BODY),
        }
        pairs = build_role_matrix(_resources(), _sessions())
        result = run_role_matrix(
            pairs, _sessions(), fetcher=self._fetcher(bodies)
        )
        assert result.confirmed == 1
        verdict = result.verdicts[0]
        assert verdict["status"] == "confirmed"
        assert verdict["subject_role"] == "user"
        assert verdict["owner_role"] == "admin"
        rows = {r["identity"]: r for r in verdict["observations"]}
        assert rows["user"]["accessible"] is True
        assert rows["anonymous"]["status_code"] == 403
        assert verdict["relational_edges"]

    def test_healthy_roles_refuted(self) -> None:
        bodies = {
            "a1": (200, OWNER_BODY),
            "u1": (403, DENIED_BODY),
        }
        pairs = build_role_matrix(_resources(), _sessions())
        result = run_role_matrix(
            pairs, _sessions(), fetcher=self._fetcher(bodies)
        )
        assert result.confirmed == 0
        assert result.refuted == 1

    def test_public_resource_not_reported_as_idor(self) -> None:
        # user's 2xx body is IDENTICAL to what anonymous sees: a public
        # page, so the differential refuses to call it access.
        bodies = {
            "a1": (200, OWNER_BODY),
            "u1": (200, "welcome to the site, sign in for more"),
        }

        def fetch(url, cookies, headers):
            if not cookies:
                return 200, "welcome to the site, sign in for more"
            return bodies[cookies.get("sid")]

        pairs = build_role_matrix(_resources(), _sessions())
        result = run_role_matrix(pairs, _sessions(), fetcher=fetch)
        assert result.confirmed == 0

    def test_probe_failure_is_skip_not_crash(self) -> None:
        def fetch(url, cookies, headers):
            if not cookies:
                return None  # control probe failed
            return 200, OWNER_BODY

        pairs = build_role_matrix(_resources(), _sessions())
        result = run_role_matrix(pairs, _sessions(), fetcher=fetch)
        assert result.skips[0]["reason"] == "probe_failed"
        assert result.verdicts == ()


class TestFlags:
    def test_defaults_off(self) -> None:
        settings = Settings()
        assert settings.enable_role_matrix is False
        assert settings.role_matrix_max_pairs == 200

    def test_env_override_and_budget(self) -> None:
        settings = Settings(enable_role_matrix=True, role_matrix_max_pairs=5)
        assert settings.enable_role_matrix is True
        assert settings.role_matrix_max_pairs == 5
        with pytest.raises(RoleMatrixError):
            build_role_matrix(_resources(), _sessions(),
                              max_pairs=settings.role_matrix_max_pairs - 10)
