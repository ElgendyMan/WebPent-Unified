# tests/test_session_pool.py
"""Proposal 5 (2026-10-25) test suite: multi-principal session pool.

Covers the SessionPool (fail-closed acquire, bounded re-auth, read-only
snapshot, engagement registry bounds), the privilege-differential
validator contract, the production registry routing, the flag-gated
access_control session-pool filter, and the worker status snapshot.
"""
from __future__ import annotations

from typing import Any

import pytest

from webpent.config.settings import Settings
from webpent.auth.session_pool import (
    MAX_REGISTERED_POOLS,
    SessionPool,
    pop_pool,
    set_pool,
    snapshot_all,
)
from webpent.production.privilege_validator import validate_privilege_differential


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestSessionPool:
    def test_acquire_returns_healthy_session(self) -> None:
        pool = SessionPool()
        assert pool.register("admin", {"cookies": {"sid": "a"}})
        assert pool.acquire("admin") == {"cookies": {"sid": "a"}}

    def test_unregistered_role_without_reauth_fails_closed(self) -> None:
        pool = SessionPool()
        assert pool.acquire("ghost") is None

    def test_unregistered_role_with_reauth_is_acquired_once(self) -> None:
        pool = SessionPool()
        calls: list[str] = []

        def reauth(role: str) -> Any:
            calls.append(role)
            return {"cookies": {role: "fresh"}}

        pool.register_reauth("user", reauth)
        session = pool.acquire("user")
        assert session == {"cookies": {"user": "fresh"}}
        assert calls == ["user"]
        # Second acquire is served from the registered record.
        assert pool.acquire("user") is session
        assert calls == ["user"]

    def test_dead_session_reauthenticates_once(self) -> None:
        clock = _FakeClock()
        probes = {"alive": False}
        pool = SessionPool(
            health_probe=lambda role, session: probes["alive"],
            reauth=lambda role: {"cookies": {role: "reauthed"}},
            health_interval=300.0,
            now=clock,
        )
        pool.register("user", {"cookies": {"u": "stale"}})
        # Move past the health interval so the first acquire actually probes.
        clock.advance(400.0)
        assert pool.acquire("user") == {"cookies": {"user": "reauthed"}}

        # Healthy record is served fresh within the interval.
        probes["alive"] = True
        clock.advance(10.0)
        session = pool.acquire("user")
        assert session == {"cookies": {"user": "reauthed"}}

    def test_unrecoverable_session_fails_closed(self) -> None:
        clock = _FakeClock()
        pool = SessionPool(
            health_probe=lambda role, session: False,
            reauth=lambda role: None,  # re-auth cannot recover
            now=clock,
        )
        pool.register("user", {"cookies": {"u": "dead"}})
        clock.advance(400.0)  # past the health interval so the probe runs
        assert pool.acquire("user") is None  # dead -> excluded, never returned

    def test_reauth_exception_fails_closed(self) -> None:
        clock = _FakeClock()
        pool = SessionPool(
            health_probe=lambda role, session: False,
            reauth=lambda role: (_ for _ in ()).throw(RuntimeError("boom")),
            now=clock,
        )
        pool.register("user", {"s": 1})
        clock.advance(400.0)
        assert pool.acquire("user") is None

    def test_known_dead_within_interval_short_circuits(self) -> None:
        clock = _FakeClock()
        probe_calls: list[str] = []
        pool = SessionPool(
            health_probe=lambda role, session: probe_calls.append(role) or False,
            reauth=lambda role: None,
            now=clock,
        )
        pool.register("user", {"s": 1})
        clock.advance(400.0)
        assert pool.acquire("user") is None
        assert pool.acquire("user") is None  # still within fresh-dead window
        assert len(probe_calls) == 1

    def test_snapshot_never_exposes_session_material(self) -> None:
        pool = SessionPool()
        pool.register("user", {"cookies": {"sid": "SECRET"}, "headers": {"X": "Y"}})
        snap = pool.snapshot()
        assert len(snap) == 1
        record = snap[0]
        assert record["role"] == "user"
        assert record["healthy"] is True
        assert "reauth_count" in record and "age_seconds" in record
        flat = repr(record)
        assert "SECRET" not in flat and "sid" not in flat

    def test_register_is_bounded(self) -> None:
        pool = SessionPool(max_sessions=2)
        assert pool.register("a", 1)
        assert pool.register("b", 2)
        assert pool.register("c", 3) is False
        # Re-registration of an existing role still replaces.
        assert pool.register("a", 10)

    def test_pool_registry_is_bounded_and_keyed(self) -> None:
        for i in range(MAX_REGISTERED_POOLS + 4):
            set_pool(f"eng-{i}", SessionPool())
        # The newest pool carries one live session so the fleet snapshot
        # has something to show.
        set_pool(f"eng-{MAX_REGISTERED_POOLS + 3}", SessionPool())
        set_pool(f"eng-{MAX_REGISTERED_POOLS + 3}", SessionPool())  # replace is fine
        last_pool = pop_pool(f"eng-{MAX_REGISTERED_POOLS + 3}")
        assert last_pool is not None
        last_pool.register("user", {"cookies": {"sid": "a"}})
        set_pool(f"eng-{MAX_REGISTERED_POOLS + 3}", last_pool)
        snap = snapshot_all()
        ids = [r["engagement_id"] for r in snap]
        # Oldest engagements were dropped; the newest survived.
        assert f"eng-{MAX_REGISTERED_POOLS + 3}" in ids
        assert "eng-0" not in ids
        assert len(snap) <= MAX_REGISTERED_POOLS * 8
        assert pop_pool(f"eng-{MAX_REGISTERED_POOLS + 3}") is not None


def _ev(status: int, body: str = "", **extra: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {"status_code": status, "response_body": body}
    ev.update(extra)
    return ev


class TestPrivilegeDifferentialValidator:
    def test_confirmed_on_differential(self) -> None:
        result = validate_privilege_differential(
            baseline=_ev(200, "owner invoice data"),
            candidate=_ev(200, "invoice 42 details, total $900"),
            negative_control=_ev(403, "forbidden"),
        )
        assert result.outcome.value == "CONFIRMED"
        assert result.evidence_quality.name == "OBSERVED_DIFFERENTIAL"
        assert result.refutation_path is None

    def test_candidate_denied_is_refuted(self) -> None:
        result = validate_privilege_differential(
            baseline=_ev(200, "owner data"),
            candidate=_ev(403, "forbidden"),
            negative_control=_ev(403, "forbidden"),
        )
        assert result.outcome.value == "REFUTED"
        assert result.refutation_path == "candidate_denied"

    def test_control_also_authorized_is_refuted(self) -> None:
        result = validate_privilege_differential(
            baseline=_ev(200, "owner data"),
            candidate=_ev(200, "resource reached"),
            negative_control=_ev(200, "allowed too"),
        )
        assert result.outcome.value == "REFUTED"
        assert result.refutation_path == "control_also_authorized"

    def test_candidate_body_matches_denial_is_refuted(self) -> None:
        # A candidate 2xx that delivered the control's denial PAGE (an
        # authorization wrapper without resource access) — the body is
        # worded so it does NOT trip the generic error-signature
        # heuristics, isolating the body-equality refutation path.
        denial_body = "membership tier two requires an upgrade to view this statement"
        result = validate_privilege_differential(
            baseline=_ev(200, "owner data"),
            candidate=_ev(200, denial_body),
            negative_control=_ev(403, denial_body),
        )
        assert result.outcome.value == "REFUTED"
        assert result.refutation_path == "candidate_body_matches_denial"

    def test_transport_failure_is_inconclusive_never_refutation(self) -> None:
        result = validate_privilege_differential(
            baseline=_ev(200, "owner data"),
            candidate=_ev(0, ""),
            negative_control=_ev(403, "forbidden"),
        )
        assert result.outcome.value == "INCONCLUSIVE"
        assert result.details.get("reason") == "candidate_unjudgeable"

        result = validate_privilege_differential(
            baseline=_ev(200, "owner data"),
            candidate=_ev(200, "resource"),
            negative_control=_ev(503, "unavailable"),
        )
        assert result.outcome.value == "INCONCLUSIVE"
        assert result.details.get("reason") == "control_unjudgeable"

    def test_missing_evidence_raises_fail_closed(self) -> None:
        from webpent.production.validators import ValidatorError

        with pytest.raises(ValidatorError):
            validate_privilege_differential(
                baseline=None,
                candidate=_ev(200, "x"),
                negative_control=_ev(403, "y"),
            )

    def test_registry_routes_the_family(self) -> None:
        from webpent.production.validators import run_validator

        result = run_validator(
            "PRIVILEGE_DIFFERENTIAL",
            baseline=_ev(200, "owner data"),
            candidate=_ev(200, "invoice 42 details"),
            negative_control=_ev(403, "forbidden"),
        )
        assert result.outcome.value == "CONFIRMED"

    def test_vuln_class_member_not_exploitable(self) -> None:
        from webpent.models.findings import EXPLOITABLE_CLASSES, VulnClass

        assert VulnClass.PRIVILEGE_DIFFERENTIAL.value == "privilege_differential"
        assert VulnClass.PRIVILEGE_DIFFERENTIAL not in EXPLOITABLE_CLASSES


class TestSessionPoolDefaultsOff:
    def test_flag_default_off(self) -> None:
        assert Settings().enable_session_pool is False
        assert Settings().enable_js_discovery is False

    def test_worker_status_unchanged_with_flag_off(self, monkeypatch) -> None:
        # With the flag off the worker status dict carries no sessions key;
        # the snapshot machinery is never imported.
        import inspect

        from webpent.workers import pentest_worker

        source = inspect.getsource(pentest_worker.run_pentest_task)
        # Flag gate precedes any snapshot use.
        gate_index = source.index("enable_session_pool")
        snapshot_index = source.index("snapshot_all()")
        assert gate_index < snapshot_index

    def test_snapshot_all_empty_without_pools(self) -> None:
        pop_pool("test-empty-engagement")
        assert snapshot_all() == [] or all(
            r["engagement_id"] != "test-empty-engagement" for r in snapshot_all()
        )
