"""UM-DR-48 Phase D — the five detection lanes: RED→GREEN + negativity.

Each lane is proven against the REAL battery labs (the same fixtures the
47 measurement ran on — ground truth unchanged): the vulnerable variant
must yield ≥1 CausalGuard-confirmed result (GREEN), the secure variant
must yield ZERO (negativity), and the flag OFF path must be a no-op
(behavioral merge discipline).
"""
from __future__ import annotations

import json
import os
import threading
from http.server import HTTPServer

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import pytest  # noqa: E402

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import umdr46_baseline_battery as battery  # noqa: E402

from webpent.production.detection_lanes_48 import (  # noqa: E402
    lanes_enabled,
    run_framing_differential_lane,
    run_graphql_cross_identity_lane,
    run_redirect_policy_lane,
    run_tenant_override_lane,
    run_workflow_skip_lane,
    workflow_skip_candidates,
)

OWNER = {"name": "user-a", "role": "owner",
         "cookies": {"session": battery.SESS_A}}
FOREIGN = {"name": "user-b", "role": "user",
           "cookies": {"session": battery.SESS_B}}


def _start(family: str, secure: bool):
    lab_cls = battery.FAMILY_LABS[family]
    lab_cls.secure = secure
    lab_cls.request_log = []
    outer = battery._OutOfScopeOrigin()
    lab_cls.out_of_scope_origin = outer.origin
    server = HTTPServer(("127.0.0.1", 0), lab_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return f"http://127.0.0.1:{server.server_address[1]}", server, outer


@pytest.fixture()
def workflow_lab():
    origin, server, _oos = _start("workflow_abuse", secure=False)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def workflow_secure_lab():
    origin, server, _oos = _start("workflow_abuse", secure=True)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def smuggling_lab():
    origin, server, _oos = _start("request_smuggling", secure=False)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def smuggling_secure_lab():
    origin, server, _oos = _start("request_smuggling", secure=True)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def graphql_lab():
    origin, server, _oos = _start("graphql_oracle", secure=False)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def graphql_secure_lab():
    origin, server, _oos = _start("graphql_oracle", secure=True)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def tenant_lab():
    origin, server, _oos = _start("tenant_confusion", secure=False)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def tenant_secure_lab():
    origin, server, _oos = _start("tenant_confusion", secure=True)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def redirect_lab():
    origin, server, _oos = _start("redirect_scope_bypass", secure=False)
    yield origin
    server.shutdown()
    _oos.shutdown()


@pytest.fixture()
def redirect_secure_lab():
    origin, server, _oos = _start("redirect_scope_bypass", secure=True)
    yield origin
    server.shutdown()
    _oos.shutdown()


def _state(origin: str, **extra):
    state = {
        "target_url": origin,
        "engagement_id": "umdr48-d-lane-test",
        "auto_approve": True,
        "identity_profiles": [OWNER, FOREIGN],
        "session_cookies": {"session": battery.SESS_A},
    }
    state.update(extra)
    return state


# ---------------------------------------------------------------------------
# The flag gate (behavioral merge discipline)
# ---------------------------------------------------------------------------
class TestFlagGate:
    def test_off_by_default(self):
        assert lanes_enabled({}) is False

    def test_on_via_state(self):
        assert lanes_enabled({"enable_umdr48_lanes": True}) is True

    def test_on_via_env(self, monkeypatch):
        monkeypatch.setenv("ENABLE_UMDR48_LANES", "true")
        from webpent.config.settings import get_settings
        get_settings.cache_clear()
        assert lanes_enabled({}) is True
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# D1 — workflow-skip
# ---------------------------------------------------------------------------
class TestD1WorkflowSkip:
    def test_candidates_extracted_from_crawl_shape(self, workflow_lab):
        crawled = {"endpoints": [
            f"{workflow_lab}/api/orders/ORD-W-101/ship",
            f"{workflow_lab}/api/orders/ORD-W-555/ship",
        ]}
        cands = workflow_skip_candidates(crawled, [])
        assert cands, "the ship-action shape must yield candidates"
        assert all(c["terminal_state"] == "ship" for c in cands)

    def test_green_on_vulnerable(self, workflow_lab):
        battery._reset_workflow_orders()
        state = _state(workflow_lab, crawled_data={
            "endpoints": [
                f"{workflow_lab}/api/orders/ORD-W-101/ship",
                f"{workflow_lab}/api/orders/ORD-W-555/ship",
            ]})
        results = run_workflow_skip_lane(state)
        assert results, "the lane must produce results on the lab"
        assert any(r["confirmed"] for r in results), (
            [r for r in results if not r["confirmed"]][:1]
            or "no candidates ran")

    def test_red_proof_and_negativity_on_secure(self, workflow_secure_lab):
        battery._reset_workflow_orders()
        state = _state(workflow_secure_lab, crawled_data={
            "endpoints": [
                f"{workflow_secure_lab}/api/orders/ORD-W-101/ship",
                f"{workflow_secure_lab}/api/orders/ORD-W-555/ship",
            ]})
        results = run_workflow_skip_lane(state)
        # the secure variant 409s the skip — nothing confirms, and the
        # lane honestly returns no confirmed results
        assert not any(r["confirmed"] for r in results), results


# ---------------------------------------------------------------------------
# D2 — framing differential
# ---------------------------------------------------------------------------
class TestD2Framing:
    def test_green_on_vulnerable(self, smuggling_lab):
        state = _state(smuggling_lab, crawled_data={
            "endpoints": [f"{smuggling_lab}/api/echo"]})
        results = run_framing_differential_lane(state)
        assert any(r["confirmed"] for r in results), (
            [r.get("reason") for r in results])

    def test_negativity_on_secure(self, smuggling_secure_lab):
        state = _state(smuggling_secure_lab, crawled_data={
            "endpoints": [f"{smuggling_secure_lab}/api/echo"]})
        results = run_framing_differential_lane(state)
        assert not any(r["confirmed"] for r in results)


# ---------------------------------------------------------------------------
# D3 — graphql cross-identity
# ---------------------------------------------------------------------------
class TestD3Graphql:
    def test_green_on_vulnerable(self, graphql_lab):
        state = _state(
            graphql_lab,
            crawled_data={"graphql_operations": []},
            umdr48_graphql_queries=[
                '{ invoice(id: "INV-G-303") { id owner status amount } }'],
        )
        results = run_graphql_cross_identity_lane(state)
        assert any(r["confirmed"] for r in results), (
            [r.get("reason") for r in results])

    def test_negativity_on_secure(self, graphql_secure_lab):
        state = _state(
            graphql_secure_lab,
            crawled_data={"graphql_operations": []},
            umdr48_graphql_queries=[
                '{ invoice(id: "INV-G-303") { id owner status amount } }'],
        )
        results = run_graphql_cross_identity_lane(state)
        assert not any(r["confirmed"] for r in results)


# ---------------------------------------------------------------------------
# D4 — tenant override
# ---------------------------------------------------------------------------
class TestD4Tenant:
    def test_green_on_vulnerable(self, tenant_lab):
        state = _state(tenant_lab, crawled_data={
            "endpoints": [
                f"{tenant_lab}/api/tenant/profiles/PROF-T2-55"]},
            umdr48_tenant_ids=["T1", "T2"])
        results = run_tenant_override_lane(state)
        assert any(r["confirmed"] for r in results), (
            [r.get("reason") for r in results])

    def test_negativity_on_secure(self, tenant_secure_lab):
        state = _state(tenant_secure_lab, crawled_data={
            "endpoints": [
                f"{tenant_secure_lab}/api/tenant/profiles/PROF-T2-55"]},
            umdr48_tenant_ids=["T1", "T2"])
        results = run_tenant_override_lane(state)
        assert not any(r["confirmed"] for r in results)


# ---------------------------------------------------------------------------
# D5 — redirect policy walk + raw path
# ---------------------------------------------------------------------------
class TestD5Redirect:
    def test_green_on_vulnerable_open_redirect(self, redirect_lab):
        oos = battery._OutOfScopeOrigin()
        try:
            state = _state(redirect_lab, crawled_data={
                "endpoints": [f"{redirect_lab}/api/redirect"]},
                umdr48_out_of_scope_origins=[oos.origin])
            results = run_redirect_policy_lane(state)
            assert any(r["confirmed"] and
                       r["vulnerability_class"] == "open_redirect"
                       for r in results), (
                [r.get("reason") for r in results])
        finally:
            oos.shutdown()

    def test_green_on_vulnerable_raw_path(self, redirect_lab):
        state = _state(redirect_lab, crawled_data={},
                       umdr48_raw_paths=["/public/../admin/reports"],
                       enable_umdr48_raw_path_lab_only=True)
        results = run_redirect_policy_lane(state)
        assert any(r["confirmed"] and
                   r["vulnerability_class"] == "path_traversal"
                   for r in results), (
            [r.get("reason") for r in results])

    def test_negativity_on_secure(self, redirect_secure_lab):
        oos = battery._OutOfScopeOrigin()
        try:
            state = _state(redirect_secure_lab, crawled_data={
                "endpoints": [f"{redirect_secure_lab}/api/redirect"]},
                umdr48_out_of_scope_origins=[oos.origin],
                umdr48_raw_paths=["/public/../admin/reports"],
                enable_umdr48_raw_path_lab_only=True)
            results = run_redirect_policy_lane(state)
            assert not any(r["confirmed"] for r in results), results
        finally:
            oos.shutdown()
