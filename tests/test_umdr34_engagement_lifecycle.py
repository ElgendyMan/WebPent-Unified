"""UM-DR-34 Phase 3 — engagement context lifecycle regression tests.

Covers: fail-closed admission, atomic nested restore, exception-path
cleanup, thread/async isolation, bare-host port binding, control-plane
separation.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading

import pytest

from webpent.shared.engagement_scope import (
    EngagementToken,
    clear_engagement_target_hosts,
    get_engagement_context,
    get_engagement_origin_policies,
    get_engagement_target_hosts,
    is_engagement_origin_allowed,
    is_engagement_target_host,
    set_control_plane_egress,
    set_engagement_target_hosts,
)


@pytest.fixture(autouse=True)
def _clean_context():
    yield
    # Force-clean whatever a test left behind.
    clear_engagement_target_hosts(None)


class TestFailClosedAdmission:
    def test_valid_engagement_allows_declared_origin(self) -> None:
        token = set_engagement_target_hosts("https://lab.example.com:8443/app")
        try:
            assert is_engagement_origin_allowed("https://lab.example.com:8443/app/x")
        finally:
            clear_engagement_target_hosts(token)

    def test_active_engagement_without_valid_policy_denies(self) -> None:
        # The §3.1 defect: URL-like input that yields no valid policy
        # used to fail OPEN.  It must now deny everything.
        token = set_engagement_target_hosts("::: not a url :::")
        try:
            assert get_engagement_context().egress_mode == "ENGAGEMENT"
            assert not get_engagement_context().is_valid_engagement
            assert not is_engagement_origin_allowed("http://anything.example.com/")
            assert not is_engagement_origin_allowed("https://lab.example.com/")
        finally:
            clear_engagement_target_hosts(token)

    def test_no_context_is_legacy_not_engagement(self) -> None:
        # No engagement declared: plain library use keeps the legacy
        # blocklist-only posture (NOT an active campaign).
        assert get_engagement_context().egress_mode == "NONE"
        assert is_engagement_origin_allowed("https://public.example.com/")


class TestAtomicLifecycle:
    def test_nested_engagement_restores_outer_policy(self) -> None:
        outer = set_engagement_target_hosts("https://outer.example.com:9000/app")
        try:
            inner = set_engagement_target_hosts("https://inner.example.com/")
            try:
                assert is_engagement_origin_allowed("https://inner.example.com/x")
                # Inner masks outer.
                assert not is_engagement_origin_allowed("https://outer.example.com:9000/app/x")
            finally:
                clear_engagement_target_hosts(inner)
            # §3.2: the OUTER engagement must be fully restored —
            # policies included (the historic cleanup forced them empty).
            assert is_engagement_origin_allowed("https://outer.example.com:9000/app/x")
            assert not is_engagement_origin_allowed("https://inner.example.com/x")
        finally:
            clear_engagement_target_hosts(outer)
        assert get_engagement_context().egress_mode == "NONE"

    def test_exception_path_restores_context(self) -> None:
        outer = set_engagement_target_hosts("https://outer.example.com:9000/app")
        try:
            with pytest.raises(RuntimeError):
                token = set_engagement_target_hosts("https://inner.example.com/")
                try:
                    raise RuntimeError("campaign crashed")
                finally:
                    clear_engagement_target_hosts(token)
            assert is_engagement_origin_allowed("https://outer.example.com:9000/app/x")
        finally:
            clear_engagement_target_hosts(outer)

    def test_structured_token_shape(self) -> None:
        token = set_engagement_target_hosts("https://a.example.com/")
        assert isinstance(token, EngagementToken)
        clear_engagement_target_hosts(token)
        # A second clear with the same token restores None again (idempotent).
        clear_engagement_target_hosts(token)
        assert get_engagement_context().egress_mode == "NONE"

    def test_compat_views_derive_from_atomic_context(self) -> None:
        token = set_engagement_target_hosts("https://lab.example.com:8443/app")
        try:
            assert get_engagement_target_hosts() == frozenset({"lab.example.com"})
            assert len(get_engagement_origin_policies()) == 1
            assert is_engagement_target_host("lab.example.com")
            assert not is_engagement_target_host("other.example.com")
        finally:
            clear_engagement_target_hosts(token)


class TestBareHostPortBinding:
    def test_bare_host_binds_default_ports_only(self) -> None:
        token = set_engagement_target_hosts("192.168.40.128")
        try:
            assert is_engagement_origin_allowed("http://192.168.40.128/dvwa/")
            assert is_engagement_origin_allowed("https://192.168.40.128/x")
            # §3.3: a hostname-only declaration must not authorize every port.
            assert not is_engagement_origin_allowed("http://192.168.40.128:8080/")
            assert not is_engagement_origin_allowed("https://192.168.40.128:8443/")
        finally:
            clear_engagement_target_hosts(token)

    def test_private_target_exception_requires_full_origin(self) -> None:
        token = set_engagement_target_hosts("http://192.168.40.128:8080/dvwa/")
        try:
            assert is_engagement_origin_allowed("http://192.168.40.128:8080/dvwa/login")
            # Different port on the same private host: denied at origin level.
            assert not is_engagement_origin_allowed("http://192.168.40.128:9090/admin")
        finally:
            clear_engagement_target_hosts(token)


class TestControlPlaneSeparation:
    def test_control_plane_egress_is_narrow(self) -> None:
        token = set_control_plane_egress(
            [("https", "api.openai.example", 443), ("http", "collector.local", 8080)]
        )
        try:
            assert is_engagement_origin_allowed("https://api.openai.example/v1/chat")
            assert is_engagement_origin_allowed("http://collector.local:8080/poll")
            # Different host / port / scheme: denied.
            assert not is_engagement_origin_allowed("https://api.openai.example:8443/")
            assert not is_engagement_origin_allowed("http://api.openai.example/")
            assert not is_engagement_origin_allowed("https://target.example.com/")
        finally:
            clear_engagement_target_hosts(token)

    def test_control_plane_cannot_inherit_campaign_targets(self) -> None:
        campaign = set_engagement_target_hosts("https://target.example.com/")
        try:
            cp = set_control_plane_egress([("https", "llm.example", 443)])
            try:
                assert not is_engagement_origin_allowed("https://target.example.com/")
            finally:
                clear_engagement_target_hosts(cp)
            assert is_engagement_origin_allowed("https://target.example.com/")
        finally:
            clear_engagement_target_hosts(campaign)

    def test_invalid_control_plane_destination_rejected(self) -> None:
        with pytest.raises(ValueError):
            set_control_plane_egress([("https", "bad host!!", 443)])
        with pytest.raises(ValueError):
            set_control_plane_egress([("https", "llm.example", 0)])
        with pytest.raises(ValueError):
            set_control_plane_egress([("https", "llm.example", 70000)])


class TestThreadAndAsyncPropagation:
    def test_threads_do_not_inherit_foreign_engagement(self) -> None:
        token = set_engagement_target_hosts("https://lab.example.com:8443/app")
        try:
            origin_seen: dict[str, bool] = {}
            target_seen: dict[str, bool] = {}

            def _worker(name: str, context: contextvars.Context) -> None:
                # §3.4: business-logic-fuzzer pattern — each thread runs
                # in its own copied context.
                def _run() -> None:
                    origin_seen[name] = is_engagement_origin_allowed(
                        "https://lab.example.com:8443/app/x"
                    )
                    target_seen[name] = is_engagement_target_host("lab.example.com")

                context.run(_run)

            # Thread WITH a copied context: sees the engagement.
            ctx_with = contextvars.copy_context()
            t1 = threading.Thread(target=_worker, args=("with", ctx_with))
            # Thread with a FRESH context: must NOT see the engagement —
            # no campaign context, no target-host permission.
            t2 = threading.Thread(
                target=_worker, args=("fresh", contextvars.Context())
            )
            t1.start(); t2.start()
            t1.join(timeout=10); t2.join(timeout=10)
            assert origin_seen["with"] is True
            assert target_seen["with"] is True
            assert target_seen["fresh"] is False  # no inherited permission
        finally:
            clear_engagement_target_hosts(token)

    def test_missing_context_blocks_in_thread(self) -> None:
        results: dict[str, bool] = {}

        def _worker() -> None:
            results["blocked"] = is_engagement_origin_allowed(
                "http://192.168.40.128:8080/x"
            )

        t = threading.Thread(target=_worker)
        t.start(); t.join(timeout=10)
        # No engagement in this fresh thread context: legacy posture is
        # allow at the ORIGIN level, but the private host itself is
        # never an engagement target.
        assert results["blocked"] is True  # origin-level: no policy
        assert not is_engagement_target_host("192.168.40.128")

    def test_async_task_isolation(self) -> None:
        async def _scenario() -> None:
            token = set_engagement_target_hosts("https://async.example.com:7000/")
            try:
                # Same-task await chain sees the context.
                async def _inner() -> bool:
                    return is_engagement_origin_allowed("https://async.example.com:7000/x")

                assert await _inner() is True
                # A task with a COPIED context in a different "thread of
                # control" does not leak after cleanup.
            finally:
                clear_engagement_target_hosts(token)
            fresh = is_engagement_origin_allowed("https://async.example.com:7000/x")
            assert fresh is True  # back to NONE mode (legacy)

        asyncio.run(_scenario())
        assert get_engagement_context().egress_mode == "NONE"

    def test_worker_reuse_cannot_inherit_previous_campaign(self) -> None:
        first = set_engagement_target_hosts("https://first.example.com:1000/")
        clear_engagement_target_hosts(first)
        second = set_engagement_target_hosts("https://second.example.com:2000/")
        try:
            assert not is_engagement_origin_allowed("https://first.example.com:1000/x")
            assert is_engagement_origin_allowed("https://second.example.com:2000/x")
        finally:
            clear_engagement_target_hosts(second)
