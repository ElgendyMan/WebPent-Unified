"""UM-DR-34 Phase 4/11 — boundary enforcement at the real transports.

Every denial test asserts the mocked network-attempt count is ZERO
(pre-network denial).  The transports exercised are the PRODUCTION
chokepoints: ``make_safe_httpx_client`` (sync), ``make_safe_httpx_async_client``
(async), and the redirect event-hook.
"""

from __future__ import annotations

import httpx
import pytest

from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import (
    RateLimitExceeded,
    SSRFRedirectBlockedError,
    make_safe_httpx_async_client,
    make_safe_httpx_client,
)


class CountingTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
    """Mock transport that counts every network attempt."""

    def __init__(self) -> None:
        self.attempts = 0
        self.urls: list[str] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        self.urls.append(str(request.url))
        return httpx.Response(200, text="ok")

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        self.urls.append(str(request.url))
        return httpx.Response(200, text="ok")


@pytest.fixture(autouse=True)
def _clean_context():
    yield
    clear_engagement_target_hosts(None)


def _sync_client(transport: CountingTransport) -> httpx.Client:
    return make_safe_httpx_client(transport=transport, timeout=5.0)


def _redirect_client(transport: CountingTransport, location: str) -> httpx.Client:
    class RedirectTransport(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            transport.attempts += 1
            transport.urls.append(str(request.url))
            if transport.attempts == 1:
                return httpx.Response(
                    302, headers={"location": location}, request=request
                )
            return httpx.Response(200, text="ok")

    return make_safe_httpx_client(
        transport=RedirectTransport(), timeout=5.0, follow_redirects=True
    )


# IP-literal engagement target: no DNS dependency inside the tests
# (the pinning transport resolves hostnames for real — the sandbox has
# no DNS for fake names, and fail-closed on DNS failure is CORRECT
# production behavior we do not want to mock away).
ENGAGEMENT = "http://10.10.0.5:8080/app"


class TestSyncBoundary:
    def test_in_scope_request_proceeds(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                response = client.get(f"{ENGAGEMENT}/login")
            assert response.status_code == 200
            assert mock.attempts == 1
        finally:
            clear_engagement_target_hosts(token)

    def test_out_of_scope_host_denied_before_network(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("https://evil.example.com/exfil")
            assert mock.attempts == 0  # pre-network denial
        finally:
            clear_engagement_target_hosts(token)

    def test_same_host_wrong_port_denied(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("http://10.10.0.5:9999/app/x")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)

    def test_scheme_mismatch_denied(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("https://10.10.0.5:8080/app/x")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)

    def test_excluded_path_denied(self) -> None:
        # Same origin declared with a path prefix: /admin is outside it.
        token = set_engagement_target_hosts("http://10.10.0.5:8080/app")
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("http://10.10.0.5:8080/admin/users")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)

    def test_private_target_port_binding_enforced(self) -> None:
        # §3.3: bare-host declaration never authorizes every port.
        token = set_engagement_target_hosts("192.168.40.128")
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("http://192.168.40.128:8080/dvwa/")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)

    def test_invalid_engagement_denies_everything(self) -> None:
        token = set_engagement_target_hosts("::: broken :::")
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("http://192.168.40.128:8080/dvwa/")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)

    def test_metadata_target_denied_unconditionally(self) -> None:
        token = set_engagement_target_hosts("http://10.10.0.5:8080/")
        try:
            mock = CountingTransport()
            with _sync_client(mock) as client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get("http://169.254.169.254/latest/meta-data/")
            assert mock.attempts == 0
        finally:
            clear_engagement_target_hosts(token)


class TestRedirectBoundary:
    def test_out_of_scope_redirect_denied_before_second_request(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            client = _redirect_client(mock, "https://evil.example.com/exfil")
            with client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get(f"{ENGAGEMENT}/redirector")
            # The FIRST request (in-scope) went out; the redirect target
            # was blocked BEFORE a second network attempt.
            assert mock.attempts == 1
        finally:
            clear_engagement_target_hosts(token)

    def test_in_scope_same_origin_redirect_allowed(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            client = _redirect_client(mock, f"{ENGAGEMENT}/final")
            with client:
                response = client.get(f"{ENGAGEMENT}/start")
            assert response.status_code == 200
            assert mock.attempts == 2
        finally:
            clear_engagement_target_hosts(token)

    def test_redirect_to_private_host_outside_engagement_denied(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            client = _redirect_client(mock, "http://169.254.169.254/meta")
            with client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get(f"{ENGAGEMENT}/redirector")
            assert mock.attempts == 1
        finally:
            clear_engagement_target_hosts(token)

    def test_redirect_port_escape_denied(self) -> None:
        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            mock = CountingTransport()
            client = _redirect_client(mock, "http://10.10.0.5:9999/app/x")
            with client:
                with pytest.raises(SSRFRedirectBlockedError):
                    client.get(f"{ENGAGEMENT}/redirector")
            assert mock.attempts == 1
        finally:
            clear_engagement_target_hosts(token)


class TestAsyncBoundary:
    def test_async_in_scope_request_proceeds(self) -> None:
        import asyncio

        async def _run() -> None:
            token = set_engagement_target_hosts(ENGAGEMENT)
            try:
                mock = CountingTransport()
                async with make_safe_httpx_async_client(
                    transport=mock, timeout=5.0
                ) as client:
                    response = await client.get(f"{ENGAGEMENT}/x")
                assert response.status_code == 200
                assert mock.attempts == 1
            finally:
                clear_engagement_target_hosts(token)

        asyncio.run(_run())

    def test_async_out_of_scope_denied_before_network(self) -> None:
        import asyncio

        async def _run() -> None:
            token = set_engagement_target_hosts(ENGAGEMENT)
            try:
                mock = CountingTransport()
                async with make_safe_httpx_async_client(
                    transport=mock, timeout=5.0
                ) as client:
                    with pytest.raises(SSRFRedirectBlockedError):
                        await client.get("https://evil.example.com/x")
                assert mock.attempts == 0  # §4.2: no reduced async policy
            finally:
                clear_engagement_target_hosts(token)

        asyncio.run(_run())

    def test_async_redirect_out_of_scope_denied(self) -> None:
        import asyncio

        class AsyncRedirectTransport(httpx.AsyncBaseTransport):
            def __init__(self) -> None:
                self.attempts = 0

            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                self.attempts += 1
                if self.attempts == 1:
                    return httpx.Response(
                        302,
                        headers={"location": "https://evil.example.com/"},
                        request=request,
                    )
                return httpx.Response(200, text="ok")

        async def _run() -> None:
            token = set_engagement_target_hosts(ENGAGEMENT)
            try:
                mock = AsyncRedirectTransport()
                async with make_safe_httpx_async_client(
                    transport=mock, timeout=5.0, follow_redirects=True
                ) as client:
                    with pytest.raises(SSRFRedirectBlockedError):
                        await client.get(f"{ENGAGEMENT}/start")
                assert mock.attempts == 1
            finally:
                clear_engagement_target_hosts(token)

        asyncio.run(_run())


class TestRateCeilingParity:
    def test_sync_engagement_ceiling_enforced(self) -> None:
        from webpent.shared import global_rate_governor as grg

        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            grg.reset_global_rate_governor()
            governor = grg.GlobalRateGovernor(max_concurrent=1, requests_per_minute=1)
            original = grg._GLOBAL_GOVERNOR
            grg._GLOBAL_GOVERNOR = governor
            try:
                mock = CountingTransport()
                with _sync_client(mock) as client:
                    # First request within the window: allowed.
                    client.get(f"{ENGAGEMENT}/a")
                    # Window budget (1/min) exhausted: second denied.
                    with pytest.raises(RateLimitExceeded):
                        client.get(f"{ENGAGEMENT}/b")
                assert mock.attempts == 1
            finally:
                grg._GLOBAL_GOVERNOR = original
                grg.reset_global_rate_governor()
        finally:
            clear_engagement_target_hosts(token)

    def test_async_engagement_ceiling_enforced(self) -> None:
        import asyncio

        from webpent.shared import global_rate_governor as grg

        async def _run() -> None:
            token = set_engagement_target_hosts(ENGAGEMENT)
            try:
                grg.reset_global_rate_governor()
                governor = grg.GlobalRateGovernor(max_concurrent=1, requests_per_minute=1)
                grg._GLOBAL_GOVERNOR = governor
                try:
                    mock = CountingTransport()
                    async with make_safe_httpx_async_client(
                        transport=mock, timeout=5.0
                    ) as client:
                        await client.get(f"{ENGAGEMENT}/a")
                        # §5.2: async transport has the SAME ceiling.
                        with pytest.raises(RateLimitExceeded):
                            await client.get(f"{ENGAGEMENT}/b")
                    assert mock.attempts == 1
                finally:
                    grg.reset_global_rate_governor()
            finally:
                clear_engagement_target_hosts(token)

        asyncio.run(_run())

    def test_governor_failure_denies_in_engagement(self) -> None:
        from webpent.shared import global_rate_governor as grg

        class ExplodingGovernor:
            def try_acquire(self, campaign_id: str) -> bool:
                raise RuntimeError("governor bug")

            def release(self, campaign_id: str) -> None:
                return None

        token = set_engagement_target_hosts(ENGAGEMENT)
        try:
            grg.reset_global_rate_governor()
            original = grg._GLOBAL_GOVERNOR
            grg._GLOBAL_GOVERNOR = ExplodingGovernor()  # type: ignore[assignment]
            try:
                mock = CountingTransport()
                with _sync_client(mock) as client:
                    # §5.4: governor exception in an ACTIVE campaign
                    # DENIES the request (fail-closed), never fails open.
                    with pytest.raises(RateLimitExceeded):
                        client.get(f"{ENGAGEMENT}/x")
                assert mock.attempts == 0
            finally:
                grg._GLOBAL_GOVERNOR = original
                grg.reset_global_rate_governor()
        finally:
            clear_engagement_target_hosts(token)

    def test_ceiling_independent_of_rate_limit_enabled(self) -> None:
        # §5.1: the engagement ceiling is on even with the legacy
        # switch off (and independent of stealth_mode, which lives
        # elsewhere): proven by test_sync_engagement_ceiling_enforced
        # running with the default rate_limit_enabled=False settings.
        from webpent.config.settings import get_settings

        assert get_settings().rate_limit_enabled is False
