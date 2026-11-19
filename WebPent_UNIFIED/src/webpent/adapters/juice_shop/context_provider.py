"""Offline-only Target Context provider for the Juice Shop adapter.

This module owns only target naming and metadata. It intentionally performs no
network I/O, authentication, token handling, or application mutation.
"""

from __future__ import annotations

from webpent.adapters.mock_target.context_provider import (
    MockContextProvider,
    MockFixtureProvider,
    MockSessionProvider,
)
from webpent.shared.target_context import (
    ContextRequest,
    FixtureRequest,
    IdentityRequest,
    SessionHandle,
    TargetScope,
)

JUICE_SHOP_TARGET_SPEC_ID = "juice-shop-target-spec"
JUICE_SHOP_CONTEXT_CAPABILITIES = frozenset(
    {"read_only_navigation", "context_snapshot", "context_restore", "context_disposal"}
)


class JuiceShopContextProvider(MockContextProvider):
    """Target-local lifecycle metadata with no transport implementation."""

    def capabilities(self) -> set[str]:
        return set(JUICE_SHOP_CONTEXT_CAPABILITIES)

    def prepare(self, request: ContextRequest):
        return super().prepare(request)


class JuiceShopSessionProvider(MockSessionProvider):
    """Maps synthetic metadata to a disposable in-memory session reference."""

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle:
        session = super().create_synthetic_context(request)
        return SessionHandle(
            session_ref="juice-shop-session-" + request.identity_ref,
            identity=session.identity,
            in_memory_only=True,
            ready=session.ready,
            reason=session.reason,
        )


class JuiceShopFixtureProvider(MockFixtureProvider):
    """Disposable offline fixture descriptors for lifecycle portability tests."""

    def provision(self, fixture_request: FixtureRequest):
        return super().provision(fixture_request)


def juice_shop_scope(
    campaign_id: str = "juice-shop-context-campaign",
    run_id: str = "juice-shop-context-run",
) -> TargetScope:
    return TargetScope(
        JUICE_SHOP_TARGET_SPEC_ID,
        campaign_id,
        run_id,
        "http://127.0.0.1:3000",
        "juice-shop-scope",
    )


__all__ = [
    "JUICE_SHOP_CONTEXT_CAPABILITIES",
    "JUICE_SHOP_TARGET_SPEC_ID",
    "JuiceShopContextProvider",
    "JuiceShopFixtureProvider",
    "JuiceShopSessionProvider",
    "juice_shop_scope",
]
