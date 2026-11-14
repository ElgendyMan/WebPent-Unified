"""WebGoat-local implementation of the generic target-context contracts.

The adapter contains only WebGoat naming and mapping. It does not perform
authentication, network I/O, or application state mutation; those operations
remain outside this offline provider until a separately approved mechanism
exists.
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

WEBGOAT_TARGET_SPEC_ID = "webgoat-target-spec"
WEBGOAT_CONTEXT_CAPABILITIES = frozenset(
    {"read_only_navigation", "context_snapshot", "context_restore", "context_disposal"}
)


class WebGoatContextProvider(MockContextProvider):
    """Target-local context lifecycle with no transport implementation."""

    def capabilities(self) -> set[str]:
        return set(WEBGOAT_CONTEXT_CAPABILITIES)

    def prepare(self, request: ContextRequest):
        if not request.scope.target_spec_id.startswith("webgoat"):
            return super().prepare(request)
        return super().prepare(request)


class WebGoatLessonSessionProvider(MockSessionProvider):
    """Maps synthetic identity metadata to an in-memory LessonSession reference."""

    def create_synthetic_context(self, request: IdentityRequest) -> SessionHandle:
        session = super().create_synthetic_context(request)
        return SessionHandle(
            session_ref="webgoat-lesson-session-" + request.identity_ref,
            identity=session.identity,
            in_memory_only=True,
            ready=session.ready,
            reason=session.reason,
        )


class WebGoatLessonFixtureProvider(MockFixtureProvider):
    """Disposable owner/requester lesson descriptors for offline adapter tests."""

    def provision(self, fixture_request: FixtureRequest):
        return super().provision(fixture_request)


def webgoat_scope(
    campaign_id: str = "webgoat-context-campaign",
    run_id: str = "webgoat-context-run",
) -> TargetScope:
    return TargetScope(
        WEBGOAT_TARGET_SPEC_ID,
        campaign_id,
        run_id,
        "http://127.0.0.1:8080",
        "webgoat-scope",
    )


__all__ = [
    "WEBGOAT_CONTEXT_CAPABILITIES",
    "WEBGOAT_TARGET_SPEC_ID",
    "WebGoatContextProvider",
    "WebGoatLessonFixtureProvider",
    "WebGoatLessonSessionProvider",
    "webgoat_scope",
]
