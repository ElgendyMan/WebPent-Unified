"""UM-DR-44 B6 — closing four structural fail-open gaps.

Verified on the current tree:

(a) ``engagement_scope.is_engagement_origin_allowed`` returns True for
    EVERY origin when no engagement context exists.  A Thread spawned
    by a campaign node does NOT inherit ``contextvars`` — inside an
    ACTIVE campaign that becomes fail-open.  Required: a thread with no
    context during an active campaign must DENY; behavior outside
    campaigns (no campaign declared at all) stays unchanged (legacy
    blocklist posture).

(b) ``h2_race._connect`` calls ``socket.create_connection`` on the
    hostname directly (no DNS pinning) and sets ``ssl.CERT_NONE``
    globally with no engagement/TLS-policy consultation.

(c) The request-smuggling raw sender checks the HOST only — the port
    is a free parameter from the caller.

(d) ``config.settings.rate_limit_enabled`` defaults to False (the one
    default change authorized by the mission's security exception,
    rule 9).
"""

from __future__ import annotations

import threading

import pytest

from webpent.shared import engagement_scope as es


class TestThreadContextPropagation:
    def test_thread_without_context_denies_during_active_engagement(self) -> None:
        """RED on the current tree: a real threading.Thread starts with
        an EMPTY contextvars context — it sees mode NONE while a
        campaign is active, and the NONE branch returns True (fail-
        open).  Required: that state must DENY."""
        scope_mod = es
        results: dict[str, object] = {}

        def _in_thread() -> None:
            results["mode"] = scope_mod._current_context().egress_mode
            results["origin_allowed"] = scope_mod.is_engagement_origin_allowed(
                "https://anything.example.com/"
            )

        token = scope_mod.set_engagement_target_hosts(
            "https://engaged-target.example.com/"
        )
        try:
            t = threading.Thread(target=_in_thread)
            t.start()
            t.join(timeout=5)
        finally:
            scope_mod.clear_engagement_target_hosts(token)

        # the thread genuinely did not see the campaign context
        assert results["mode"] == "NONE"
        # and in that state the decision must be DENY, not allow
        assert results["origin_allowed"] is False

    def test_no_campaign_legacy_behavior_unchanged(self) -> None:
        """Outside any campaign the legacy posture stays allowed."""
        # ensure clean state
        scope_mod = es
        assert scope_mod.is_engagement_origin_allowed(
            "https://public.example.com/"
        ) is True




class TestEngagementThreadWrapper:
    def test_wrapper_exists_and_propagates(self) -> None:
        """The engagement-aware Thread wrapper must exist and carry the
        campaign context into the thread."""
        from webpent.shared.engagement_scope import EngagementThread

        seen: dict[str, object] = {}
        token = es.set_engagement_target_hosts("https://wrapped.example.com/")
        try:
            t = EngagementThread(
                target=lambda: seen.update(
                    ctx=es._current_context(),
                    allowed=es.is_engagement_origin_allowed(
                        "https://wrapped.example.com/"),
                )
            )
            t.start()
            t.join(timeout=5)
        finally:
            es.clear_engagement_target_hosts(token)
        assert not t.is_alive()
        assert seen.get("allowed") is True


class TestH2RaceConnectGated:
    def test_connect_refuses_out_of_scope_host(self) -> None:
        """RED on the current tree: _connect dials any host directly."""
        from webpent.shared.h2_race import _connect

        with pytest.raises(Exception, match="scope|engagement|blocked|denied"):
            _connect("not-a-target.example.com", 443, use_tls=False, timeout_s=1.0)


class TestSmugglingPortRestricted:
    def test_raw_sender_refuses_undeclared_port(self) -> None:
        """RED on the current tree: port is caller-free even for an
        in-scope host (bare-host engagement binds defaults only)."""
        from webpent.agents.request_smuggling.agent import _send_raw_http

        token = es.set_engagement_target_hosts("scope-host.example.com")
        try:
            result = _send_raw_http(
                "scope-host.example.com", 8080,
                b"GET / HTTP/1.1\r\nHost: scope-host.example.com\r\n\r\n",
                use_tls=False, timeout=2.0,
            )
            # undeclared non-default port must be refused (None), not dialed
            assert result is None
        finally:
            es.clear_engagement_target_hosts(token)


class TestRateLimitDefaultOn:
    def test_rate_limit_enabled_defaults_true(self) -> None:
        """RED on the current tree: default was False (fail-open)."""
        from webpent.config.settings import Settings

        s = Settings()
        assert s.rate_limit_enabled is True
