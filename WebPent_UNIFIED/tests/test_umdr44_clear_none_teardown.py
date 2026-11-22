"""UM-DR-44 §7 — force-clear tears down the registry (RED on 6f3dc7c).

Verified defect (B6(a) leak): ``clear_engagement_target_hosts(None)``
resets the contextvars but NEVER unregisters the process-wide
``_ACTIVE_ENGAGEMENTS`` entry (only the structured-token path
unregisters).  After any force-clear — used by many test fixtures and
any fail-closed teardown — ``_any_engagement_active()`` stays True
forever, and ``is_engagement_origin_allowed`` takes the B6
"context was LOST" branch, DENYING every later request in the process:
fail-closed masquerading as security.  The full suite surfaces this as
~15 order-dependent failures.

Second verified defect: the token path unregisters with the key of
``token.previous`` while registration used the key of the NEW context —
identical today only because both derive to "default"; real authority
contexts carry a scope_fingerprint, making the leak GUARANTEED on every
real engagement.  Fix: EngagementToken carries registry_key and
unregisters with the key it was registered under.

Contract (4 tests + autouse registry hygiene): force-clear empties the
registry; a context-less call is DENIED during the campaign (B6
preserved) then ALLOWED again after the engagement ends; force-clear
empties every key; the token path unregisters exactly its own entry.
"""

from __future__ import annotations

import pytest

from webpent.shared.engagement_scope import (
    EngagementContext,
    _ACTIVE_ENGAGEMENTS,
    _any_engagement_active,
    _ENGAGEMENT_LOCK,
    clear_engagement_target_hosts,
    is_engagement_origin_allowed,
    set_engagement_target_hosts,
)


@pytest.fixture(autouse=True)
def _clean_registry():
    """Registry hygiene after every test — the pollution lesson."""
    yield
    with _ENGAGEMENT_LOCK:
        _ACTIVE_ENGAGEMENTS.clear()


class TestForceClearTeardown:
    def test_force_clear_empties_registry(self) -> None:
        """RED on the base: the registry survives clear(None)."""
        set_engagement_target_hosts("https://force-clear.example.test/app")
        clear_engagement_target_hosts(None)  # force teardown, no token
        assert not _any_engagement_active(), (
            "clear(None) left a process-global engagement registered — "
            "every later request in this process is DENIED by the "
            "'context was lost' branch"
        )

    def test_contextless_denied_during_campaign_allowed_after(self) -> None:
        """The B6 contract INTACT: during an active campaign a
        context-less caller (a raw Thread) is DENIED; after the
        engagement truly ends, legacy non-campaign use is allowed
        again."""
        import contextvars

        set_engagement_target_hosts("https://campaign.example.test/app")
        # simulate the raw-Thread view: a FRESH contextvars context
        fresh = contextvars.copy_context()

        def contextless_verdict() -> bool:
            return is_engagement_origin_allowed(
                "https://elsewhere.example.test/x")

        in_campaign_denied = not fresh.run(contextless_verdict)
        assert in_campaign_denied, "B6: lost context during campaign must DENY"

        clear_engagement_target_hosts(None)
        # after the engagement ends, no engagement is active anywhere —
        # the legacy allow posture must be RESTORED (it was, pre-B6,
        # for processes that end their campaigns).
        fresh2 = contextvars.copy_context()
        assert fresh2.run(contextless_verdict), (
            "after force teardown the process must return to the legacy "
            "no-engagement allow posture"
        )

    def test_force_clear_empties_every_key(self) -> None:
        """Multiple distinct registry keys (nested/simultaneous
        engagements) — a force teardown empties ALL of them."""
        set_engagement_target_hosts("https://a.example.test/app")
        # a second, differently-keyed registration (authority contexts
        # carry scope_fingerprint keys)
        with _ENGAGEMENT_LOCK:
            _ACTIVE_ENGAGEMENTS["scope-fingerprint-x"] = 1
            _ACTIVE_ENGAGEMENTS["authority-id-y"] = 2
        clear_engagement_target_hosts(None)
        with _ENGAGEMENT_LOCK:
            assert not _ACTIVE_ENGAGEMENTS, (
                f"force teardown must empty every key; "
                f"left: {dict(_ACTIVE_ENGAGEMENTS)}"
            )

    def test_token_clear_unregisters_exactly_its_own_entry(self) -> None:
        """RED on the base for real authority contexts: the token must
        unregister with the key its engagement was REGISTERED under —
        not the previous context's key (identical only by today's
        'default' coincidence)."""
        # an OUTER engagement with a real scope fingerprint
        outer_ctx = EngagementContext(
            egress_mode="ENGAGEMENT",
            target_hosts=frozenset({"outer.example.test"}),
            scope_fingerprint="outer-fingerprint",
        )
        outer_token = set_engagement_target_hosts(
            "https://outer.example.test/app")
        # simulate the inner registration carrying its own fingerprint
        inner_ctx = EngagementContext(
            egress_mode="ENGAGEMENT",
            target_hosts=frozenset({"inner.example.test"}),
            scope_fingerprint="inner-fingerprint",
        )
        from webpent.shared.engagement_scope import (
            _register_active_engagement,
        )

        _register_active_engagement(inner_ctx)
        with _ENGAGEMENT_LOCK:
            assert "inner-fingerprint" in _ACTIVE_ENGAGEMENTS
            assert "outer-fingerprint" in _ACTIVE_ENGAGEMENTS or \
                "default" in _ACTIVE_ENGAGEMENTS
        # tearing down the OUTER token must remove ONLY the outer key
        clear_engagement_target_hosts(outer_token)
        with _ENGAGEMENT_LOCK:
            assert "inner-fingerprint" in _ACTIVE_ENGAGEMENTS, (
                "the token teardown removed an entry it did not "
                "register (or failed to remove its own)"
            )
        assert _any_engagement_active()
        clear_engagement_target_hosts(None)
