# tests/team1_acceptance/test_sprint_i1b_part2_byp05.py
"""Sprint I-1b, item 2.1 -- BYP-05: the UNSUPPORTED_LEGACY_ONLY early-
return in modern_spine_integration.py used to re-route to the legacy
path silently. It now raises a loud, named exception instead --
"never re-route, only reject"."""
from __future__ import annotations

import importlib

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("WEBPENT_MODERN_SPINE_MODE", raising=False)
    monkeypatch.delenv("WEBPENT_MODERN_SPINE", raising=False)
    yield


def _reload_module():
    import webpent.production.modern_spine_integration as m
    importlib.reload(m)
    return m


class TestUnsupportedLegacyOnlyRaises:
    def test_unsupported_legacy_only_raises_and_never_degrades(self, monkeypatch):
        from webpent.shared.exceptions import UnsupportedLegacyOnlyModeError

        monkeypatch.setenv("WEBPENT_MODERN_SPINE_MODE", "UNSUPPORTED_LEGACY_ONLY")
        m = _reload_module()
        state = {"engagement_id": "e1", "target_url": "https://lab.example.com"}
        with pytest.raises(UnsupportedLegacyOnlyModeError):
            m.modern_spine_recon_node(state)
        # The old silent-degrade behavior set these keys on the state dict
        # before returning -- confirm the state was never touched, since
        # the function now raises before reaching that code at all.
        assert "modern_spine_disabled" not in state
        assert "legacy_authority_blocked" not in state

    def test_unsupported_legacy_only_mode_enabled_flag_is_false(self, monkeypatch):
        monkeypatch.setenv("WEBPENT_MODERN_SPINE_MODE", "UNSUPPORTED_LEGACY_ONLY")
        m = _reload_module()
        assert m.MODERN_SPINE_ENABLED is False


class TestOtherModesUnaffected:
    def test_compatibility_legacy_via_env_disable_does_not_raise(self, monkeypatch):
        monkeypatch.setenv("WEBPENT_MODERN_SPINE", "0")
        m = _reload_module()
        assert m.MODERN_SPINE_MODE == "COMPATIBILITY_LEGACY"
        assert m.MODERN_SPINE_ENABLED is True

    def test_default_production_modern_does_not_raise(self, monkeypatch):
        m = _reload_module()
        assert m.MODERN_SPINE_MODE == "PRODUCTION_MODERN"
        assert m.MODERN_SPINE_ENABLED is True

    @pytest.mark.parametrize("value", ["false", "no", "off", "False", "OFF"])
    def test_env_disable_variants_downgrade_not_block(self, monkeypatch, value):
        monkeypatch.setenv("WEBPENT_MODERN_SPINE", value)
        m = _reload_module()
        assert m.MODERN_SPINE_MODE == "COMPATIBILITY_LEGACY"
        assert m.MODERN_SPINE_ENABLED is True
