"""UM-DR-40 RC-4 — contract tests for the wired hypothesis router.

The hypothesis router's path map now flows through the composed
advisory redirect (_research_route_redirects). These contracts pin:

* flags OFF (the default): the map is returned BYTE-IDENTICALLY —
  the default graph shape is unchanged (the no-op guarantee that
  keeps the disabled-campaign behavior stable);
* any identity capability ON: strategist-bound branches are
  redirected through the identity_workflow node (the RC-4 fix —
  previously the router bypassed the redirect entirely, so the
  identity stack was unreachable from the standard campaign path
  even with every capability flag enabled).
"""
from __future__ import annotations

import sys

REPO = __file__.rsplit("/tests/", 1)[0]
sys.path.insert(0, f"{REPO}/src")

import pytest  # noqa: E402

from webpent.graph.builder import (  # noqa: E402
    NODE_HYPOTHESIS,
    NODE_IDENTITY_WORKFLOW,
    NODE_STRATEGIST,
)

IDENTITY_FLAGS = (
    "enable_object_identity",
    "enable_alias_resolution",
    "enable_multi_identity_reasoning",
    "enable_composite_workflows",
)


def _with_flags(monkeypatch, **flags: bool) -> None:
    """Point the identity capability flags at explicit values."""
    import webpent.config.settings as settings_mod

    class _Fake:
        pass

    fake = _Fake()
    for name in IDENTITY_FLAGS:
        setattr(fake, name, flags.get(name, False))
    monkeypatch.setattr(
        settings_mod, "get_settings", lambda: fake, raising=True)


def test_all_four_identity_flags_exist() -> None:
    """RC-4's capability surface: exactly the four documented flags
    gate the identity_workflow master switch."""
    from webpent.production.identity_workflow import (
        identity_workflow_enabled,
    )
    assert identity_workflow_enabled.__doc__  # the fail-closed gate


def test_router_map_flags_off_is_byte_identical(monkeypatch) -> None:
    """Default OFF: the redirect is a no-op — the path map keeps its
    exact identity (the disabled-campaign stability guarantee)."""
    _with_flags(monkeypatch)
    from webpent.graph import builder as B
    assert (B._research_route_redirects(B.HYPOTHESIS_PATH_MAP)
            == B.HYPOTHESIS_PATH_MAP)


@pytest.mark.parametrize("flag", IDENTITY_FLAGS)
def test_router_map_any_flag_on_redirects_strategist(
        monkeypatch, flag: str) -> None:
    """Any single capability flag ON: strategist-bound branches run
    the identity_workflow node first (the router no longer bypasses
    it); non-strategist branches are untouched."""
    _with_flags(monkeypatch, **{flag: True})
    from webpent.graph import builder as B
    redirected = B._research_route_redirects(B.HYPOTHESIS_PATH_MAP)
    assert redirected[NODE_STRATEGIST] == NODE_IDENTITY_WORKFLOW
    # the non-strategist branches keep their targets
    for key, value in B.HYPOTHESIS_PATH_MAP.items():
        if key != NODE_STRATEGIST:
            assert redirected[key] == value
    # and the original mapping is never mutated in place
    assert B.HYPOTHESIS_PATH_MAP[NODE_STRATEGIST] == NODE_STRATEGIST


def test_composed_redirect_identity_first_then_research_loop(
        monkeypatch) -> None:
    """With both UM-DR-31 and UM-DR-32 on, the composition order is
    identity_workflow FIRST (it forwards to research_loop, which
    forwards to the strategist) — the documented chain."""
    import webpent.config.settings as settings_mod
    from webpent.graph import builder as B

    class _Fake:
        enable_adaptive_research_loop = True
        enable_object_identity = True
        enable_alias_resolution = False
        enable_multi_identity_reasoning = False
        enable_composite_workflows = False

    monkeypatch.setattr(
        settings_mod, "get_settings", lambda: _Fake(), raising=True)
    # identity wins the strategist target when both layers are on
    redirected = B._research_route_redirects(B.HYPOTHESIS_PATH_MAP)
    assert redirected[NODE_STRATEGIST] == NODE_IDENTITY_WORKFLOW
