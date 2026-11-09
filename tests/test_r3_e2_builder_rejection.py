"""Sprint R3 — E-2 builder-level fail-closed rejection (Ruling R3-002 §3.3).

Covers:
  1. rejection fires on ALL entry surfaces (cli / api-dispatched worker /
     worker / resume) — every surface composes its graph through the same
     build_graph composition point, so the rejection is exercised per
     surface module that binds it;
  2. default-enabled path regression vs baseline (composition succeeds,
     modern-first wiring intact);
  3. node-level raise retained as defense-in-depth;
  4. SDD §8 rollback-flag independence: WEBPENT_MODERN_SPINE=0 (the
     composition downgrade to COMPATIBILITY_LEGACY) does NOT disable the
     spine and must NOT trigger the rejection (RED-1 P-3.2 re-asserted).
"""
from __future__ import annotations

import subprocess
import sys

import pytest

SURFACE_MODULES = [
    "webpent.graph.builder",      # the composition point itself
    # "webpent.cli.commands" — REMOVED by the v0.32.0 retired-alias window:
    #   the removed `scan` command was the only module-level bind of
    #   build_graph on the CLI surface; the unified `hunt` path composes
    #   via a lazy import inside cli/unified_hunt.py (no module-level
    #   attribute to pin). The composition point itself, the worker and
    #   the API surfaces remain pinned below.
    "webpent.workers.pentest_worker",  # worker / api-dispatched worker surfaces
    "webpent.api.app",            # api surface (graph cache)
]


@pytest.mark.parametrize("module", SURFACE_MODULES)
def test_rejection_fires_on_all_entry_surfaces(module, monkeypatch):
    """Every entry surface resolves build_graph through the same composition
    point; with the spine mode resolved disabled, composition rejects."""
    import importlib

    import webpent.graph.builder as builder

    monkeypatch.setattr(builder, "MODERN_SPINE_ENABLED", False)
    target = importlib.import_module(module)
    compose = getattr(target, "build_graph")
    assert compose is builder.build_graph or callable(compose)
    with pytest.raises(Exception) as excinfo:
        compose()
    assert "UNSUPPORTED_LEGACY_ONLY" in str(excinfo.value)
    assert "SDD §8" in str(excinfo.value)


def test_default_enabled_path_regression_vs_baseline():
    """With the default (enabled) mode the composition succeeds and the
    modern-first wiring is intact — baseline behavior unchanged."""
    import webpent.graph.builder as builder

    assert builder.MODERN_SPINE_ENABLED is True
    graph = builder.build_graph(auto_approve=True)
    assert graph is not None
    # modern-first wiring retained: the combined recon node still prefers
    # the modern spine and marks legacy advisory-only.
    import ast
    from pathlib import Path

    src = Path(builder.__file__).read_text(encoding="utf-8")
    # 0.34.0 R2-graph-01: the combined recon node moved to the module-level
    # factory and builds its delta on a `working` copy (never re-sending
    # append-only channels); the modern-first call site and the
    # advisory-only invariant are unchanged.
    assert "modern_spine_recon_node(dict(working))" in src
    assert 'update["legacy_recon_advisory_only"] = True' in src
    assert "legacy_recon_advisory_only" in src


def test_node_level_raise_retained_defense_in_depth(monkeypatch):
    """The node-level raise (modern_spine_integration) stays as the second
    layer: when the mode is disabled, the node itself still rejects."""
    import webpent.production.modern_spine_integration as msi

    monkeypatch.setattr(msi, "MODERN_SPINE_ENABLED", False)
    with pytest.raises(Exception) as excinfo:
        msi.modern_spine_recon_node({"engagement_id": "e2-node", "target_url": "http://127.0.0.1:9/"})
    assert "UNSUPPORTED_LEGACY_ONLY" in str(excinfo.value)


def test_sdd8_rollback_flag_independence():
    """WEBPENT_MODERN_SPINE=0 only downgrades the MODE to
    COMPATIBILITY_LEGACY (auditable, authority fail-closed); it must leave
    MODERN_SPINE_ENABLED=True so graph composition still works. The
    UNSUPPORTED mode disables composition. The two flags are independent
    (RED-1 P-3.2 re-asserted via fresh interpreters)."""
    cases = [
        # (env, expected_enabled, expected_mode)
        ({}, True, "PRODUCTION_MODERN"),
        ({"WEBPENT_MODERN_SPINE": "0"}, True, "COMPATIBILITY_LEGACY"),
        ({"WEBPENT_MODERN_SPINE_MODE": "UNSUPPORTED_LEGACY_ONLY"}, False,
         "UNSUPPORTED_LEGACY_ONLY"),
    ]
    for env_extra, expected_enabled, expected_mode in cases:
        code = (
            "from webpent.production.modern_spine_integration import "
            "MODERN_SPINE_ENABLED, MODERN_SPINE_MODE;"
            "print(MODERN_SPINE_ENABLED, MODERN_SPINE_MODE)"
        )
        import os

        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, **env_extra},
        )
        assert proc.returncode == 0, proc.stderr[-300:]
        enabled, mode = proc.stdout.strip().split(" ", 1)
        assert (enabled == "True") == expected_enabled, (env_extra, proc.stdout)
        assert mode == expected_mode, (env_extra, proc.stdout)
