"""Sprint R3 — E-4 entrypoint truthfulness (Ruling R3-002 §3.4, mechanism (b)).

Mechanism per the D3 probe evidence: explicit env var at editable launch
surfaces + process derivation + fail-closed rejection. The silent
``or "direct_invoke"`` fallback is REMOVED — never a silent wrong label.

Matrix:
  - per-surface truthfulness: WEBPENT_ENTRYPOINT=cli/api/worker is recorded
    verbatim in the production trace;
  - state-pinned truthful value (highest priority) is honored; unknown
    state value fails closed;
  - unknown env value fails closed;
  - `python -m webpent.cli` launches are derivable from __main__.__file__;
  - missing env + underivable process -> fail-closed rejection;
  - the silent fallback is gone (comment-stripped source check).
"""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "webpent"


def _run_node():
    from webpent.production.modern_spine_integration import modern_spine_recon_node

    state = {
        "engagement_id": f"e4fix_{uuid.uuid4().hex[:10]}",
        "target_url": "https://target.example.com",
    }
    out = modern_spine_recon_node(state)
    trace = out.get("_production_trace")
    assert isinstance(trace, dict)
    return trace


@pytest.mark.parametrize("surface", ["cli", "api", "worker", "direct_invoke"])
def test_surface_labels_recorded_verbatim(monkeypatch, surface):
    monkeypatch.setenv("WEBPENT_ENTRYPOINT", surface)
    trace = _run_node()
    assert trace["entrypoint"] == surface


def test_state_pinned_truthful_value_highest_priority(monkeypatch):
    monkeypatch.setenv("WEBPENT_ENTRYPOINT", "api")
    from webpent.production.modern_spine_integration import modern_spine_recon_node

    state = {
        "engagement_id": f"e4fix_{uuid.uuid4().hex[:10]}",
        "target_url": "https://target.example.com",
        "entrypoint": "worker",  # caller KNOWS the surface — truthful wins
    }
    out = modern_spine_recon_node(state)
    assert out["_production_trace"]["entrypoint"] == "worker"


def test_unknown_state_value_fails_closed(monkeypatch):
    monkeypatch.setenv("WEBPENT_ENTRYPOINT", "cli")
    from webpent.production.modern_spine_integration import modern_spine_recon_node
    from webpent.production.production_spine import ProductionSpineError

    state = {
        "engagement_id": f"e4fix_{uuid.uuid4().hex[:10]}",
        "target_url": "https://target.example.com",
        "entrypoint": "carrier-pigeon",
    }
    with pytest.raises(ProductionSpineError, match="KNOWN_ENTRYPOINTS"):
        modern_spine_recon_node(state)


def test_unknown_env_value_fails_closed(monkeypatch):
    monkeypatch.setenv("WEBPENT_ENTRYPOINT", "semaphore")
    from webpent.production.modern_spine_integration import modern_spine_recon_node
    from webpent.production.production_spine import ProductionSpineError

    with pytest.raises(ProductionSpineError, match="KNOWN_ENTRYPOINTS"):
        _run_node()


def test_cli_derivation_from_main_module(monkeypatch):
    """`python -m webpent.cli` launches expose __main__.__file__ inside
    webpent/cli/ — the documented invocation is derivable without env."""
    monkeypatch.delenv("WEBPENT_ENTRYPOINT", raising=False)
    import sys
    import types

    fake_main = types.ModuleType("__main__")
    fake_main.__file__ = str(SRC.parent / "webpent" / "cli" / "__main__.py")
    monkeypatch.setitem(sys.modules, "__main__", fake_main)
    trace = _run_node()
    assert trace["entrypoint"] == "cli"


def test_underivable_process_fails_closed(monkeypatch):
    """Missing env + main module that is no documented surface -> loud
    rejection, never a silent wrong label."""
    monkeypatch.delenv("WEBPENT_ENTRYPOINT", raising=False)
    import sys
    import types

    fake_main = types.ModuleType("__main__")
    fake_main.__file__ = "/opt/somewhere/else/entrypoint.py"
    monkeypatch.setitem(sys.modules, "__main__", fake_main)
    from webpent.production.modern_spine_integration import modern_spine_recon_node
    from webpent.production.production_spine import ProductionSpineError

    with pytest.raises(ProductionSpineError, match="underivable"):
        _run_node()


def test_silent_fallback_is_gone():
    """The removed fallback must stay removed: no `or "direct_invoke"` on
    any live code line of the integration module (T-07 comment-strip
    pattern — comments may explain, code must not fall back)."""
    src = (SRC / "production" / "modern_spine_integration.py").read_text(encoding="utf-8")
    code_lines = [
        ln for ln in src.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    code = "\n".join(code_lines)
    assert not re.search(r"or\s+[\"']direct_invoke[\"']", code), (
        "the silent direct_invoke fallback must not return"
    )


def test_launch_surfaces_set_the_explicit_label():
    """The editable launch surfaces set WEBPENT_ENTRYPOINT (mechanism (b)
    wiring): worker.py -> worker, server.py -> api, webpent-cli.sh -> cli."""
    root = SRC.parent.parent
    assert 'os.environ.setdefault("WEBPENT_ENTRYPOINT", "worker")' in (
        root / "worker.py").read_text(encoding="utf-8")
    assert 'os.environ.setdefault("WEBPENT_ENTRYPOINT", "api")' in (
        root / "server.py").read_text(encoding="utf-8")
    assert 'export WEBPENT_ENTRYPOINT="${WEBPENT_ENTRYPOINT:-cli}"' in (
        root / "webpent-cli.sh").read_text(encoding="utf-8")
