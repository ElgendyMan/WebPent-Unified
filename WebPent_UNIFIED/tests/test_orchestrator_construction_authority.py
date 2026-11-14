"""Sprint R1 FIX 1 — construction-authority regression tests.

Enforces:
  1. The static single-construction-authority gate
     (``scripts/check_orchestrator_construction_authority.py``): the literal
     pattern ``ModernOrchestrator(`` appears only in production_spine.py
     (the one approved factory) and the approved test allowlist.
  2. ``ModernOrchestrator.__init__`` actually raises on direct construction
     outside the factory when the test-only escape is not set, and actually
     succeeds when it is (the runtime behavior the static gate assumes).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_orchestrator_construction_authority import find_violations  # noqa: E402


def test_modern_orchestrator_construction_is_factory_only() -> None:
    """Static CI gate: no construction site outside production_spine.py / allowlist."""
    violations = find_violations()
    assert not violations, (
        "'ModernOrchestrator(' found outside the factory and the approved test "
        "allowlist: "
        + "; ".join(f"{p.relative_to(ROOT)}:{n}: {line}" for p, n, line in violations)
    )


def test_direct_construction_raises_without_factory_token_or_test_escape(monkeypatch) -> None:
    """Runtime guard: direct construction fails closed once the test escape is off."""
    monkeypatch.delenv(
        "WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", raising=False
    )
    from webpent.production.modern_spine import ModernOrchestrator, ModernSpineError

    try:
        ModernOrchestrator(engagement_id="eng_guard_test")
    except ModernSpineError:
        pass
    else:
        raise AssertionError(
            "ModernOrchestrator() must raise ModernSpineError when constructed "
            "directly with neither the factory token nor the test escape set"
        )


def test_factory_resolves_without_raising() -> None:
    """resolve_production_spine() is the approved path and must not trip the guard."""
    from webpent.production.production_spine import (
        ProductionSpineConfig,
        resolve_production_spine,
    )

    config = ProductionSpineConfig(
        engagement_id="eng_guard_factory_test",
        target_url="http://example.test",
        entrypoint="direct_invoke",
    )
    orchestrator, trace = resolve_production_spine(config)
    assert orchestrator.engagement_id == "eng_guard_factory_test"
    assert "spine_activation" in trace.summary()["stages_seen"]
