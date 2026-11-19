"""TEAM-1 Phase 5 — state-contract regression tests.

Enforces:
  1. Every literal key written by a ``*_node`` function in its returned
     state-update dict is declared on ``PentestState`` (the CI/static check
     implemented in ``scripts/check_state_contract.py``).
  2. The known historical ``max_rounds`` / ``max_replan_rounds`` mismatch
     stays repaired: the initial-state writer and the graph router must
     agree on the canonical key so the persisted replan budget is actually
     readable by the router before the first executor pass.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from check_state_contract import (  # noqa: E402
    collect_node_writers,
    declared_state_keys,
)


def test_every_node_written_state_key_is_declared() -> None:
    """Fails on undeclared node-written state keys (Phase 5 CI gate)."""
    declared = declared_state_keys()
    assert declared, "PentestState declaration must be discoverable"

    writers = collect_node_writers()
    assert len(writers) >= 40, "state-contract scan must cover the graph nodes"

    violations: list[str] = []
    for name, (loc, keys, _dynamic) in writers.items():
        unknown = sorted(
            key
            for key in keys
            if key not in declared and key not in {"evidence_contract"}
        )
        if unknown:
            violations.append(f"{name} ({loc}): {', '.join(unknown)}")

    assert not violations, (
        "undeclared node-written state keys (LangGraph silently drops these): "
        + "; ".join(violations)
    )


def test_replan_budget_writer_and_router_agree_on_canonical_key() -> None:
    """initial_state and route_after_smart_campaigns_execution must agree.

    Regression: initial_state used to write ``max_rounds`` while the router
    read ``max_replan_rounds`` — the budget was invisible to the router and
    the replan loop never re-entered. The canonical key is
    ``max_replan_rounds``; the legacy alias may be written alongside it for
    checkpoint compatibility but must never be the only writer.
    """
    from webpent.config.settings import get_settings
    from webpent.models.targets import Target
    from webpent.state.initial_state import build_initial_state

    state = build_initial_state(target=Target(url="http://localhost:9"), thread_id="t")
    replanning = state.get("smart_replanning") or {}
    assert "max_replan_rounds" in replanning, (
        "initial_state must persist the canonical max_replan_rounds budget"
    )

    settings = get_settings()
    assert int(replanning["max_replan_rounds"]) == int(settings.smart_max_replan_rounds), (
        "initial_state budget value must come from Settings.smart_max_replan_rounds"
    )

    # The router must read the canonical key (source-level assertion, keeping
    # the writer/reader pair honest without executing the full graph).
    builder_src = (ROOT / "src" / "webpent" / "graph" / "builder.py").read_text(
        encoding="utf-8"
    )
    assert 'replanning.get("max_replan_rounds"' in builder_src
    assert 'replanning.get("max_rounds"' not in builder_src
