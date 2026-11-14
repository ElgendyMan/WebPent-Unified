"""U-APEX-7 — The Tool Selector (v87).

Laws under proof: APEX-L-8 SPEED IS THE EDGE (fastest capable tool wins at
neutral context), APEX-L-7 (historical accuracy reorders equal tools),
determinism. Every selection carries a reason and alternatives. Scoring
weights come from config/apex/selection.yaml.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from webpent.apex.tool_registry import ToolRegistry
from webpent.apex.tool_selector import (
    PREAMBLE_LINE,
    DictLedger,
    SelectionContext,
    ToolSelector,
)

WORK = Path(__file__).resolve().parents[2]
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
SELECTION_PATH = WORK / "config" / "apex" / "selection.yaml"


@pytest.fixture()
def registry() -> ToolRegistry:
    return ToolRegistry.load(REGISTRY_PATH)


@pytest.fixture()
def selector(registry: ToolRegistry) -> ToolSelector:
    return ToolSelector.load(SELECTION_PATH, registry)


def test_select_fastest_meeting_criteria(selector: ToolSelector) -> None:
    """subfinder (fast) must beat amass (slow) for subdomain_enum when
    nothing else is demanded (APEX-L-8)."""
    selection = selector.select("subdomain_enum", SelectionContext())
    assert selection.tool_id == "subfinder"
    assert selection.reason, "every selection must state why"
    assert "amass" in selection.alternatives


def test_select_stealthy_when_needed(tmp_path: Path) -> None:
    """A high stealth requirement flips the ranking toward the stealthier
    tool, even when it is slower."""
    path = tmp_path / "tools.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "tools": [
                    {
                        "id": "quickprobe",
                        "name": "Quick Probe",
                        "category": "recon",
                        "binary": "quickprobe",
                        "install_command": "go install quickprobe",
                        "input_type": "url",
                        "output_format": "json",
                        "capabilities": ["probe"],
                        "speed": "fast",
                        "stealth": "low",
                        "vetted": True,
                    },
                    {
                        "id": "ghostprobe",
                        "name": "Ghost Probe",
                        "category": "recon",
                        "binary": "ghostprobe",
                        "install_command": "go install ghostprobe",
                        "input_type": "url",
                        "output_format": "json",
                        "capabilities": ["probe"],
                        "speed": "medium",
                        "stealth": "high",
                        "vetted": True,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    registry = ToolRegistry.load(path)
    selector = ToolSelector.load(SELECTION_PATH, registry)

    neutral = selector.select("probe", SelectionContext(stealth_requirement="low"))
    assert neutral.tool_id == "quickprobe"

    quiet = selector.select("probe", SelectionContext(stealth_requirement="high"))
    assert quiet.tool_id == "ghostprobe", (
        "high stealth requirement must flip toward the stealthier tool"
    )
    assert "quickprobe" in quiet.alternatives


def test_alternatives_provided(selector: ToolSelector) -> None:
    selection = selector.select("secret_scan", SelectionContext())
    assert selection.alternatives, "multi-candidate selection needs alternatives"
    assert selection.tool_id not in selection.alternatives
    assert selection.score > 0


def test_deterministic_selection(selector: ToolSelector) -> None:
    first = selector.select("dir_fuzz", SelectionContext()).__dict__.copy()
    second = selector.select("dir_fuzz", SelectionContext()).__dict__.copy()
    assert first == second


def test_historical_success_weighted(selector: ToolSelector) -> None:
    """Equal-speed, equal-stealth tools are separated by the accuracy
    ledger (APEX-L-7): trufflehog's proven record lifts it over gitleaks."""
    context = SelectionContext()
    without_ledger = selector.select("secret_scan", context)
    ledger = DictLedger({"trufflehog": 0.95, "gitleaks": 0.35})
    with_ledger = selector.select("secret_scan", context, ledger=ledger)
    assert with_ledger.tool_id == "trufflehog"
    assert "accuracy" in with_ledger.reason
    # and without a ledger the tie is broken deterministically by id
    assert without_ledger.tool_id == "gitleaks"


def test_unknown_capability_refused(selector: ToolSelector) -> None:
    with pytest.raises(ValueError):
        selector.select("telepathy", SelectionContext())


def test_rank_orders_by_score(selector: ToolSelector) -> None:
    ranked = selector.rank(
        [t for t in selector._registry.list_tools()
         if "subdomain_enum" in t.capabilities],
        SelectionContext(),
    )
    scores = [s.score for s in ranked]
    assert scores == sorted(scores, reverse=True)
    assert PREAMBLE_LINE in ranked[0].reason or ranked[0].reason


def test_preamble_present() -> None:
    assert "advisory" in PREAMBLE_LINE
