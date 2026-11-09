"""U-APEX-4 — The Tool Chain Builder (v87).

Laws under proof: APEX-L-1 (chains compose tools), APEX-L-5 (independent
steps declared for parallelism), determinism (byte-identical chains for
identical inputs).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from webpent.apex.tool_chain_builder import (
    PREAMBLE_LINE,
    ChainStep,
    ToolChain,
    ToolChainBuilder,
)
from webpent.apex.tool_registry import ToolRegistry

WORK = Path(__file__).resolve().parents[2]
REGISTRY_PATH = WORK / "config" / "apex" / "tools.yaml"
CHAINS_PATH = WORK / "config" / "apex" / "chains.yaml"


@pytest.fixture()
def registry() -> ToolRegistry:
    return ToolRegistry.load(REGISTRY_PATH)


@pytest.fixture()
def builder(registry: ToolRegistry) -> ToolChainBuilder:
    return ToolChainBuilder.load(CHAINS_PATH, registry)


def test_build_from_hypothesis_type(builder: ToolChainBuilder) -> None:
    chain = builder.build("sqli", target="target.test")
    assert isinstance(chain, ToolChain)
    assert chain.hypothesis_type == "sqli"
    assert chain.target == "target.test"
    tool_ids = [s.tool_id for s in chain.steps]
    assert "sqlmap" in tool_ids
    assert "katana" in tool_ids


def test_chain_dependencies_wired(builder: ToolChainBuilder) -> None:
    chain = builder.build("cve_exposure", target="target.test")
    by_tool = {s.tool_id: s for s in chain.steps}
    assert by_tool["searchsploit"].after == ["httpx"]
    assert by_tool["nuclei"].after == ["httpx"]
    assert by_tool["httpx"].after == []


def test_independent_steps_parallelizable(builder: ToolChainBuilder) -> None:
    chain = builder.build("cve_exposure", target="target.test")
    independent = chain.independent_steps()
    assert [s.tool_id for s in independent] == ["httpx"]


def test_optimize_removes_duplicate_tool_steps(builder: ToolChainBuilder) -> None:
    chain = builder.build("leaked_secrets", target="target.test")
    # both trufflehog and gitleaks depend on gau; gau appears once. inject a
    # duplicate gau step to prove the optimizer dedupes.
    chain.steps.append(ChainStep(tool_id="gau", capability="url_discovery"))
    optimized = chain.optimize()
    tool_ids = [s.tool_id for s in optimized.steps]
    assert tool_ids.count("gau") == 1


def test_optimize_removes_orphans(builder: ToolChainBuilder) -> None:
    chain = builder.build("xss", target="target.test")
    # a step depending on a removed parent becomes an orphan
    chain.steps = [s for s in chain.steps if s.tool_id != "gau"]
    optimized = chain.optimize()
    ids = [s.tool_id for s in optimized.steps]
    assert "dalfox" not in ids, "dependent of removed parent is an orphan"


def test_estimated_metrics(builder: ToolChainBuilder) -> None:
    chain = builder.build("sqli", target="target.test")
    assert chain.estimated_requests() > 0
    assert chain.estimated_duration_seconds() > 0


def test_estimated_duration_reflects_speed(builder: ToolChainBuilder) -> None:
    fast = builder.build("xss", target="t.test")          # gau + dalfox (fast)
    slow = builder.build("sqli", target="t.test")          # katana+arjun+sqlmap
    assert slow.estimated_duration_seconds() > fast.estimated_duration_seconds()


def test_chain_is_deterministic(builder: ToolChainBuilder) -> None:
    first = builder.build("subdomain_takeover", target="target.test")
    second = builder.build("subdomain_takeover", target="target.test")
    assert json.dumps(first.to_dict(), sort_keys=True) == json.dumps(
        second.to_dict(), sort_keys=True
    )


def test_unknown_hypothesis_falls_back(builder: ToolChainBuilder) -> None:
    chain = builder.build("telepathy", target="target.test")
    assert chain.hypothesis_type == "fallback"
    assert chain.fallback_reason, "fallback must state its reason"
    assert [s.tool_id for s in chain.steps] == ["subfinder", "httpx", "nuclei"]


def test_fallback_chain_declared_in_yaml(builder: ToolChainBuilder) -> None:
    chain = builder.build("sqli", target="t.test")
    assert PREAMBLE_LINE in chain.advisory_note


def test_chain_has_chain_id(builder: ToolChainBuilder) -> None:
    chain = builder.build("sqli", target="t.test")
    assert chain.chain_id.startswith("chain-")


def test_known_hypothesis_types_listed(builder: ToolChainBuilder) -> None:
    types = builder.list_hypothesis_types()
    for expected in ("sqli", "xss", "cve_exposure", "leaked_secrets",
                     "subdomain_takeover", "exposed_panels",
                     "directory_enumeration"):
        assert expected in types


def test_step_defaults(builder: ToolChainBuilder) -> None:
    chain = builder.build("xss", target="t.test")
    first = chain.steps[0]
    assert first.after == []
    assert first.step_id


def test_all_chain_tools_are_registered(builder: ToolChainBuilder) -> None:
    for hyp in builder.list_hypothesis_types():
        chain = builder.build(hyp, target="t.test")
        for step in chain.steps:
            assert builder._registry.has(step.tool_id), (
                f"{hyp}: step tool {step.tool_id} not in registry"
            )


def test_chain_to_dict_shape(builder: ToolChainBuilder) -> None:
    chain = builder.build("xss", target="t.test")
    data = chain.to_dict()
    for key in ("chain_id", "hypothesis_type", "target", "steps",
                "estimated_requests", "estimated_duration_seconds"):
        assert key in data
