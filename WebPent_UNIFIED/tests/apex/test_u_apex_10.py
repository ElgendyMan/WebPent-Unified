"""U-APEX-10 — The MCP Server (v87).

Spec tools: apex_recon, apex_scan, apex_chain, apex_status, apex_tools.
Manifest exposes all five with JSON schemas; dispatch carries the
preamble (advisory, APEX-L-9); auth is enforced with a constant-time
compare; the server declares local-only binding — the networked MCP
transport is the operator's deployment concern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from webpent.apex.mcp_server import PREAMBLE_LINE, ApexMcpServer
from webpent.apex.tool_chain_builder import ToolChainBuilder
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


@pytest.fixture()
def server(builder: ToolChainBuilder) -> ApexMcpServer:
    return ApexMcpServer(
        builder=builder,
        token="operator-secret-token",
        bind="127.0.0.1:9377",
    )


def test_mcp_tools_registered(server: ApexMcpServer) -> None:
    manifest = server.manifest()
    names = [tool["name"] for tool in manifest["tools"]]
    assert names == [
        "apex_recon", "apex_scan", "apex_chain", "apex_status", "apex_tools",
    ]
    for tool in manifest["tools"]:
        assert "schema" in tool, "every tool must declare its schema"
        assert "description" in tool


def test_manifest_schema_shapes(server: ApexMcpServer) -> None:
    manifest = server.manifest()
    by_name = {t["name"]: t for t in manifest["tools"]}
    assert by_name["apex_scan"]["schema"]["required"] == ["target", "capability"]
    assert by_name["apex_chain"]["schema"]["required"] == ["hypothesis", "target"]
    assert "properties" in by_name["apex_recon"]["schema"]
    assert by_name["apex_status"]["schema"]["required"] == []


def test_mcp_calls_work(server: ApexMcpServer, builder: ToolChainBuilder) -> None:
    token = "operator-secret-token"
    recon = server.dispatch("apex_recon", {"target": "t.test"}, token=token)
    assert recon["ok"] is True
    assert PREAMBLE_LINE in recon["advisory_note"]
    assert "chain_id" in recon["result"]

    scan = server.dispatch(
        "apex_scan", {"target": "t.test", "capability": "cve_detection"},
        token=token,
    )
    assert scan["ok"] is True
    assert scan["result"]["capability"] == "cve_detection"

    chain = server.dispatch(
        "apex_chain", {"hypothesis": "xss", "target": "t.test"}, token=token
    )
    assert chain["ok"] is True
    assert chain["result"]["chain"]["hypothesis_type"] == "xss"

    status = server.dispatch("apex_status", {}, token=token)
    assert status["ok"] is True
    assert status["result"]["state"] in ("idle", "running")

    tools = server.dispatch("apex_tools", {}, token=token)
    assert tools["ok"] is True
    assert len(tools["result"]) == 31
    filtered = server.dispatch(
        "apex_tools", {"category": "recon"}, token=token
    )
    assert all(t["category"] == "recon" for t in filtered["result"])


def test_mcp_auth_enforced(server: ApexMcpServer) -> None:
    # RT-14: auth failures are structured error responses now, but they
    # must still be rejections, never a success payload.
    for bad in ("wrong-token", ""):
        payload = server.dispatch("apex_status", {}, token=bad)
        assert payload["ok"] is False, payload
        assert "token" in payload["error"], payload
        assert PREAMBLE_LINE in payload["advisory_note"]
    assert not hasattr(server, "_token"), (
        "the raw token must not be stored for accidental exposure"
    )


def test_local_only_binding_declared(server: ApexMcpServer) -> None:
    manifest = server.manifest()
    assert manifest["server"]["bind"] == "127.0.0.1:9377"
    assert manifest["server"]["local_only"] is True
    assert manifest["server"]["transport_note"], (
        "the networked transport must be named as the operator's concern"
    )


def test_unknown_tool_rejected(server: ApexMcpServer) -> None:
    payload = server.dispatch("apex_nuke", {}, token="operator-secret-token")
    assert payload["ok"] is False
    assert "apex_nuke" in payload["error"]
