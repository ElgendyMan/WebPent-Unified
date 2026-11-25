"""UM-DR-48 Phase D — graph-level integration: the lanes through the
official entrypoint with the flag ON produce Tool-Confirmed findings on
the silent families (the battery v2 preview), and OFF is the 47
behavior (byte-identical no-op).
"""
from __future__ import annotations

import os
import threading
from http.server import HTTPServer

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import pytest  # noqa: E402

import sys  # noqa: E402
from pathlib import Path  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import umdr46_baseline_battery as battery  # noqa: E402


@pytest.fixture()
def tenant_lab():
    battery.TenantConfusionLab.secure = False
    battery.TenantConfusionLab.request_log = []
    oos = battery._OutOfScopeOrigin()
    battery.TenantConfusionLab.out_of_scope_origin = oos.origin
    server = HTTPServer(("127.0.0.1", 0), battery.TenantConfusionLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    oos.shutdown()


def _campaign(origin: str, *, lanes_on: bool):
    from webpent.cli.unified_hunt import run_unified_hunt

    return run_unified_hunt(
        url=origin, mode="standard",
        authorization="umdr48-d-integration-lab",
        cookies=f"session={battery.SESS_A}",
        identity_profiles={
            "user-b": {"name": "user-b", "role": "user",
                       "cookies": {"session": battery.SESS_B}},
        },
        auto_approve=True, no_llm=True, progress=False,
        run_graph=True, engagement_id=f"umdr48-di-{'on' if lanes_on else 'off'}",
        enable_umdr48_lanes=lanes_on,
    )


class TestGraphIntegration:
    def test_lanes_off_is_the_47_behavior(self, tenant_lab):
        summary = _campaign(tenant_lab, lanes_on=False)
        # OFF: no lane findings — the family stays silent (the honest
        # baseline this mission breaks)
        assert summary.get("findings_confirmed", 0) == 0

    def test_lanes_on_confirms_the_silent_family(self, tenant_lab):
        summary = _campaign(tenant_lab, lanes_on=True)
        # ON: the tenant-confusion family confirms through the lanes
        assert summary.get("findings_confirmed", 0) >= 1, (
            "the D4 lane must confirm through the graph")
        confirmed = [
            f for f in summary.get("findings_detail") or []
            if f.get("confidence_level") == "Tool-Confirmed"]
        assert confirmed, "a Tool-Confirmed finding must be in the detail"
        assert any(
            f.get("vuln_class") == "auth_bypass" for f in confirmed)
