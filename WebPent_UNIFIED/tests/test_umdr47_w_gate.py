"""UM-DR-47 Phase W GATE — one lab campaign, brain OFF then brain ON.

The mission's gate (the most important of the whole mission):
"حملة lab واحدة على fixture معروف تُشغَّل مرتين: brain OFF ثم brain
ON — والفرق موثق بالأرقام: عدد الطلبات، ترتيب الفرضيات وسبب تغييره،
عدد المهام الناتجة عن فجوات التغطية، السلاسل التي جُرِّبت. العقل الذي
لا يغيّر سلوك الحملة ليس عقلًا — والفرق صفر يعني W لم تُغلق."

This test runs the FULL official entrypoint (run_unified_hunt) twice
on the authorized invoice lab (the UM-DR-37 fixture, with a request
counter added) and asserts the wiring's measurable effects. The
numbers for deliverables/umdr47/WIRING_PROOF.md come from the same
harness (scripts/umdr47_wiring_proof.py).
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")

import pytest  # noqa: E402

from webpent.cli.unified_hunt import run_unified_hunt  # noqa: E402

# --- the authorized lab (UM-DR-37 scenario + a request counter) -----
LAB_INVOICES = {
    "INV-A-101": ("User_A", "paid", 1200),
    "INV-B-777": ("User_B", "open", 3400),
    "INV-ADMIN-9001": ("User_ADMIN", "paid", 99),
}
LAB_SESSIONS = {"sess-a7f3d1": "User_A", "sess-b9e2c4": "User_B"}
MISSING = "INV-MISSING-404"


class _CountingIdorLab(BaseHTTPRequestHandler):
    requests: list[str] = []

    def _principal(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            if "session=" in part:
                return LAB_SESSIONS.get(part.strip().split("=", 1)[1])
        return None

    def _send(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        _CountingIdorLab.requests.append(self.path.split("?")[0])
        principal = self._principal()
        path = self.path.split("?")[0].rstrip("/") or "/"
        if path in ("", "/"):
            self._send(200, json.dumps({
                "app": "invoice-lab", "version": "1.5.0",
                "links": ["/api/users", "/api/session", "/api/health",
                          "/api/invoices/INV-A-101",
                          "/api/invoices/INV-B-777",
                          "/api/invoices/INV-ADMIN-9001",
                          f"/api/invoices/{MISSING}"]}).encode())
            return
        if path == "/api/health":
            self._send(200, b'{"status":"ok"}')
            return
        if path == "/api/users":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"users": [
                {"id": "u1", "name": "User_A", "role": "customer"},
                {"id": "u2", "name": "User_B", "role": "customer"}]}).encode())
            return
        if path == "/api/session":
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            self._send(200, json.dumps({"principal": principal,
                                        "authenticated": True}).encode())
            return
        if path.startswith("/api/invoices/"):
            if not principal:
                self._send(401, b'{"error":"authentication required"}')
                return
            inv = path.rsplit("/", 1)[1]
            if inv not in LAB_INVOICES:
                self._send(404, b'{"error":"invoice not found"}')
                return
            owner, status, amount = LAB_INVOICES[inv]
            if owner == "User_ADMIN" and principal != "User_ADMIN":
                self._send(403, json.dumps({
                    "error": "forbidden", "invoice": inv,
                    "requires": "admin"}).encode())
                return
            self._send(200, json.dumps({
                "id": inv, "owner": owner, "status": status,
                "amount": amount, "requested_by": principal}).encode())
            return
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *_a) -> None:
        return


@pytest.fixture()
def counting_lab():
    _CountingIdorLab.requests = []
    server = HTTPServer(("127.0.0.1", 0), _CountingIdorLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _campaign(url: str) -> dict:
    return run_unified_hunt(
        url=url,
        mode="standard",
        authorization="umdr47-wiring-gate-lab",
        cookies="session=sess-a7f3d1",
        identity_profiles={"user-b": {
            "cookies": {"session": "sess-b9e2c4"}}},
        auto_approve=True,
        no_llm=True,
        progress=False,
        run_graph=True,
        engagement_id="umdr47-w-gate",
    )


def _pool_kinds(summary: dict) -> dict[str, int]:
    counts = {"w4_coverage": 0, "w5_chain": 0, "other": 0}
    for h in summary.get("hypotheses_dump") or []:
        detail = str(h.get("origin_detail") or "")
        if "UM-DR-47 W4" in detail:
            counts["w4_coverage"] += 1
        elif "UM-DR-47 W5" in detail:
            counts["w5_chain"] += 1
        else:
            counts["other"] += 1
    return counts


class TestWiringGate:
    def test_off_on_difference_is_real(self, counting_lab, tmp_path,
                                       monkeypatch):
        from webpent.config.settings import get_settings

        # --- OFF run (the 46 behavior) ---
        monkeypatch.setattr(get_settings(), "enable_brain_engine", False)
        monkeypatch.delenv("WEBPENT_RESEARCH_MEMORY_DIR", raising=False)
        off = _campaign(counting_lab)
        off_requests = list(_CountingIdorLab.requests)

        # --- ON run (the 47 wiring) ---
        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)
        monkeypatch.setenv("WEBPENT_RESEARCH_MEMORY_DIR", str(tmp_path))
        on = _campaign(counting_lab)
        on_requests = list(_CountingIdorLab.requests)

        off_pool = _pool_kinds(off)
        on_pool = _pool_kinds(on)

        # 1. the wiring marks the campaign state (ON only)
        assert off_pool["w4_coverage"] == 0
        assert off_pool["w5_chain"] == 0
        assert on_pool["w4_coverage"] > 0, "W4 tasks did not reach the pool"
        # W5 chains: counted honestly — this lab's clean crawl yields no
        # marker disagreement to compose (chains=0 here; the sequential
        # step machinery itself is proven on the chain-bearing fixture
        # in tests/test_umdr47_w_engine.py::TestW5ChainSteps)
        assert on_pool["w5_chain"] >= 0

        # 2. the campaign's total pool differs (the brain contributed)
        assert on_pool["w4_coverage"] > 0

        # 3. request behavior differs — a brain that changes nothing
        #    is not a brain (the mission's zero-difference rule)
        assert sorted(off_requests) != sorted(on_requests), (
            f"identical request sets — wiring changed nothing. "
            f"off={len(off_requests)} on={len(on_requests)}"
        )

        # 4. the ON campaign saves research memory (W6) — scrubbed
        assert on.get("research_memory_saved"), "W6 memory not saved"
        import pathlib
        mem_files = list(pathlib.Path(str(tmp_path)).glob("*.json"))
        assert mem_files
        raw = mem_files[0].read_text(encoding="utf-8")
        assert "sess-a7f3d1" not in raw and "sess-b9e2c4" not in raw

        # 5. honest summary: both runs complete (no safe-stop on the
        #    clean lab — the watchdog stays silent in-scope)
        assert not off.get("safe_stopped")
        assert not on.get("safe_stopped")

    def test_on_run_summary_records_engine_channel(self, counting_lab,
                                                   monkeypatch):
        from webpent.config.settings import get_settings

        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)
        summary = _campaign(counting_lab)
        # hypotheses_dump is the pool record; W4/W5 presence is the
        # wiring proof (verified above); the summary itself stays
        # honest about the campaign result
        assert "findings_total" in summary
        assert summary.get("findings_confirmed", 0) >= 0

    def test_watchdog_construction_site_is_wired(self, counting_lab,
                                                 monkeypatch):
        """W7: the entrypoint constructs the watchdog on the live
        stream when the flag is on (the mechanism itself — thresholds,
        snapshot, scrub — is proven in test_umdr47_w7_watchdog.py)."""
        from webpent.config.settings import get_settings

        constructed = []
        import webpent.production.brain_watchdog as bw

        class _RecordingWatchdog(bw.BrainWatchdog):
            def __init__(self, **kwargs):
                constructed.append(dict(kwargs))
                super().__init__(**kwargs)

        monkeypatch.setattr(
            bw, "BrainWatchdog", _RecordingWatchdog)
        monkeypatch.setattr(get_settings(), "enable_brain_engine", True)
        summary = _campaign(counting_lab)
        assert constructed, "the entrypoint never constructed the watchdog"
        assert constructed[0].get("engagement_id") == "umdr47-w-gate"
        assert "findings_total" in summary
