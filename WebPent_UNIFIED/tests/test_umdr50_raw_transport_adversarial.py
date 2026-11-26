"""UM-DR-50 W1 — the seven MANDATORY adversarial tests for the raw-transport
contract (Phase 1 gate). Each test runs against a REAL local socket server
(no mocks): a thread accepting connections and answering over the wire.

The seven adversarial scenarios (master plan, Phase 1):

1. a link discovered in a response points OUTSIDE the authorized origin
   -> ZERO outbound connections (the dial is refused pre-connect);
2. cookies never travel to an unauthorized origin (cross-asset denial);
3. a redirect does not move the channel to a new destination (the raw
   channel records the fact, it does not follow);
4. DNS rebinding: the pinned IP decides, a second resolution cannot
   change the dialed destination mid-flight;
5. loopback/private/link-local/metadata destinations are refused
   unless the engagement explicitly declares an isolated lab;
6. the VERBATIM original path works on an authorized lab target
   (the D5 seam keeps its production purpose);
7. limits cannot be exceeded through the raw channel (rate ceiling,
   response cap, header cap, timeout) — no bypass via the bare wire.
"""
from __future__ import annotations

import http.server
import socket
import threading

import pytest

from webpent.shared import raw_transport
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.raw_transport import (
    MAX_HEADER_BYTES,
    MAX_RESPONSE_BYTES,
    RawTransportRefused,
    governed_raw_request,
)


# ---------------------------------------------------------------------------
# a real tiny HTTP server on loopback (the authorized lab target)
# ---------------------------------------------------------------------------

class _LabTarget(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 — http.server API
        path = self.path
        if path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.999/evil")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/huge"):
            self.send_response(200)
            self.send_header("Content-Length", str(2 * MAX_RESPONSE_BYTES))
            self.end_headers()
            self.wfile.write(b"A" * (2 * MAX_RESPONSE_BYTES))
        elif path.startswith("/bigheader"):
            self.send_response(200)
            self.send_header("X-Big", "B" * (2 * MAX_HEADER_BYTES))
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/public/../admin"):
            # the literal traversal-lookalike path (the D5 seam)
            self.send_response(200)
            body = b'{"router_note": "raw path reached the router"}'
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b'{"links": ["http://198.51.100.7/public/../admin"]}'
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *args: object) -> None:  # silence
        pass


@pytest.fixture()
def lab_target():
    """A real lab HTTP server on 127.0.0.1 with its port recorded."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _LabTarget)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[:2]
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


@pytest.fixture()
def lab_engagement(lab_target):
    """An ENGAGEMENT context declaring the lab target (isolated lab)."""
    token = set_engagement_target_hosts(lab_target)
    yield lab_target
    clear_engagement_target_hosts(token)


# ---------------------------------------------------------------------------
# adversarial 1 — a discovered link pointing OUTSIDE the authorized origin
# results in ZERO outbound connections
# ---------------------------------------------------------------------------

def test_adv1_discovered_outside_link_never_dials(lab_engagement) -> None:
    outside = "http://198.51.100.7/public/../admin"
    with pytest.raises(RawTransportRefused) as ref:
        governed_raw_request(outside)
    assert "clause-1" in str(ref.value)
    # the refusal is a RECORDED policy decision (clause 8)
    decisions = raw_transport.raw_transport_ledger()
    assert any(
        d["url"] == outside and d["allowed"] is False for d in decisions)


# ---------------------------------------------------------------------------
# adversarial 2 — cookies never travel to an unauthorized origin
# ---------------------------------------------------------------------------

def test_adv2_cookies_never_cross_assets(lab_engagement) -> None:
    other_origin = "http://127.0.0.1:9/"  # same host, different port
    with pytest.raises(RawTransportRefused) as ref:
        governed_raw_request(
            other_origin,
            cookies={"session": "owner-token"},
            cookie_origin=lab_engagement + "/",
        )
    assert "clause-5" in str(ref.value)


# ---------------------------------------------------------------------------
# adversarial 3 — a redirect does NOT move the channel to a new destination
# ---------------------------------------------------------------------------

def test_adv3_redirect_is_a_recorded_fact_not_a_hop(lab_engagement) -> None:
    out = governed_raw_request(
        lab_engagement + "/redirect",
        cookies=None, cookie_origin=None)
    assert out["status_code"] == 302
    # the Location header is recorded, NOT followed: exactly one
    # exchange, the pinned destination unchanged
    assert out["headers"].get("Location", "").startswith("http://192.0.2.999")
    assert out["pinned_ip"] in ("127.0.0.1", "::1")


# ---------------------------------------------------------------------------
# adversarial 4 — rebinding: the pinned IP decides the destination
# ---------------------------------------------------------------------------

def test_adv4_rebinding_cannot_change_pinned_destination(
        monkeypatch) -> None:
    """Adversarial 4 — the pinned IP decides, not a later resolution.

    A dedicated simple server (self-contained, like every other
    passing shape): the resolver is patched to answer 127.0.0.1 first
    and 203.0.113.99 afterwards — a rebinding attack's second answer.
    The exchange must go to the FIRST pin and complete there.
    """
    from webpent.shared import http as shared_http

    class _Echo(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            body = b'{"ok": 1}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}"
    token = set_engagement_target_hosts(url)
    calls = {"n": 0}

    def flaky_resolve(host, port, *, allow_blocked=None):
        calls["n"] += 1
        # a "rebinding" second resolution would answer a DIFFERENT IP;
        # the pin must have been made from the FIRST call
        return "127.0.0.1" if calls["n"] == 1 else "203.0.113.99"

    monkeypatch.setattr(shared_http, "_resolve_first_ip", flaky_resolve)
    try:
        out = governed_raw_request(url + "/")
        assert out["pinned_ip"] == "127.0.0.1"
        # the connection went to the pinned IP (it answered)
        assert out["status_code"] == 200
    finally:
        clear_engagement_target_hosts(token)
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------
# adversarial 5 — loopback/private/metadata refused without an isolated lab
# ---------------------------------------------------------------------------

def test_adv5_loopback_refused_without_isolated_lab(lab_target) -> None:
    # NO engagement context at all: the destination is loopback but
    # nothing declares it — fail-closed
    import webpent.shared.raw_transport as rt

    saved = rt._DECISIONS.copy()
    rt._DECISIONS.clear()
    try:
        with pytest.raises(RawTransportRefused) as ref:
            governed_raw_request(lab_target + "/")
        assert "clause-1" in str(ref.value)
    finally:
        rt._DECISIONS.extend(saved)


# ---------------------------------------------------------------------------
# adversarial 6 — the verbatim original path works on the authorized lab
# ---------------------------------------------------------------------------

def test_adv6_verbatim_path_reaches_the_router(lab_engagement) -> None:
    out = governed_raw_request(
        lab_engagement + "/public/../admin",
        path_verbatim="/public/../admin")
    assert out["status_code"] == 200
    assert b"raw path reached the router" in out["body"]


# ---------------------------------------------------------------------------
# adversarial 7 — limits cannot be exceeded through the raw channel
# ---------------------------------------------------------------------------

def test_adv7a_response_cap_stops_the_read(lab_engagement) -> None:
    out = governed_raw_request(
        lab_engagement + "/huge",
        max_response_bytes=4096)
    assert out["truncated"] is True
    assert len(out["body"]) <= 4096


def test_adv7b_header_cap_refuses(lab_engagement) -> None:
    with pytest.raises(RawTransportRefused) as ref:
        governed_raw_request(lab_engagement + "/bigheader")
    assert "clause-7" in str(ref.value)


def test_adv7c_timeout_is_bounded(lab_engagement, monkeypatch) -> None:
    # a server that accepts and never answers — the dial must time out
    stop = threading.Event()
    accepted = {"sock": None}

    def silent_listener():
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        host, port = srv.getsockname()[:2]
        accepted["addr"] = f"http://127.0.0.1:{port}"
        accepted["sock"] = srv
        conn, _ = srv.accept()
        accepted["conn"] = conn  # hold it open, never answer
        stop.wait(10)
        conn.close()
        srv.close()

    th = threading.Thread(target=silent_listener, daemon=True)
    th.start()
    for _ in range(100):
        if "addr" in accepted:
            break
        import time as _t
        _t.sleep(0.02)
    # authorize the silent listener's origin as the engagement target
    token = set_engagement_target_hosts(accepted["addr"])
    try:
        with pytest.raises((RawTransportRefused, OSError, socket.timeout)):
            governed_raw_request(accepted["addr"] + "/", timeout_s=0.5)
    finally:
        clear_engagement_target_hosts(token)
        stop.set()


# ---------------------------------------------------------------------------
# the D5 production seam: the raw-path arm is LAB-ONLY on real engagements
# ---------------------------------------------------------------------------

def test_d5_raw_path_arm_disabled_on_real_engagements() -> None:
    from webpent.production import detection_lanes_48 as lanes

    # no isolated-lab declaration at all -> the raw-path arm is OFF
    # (the lanes flag alone must NEVER enable the bare-socket arm)
    assert lanes.raw_path_channel_enabled(
        {"enable_umdr48_lanes": True}) is False
    assert lanes.raw_path_channel_enabled({}) is False
    # explicit isolated-lab declaration -> ON (the arm's own gate,
    # independent of the general lanes OFF/ON flag — the battery labs
    # invoke the lane directly under this declaration)
    assert lanes.raw_path_channel_enabled(
        {"enable_umdr48_raw_path_lab_only": True}) is True
