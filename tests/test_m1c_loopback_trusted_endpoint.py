"""M1-C (UM-DR-12) regression: loopback-trusted-endpoint exemption.

Contract:
  * The OOB poll reaches a LOOPBACK OAST collector through the REAL safe
    transport (the exact M-5 regression the OAST round-trip tests caught:
    4 live failures with ``assert 0 == 64``).
  * A private NON-loopback collector (192.168.x) stays blocked: poll → []
    (M-5's pinned contract holds — the exemption can never widen).
  * The exemption is context-scoped: after the poll returns, the flag is
    reset — a subsequent loopback request from the same context is
    blocked again (fail-closed).
  * Notification dispatch to a loopback receiver now actually connects
    (the documented https/loopback rule becomes true end-to-end).
  * The flag does not leak across contexts (contextvar default OFF).
"""
from __future__ import annotations

import httpx
import pytest

from webpent.shared.http import (
    clear_loopback_trusted_endpoint,
    make_safe_httpx_client,
    set_loopback_trusted_endpoint,
)
from webpent.shared.oob import poll_remote_collector


def _start_loopback_collector(monkeypatch, records: list[dict]):
    """Serve GET /poll?token=... returning ``records`` on 127.0.0.1."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            body = httpx.Response(200, json=records).content
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def test_poll_reaches_loopback_collector_through_real_transport(monkeypatch):
    records = [{"protocol": "dns", "seen_at": "2026-11-05T00:00:00Z"}]
    collector_url = next(_start_loopback_collector(monkeypatch, records))
    got = poll_remote_collector(collector_url, token="tok", timeout=5)
    assert got == records, (
        "M1-C REGRESSION: loopback OOB collector poll must go through "
        "the safe transport with the loopback-trusted exemption set."
    )


def test_poll_private_nonloopback_still_blocked():
    """M-5 pinned contract holds: private non-loopback collector → []."""
    assert poll_remote_collector("http://192.168.1.10:8080", token="tok", timeout=2) == []


def test_exemption_is_context_scoped_fail_closed():
    """After the exemption clears, loopback is blocked again."""
    host = "127.0.0.1"
    token = set_loopback_trusted_endpoint()
    try:
        with make_safe_httpx_client(timeout=2, follow_redirects=False) as client:
            # The exempted request may connect or fail on connection —
            # what it must NEVER raise here is SSRFRedirectBlockedError
            # for the loopback host itself.
            try:
                client.get(f"http://{host}:9/x", headers={"x-probe": "1"})
            except httpx.ConnectError:
                pass  # nothing listens on port 9 — connection-level error is fine
    finally:
        clear_loopback_trusted_endpoint(token)

    # Exemption cleared: the same loopback request is now SSRF-blocked.
    with make_safe_httpx_client(timeout=2, follow_redirects=False) as client:
        with pytest.raises(httpx.RequestError) as excinfo:
            client.get(f"http://{host}:9/x")
    assert "internal/reserved" in str(excinfo.value) or isinstance(
        excinfo.value, httpx.ConnectError
    ) is False, "loopback must be SSRF-blocked once the exemption is cleared"


def test_exemption_cannot_widen_to_private_nonloopback():
    """Setting the flag must NOT allow 192.168.x — loopback-only inside."""
    set_loopback_trusted_endpoint()
    try:
        with make_safe_httpx_client(timeout=2, follow_redirects=False) as client:
            with pytest.raises(httpx.RequestError, match="internal/reserved"):
                client.get("http://192.168.1.10:8080/hook")
    finally:
        clear_loopback_trusted_endpoint(None)


def test_dispatch_loopback_receiver_connects(monkeypatch):
    """The documented https/loopback dispatch rule is now truly end-to-end."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    seen: list[tuple[str, int]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            seen.append((self.path, 200))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok": true}')

        def log_message(self, *args):  # silence
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        from webpent.integrations.notifications.dispatch import _default_send

        ok = _default_send(
            f"http://127.0.0.1:{server.server_address[1]}/hook", {"k": "v"}
        )
        assert ok is True
        assert seen, "loopback dispatch must actually reach the receiver"
    finally:
        server.shutdown()
        server.server_close()


def test_no_ssrf_block_for_flag_default_off():
    """The contextvar default is OFF — fresh context, loopback blocked."""
    with make_safe_httpx_client(timeout=2, follow_redirects=False) as client:
        with pytest.raises(httpx.RequestError, match="internal/reserved"):
            client.get("http://127.0.0.1:9/x")
