"""UM-DR-44 B8 — TE.CL parser_rejected verdict is wrong-footed by the
literal ``\\\\r\\\\n`` split.

``_probe_te_cl_outcome`` line 295 splits the combined responses on the
4 LITERAL bytes ``backslash-r-backslash-n`` instead of the real CRLF
(the CL.TE twin at line 178 uses the correct ``b"\\r\\n"``).  The split
therefore never actually separates status lines: it returns the whole
response as ONE element.  The ``HTTP/`` prefix check then only ever
inspects the FIRST response's first line — when the second response is
the 4xx one and the first is healthy (exactly the connection-poisoning
shape this probe exists to catch), the scan misses it and the verdict
falls through to ``inconclusive``.

The fix uses the real CRLF split (identical to the CL.TE twin), making
every status line individually visible to the scan.
"""

from __future__ import annotations

import socket
import threading

import pytest

from webpent.agents.request_smuggling.agent import (
    _probe_te_cl_outcome,
)
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)


@pytest.fixture(autouse=True)
def loopback_engagement() -> None:
    """The raw sender refuses hosts outside the declared engagement
    targets (fail-closed) — declare loopback for the local test server."""
    token = set_engagement_target_hosts("127.0.0.1")
    yield
    clear_engagement_target_hosts(token)


def _serve_once(responses: list[bytes], port_holder: dict) -> None:
    """Serve raw bytes for each accepted connection, then close."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port_holder["port"] = srv.getsockname()[1]

    def _worker() -> None:
        served = 0
        srv.settimeout(5)
        while served < len(responses):
            try:
                conn, _ = srv.accept()
            except OSError:
                break
            with conn:
                conn.settimeout(2)
                try:  # drain the request
                    conn.recv(65536)
                except OSError:
                    pass
                conn.sendall(responses[served % len(responses)])
            served += 1
        srv.close()

    threading.Thread(target=_worker, daemon=True).start()


OK = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
BAD = (
    b"HTTP/1.1 400 Bad Request\r\n"
    b"Server: nginx\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)


class TestTeClStatusLineScan:
    def test_second_response_400_first_healthy_is_parser_rejected(self) -> None:
        """RED on the current tree: the literal-backslash split returns
        one element starting with the FIRST response's 200 line, so the
        second response's 400 is never scanned -> inconclusive."""
        holder: dict = {}
        _serve_once([OK, BAD], holder)
        outcome = _probe_te_cl_outcome(
            "127.0.0.1", holder["port"], use_tls=False, cookies=None
        )
        assert outcome == "parser_rejected"

    def test_first_response_400_still_parser_rejected(self) -> None:
        holder: dict = {}
        _serve_once([BAD, OK], holder)
        outcome = _probe_te_cl_outcome(
            "127.0.0.1", holder["port"], use_tls=False, cookies=None
        )
        assert outcome == "parser_rejected"

    def test_admin_leak_still_confirms(self) -> None:
        """The confirmed verdict (content oracle) is unaffected."""
        leak = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 21\r\n"
            b"\r\n"
            b"<h1>/admin found</h1>"
        )
        holder: dict = {}
        _serve_once([leak, leak], holder)
        outcome = _probe_te_cl_outcome(
            "127.0.0.1", holder["port"], use_tls=False, cookies=None
        )
        assert outcome == "confirmed"

    def test_unreachable_server_is_inconclusive(self) -> None:
        outcome = _probe_te_cl_outcome(
            "127.0.0.1", 1, use_tls=False, cookies=None  # nothing listens
        )
        assert outcome == "inconclusive"

    def test_both_healthy_is_inconclusive(self) -> None:
        holder: dict = {}
        _serve_once([OK, OK], holder)
        outcome = _probe_te_cl_outcome(
            "127.0.0.1", holder["port"], use_tls=False, cookies=None
        )
        assert outcome == "inconclusive"
