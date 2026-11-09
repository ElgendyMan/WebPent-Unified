#!/usr/bin/env python3
"""scripts/mock_oob_server.py — V7 Sprint 0.3 Mock OOB Server.

A minimal local HTTP listener that records "I received a ping for
canary token X," mimicking the behavior of a real OOB provider
(Interactsh / Burp Collaborator). This enables ``_poll_for_oob_callback``
(the pattern reviewed in ``validator/agent.py``) to be tested
end-to-end in Dev Mode without contacting real OOB providers or
leaking canary tokens externally.

The server exposes two endpoints:

  GET  /oob/{finding_id}/{token}
      — Records the ping (finding_id + token + timestamp + source IP).
        Returns 200 OK so the target's HTTP client sees a normal
        response (real OOB providers return 200 too).

  POST /oob/{finding_id}/{token}
      — Same as GET but for POST-based OOB callbacks (some gadget
        chains POST to the callback URL).

  GET  /poll/{finding_id}/{token}
      — Returns JSON ``{"confirmed": true/false, "ping_count": N,
        "first_ping_at": "ISO-8601", "last_ping_at": "ISO-8601"}``.
        This is the endpoint ``_poll_for_oob_callback`` polls to
        check whether a canary token has been received.

  GET  /health
      — Health check. Returns ``{"status": "ok"}``.

  POST /reset
      — Clears all recorded pings. Used between tests.

  GET  /stats
      — Returns a summary of all recorded pings (for debugging).

Usage::

    python scripts/mock_oob_server.py --port 18099
    python scripts/mock_oob_server.py --host 127.0.0.1 --port 18099 --log-level debug

The server uses only the Python standard library (``http.server``) —
no external dependencies. It listens on 127.0.0.1 by default (never
0.0.0.0) so it's unreachable from external networks.

Per Principle 2 (fail-closed, not fail-open): if the server crashes
or is unreachable, ``_poll_for_oob_callback`` will fail to connect
and return ``None`` — the validator treats that as "no callback
received" and does NOT auto-confirm the finding.
"""

from __future__ import annotations

import argparse
import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("mock_oob_server")

# Thread-safe store of recorded pings.
# Structure: {finding_id: {token: [{"pinged_at": ISO-8601, "source_ip": str, "method": str}]}}
_PINGS: dict[str, dict[str, list[dict]]] = {}
_PINGS_LOCK = threading.Lock()


def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _record_ping(finding_id: str, token: str, source_ip: str, method: str) -> None:
    """Record a canary-token ping in the in-memory store."""
    with _PINGS_LOCK:
        if finding_id not in _PINGS:
            _PINGS[finding_id] = {}
        if token not in _PINGS[finding_id]:
            _PINGS[finding_id][token] = []
        _PINGS[finding_id][token].append(
            {
                "pinged_at": _now_iso(),
                "source_ip": source_ip,
                "method": method,
            }
        )
    logger.info(
        "OOB ping recorded: finding_id=%s token=%s source=%s method=%s",
        finding_id,
        token[:8] + "…",
        source_ip,
        method,
    )


def _get_pings(finding_id: str, token: str) -> list[dict]:
    """Return the list of recorded pings for (finding_id, token)."""
    with _PINGS_LOCK:
        return list(_PINGS.get(finding_id, {}).get(token, []))


def _reset_pings() -> None:
    """Clear all recorded pings."""
    with _PINGS_LOCK:
        _PINGS.clear()


def _all_stats() -> dict:
    """Return a summary of all recorded pings (for debugging)."""
    with _PINGS_LOCK:
        stats: dict[str, Any] = {}
        for finding_id, tokens in _PINGS.items():
            stats[finding_id] = {token: len(pings) for token, pings in tokens.items()}
        return stats



class MockOOBHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the mock OOB server."""

    # Quiet logging — override BaseHTTPRequestHandler's noisy default.
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("HTTP %s - %s", self.address_string(), format % args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        """Handle GET requests to /oob/{finding_id}/{token}, /poll/..., /health, /stats."""
        parsed = urlparse(self.path)
        path = parsed.path
        source_ip = self.client_address[0]

        # Health check
        if path == "/health":
            self._send_json(200, {"status": "ok", "service": "mock_oob_server"})
            return

        # Stats endpoint (debugging)
        if path == "/stats":
            self._send_json(200, {"pings": _all_stats()})
            return

        # OOB callback: GET /oob/{finding_id}/{token}
        if path.startswith("/oob/"):
            parts = path.strip("/").split("/")
            if len(parts) != 3:
                self._send_json(400, {"error": "path must be /oob/{finding_id}/{token}"})
                return
            _, finding_id, token = parts
            _record_ping(finding_id, token, source_ip, "GET")
            # Real OOB providers return 200 so the target's HTTP client
            # sees a normal response and doesn't retry.
            self._send_text(200, "ok")
            return

        # Poll endpoint: GET /poll/{finding_id}/{token}
        if path.startswith("/poll/"):
            parts = path.strip("/").split("/")
            if len(parts) != 3:
                self._send_json(400, {"error": "path must be /poll/{finding_id}/{token}"})
                return
            _, finding_id, token = parts
            pings = _get_pings(finding_id, token)
            if pings:
                self._send_json(
                    200,
                    {
                        "confirmed": True,
                        "ping_count": len(pings),
                        "first_ping_at": pings[0]["pinged_at"],
                        "last_ping_at": pings[-1]["pinged_at"],
                    },
                )
            else:
                self._send_json(
                    200,
                    {
                        "confirmed": False,
                        "ping_count": 0,
                        "first_ping_at": None,
                        "last_ping_at": None,
                    },
                )
            return

        self._send_json(404, {"error": f"unknown path: {path}"})

    def do_POST(self) -> None:
        """Handle POST requests to /oob/{finding_id}/{token} and /reset."""
        parsed = urlparse(self.path)
        path = parsed.path
        source_ip = self.client_address[0]

        # Reset endpoint (clears all pings — used between tests)
        if path == "/reset":
            _reset_pings()
            self._send_json(200, {"status": "reset", "pings_cleared": True})
            return

        # OOB callback: POST /oob/{finding_id}/{token}
        if path.startswith("/oob/"):
            parts = path.strip("/").split("/")
            if len(parts) != 3:
                self._send_json(400, {"error": "path must be /oob/{finding_id}/{token}"})
                return
            _, finding_id, token = parts
            # Read the body (some gadget chains POST data to the callback)
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length > 0 else b""
            _record_ping(finding_id, token, source_ip, "POST")
            logger.debug(
                "OOB POST body (%d bytes) for finding_id=%s: %r",
                len(body),
                finding_id,
                body[:200],
            )
            self._send_text(200, "ok")
            return

        self._send_json(404, {"error": f"unknown path: {path}"})


def main() -> int:
    """Run the mock OOB server."""
    parser = argparse.ArgumentParser(
        description=(
            "V7 Sprint 0.3 Mock OOB Server — records canary-token pings "
            "for Dev Mode testing."
        )
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Bind address (default: 127.0.0.1 — never 0.0.0.0, the mock server "
            "must be unreachable from external networks)."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=18099,
        help="Listen port (default: 18099, matching settings.mock_oob_server_url).",
    )
    parser.add_argument(
        "--log-level",
        default="info",
        choices=["debug", "info", "warning", "error"],
        help="Logging level (default: info).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper()),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    server = ThreadingHTTPServer((args.host, args.port), MockOOBHandler)
    logger.info(
        "Mock OOB server starting on %s:%d (endpoints: /oob/{id}/{token}, "
        "/poll/{id}/{token}, /health, /stats, /reset)",
        args.host,
        args.port,
    )
    logger.info(
        "Configure WebPent with MOCK_OOB_SERVER_URL=http://%s:%d "
        "(already the default in Dev Mode).",
        args.host,
        args.port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Mock OOB server shutting down (KeyboardInterrupt).")
        server.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
