"""The OAST collector server (PROPOSALS_ULTIMATE_V2 §1, 2026-10-29).

An operator-hosted listener that closes the loop the correlation engine
(``webpent.shared.oob``) already opens: probes minted by
``OOBCollaborator.register_probe`` carry tokens; the TARGET resolves or
fetches a URL containing that token; THIS server is what receives that
request on the operator's own zone and remembers it.

Two listeners, both optional and both bounded:

HTTP collector
    Any request carrying a probe token (any path segment matching the
    minted 32-hex-char token shape, or the leading label of the
    ``Host`` header when a zone is configured) is recorded as a
    callback. ``GET {base}?token=`` and ``GET /poll?token=`` serve the
    recorded callbacks as a JSON array
    of ``{protocol, seen_at, source_ip, details}`` — exactly the record
    shape :func:`webpent.shared.oob.poll_remote_collector` builds its
    request in, so the existing adapter works against this server with
    the bare base URL. Poll GETs are never recorded as callbacks.

DNS responder (minimal, A-records only)
    Binds one UDP socket; any A query for a name under the configured
    zone is answered with the configured response IP AND recorded as a
    ``dns`` callback whose token is the leading label of the queried
    name. This is the signal that makes blind XXE and DNS-exfil SQLi
    confirmable at all: many blind classes can trigger a DNS lookup
    when no outbound HTTP is possible. Anything outside the zone gets
    no answer (we are not a resolver) and nothing is recorded.

Fail-closed / privacy rules:

  * A request with no recognisable token is dropped (404 for HTTP; no
    answer, no record for DNS) — the collector cannot be poisoned.
  * Callback records keep a bounded detail string (method + bounded
    path, or the queried hostname) and a 4 KiB body cap with a
    SHA-256 digest (16 hex chars) — never a full body dump.
  * Source identity is kept in the record as ``source_ip`` for the
    operator's own triage; the webpent-side ingestion
    (``OOBCollaborator.record_callback``) is what reduces it to a
    truncated fingerprint before anything enters evidence.
  * Defaults bind to 127.0.0.1 — an internet-exposed collector is an
    explicit operator act (see docs/oast-deployment.md).
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

DEFAULT_MAX_CALLBACKS_PER_TOKEN = 64
_MAX_BODY_BYTES = 4_096
_MAX_DETAIL_CHARS = 200
_MAX_TOKEN_CHARS = 128
# Probe tokens are minted by OOBCollaborator as secrets.token_hex(16):
# 32 lowercase hex chars. The collector only recognises that shape.
_TOKEN_SHAPE = re.compile(r"[0-9a-f]{16,64}")
_DNS_ANSWER_TTL = 60
_DNS_PACKET_MAX = 1_500


class _CallbackRing:
    """Thread-safe, bounded per-token callback log."""

    def __init__(self, max_per_token: int = DEFAULT_MAX_CALLBACKS_PER_TOKEN) -> None:
        self._max = max(1, int(max_per_token))
        self._lock = threading.Lock()
        self._by_token: dict[str, list[dict[str, Any]]] = {}

    def append(self, token: str, record: dict[str, Any]) -> None:
        with self._lock:
            bucket = self._by_token.setdefault(str(token)[:_MAX_TOKEN_CHARS], [])
            bucket.append(record)
            if len(bucket) > self._max:
                del bucket[: len(bucket) - self._max]

    def get(self, token: str) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._by_token.get(str(token)[:_MAX_TOKEN_CHARS], []))

    def total(self) -> int:
        with self._lock:
            return sum(len(bucket) for bucket in self._by_token.values())


class _CollectorHandler(BaseHTTPRequestHandler):
    """Record any token-bearing request; serve GET /poll."""

    server_version = "webpent-oast"
    sys_version = ""
    # The collector deliberately does NOT mirror the target's protocol
    # details back; keep the response minimal and constant-shaped.
    protocol_version = "HTTP/1.1"

    @property
    def ring(self) -> _CallbackRing:
        return self.server.ring  # type: ignore[attr-defined]

    @property
    def zone(self) -> str:
        return self.server.zone  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        # Never log request paths/tokens — they ARE the probe identities.
        return

    def _extract_token(self) -> str:
        parsed = urlparse(self.path)
        # 1) any path segment that matches the minted token shape.
        # OOBCollaborator mints tokens with secrets.token_hex(16): 32
        # lowercase hex chars. Strict shape, so "/probe/<token>" and
        # "/<token>" both resolve and random paths never impersonate a
        # token.
        for segment in parsed.path.split("/"):
            candidate = segment.strip().lower()
            if _TOKEN_SHAPE.fullmatch(candidate):
                return candidate[:_MAX_TOKEN_CHARS]
        # 3) leading label of the Host header when it ends in our zone
        host_header = (self.headers.get("Host") or "").strip().lower()
        if host_header:
            host = host_header.split(":")[0]
            zone = self.zone
            if zone and host.endswith("." + zone):
                labels = host[: -len("." + zone)].split(".")
                if labels and labels[0]:
                    return labels[0][:_MAX_TOKEN_CHARS]
        return ""

    def _record(self) -> tuple[bool, str]:
        token = self._extract_token()
        if not token:
            return False, ""
        body = b""
        length = self.headers.get("Content-Length")
        try:
            if length and int(length) > 0:
                body = self.rfile.read(min(int(length), _MAX_BODY_BYTES))
        except (ValueError, OSError):
            body = b""
        record: dict[str, Any] = {
            "protocol": "http",
            "seen_at": _now(),
            "source_ip": self.client_address[0] if self.client_address else "",
            "details": f"{self.command} {urlparse(self.path).path}"[:_MAX_DETAIL_CHARS],
        }
        if body:
            record["body_sha256_16"] = hashlib.sha256(body).hexdigest()[:16]
            record["body_bytes"] = len(body)
        self.ring.append(token, record)
        return True, token

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query or "")
        # GET with a token query parameter IS the poll: this matches
        # webpent.shared.oob.poll_remote_collector exactly, which builds
        # "{base}?token=..." — the operator passes the bare base URL and
        # the adapter works unchanged. Poll GETs are never recorded.
        token_param = (query.get("token") or [""])[0].strip()[:_MAX_TOKEN_CHARS]
        if self.command == "GET" and token_param:
            self._send_json(self.ring.get(token_param))
            return
        if self.command == "GET" and parsed.path == "/healthz":
            self._send_json({"ok": True})
            return
        recorded, _token = self._record()
        if not recorded:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send_json({"ok": True})

    def do_GET(self) -> None:  # noqa: N802
        self._handle()

    do_POST = do_GET
    do_PUT = do_GET
    do_HEAD = do_GET


def _now() -> float:
    import time

    return time.time()


class OastCollectorServer:
    """HTTP collector: record callbacks, serve GET /poll?token=..."""

    def __init__(
        self,
        *,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        zone: str = "",
        max_callbacks_per_token: int = DEFAULT_MAX_CALLBACKS_PER_TOKEN,
    ) -> None:
        self.zone = str(zone or "").strip().lstrip(".").lower()
        self.ring = _CallbackRing(max_callbacks_per_token)
        self._httpd = ThreadingHTTPServer((bind_host, int(bind_port)), _CollectorHandler)
        self._httpd.ring = self.ring  # type: ignore[attr-defined]
        self._httpd.zone = self.zone  # type: ignore[attr-defined]
        self._thread: threading.Thread | None = None

    @property
    def bound_host(self) -> str:
        return self._httpd.server_address[0]

    @property
    def bound_port(self) -> int:
        return int(self._httpd.server_address[1])

    @property
    def base_url(self) -> str:
        host = self.bound_host
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        return f"http://{host}:{self.bound_port}"

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="webpent-oast-collector",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        # shutdown() blocks until a running serve_forever loop notices;
        # calling it on a never-started server deadlocks, so gate it on
        # the serving thread. server_close() is safe either way.
        if self._thread is not None and self._thread.is_alive():
            self._httpd.shutdown()
        self._httpd.server_close()

    def total_callbacks(self) -> int:
        return self.ring.total()


class OastDnsResponder:
    """Minimal UDP A-responder for the operator's own OAST zone.

    Answers A queries for names under ``zone`` with ``response_ip`` and
    records each answered query as a ``dns`` callback whose token is the
    LEADING label of the queried name (probe hosts are minted as
    ``<token>.<engagement>.<zone>`` by OOBCollaborator, so the leading
    label carries the probe identity). Names outside the zone get no
    answer: this is not a public resolver.
    """

    def __init__(
        self,
        *,
        zone: str,
        response_ip: str = "127.0.0.1",
        # M1-A (L-4): loopback by default. The previous 0.0.0.0 default
        # bound the responder on EVERY interface — on a host with a
        # public interface that silently published a DNS oracle for the
        # operator's OAST zone. An explicit bind_host (e.g. the docker
        # bridge IP) is still available for deliberate exposure.
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        ring: _CallbackRing | None = None,
    ) -> None:
        self.zone = str(zone or "").strip().lstrip(".").lower()
        if not self.zone:
            raise ValueError("OastDnsResponder requires a non-empty zone (fail-closed)")
        self.response_ip = str(response_ip)
        self.ring = ring or _CallbackRing()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((bind_host, int(bind_port)))
        self._sock.settimeout(0.5)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()

    @property
    def bound_port(self) -> int:
        return int(self._sock.getsockname()[1])

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._thread = threading.Thread(
            target=self._serve,
            name="webpent-oast-dns",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._sock.close()

    # -- DNS wire handling ------------------------------------------------

    def _serve(self) -> None:
        while not self._stop_event.is_set():
            try:
                data, address = self._sock.recvfrom(_DNS_PACKET_MAX)
            except OSError:
                if self._stop_event.is_set():
                    return
                continue
            try:
                reply = self._handle_query(data)
            except (struct.error, IndexError, ValueError, OSError):
                reply = None
            if reply is None:
                continue
            try:
                self._sock.sendto(reply, address)
            except OSError:
                continue

    def _handle_query(self, data: bytes) -> bytes | None:
        if len(data) < 12:
            return None
        query_id, _flags, qdcount = struct.unpack_from("!HHH", data, 0)
        if qdcount != 1:
            return None
        offset = 12
        labels: list[bytes] = []
        while True:
            if offset >= len(data):
                return None
            length = data[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                return None  # compression pointers are not valid in queries
            labels.append(data[offset : offset + length])
            offset += length
        if offset + 4 > len(data):
            return None
        qtype, _qclass = struct.unpack_from("!HH", data, offset)
        if qtype != 1:  # A records only
            return None
        # Probe zone labels are ASCII by construction (hex tokens, slugs,
        # the operator's zone); "ascii" — the idna codec rejects the
        # errors= argument outright.
        qname = ".".join(
            label.decode("ascii", errors="ignore") for label in labels
        )
        qname = qname.lower().rstrip(".")
        if not qname.endswith("." + self.zone) and qname != self.zone:
            return None  # outside the zone: not a resolver, never an answer
        token = labels[0].decode("ascii", errors="ignore").lower()[:_MAX_TOKEN_CHARS] if labels else ""
        if token:
            self.ring.append(
                token,
                {
                    "protocol": "dns",
                    "seen_at": _now(),
                    "source_ip": "",
                    "details": f"A {qname}"[:_MAX_DETAIL_CHARS],
                },
            )
        # Build the reply: header + echoed question + one A answer.
        ip_parts = self.response_ip.split(".")
        if len(ip_parts) != 4:
            return None
        rdata = bytes(int(part) & 0xFF for part in ip_parts)
        header = struct.pack("!HHHHHH", query_id, 0x8180, qdcount, 1, 0, 0)
        question = b""
        for label in labels:
            question += bytes([len(label)]) + label
        question += b"\x00" + struct.pack("!HH", 1, 1)
        # Answer name = pointer to offset 12 (the question's name).
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, _DNS_ANSWER_TTL, 4) + rdata
        return header + question + answer
