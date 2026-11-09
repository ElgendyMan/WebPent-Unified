# src/webpent/shared/h2_race.py
"""HTTP/2 single-packet race transport (PROPOSALS_ULTIMATE_V2 §5, 2026-10-30).

Sends a burst of N requests as N H2 streams opened back-to-back on ONE
connection with a SINGLE flush of the HEADERS+DATA frames, so they land in
one TCP segment and are processed by the server essentially atomically —
the strongest available race window short of raw packet crafting.

Contracts:
- Flag-gated: the caller (workflow_fuzzing) checks
  ``enable_h2_race`` and only calls :func:`run_race` when on.
- Fail-closed on the request budget: more than ``max_requests`` specs
  is a refusal, not a truncation — a silently truncated race would
  report a false negative.
- Honest negotiation: H2 prior-knowledge (or ALPN ``h2`` for https). If
  the target refuses HTTP/2, :class:`H2Unavailable` is raised and the
  CALLER falls back to the serialized-thread path — this module does
  not pretend a fallback happened. A timeout AFTER the burst was sent
  raises :class:`H2ResponseTimeout` instead: the requests are already
  on the wire, so re-firing them (serialized or not) would double-send.
- Governor: the whole burst runs under ONE governor acquisition (the
  caller holds it), so the spend-cap counts N requests as one batch.

The ``h2`` dependency is imported lazily: without it installed the module
imports fine and only the live functions refuse, keeping the rest of the
suite environment-independent.
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

__all__ = [
    "H2RaceError",
    "H2ResponseTimeout",
    "H2Unavailable",
    "RaceRequestSpec",
    "RaceResult",
    "run_race",
]

DEFAULT_MAX_REQUESTS = 50
H2_ALPN = b"h2"


class H2RaceError(ValueError):
    """Raised when a single-packet race cannot be run fail-closed."""


class H2Unavailable(H2RaceError):
    """The target does not speak HTTP/2, or the h2 library is missing."""


class H2ResponseTimeout(H2RaceError):
    """The burst was SENT but not all responses arrived in time.

    Distinct from pre-send refusals on purpose: by the time this is
    raised the requests are already on the wire, so the caller must
    NOT re-fire them (a serialized fallback would double-fire a race
    that may have partially landed). Callers record failed steps and
    stop.
    """


@dataclass(frozen=True)
class RaceRequestSpec:
    """One request in the burst (method/path/headers/body, no secrets)."""

    method: str = "POST"
    url: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes | None = None


@dataclass(frozen=True)
class RaceResult:
    """What the burst produced, with the transport stated honestly."""

    transport: str  # "h2_single_packet"
    streams: int
    responses: "tuple[dict[str, Any], ...]"
    elapsed_s: float


def _authority_and_path(url: str) -> "tuple[str, str, bool, str, int]":
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise H2RaceError("h2_race_scheme_must_be_http_or_https")
    host = parts.hostname or ""
    if not host:
        raise H2RaceError("h2_race_host_required")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, path, parts.scheme == "https", host, port


def _import_h2() -> Any:
    try:
        import h2.connection  # noqa: PLC0415 - lazy, documented
        import h2.events  # noqa: PLC0415
        return h2
    except ImportError as exc:
        raise H2Unavailable("h2_library_not_installed") from exc


def _connect(
    host: str, port: int, use_tls: bool, timeout_s: float
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout_s)
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.set_alpn_protocols([H2_ALPN.decode()])
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # pentest targets, self-signed
        wrapped = context.wrap_socket(sock, server_hostname=host)
        if wrapped.selected_alpn_protocol() != H2_ALPN.decode():
            wrapped.close()
            raise H2Unavailable("h2_alpn_not_negotiated")
        return wrapped
    return sock


def _drain(sock: socket.socket, conn: Any) -> None:
    payload = conn.data_to_send()
    if payload:
        sock.sendall(payload)


def run_race(
    specs: Sequence[RaceRequestSpec],
    *,
    enable_h2_race: bool,
    timeout_s: float = 10.0,
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> RaceResult:
    """Fire the burst on one H2 connection with a single request flush.

    Raises (never silently downgrades): flag off, budget exceeded, h2
    library missing, or H2 negotiation refused. The caller owns the
    serialized fallback.
    """
    if not enable_h2_race:
        raise H2RaceError("h2_race_flag_off")
    specs = list(specs)
    if not specs:
        raise H2RaceError("h2_race_requires_specs")
    if len(specs) > max_requests:
        raise H2RaceError("h2_race_budget_exceeded")
    h2 = _import_h2()

    host, path0, use_tls, authority, port = _authority_and_path(specs[0].url)
    for spec in specs:
        other_host, _, _, _, other_port = _authority_and_path(spec.url)
        if (other_host, other_port) != (host, port):
            raise H2RaceError("h2_race_requires_single_authority")

    sock = _connect(host, port, use_tls, timeout_s)
    started = time.monotonic()
    responses: list[dict[str, Any]] = []
    try:
        conn = h2.connection.H2Connection()
        conn.initiate_connection()
        _drain(sock, conn)  # preface + SETTINGS

        # Open EVERY stream before flushing once: the burst leaves in a
        # single TCP segment.
        stream_ids: list[int] = []
        for spec in specs:
            stream_id = conn.get_next_available_stream_id()
            stream_ids.append(stream_id)
            headers = [
                (":method", spec.method.upper()),
                (":scheme", "https" if use_tls else "http"),
                (":authority", authority),
                (":path", _authority_and_path(spec.url)[1]),
            ]
            headers.extend(
                (name.lower(), value) for name, value in spec.headers.items()
            )
            conn.send_headers(stream_id, headers, end_stream=spec.body is None)
            if spec.body is not None:
                conn.send_data(stream_id, spec.body, end_stream=True)
        _drain(sock, conn)  # THE single flush

        pending = set(stream_ids)
        buffers: dict[int, dict[str, Any]] = {}
        deadline = started + timeout_s
        while pending and time.monotonic() < deadline:
            data = sock.recv(65536)
            if not data:
                break
            for event in conn.receive_data(data):
                stream_id = getattr(event, "stream_id", None)
                if stream_id not in stream_ids:
                    continue
                state = buffers.setdefault(
                    stream_id, {"status": 0, "headers": [], "body": b""}
                )
                if isinstance(event, h2.events.ResponseReceived):
                    for name, value in event.headers:
                        if name == b":status":
                            state["status"] = int(value)
                    state["headers"].extend(
                        (n.decode("latin-1"), v.decode("latin-1"))
                        for n, v in event.headers
                    )
                elif isinstance(event, h2.events.DataReceived):
                    state["body"] += event.data
                elif isinstance(event, h2.events.StreamEnded):
                    pending.discard(stream_id)
            _drain(sock, conn)
        elapsed = time.monotonic() - started
        if pending:
            raise H2ResponseTimeout("h2_race_response_timeout")
        responses = [buffers[sid] for sid in stream_ids]
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return RaceResult(
        transport="h2_single_packet",
        streams=len(specs),
        responses=tuple(responses),
        elapsed_s=elapsed,
    )
