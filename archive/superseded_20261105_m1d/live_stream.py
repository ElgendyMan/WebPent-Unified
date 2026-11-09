# src/webpent/api/live_stream.py
"""Live ops stream (PROPOSALS_ULTIMATE_V2 §12, 2026-10-31).

An SSE endpoint over ``StreamingResponse`` (no new dependencies) that
broadcasts campaign state as it stands RIGHT NOW: one event = one JSON
line from the current ``status_snapshot`` — kill-switch state, request
ledger, LLM spend, the last target-selection recommendation. No new
state is stored anywhere: the stream is a read-only view over what
already exists, polled on an interval.

Flag-gated by ``enable_live_stream`` (default False): with the flag off
the route refuses before any snapshot is built, so a stream the
operator never asked for can never start. Client disconnects close the
generator cleanly (the async generator is cancelled by the transport;
nothing is buffered on close).
"""

from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any

__all__ = [
    "STREAM_ROUTE_PATH",
    "DEFAULT_POLL_SECONDS",
    "MIN_POLL_SECONDS",
    "MAX_POLL_SECONDS",
    "LiveStreamError",
    "live_stream_refusal",
    "clamp_poll_seconds",
    "event_stream",
    "sse_frame",
]

STREAM_ROUTE_PATH = "/api/v1/stream"

DEFAULT_POLL_SECONDS = 1.0
MIN_POLL_SECONDS = 0.05
MAX_POLL_SECONDS = 30.0


class LiveStreamError(ValueError):
    """Raised when the live stream cannot proceed fail-closed."""


def live_stream_refusal() -> str | None:
    """Refusal code when the operator's flag is off, else None.

    Reads settings through ``webpent.config.settings.get_settings`` at
    call time so target-scoped activation and test overrides behave the
    same as everywhere else in the API layer.
    """
    from webpent.config.settings import get_settings

    if not get_settings().enable_live_stream:
        return "live_stream_flag_off"
    return None


def clamp_poll_seconds(value: float) -> float:
    """Clamp the poll interval into [MIN_POLL_SECONDS, MAX_POLL_SECONDS]."""
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise LiveStreamError(f"live_stream_invalid_poll_seconds: {value!r}") from exc
    if value != value or value in (float("inf"), float("-inf")):  # NaN check
        raise LiveStreamError(f"live_stream_invalid_poll_seconds: {value!r}")
    return max(MIN_POLL_SECONDS, min(MAX_POLL_SECONDS, value))


def sse_frame(seq: int, snapshot: dict[str, Any]) -> str:
    """Format one snapshot as a single SSE frame (one JSON line)."""
    payload = {"seq": seq, "ts": time.time(), "snapshot": snapshot}
    return f"event: snapshot\ndata: {json.dumps(payload, sort_keys=True)}\n\n"


async def event_stream(
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    max_events: int | None = None,
) -> AsyncIterator[str]:
    """Yield SSE frames of the current status snapshot until closed.

    No new state is stored: each frame re-reads ``safety_snapshot()``
    (which never raises). ``max_events`` bounds the stream for callers
    that want a finite view (and for tests); ``None`` streams until the
    client disconnects, at which point the transport cancels this
    generator and it returns cleanly.
    """
    interval = clamp_poll_seconds(poll_seconds)
    if max_events is not None:
        max_events = max(0, int(max_events))
    seq = 0
    try:
        from webpent.safety.status_snapshot import safety_snapshot

        while max_events is None or seq < max_events:
            yield sse_frame(seq, safety_snapshot())
            seq += 1
            if max_events is not None and seq >= max_events:
                break
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        # Clean close on client disconnect: no error, no partial frame.
        return
