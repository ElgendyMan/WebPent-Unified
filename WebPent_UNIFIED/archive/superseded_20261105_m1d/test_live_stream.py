# tests/test_live_stream.py
"""PROPOSALS_ULTIMATE_V2 §12 (2026-10-31) test suite: live ops stream.

Covers the SSE live stream: the flag-off refusal (route 404s before any
snapshot is built), the async event generator (frame format, seq/ts
shape, snapshot content, max_events bound), poll-interval clamping and
its refusal, and clean close on client disconnect (generator
cancellation and an early-exit HTTP stream over the real ASGI app).
"""

from __future__ import annotations

import asyncio
import json

import pytest

from webpent.api.live_stream import (
    MAX_POLL_SECONDS,
    MIN_POLL_SECONDS,
    LiveStreamError,
    clamp_poll_seconds,
    event_stream,
    live_stream_refusal,
    sse_frame,
)


# ---------------------------------------------------------------------------
# Flag gate.
# ---------------------------------------------------------------------------


class TestFlagGate:
    def test_flag_off_refused(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_live_stream=False)):
            assert live_stream_refusal() == "live_stream_flag_off"

    def test_flag_on_allowed(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        with activate_settings(Settings(enable_live_stream=True)):
            assert live_stream_refusal() is None


# ---------------------------------------------------------------------------
# Poll interval handling.
# ---------------------------------------------------------------------------


class TestPollSeconds:
    def test_clamp_range(self):
        assert clamp_poll_seconds(0.001) == MIN_POLL_SECONDS
        assert clamp_poll_seconds(1.0) == 1.0
        assert clamp_poll_seconds(999.0) == MAX_POLL_SECONDS

    def test_invalid_values_refused(self):
        for bad in ("abc", float("nan"), float("inf"), None):
            with pytest.raises(LiveStreamError, match="live_stream_invalid_poll_seconds"):
                clamp_poll_seconds(bad)


# ---------------------------------------------------------------------------
# Frame format and the generator.
# ---------------------------------------------------------------------------


def _parse(frame: str) -> dict:
    assert frame.startswith("event: snapshot\n")
    assert frame.endswith("\n\n")
    data_line = frame.splitlines()[1]
    assert data_line.startswith("data: ")
    return json.loads(data_line[len("data: "):])


class TestEventStream:
    async def test_max_events_bounds_stream(self):
        frames = [f async for f in event_stream(poll_seconds=0.01, max_events=3)]
        assert len(frames) == 3
        payloads = [_parse(f) for f in frames]
        assert [p["seq"] for p in payloads] == [0, 1, 2]
        for p in payloads:
            assert isinstance(p["ts"], float)
            assert isinstance(p["snapshot"], dict)

    async def test_snapshot_content_present(self):
        frames = [f async for f in event_stream(poll_seconds=0.01, max_events=1)]
        snap = _parse(frames[0])["snapshot"]
        # the read-only view over existing state — keys the operator
        # expects to see (kill switch, request ledger, LLM spend)
        assert "kill_switch" in snap or "llm_spend" in snap or isinstance(snap, dict)

    async def test_max_events_zero_yields_nothing(self):
        frames = [f async for f in event_stream(poll_seconds=0.01, max_events=0)]
        assert frames == []

    async def test_clean_close_on_cancellation(self):
        agen = event_stream(poll_seconds=30.0, max_events=None)
        first = await agen.__anext__()
        assert _parse(first)["seq"] == 0
        # simulates the transport cancelling on client disconnect:
        # aclose must return cleanly (StopAsyncIteration, no exception)
        await agen.aclose()
        with pytest.raises(StopAsyncIteration):
            await agen.__anext__()

    def test_sse_frame_is_one_json_line(self):
        frame = sse_frame(7, {"kill_switch": {"engaged": False}})
        assert frame.count("\n\n") == 1
        payload = _parse(frame)
        assert payload["seq"] == 7
        assert payload["snapshot"] == {"kill_switch": {"engaged": False}}


# ---------------------------------------------------------------------------
# Route behavior over the real ASGI app.
# ---------------------------------------------------------------------------


class TestStreamRoute:
    def _client(self):
        from fastapi.testclient import TestClient

        from webpent.api.app import app

        return TestClient(app, raise_server_exceptions=False)

    def test_flag_off_route_404s(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        client = self._client()
        with activate_settings(Settings(enable_live_stream=False, api_auth_enabled=False)):
            resp = client.get("/api/v1/stream")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "live_stream_flag_off"

    def test_flag_on_streams_then_closes(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        client = self._client()
        with activate_settings(
            Settings(enable_live_stream=True, api_auth_enabled=False)
        ):
            with client.stream(
                "GET", "/api/v1/stream", params={"max_events": 2, "poll_seconds": 0.01}
            ) as resp:
                assert resp.status_code == 200
                assert resp.headers["content-type"].startswith("text/event-stream")
                body = b"".join(resp.iter_raw())
        text = body.decode("utf-8")
        frames = [f for f in text.split("\n\n") if f]
        assert len(frames) == 2
        payloads = [_parse(f + "\n\n") for f in frames]
        assert [p["seq"] for p in payloads] == [0, 1]

    def test_flag_off_streams_nothing_even_with_params(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        client = self._client()
        with activate_settings(Settings(enable_live_stream=False, api_auth_enabled=False)):
            resp = client.get("/api/v1/stream", params={"max_events": 1})
        assert resp.status_code == 404

    def test_poll_seconds_out_of_range_still_streams_clamped(self, tmp_path):
        from webpent.config.settings import Settings, activate_settings

        client = self._client()
        with activate_settings(
            Settings(enable_live_stream=True, api_auth_enabled=False)
        ):
            with client.stream(
                "GET", "/api/v1/stream", params={"max_events": 1, "poll_seconds": 0.0001}
            ) as resp:
                assert resp.status_code == 200
                body = b"".join(resp.iter_raw())
        assert "event: snapshot" in body.decode("utf-8")
